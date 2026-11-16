package io.github.erwsim.vigie

import io.github.erwsim.vigie.core.command.CommandEnvelope
import io.github.erwsim.vigie.core.command.CommandExecutor
import io.github.erwsim.vigie.core.command.CommandProcessor
import io.github.erwsim.vigie.core.command.CommandTypes
import io.github.erwsim.vigie.core.command.CommandVerifier
import io.github.erwsim.vigie.core.command.ExecutionResult
import io.github.erwsim.vigie.core.command.LocateExecutor
import io.github.erwsim.vigie.core.command.WipeGate
import io.github.erwsim.vigie.core.testing.CommandKit
import io.github.erwsim.vigie.core.testing.Contract
import io.github.erwsim.vigie.core.testing.RecordingSink
import io.github.erwsim.vigie.policy.remote.ClearLockMessageExecutor
import io.github.erwsim.vigie.policy.remote.LockExecutor
import io.github.erwsim.vigie.policy.remote.LockScreenGateway
import io.github.erwsim.vigie.policy.remote.WipeExecutor
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Contract §8 conformity of `command.result` as the APK produces it: every command type, every outcome
 * (executed, failed, each refusal reason) and an unreadable delivery go through the real verifier and
 * processor with the APK's `:core` and `:policy` executors (platform calls faked); each event is checked
 * against [Contract] (fields, JSON types, closed lists) and against the severities of the contract.
 */
class CommandResultContractTest {
    private val lockScreen = object : LockScreenGateway {
        var owner = true
        override fun isDeviceOwner() = owner
        override fun lockNow() = Unit
        override fun setLockScreenInfo(info: String?) = Unit
        override fun lockScreenInfo(): String? = null
    }

    @Test
    fun everyOutcomeFollowsTheContract() = runBlocking {
        val kit = CommandKit()
        val sink = RecordingSink()
        var channelOn = true
        var wipeAllowed = true
        var owner = true
        val wipes = java.util.concurrent.atomic.AtomicInteger()
        val processor = CommandProcessor(
            clock = kit.clock,
            verifier = kit.verifier,
            state = kit.state,
            sink = sink,
            environment = { CommandVerifier.Environment(channelOn, kit.deviceId, wipeAllowed) { owner } },
            executors = {
                mapOf<String, CommandExecutor>(
                    CommandTypes.RING to CommandExecutor { ExecutionResult.executed("dnd_alarms_muted") },
                    CommandTypes.VIBRATE to CommandExecutor { ExecutionResult.failed("no_vibrator") },
                    CommandTypes.STOP_RING to CommandExecutor { ExecutionResult.executed("not_ringing") },
                    // No collector host on the JVM: the real executor fails cleanly.
                    CommandTypes.LOCATE to LocateExecutor({ null }),
                    CommandTypes.LOCK to LockExecutor(lockScreen),
                    CommandTypes.CLEAR_LOCK_MESSAGE to ClearLockMessageExecutor(lockScreen),
                    CommandTypes.WIPE to WipeExecutor(
                        { WipeGate.Live(channelOn, kit.keys.isConfigured(kit.deviceId), wipeAllowed, kit.clock.now) },
                        { owner },
                        { wipes.incrementAndGet() },
                    ),
                )
            },
            hooks = object : CommandProcessor.Hooks {
                override suspend fun beforeIrreversible(timeoutMs: Long) = Unit
            },
        )

        // Executed / failed, every type.
        processor.process(kit.simple("ring"))
        processor.process(kit.simple("vibrate", """{"duration_s":5}"""))
        processor.process(kit.simple("stop_ring"))
        processor.process(kit.simple("locate"))
        processor.process(kit.signed("lock", """{"message":"Rapportez-le, merci"}"""))
        processor.process(kit.signed("clear_lock_message"))
        processor.process(kit.signed("wipe"))
        assertEquals(1, wipes.get())

        // Every refusal reason.
        processor.process(CommandEnvelope(kit.newId(), "{", null)) // malformed
        val (otherId, otherPayload) = kit.payload("ring", device = "dev_other")
        processor.process(CommandEnvelope(otherId, otherPayload, null)) // wrong_device
        processor.process(kit.simple("reboot")) // unknown_type
        processor.process(kit.simple("ring", """{"duration_s":999}""")) // bad_params
        val (oldId, oldPayload) = kit.payload("ring", issuedAtMs = kit.clock.now - 7_200_000, expiresAtMs = kit.clock.now - 3_600_000)
        processor.process(CommandEnvelope(oldId, oldPayload, null)) // expired
        val replayed = kit.signed("lock")
        kit.state.markSeen(replayed.id, signed = true) // in the window, but no result remembered
        processor.process(replayed) // replay
        owner = false
        processor.process(kit.signed("lock")) // not_device_owner
        owner = true
        wipeAllowed = false
        processor.process(kit.signed("wipe")) // disabled (wipe not allowed)
        wipeAllowed = true
        channelOn = false
        processor.process(kit.simple("ring")) // disabled (channel)
        channelOn = true
        repeat(5) { processor.process(kit.signed("lock", key = ByteArray(32))) } // bad_signature ×5
        processor.process(kit.signed("lock")) // locked_out
        processor.processUnreadable()
        val noCode = CommandKit(configureKey = false)
        val p2 = CommandProcessor(
            noCode.clock, noCode.verifier, noCode.state, sink, { noCode.env() }, { emptyMap() },
            object : CommandProcessor.Hooks {
                override suspend fun beforeIrreversible(timeoutMs: Long) = Unit
            },
        )
        p2.process(noCode.signed("lock")) // no_code_configured
        p2.process(noCode.simple("ring")) // no executor registered → failed "unsupported"

        val results = sink.of("command.result")
        results.forEach { Contract.check(it.type, it.data) }
        val details = results.filter { it.data["status"]!!.jsonPrimitive.content == "refused" }.map { it.data["detail"]!!.jsonPrimitive.content }.toSet()
        assertEquals(Contract.COMMAND_REFUSALS, details)
        assertEquals(Contract.COMMAND_TYPES + "unknown", results.map { it.data["type"]!!.jsonPrimitive.content }.toSet())

        // Severities (contract §8).
        for (r in results) {
            val type = r.data["type"]!!.jsonPrimitive.content
            val status = r.data["status"]!!.jsonPrimitive.content
            val detail = r.data["detail"]!!.jsonPrimitive.content
            val expected = when {
                status == "executed" && type in setOf("lock", "wipe") -> 2
                status == "executed" && type == "clear_lock_message" -> 1
                status == "executed" -> 0
                status == "refused" && detail in setOf("bad_signature", "locked_out") -> 3
                else -> 1
            }
            assertEquals("$type $status $detail", expected, r.sev)
            assertEquals("signed only for verified sensitive commands", type in CommandTypes.SENSITIVE && detail !in setOf("bad_signature", "locked_out", "no_code_configured"), r.data["signed"]!!.jsonPrimitive.content.toBoolean())
        }
        assertTrue(results.any { it.data["detail"]!!.jsonPrimitive.content == "location_unavailable" })
    }
}
