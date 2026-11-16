package io.github.erwsim.watchpost.policy

import io.github.erwsim.watchpost.core.command.CommandEnvelope
import io.github.erwsim.watchpost.core.command.CommandExecutor
import io.github.erwsim.watchpost.core.command.CommandProcessor
import io.github.erwsim.watchpost.core.command.CommandTypes
import io.github.erwsim.watchpost.core.command.CommandVerifier
import io.github.erwsim.watchpost.core.command.WipeGate
import io.github.erwsim.watchpost.core.testing.CommandKit
import io.github.erwsim.watchpost.core.testing.RecordingSink
import io.github.erwsim.watchpost.policy.remote.ClearLockMessageExecutor
import io.github.erwsim.watchpost.policy.remote.FactoryReset
import io.github.erwsim.watchpost.policy.remote.LockExecutor
import io.github.erwsim.watchpost.policy.remote.LockScreenGateway
import io.github.erwsim.watchpost.policy.remote.WipeExecutor
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.util.concurrent.atomic.AtomicInteger

/**
 * Contract §8 Device Owner commands. The wipe guard matrix: every combination of the six conditions
 * (channel on, code set, valid signature, "Allow remote erase" on, not expired, never
 * seen) goes through the real verifier, processor and [WipeExecutor]; the (fake) reset runs only when
 * all six hold. No test can reach the real reset: it exists only in `AndroidFactoryReset`.
 */
class RemoteCommandsPolicyTest {
    private class RecordingReset : FactoryReset {
        val calls = AtomicInteger()
        override fun wipe() {
            calls.incrementAndGet()
        }
    }

    private class FakeLockScreen(var owner: Boolean = true) : LockScreenGateway {
        val calls = ArrayList<String>()
        var info: String? = null
        override fun isDeviceOwner() = owner
        override fun lockNow() {
            calls += "lockNow"
        }
        override fun setLockScreenInfo(info: String?) {
            calls += "info=$info"
            this.info = info
        }
        override fun lockScreenInfo() = info
    }

    private class Setup(
        val channelEnabled: Boolean = true,
        codeConfigured: Boolean = true,
        val wipeAllowed: Boolean = true,
        val deviceOwner: Boolean = true,
        val lockScreen: FakeLockScreen = FakeLockScreen(),
    ) {
        val kit = CommandKit(configureKey = codeConfigured)
        val sink = RecordingSink()
        val reset = RecordingReset()

        @Volatile var liveWipeAllowed = wipeAllowed
        val beforeIrreversible = AtomicInteger()

        val processor = CommandProcessor(
            clock = kit.clock,
            verifier = kit.verifier,
            state = kit.state,
            sink = sink,
            environment = { CommandVerifier.Environment(channelEnabled, kit.deviceId, wipeAllowed) { deviceOwner } },
            executors = {
                mapOf<String, CommandExecutor>(
                    CommandTypes.WIPE to WipeExecutor(
                        live = { WipeGate.Live(channelEnabled, kit.keys.isConfigured(kit.deviceId), liveWipeAllowed, kit.clock.now) },
                        isDeviceOwner = { deviceOwner },
                        reset = reset,
                    ),
                    CommandTypes.LOCK to LockExecutor(lockScreen),
                    CommandTypes.CLEAR_LOCK_MESSAGE to ClearLockMessageExecutor(lockScreen),
                )
            },
            hooks = object : CommandProcessor.Hooks {
                override suspend fun beforeIrreversible(timeoutMs: Long) {
                    assertEquals(10_000L, timeoutMs)
                    beforeIrreversible.incrementAndGet()
                }
            },
        )

        fun process(e: CommandEnvelope) = runBlocking { processor.process(e) }
    }

    @Test
    fun wipeRunsOnlyWhenEverySafeguardHolds() {
        var allowedRuns = 0
        for (mask in 0 until 64) {
            val channel = mask and 1 != 0
            val code = mask and 2 != 0
            val signature = mask and 4 != 0
            val allowed = mask and 8 != 0
            val notExpired = mask and 16 != 0
            val neverSeen = mask and 32 != 0
            val s = Setup(channelEnabled = channel, codeConfigured = code, wipeAllowed = allowed)
            val kit = s.kit
            val id = kit.newId()
            val (_, payload) = if (notExpired) {
                kit.payload("wipe", id = id)
            } else {
                kit.payload("wipe", id = id, issuedAtMs = kit.clock.now - 3 * 86_400_000L, expiresAtMs = kit.clock.now - 86_400_000L)
            }
            val envelope = if (signature) kit.sign(id, payload) else kit.sign(id, payload, key = ByteArray(32) { 7 })
            if (!neverSeen) kit.state.markSeen(id, signed = true)
            val entry = s.process(envelope)!!
            val all = channel && code && signature && allowed && notExpired && neverSeen
            assertEquals("mask=$mask entry=$entry", if (all) 1 else 0, s.reset.calls.get())
            if (all) {
                allowedRuns++
                assertEquals("executed", entry.status)
                // The event and the upload attempt come before the reset.
                assertEquals(1, s.beforeIrreversible.get())
                val e = s.sink.of("command.result").single()
                assertEquals(2, e.sev)
                assertEquals("wipe", e.data["type"]!!.jsonPrimitive.content)
            } else {
                assertEquals("mask=$mask", "refused", entry.status)
                assertEquals(0, s.beforeIrreversible.get())
            }
        }
        assertEquals(1, allowedRuns)
    }

    @Test
    fun wipeIsRefusedWhenTheSettingIsTurnedOffBeforeTheResetOrTheRoleIsLost() {
        val s = Setup()
        s.liveWipeAllowed = false // switched off by the user during the 10 s upload window
        val entry = s.process(s.kit.signed("wipe"))!!
        assertEquals(0, s.reset.calls.get())
        assertEquals("refused", entry.status)
        assertEquals("disabled", entry.detail)
        // Two results for the same id: the announcement, then the refusal, which replaces it in the queue.
        assertEquals(listOf("executed", "refused"), s.sink.of("command.result").map { it.data["status"]!!.jsonPrimitive.content })
        assertEquals("refused", s.kit.state.pendingResults().single().status)

        val notOwner = Setup(deviceOwner = false)
        val refused = notOwner.process(notOwner.kit.signed("wipe"))!!
        assertEquals("not_device_owner", refused.detail)
        assertEquals(0, notOwner.reset.calls.get())
    }

    /**
     * Contract §8 "Renvoi": the server delivers a command again when its result did not arrive. The agent
     * answers with the original result and never executes again — for wipe, lock and ring alike.
     */
    @Test
    fun aRedeliveredCommandIsAnsweredWithItsOriginalResultAndNeverRunAgain() {
        val screen = FakeLockScreen()
        val s = Setup(lockScreen = screen)
        val wipe = s.kit.signed("wipe")
        val lock = s.kit.signed("lock", """{"message":"Lost"}""")
        s.process(wipe)
        s.process(lock)
        assertEquals(1, s.reset.calls.get())
        val eventsBefore = s.sink.events.size
        for (round in 1..3) {
            // Result acknowledged (or lost): the server delivers the same command again.
            s.kit.state.removePendingResult(wipe.id)
            s.kit.state.removePendingResult(lock.id)
            s.liveWipeAllowed = round != 2 // even with the gate open again, nothing runs twice
            assertNull(s.process(wipe))
            assertNull(s.process(lock))
            // Delivered twice before the result could be posted: still nothing.
            assertNull(s.process(wipe))
        }
        assertEquals(1, s.reset.calls.get())
        assertEquals(listOf("info=Lost", "lockNow"), screen.calls)
        assertEquals("no new event, no new history line", eventsBefore, s.sink.events.size)
        assertEquals(2, s.kit.state.history.value.size)
        val pending = s.kit.state.pendingResults().associateBy { it.id }
        assertEquals("executed", pending[wipe.id]!!.status)
        assertEquals("executed", pending[lock.id]!!.status)
        assertEquals("ok_message", pending[lock.id]!!.detail)
        // Only an id still in the anti-replay window whose result is no longer remembered gets "replay".
        val forgotten = s.kit.signed("wipe")
        s.kit.state.markSeen(forgotten.id, signed = true)
        assertEquals("replay", s.process(forgotten)!!.detail)
        assertEquals(1, s.reset.calls.get())
    }

    @Test
    fun aWipeExecutorNeverRunsAnotherCommand() = runBlocking {
        val s = Setup()
        val v = s.kit.verifier.verify(s.kit.signed("lock"), s.kit.env(wipeAllowed = true)) as CommandVerifier.Verification.Accepted
        val reset = RecordingReset()
        val r = WipeExecutor({ WipeGate.Live(true, true, true, s.kit.clock.now) }, { true }, reset).execute(v.command)
        assertEquals("refused", r.status.wire)
        assertEquals(0, reset.calls.get())
        // A simple command can never satisfy the gate either (no signature).
        val ring = s.kit.verifier.verify(s.kit.simple("ring"), s.kit.env()) as CommandVerifier.Verification.Accepted
        assertTrue(!ring.command.gate.all())
    }

    @Test
    fun lockSetsTheMessageThenLocks() {
        val screen = FakeLockScreen()
        val s = Setup(lockScreen = screen)
        val entry = s.process(s.kit.signed("lock", """{"message":"Lost phone"}"""))!!
        assertEquals("executed", entry.status)
        assertEquals("ok_message", entry.detail)
        assertEquals(listOf("info=Lost phone", "lockNow"), screen.calls)
        assertEquals(2, s.sink.of("command.result").single().sev)
        // Without a message: lock only, the current message is left as it is.
        s.process(s.kit.signed("lock"))
        assertEquals(listOf("info=Lost phone", "lockNow", "lockNow"), screen.calls)
        val cleared = s.process(s.kit.signed("clear_lock_message"))!!
        assertEquals("executed", cleared.status)
        assertNull(screen.info)
        assertEquals(1, s.sink.of("command.result").last().sev)
    }

    @Test
    fun withoutTheDeviceOwnerRoleLockIsRefused() {
        val screen = FakeLockScreen(owner = false)
        // Role lost between verification and execution: the executor checks again.
        val s = Setup(lockScreen = screen, deviceOwner = true)
        val entry = s.process(s.kit.signed("lock", """{"message":"x"}"""))!!
        assertEquals("refused", entry.status)
        assertEquals("not_device_owner", entry.detail)
        assertTrue(screen.calls.isEmpty())
        // Known to the verifier: refused before any executor.
        val s2 = Setup(deviceOwner = false)
        assertEquals("not_device_owner", s2.process(s2.kit.signed("clear_lock_message"))!!.detail)
    }

    /**
     * Static guarantee: the platform reset is called in one file, the real [FactoryReset] is built in one
     * place, and nothing else in the sources of the app calls a wipe API.
     */
    @Test
    fun theRealResetIsIsolated() {
        val root = generateSequence(File("").absoluteFile) { it.parentFile }.first { File(it, "settings.gradle.kts").exists() }
        val sources = root.walkTopDown()
            .onEnter { it.name != "build" && it.name != ".gradle" }
            .filter { it.isFile && it.extension == "kt" && "/src/main/" in it.invariantSeparatorsPath }
            .toList()
        assertTrue(sources.size > 50)
        val wipeCalls = sources.filter { Regex("""\.(wipeDevice|wipeData)\s*\(""").containsMatchIn(it.readText()) }
        assertEquals(listOf("AndroidRemoteGateways.kt"), wipeCalls.map { it.name })
        val builders = sources.filter { Regex("""AndroidFactoryReset\s*\(""").containsMatchIn(it.readText().replace(Regex("class AndroidFactoryReset\\s*\\("), "")) }
        assertEquals(listOf("PolicyModule.kt"), builders.map { it.name })
        // Implementations: classes or objects declaring the interface, or SAM lambdas `FactoryReset { … }`.
        val implementations = sources.filter {
            Regex("""(class\s+\w+\s*(\([^)]*\))?|object)\s*:\s*FactoryReset\b|(?<!interface )FactoryReset\s*\{""").containsMatchIn(it.readText())
        }
        assertEquals(listOf("AndroidRemoteGateways.kt"), implementations.map { it.name })
        // And no other way to the factory reset (MASTER_CLEAR broadcast, recovery).
        val other = sources.filter { Regex("""MASTER_CLEAR|RecoverySystem""").containsMatchIn(it.readText()) }
        assertEquals(emptyList<String>(), other.map { it.name })
    }
}
