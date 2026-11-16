package io.github.erwsim.watchpost.core.command

import io.github.erwsim.watchpost.core.testing.CommandKit
import io.github.erwsim.watchpost.core.testing.MemoryPrefs
import io.github.erwsim.watchpost.core.testing.RecordingSink
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import java.util.concurrent.atomic.AtomicInteger

/** Contract §8 "Renvoi": a command delivered again is answered with its original result, never re-run. */
class CommandProcessorTest {
    private fun processor(kit: CommandKit, sink: RecordingSink, rings: AtomicInteger) = CommandProcessor(
        clock = kit.clock,
        verifier = kit.verifier,
        state = kit.state,
        sink = sink,
        environment = { kit.env() },
        executors = { mapOf(CommandTypes.RING to CommandExecutor { rings.incrementAndGet(); ExecutionResult.executed("dnd_alarms_muted") }) },
        hooks = object : CommandProcessor.Hooks {
            override suspend fun beforeIrreversible(timeoutMs: Long) = Unit
        },
    )

    @Test
    fun aRingDeliveredAgainIsNotRungAgainEvenAfterARestart() = runBlocking {
        val statePrefs = MemoryPrefs()
        val kit = CommandKit(statePrefs = statePrefs)
        val sink = RecordingSink()
        val rings = AtomicInteger()
        val ring = kit.simple("ring")
        processor(kit, sink, rings).process(ring)
        kit.state.removePendingResult(ring.id) // acknowledged, then the server delivers it again (5 min later)
        // Restart: new objects on the same storage.
        val again = CommandKit(statePrefs = statePrefs, clock = kit.clock)
        val p2 = processor(again, sink, rings)
        repeat(3) {
            kit.clock.advance(5 * 60_000)
            assertNull(p2.process(ring))
        }
        assertEquals(1, rings.get())
        assertEquals(1, sink.of("command.result").size)
        val resent = again.state.pendingResults().single()
        assertEquals(ring.id, resent.id)
        assertEquals("executed", resent.status)
        assertEquals("dnd_alarms_muted", resent.detail)
    }

    /**
     * The server keeps every signed command until it expires (7 days by default). A `wipe` refused because the
     * permission was off must not run when the server delivers it again after the owner switched the permission
     * on — not even once unsigned traffic (which a compromised server produces at will) has pushed its result
     * out of the result memory.
     */
    @Test
    fun aWipeRefusedWhileNotAllowedNeverRunsLaterEvenAfterTheResultMemoryIsFlooded() = runBlocking {
        val kit = CommandKit()
        val sink = RecordingSink()
        val wipes = AtomicInteger()
        var wipeAllowed = false
        val p = CommandProcessor(
            clock = kit.clock,
            verifier = kit.verifier,
            state = kit.state,
            sink = sink,
            environment = { kit.env(wipeAllowed = wipeAllowed) },
            executors = { mapOf(CommandTypes.WIPE to CommandExecutor { wipes.incrementAndGet(); ExecutionResult.executed() }) },
            hooks = object : CommandProcessor.Hooks {
                override suspend fun beforeIrreversible(timeoutMs: Long) = Unit
            },
        )
        val wipe = kit.signed("wipe")
        assertEquals("disabled", p.process(wipe)!!.detail)
        kit.state.removePendingResult(wipe.id) // acknowledged by the server
        // Unsigned traffic until the refusal is no longer remembered.
        repeat(CommandStateStore.RESULT_MEMORY + 10) {
            val filler = kit.simple("stop_ring")
            p.process(filler)
            kit.state.removePendingResult(filler.id)
        }
        assertNull(kit.state.originalResult(wipe.id))
        wipeAllowed = true
        val again = p.process(wipe)
        assertEquals(0, wipes.get())
        assertEquals("refused", again!!.status)
        assertEquals("replay", again.detail)
    }

    @Test
    fun aRefusalIsAlsoAnsweredWithTheOriginalRefusal() = runBlocking {
        val kit = CommandKit()
        val sink = RecordingSink()
        val rings = AtomicInteger()
        val p = processor(kit, sink, rings)
        val bad = kit.simple("ring", """{"duration_s":0}""")
        assertEquals("bad_params", p.process(bad)!!.detail)
        kit.state.removePendingResult(bad.id)
        assertNull(p.process(bad))
        assertEquals("bad_params", kit.state.pendingResults().single().detail)
        assertEquals(0, rings.get())
    }
}
