package io.github.erwsim.watchpost.core.command

import io.github.erwsim.watchpost.core.command.CommandVerifier.Verification
import io.github.erwsim.watchpost.core.testing.CommandKit
import io.github.erwsim.watchpost.core.testing.CommandVector
import io.github.erwsim.watchpost.core.testing.MemoryPrefs
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Contract §8, additional precisions, on the agent side:
 * validity of `wipe` (24 h at most), consumption of sensitive commands refused `disabled` or
 * `no_code_configured`, separators U+2028/U+2029 in the lock message, floor of the command passphrase.
 */
class CommandEdgeCasesTest {
    private fun Verification.reason(): String = (this as? Verification.Refused)?.reason ?: "accepted"

    @Test
    fun `a wipe valid for more than 24 hours is refused expired, lock keeps its 30 days`() {
        val kit = CommandKit()
        val ok = kit.env(wipeAllowed = true)
        val issued = kit.clock.now - 60_000
        // 24 h exactly: accepted.
        val (id1, p1) = kit.payload("wipe", issuedAtMs = issued, expiresAtMs = issued + 86_400_000)
        assertEquals("accepted", kit.verifier.verify(kit.sign(id1, p1), ok).reason())
        // 24 h + 1 ms: expired, and not consumed (it can never run).
        val (id2, p2) = kit.payload("wipe", issuedAtMs = issued, expiresAtMs = issued + 86_400_001)
        assertEquals(Refusal.EXPIRED, kit.verifier.verify(kit.sign(id2, p2), ok).reason())
        assertFalse(kit.state.wasSeen(id2))
        // The 7-day default of the other sensitive commands is still accepted for lock.
        val (id3, p3) = kit.payload("lock", issuedAtMs = issued, expiresAtMs = issued + 7 * 86_400_000L)
        assertEquals("accepted", kit.verifier.verify(kit.sign(id3, p3), kit.env()).reason())
        // A 7-day wipe (above the 24 h wipe cap) refused while the switch is off is not consumed either: it would be
        // expired anyway once the switch is on.
        val (id4, p4) = kit.payload("wipe", issuedAtMs = issued, expiresAtMs = issued + 7 * 86_400_000L)
        assertEquals(Refusal.DISABLED, kit.verifier.verify(kit.sign(id4, p4), kit.env(wipeAllowed = false)).reason())
        assertEquals(Refusal.EXPIRED, kit.verifier.verify(kit.sign(id4, p4), ok).reason())
    }

    @Test
    fun `a sensitive command refused no_code_configured is consumed and never runs once the code is set`() {
        val statePrefs = MemoryPrefs()
        val keyPrefs = MemoryPrefs()
        val noCode = CommandKit(statePrefs = statePrefs, keyPrefs = keyPrefs, configureKey = false)
        val lock = noCode.signed("lock")
        assertEquals(Refusal.NO_CODE_CONFIGURED, noCode.verifier.verify(lock, noCode.env()).reason())
        assertTrue(noCode.state.wasSeen(lock.id))
        // The user sets the passphrase afterwards (same state on disk): the command stays consumed.
        val withCode = CommandKit(statePrefs = statePrefs, keyPrefs = keyPrefs, clock = noCode.clock)
        assertEquals(Refusal.REPLAY, withCode.verifier.verify(lock, withCode.env()).reason())
        // A new command signed after the code was set runs.
        assertEquals("accepted", withCode.verifier.verify(withCode.signed("lock"), withCode.env()).reason())
        // A simple command is not consumed by a no_code_configured refusal (it needs no code).
        assertEquals("accepted", noCode.verifier.verify(noCode.simple("ring"), noCode.env()).reason())
    }

    @Test
    fun `a sensitive command refused because the channel is off is consumed, a simple one is not`() {
        val kit = CommandKit()
        val wipe = kit.signed("wipe")
        val ring = kit.simple("ring")
        assertEquals(Refusal.DISABLED, kit.verifier.verify(wipe, kit.env(channelEnabled = false, wipeAllowed = true)).reason())
        assertEquals(Refusal.DISABLED, kit.verifier.verify(ring, kit.env(channelEnabled = false)).reason())
        assertEquals(Refusal.REPLAY, kit.verifier.verify(wipe, kit.env(wipeAllowed = true)).reason())
        assertEquals("accepted", kit.verifier.verify(ring, kit.env()).reason())
    }

    @Test
    fun `unverified consumption never evicts a verified signed id`() {
        val kit = CommandKit()
        val executed = kit.signed("lock")
        assertEquals("accepted", kit.verifier.verify(executed, kit.env()).reason())
        // A compromised server floods the phone while no code is set: the forged ids fill the unverified window only.
        val noCode = CommandKit(statePrefs = kit.statePrefs, clock = kit.clock, configureKey = false)
        repeat(CommandStateStore.REPLAY_WINDOW + 20) {
            assertEquals(Refusal.NO_CODE_CONFIGURED, noCode.verifier.verify(noCode.signed("lock", key = ByteArray(32)), noCode.env()).reason())
        }
        assertEquals(Refusal.REPLAY, kit.verifier.verify(executed, kit.env()).reason())
    }

    @Test
    fun `routing fields of another device or an expired command are not consumed`() {
        val kit = CommandKit(configureKey = false)
        val (id1, p1) = kit.payload("lock", device = "dev_other")
        kit.verifier.verify(kit.sign(id1, p1), kit.env(channelEnabled = false))
        assertFalse(kit.state.wasSeen(id1))
        val (id2, p2) = kit.payload("lock", issuedAtMs = kit.clock.now - 7_200_000, expiresAtMs = kit.clock.now - 3_600_000)
        assertEquals(Refusal.NO_CODE_CONFIGURED, kit.verifier.verify(kit.sign(id2, p2), kit.env()).reason())
        assertFalse(kit.state.wasSeen(id2))
    }

    @Test
    fun `line and paragraph separators are refused in the lock message`() {
        val kit = CommandKit()
        assertEquals(Refusal.BAD_PARAMS, kit.verifier.verify(kit.signed("lock", "{\"message\":\"a\\u2028b\"}"), kit.env()).reason())
        assertEquals(Refusal.BAD_PARAMS, kit.verifier.verify(kit.signed("lock", "{\"message\":\"a\\u2029b\"}"), kit.env()).reason())
        assertEquals(Refusal.BAD_PARAMS, kit.verifier.verify(kit.signed("lock", "{\"message\":\"a\\u0007b\"}"), kit.env()).reason())
        assertEquals("accepted", kit.verifier.verify(kit.signed("lock", "{\"message\":\"line 1\\nline 2\"}"), kit.env()).reason())
    }

    @Test
    fun `the passphrase floor is enforced`() {
        assertTrue(CommandCrypto.isTooWeak("aaaaabbbbbcc")) // 3 distinct characters
        assertTrue(CommandCrypto.isTooWeak("1234567890123")) // digits only, fewer than 20
        assertFalse(CommandCrypto.isTooWeak("12345678901234567890"))
        assertFalse(CommandCrypto.isTooWeak(CommandVector.CODE))
    }
}
