package io.github.erwsim.vigie.core.command

import io.github.erwsim.vigie.core.command.CommandVerifier.Verification
import io.github.erwsim.vigie.core.testing.CommandKit
import io.github.erwsim.vigie.core.testing.CommandVector
import io.github.erwsim.vigie.core.testing.MemoryPrefs
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** Contract §8: the test vector, every refusal reason, and the order of the checks. */
class CommandVerifierTest {
    private fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }

    private fun Verification.reason(): String = (this as? Verification.Refused)?.reason ?: "accepted"

    @Test
    fun reproducesTheContractTestVectorToTheByte() {
        assertEquals(CommandVector.KEY_HEX, hex(CommandVector.key))
        assertEquals(CommandVector.SIG, CommandCrypto.sign(CommandVector.key, CommandVector.PAYLOAD))
        // The accented characters are signed as UTF-8 (2 bytes each), not as Latin-1 or UTF-16.
        assertTrue(CommandVector.PAYLOAD.toByteArray(Charsets.UTF_8).size > CommandVector.PAYLOAD.length)
        assertTrue(CommandCrypto.verify(CommandVector.key, CommandVector.PAYLOAD, CommandVector.SIG))
        assertFalse(CommandCrypto.verify(CommandVector.key, CommandVector.PAYLOAD.replace("Téléphone", "Telephone"), CommandVector.SIG))
    }

    @Test
    fun pbkdf2MatchesRfc7914Vectors() {
        // RFC 7914 §11, PBKDF2-HMAC-SHA256 ("passwd", "salt", 1 iteration, 64 bytes).
        val out = CommandCrypto.pbkdf2HmacSha256("passwd".toByteArray(), "salt".toByteArray(), 1, 64)
        assertEquals(
            "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783",
            hex(out),
        )
        val out2 = CommandCrypto.pbkdf2HmacSha256("Password".toByteArray(), "NaCl".toByteArray(), 80000, 64)
        assertEquals(
            "4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d",
            hex(out2),
        )
    }

    @Test
    fun theVectorCommandIsAcceptedWithItsMessage() {
        val kit = CommandKit()
        val v = kit.verifier.verify(CommandEnvelope(CommandVector.ID, CommandVector.PAYLOAD, CommandVector.SIG), kit.env())
        val accepted = (v as Verification.Accepted).command
        assertEquals(CommandTypes.LOCK, accepted.type)
        assertEquals(CommandParams.Lock("Téléphone perdu, appelez le 01 23 45 67 89"), accepted.params)
        assertTrue(accepted.signatureVerified)
        assertTrue(accepted.gate.all().not()) // wipeAllowed false in this environment: the gate records it
    }

    @Test
    fun eachRefusalReasonOfTheContract() {
        val kit = CommandKit()
        val ok = kit.env()
        // disabled
        assertEquals(Refusal.DISABLED, kit.verifier.verify(kit.simple("ring"), kit.env(channelEnabled = false)).reason())
        // malformed: not JSON, v, id mismatch, outer id not a ULID, missing dates, unknown key, signed simple command
        assertEquals(Refusal.MALFORMED, kit.verifier.verify(CommandEnvelope(kit.newId(), "not json", null), ok).reason())
        val (id1, p1) = kit.payload("ring")
        assertEquals(Refusal.MALFORMED, kit.verifier.verify(CommandEnvelope(id1, p1.replace("\"v\":1", "\"v\":2"), null), ok).reason())
        assertEquals(Refusal.MALFORMED, kit.verifier.verify(CommandEnvelope(id1, p1.replace("\"v\":1", "\"v\":\"1\""), null), ok).reason())
        assertEquals(Refusal.MALFORMED, kit.verifier.verify(CommandEnvelope(kit.newId(), p1, null), ok).reason())
        assertEquals(Refusal.MALFORMED, kit.verifier.verify(CommandEnvelope("x", p1.replace(id1, "x"), null), ok).reason())
        assertEquals(Refusal.MALFORMED, kit.verifier.verify(CommandEnvelope(id1, p1.replace(",\"issued_at\"", ",\"issued\""), null), ok).reason())
        assertEquals(Refusal.MALFORMED, kit.verifier.verify(CommandEnvelope(id1, p1.replace("\"params\"", "\"extra\":1,\"params\""), null), ok).reason())
        assertEquals(Refusal.MALFORMED, kit.verifier.verify(kit.signed("ring"), ok).reason())
        // wrong_device (also when not enrolled)
        val (id2, p2) = kit.payload("ring", device = "dev_other")
        assertEquals(Refusal.WRONG_DEVICE, kit.verifier.verify(CommandEnvelope(id2, p2, null), ok).reason())
        assertEquals(Refusal.WRONG_DEVICE, kit.verifier.verify(kit.simple("ring"), kit.env(deviceId = null)).reason())
        // unknown_type
        assertEquals(Refusal.UNKNOWN_TYPE, kit.verifier.verify(kit.simple("set_setting"), ok).reason())
        assertEquals(Refusal.UNKNOWN_TYPE, kit.verifier.verify(kit.simple("format"), ok).reason())
        // no_code_configured
        val noKey = CommandKit(configureKey = false)
        assertEquals(Refusal.NO_CODE_CONFIGURED, noKey.verifier.verify(noKey.signed("lock"), noKey.env()).reason())
        // bad_signature: wrong key, missing sig, garbage sig, one flipped byte of the payload
        assertEquals(Refusal.BAD_SIGNATURE, kit.verifier.verify(kit.signed("lock", key = ByteArray(32)), ok).reason())
        assertEquals(Refusal.BAD_SIGNATURE, kit.verifier.verify(kit.simple("lock"), ok).reason())
        val s = kit.signed("clear_lock_message")
        assertEquals(Refusal.BAD_SIGNATURE, kit.verifier.verify(s.copy(sig = "%%%"), ok).reason())
        assertEquals(Refusal.BAD_SIGNATURE, kit.verifier.verify(s.copy(payload = s.payload.replace("\"params\":{}", "\"params\":{ }")), ok).reason())
    }

    @Test
    fun remainingRefusals() {
        val kit = CommandKit()
        val ok = kit.env()
        // wipe not allowed locally → disabled (after a valid signature)
        val wipe = kit.verifier.verify(kit.signed("wipe"), kit.env(wipeAllowed = false))
        assertEquals(Refusal.DISABLED, wipe.reason())
        assertTrue(wipe.signed)
        // expired: past expiry + tolerance, issued in the future, validity above 30 days
        val (id1, p1) = kit.payload("ring", issuedAtMs = kit.clock.now - 7_200_000, expiresAtMs = kit.clock.now - 5 * 60_000 - 1)
        assertEquals(Refusal.EXPIRED, kit.verifier.verify(CommandEnvelope(id1, p1, null), ok).reason())
        val (id1b, p1b) = kit.payload("ring", issuedAtMs = kit.clock.now - 7_200_000, expiresAtMs = kit.clock.now - 4 * 60_000)
        assertEquals("accepted", kit.verifier.verify(CommandEnvelope(id1b, p1b, null), ok).reason()) // within tolerance
        val (id2, p2) = kit.payload("ring", issuedAtMs = kit.clock.now + 6 * 60_000, expiresAtMs = kit.clock.now + 3_600_000)
        assertEquals(Refusal.EXPIRED, kit.verifier.verify(CommandEnvelope(id2, p2, null), ok).reason())
        val (id3, p3) = kit.payload("lock", expiresAtMs = kit.clock.now - 60_000 + 31L * 86_400_000)
        assertEquals(Refusal.EXPIRED, kit.verifier.verify(kit.sign(id3, p3), ok).reason())
        // replay
        val ring = kit.simple("ring")
        assertEquals("accepted", kit.verifier.verify(ring, ok).reason())
        assertEquals(Refusal.REPLAY, kit.verifier.verify(ring, ok).reason())
        // bad_params: out of bounds, wrong JSON type, extra parameter, parameter on a type without one, long message
        for (params in listOf(
            """{"duration_s":0}""", """{"duration_s":301}""", """{"duration_s":"60"}""", """{"duration_s":6.5}""",
            """{"vibrate":"yes"}""", """{"duration_s":60,"volume":100}""",
        )) {
            assertEquals(params, Refusal.BAD_PARAMS, kit.verifier.verify(kit.simple("ring", params), ok).reason())
        }
        assertEquals(Refusal.BAD_PARAMS, kit.verifier.verify(kit.simple("vibrate", """{"duration_s":61}"""), ok).reason())
        assertEquals(Refusal.BAD_PARAMS, kit.verifier.verify(kit.simple("locate", """{"provider":"fused"}"""), ok).reason())
        assertEquals(Refusal.BAD_PARAMS, kit.verifier.verify(kit.simple("stop_ring", "[]"), ok).reason())
        assertEquals(Refusal.BAD_PARAMS, kit.verifier.verify(kit.signed("lock", """{"message":"${"x".repeat(201)}"}"""), ok).reason())
        assertEquals(Refusal.BAD_PARAMS, kit.verifier.verify(kit.signed("lock", """{"message":42}"""), ok).reason())
        assertEquals("accepted", kit.verifier.verify(kit.signed("lock", """{"message":"${"é".repeat(200)}"}"""), ok).reason())
        // not_device_owner
        assertEquals(Refusal.NOT_DEVICE_OWNER, kit.verifier.verify(kit.signed("lock"), kit.env(deviceOwner = false)).reason())
        assertEquals("accepted", kit.verifier.verify(kit.simple("ring"), kit.env(deviceOwner = false)).reason())
        // Defaults of the contract.
        val accepted = kit.verifier.verify(kit.simple("ring"), ok) as Verification.Accepted
        assertEquals(CommandParams.Ring(60, true), accepted.command.params)
        val vib = kit.verifier.verify(kit.simple("vibrate", "{}"), ok) as Verification.Accepted
        assertEquals(CommandParams.Vibrate(10), vib.command.params)
    }

    @Test
    fun checksRunInTheContractOrder() {
        val kit = CommandKit()
        // A command wrong in every way reports the first failing check, step by step.
        val (id, p) = kit.payload("wipe", params = """{"x":1}""", device = "dev_other", expiresAtMs = kit.clock.now - 3_600_000)
        assertEquals(Refusal.DISABLED, kit.verifier.verify(CommandEnvelope(id, p, "bad"), kit.env(channelEnabled = false)).reason())
        assertEquals(Refusal.WRONG_DEVICE, kit.verifier.verify(CommandEnvelope(id, p, "bad"), kit.env()).reason())
        val (id2, p2) = kit.payload("wipe", params = """{"x":1}""", issuedAtMs = kit.clock.now - 7_200_000, expiresAtMs = kit.clock.now - 3_600_000)
        assertEquals(Refusal.BAD_SIGNATURE, kit.verifier.verify(CommandEnvelope(id2, p2, "bad"), kit.env()).reason())
        // Signature checked before the content: a bad signature on an expired, replayed or out-of-bounds command is bad_signature.
        val signedBad = kit.sign(id2, p2)
        assertEquals(Refusal.DISABLED, kit.verifier.verify(signedBad, kit.env(wipeAllowed = false)).reason())
        assertEquals(Refusal.EXPIRED, kit.verifier.verify(signedBad, kit.env(wipeAllowed = true)).reason())
        // expired comes before replay: an expired command is not recorded as seen (not even when it was first
        // refused because wipe is switched off).
        assertFalse(kit.state.wasSeen(id2))
        val (id3, p3) = kit.payload("wipe", params = """{"x":1}""")
        val s3 = kit.sign(id3, p3)
        assertEquals(Refusal.BAD_PARAMS, kit.verifier.verify(s3, kit.env(wipeAllowed = true, deviceOwner = false)).reason())
        // replay before bad_params
        assertEquals(Refusal.REPLAY, kit.verifier.verify(s3, kit.env(wipeAllowed = true, deviceOwner = false)).reason())
        // bad_params before not_device_owner
        val s4 = kit.signed("wipe")
        assertEquals(Refusal.NOT_DEVICE_OWNER, kit.verifier.verify(s4, kit.env(wipeAllowed = true, deviceOwner = false)).reason())
        // unknown type before signature (an unsigned unknown type never counts as a bad signature)
        assertEquals(Refusal.UNKNOWN_TYPE, kit.verifier.verify(kit.simple("erase_all"), kit.env()).reason())
        assertEquals(0L, kit.state.lockedOutUntil(kit.clock.now))
    }

    @Test
    fun aSignedWipeRefusedWhileTheSwitchIsOffIsConsumedForGood() {
        val statePrefs = MemoryPrefs()
        val kit = CommandKit(statePrefs = statePrefs)
        val wipe = kit.signed("wipe")
        assertEquals(Refusal.DISABLED, kit.verifier.verify(wipe, kit.env(wipeAllowed = false)).reason())
        // The owner switches "Autoriser l'effacement à distance" on later (also after a restart): the signed
        // command the server still holds must not run then.
        val later = CommandKit(statePrefs = statePrefs, clock = kit.clock)
        assertEquals(Refusal.REPLAY, later.verifier.verify(wipe, later.env(wipeAllowed = true)).reason())
        // A new command signed after the switch was turned on runs.
        assertEquals("accepted", later.verifier.verify(later.signed("wipe"), later.env(wipeAllowed = true)).reason())
        // Nothing is consumed without a valid signature: a forged wipe cannot use up the signed window.
        val forged = kit.signed("wipe", key = ByteArray(32))
        assertEquals(Refusal.BAD_SIGNATURE, kit.verifier.verify(forged, kit.env(wipeAllowed = false)).reason())
        assertFalse(kit.state.wasSeen(forged.id))
    }

    /**
     * The payload of a simple command is not signed: the server can put anything in it. A few thousand nested
     * arrays must be a plain `malformed` whatever the stack of the thread, not a StackOverflowError (which no
     * `catch (Exception)` stops and which would end the command worker). Without the depth check made before
     * parsing, this test overflows in the JSON parser on its 128 KiB stack.
     */
    @Test
    fun aDeeplyNestedUnsignedPayloadIsRefusedWithoutOverflowingTheStack() {
        val kit = CommandKit()
        val deep = "[".repeat(3_900) + "]".repeat(3_900)
        val (id, p) = kit.payload("ring", params = deep)
        assertTrue(p.length <= CommandVerifier.MAX_PAYLOAD_CHARS)
        var reason: String? = null
        var error: Throwable? = null
        val t = Thread(null, {
            try {
                reason = kit.verifier.verify(CommandEnvelope(id, p, null), kit.env()).reason()
            } catch (e: Throwable) {
                error = e
            }
        }, "small-stack", 128 * 1024)
        t.start()
        t.join()
        assertEquals("$error", Refusal.MALFORMED, reason)
        // Brackets inside strings are text, not nesting.
        assertFalse(JsonNesting.deeperThan("""{"a":"[[[[[[[[[[[[[[[[[[[[","b":"\"[[[[[[[[[[[[[[[[[[[[["}""", 2))
        assertTrue(JsonNesting.deeperThan("""{"a":[[1]]}""", 2))
        assertFalse(JsonNesting.deeperThan("""{"a":[[1]]}""", 3))
        // Nesting the contract never produces, even shallow enough for any stack, is refused the same way.
        val (id2, p2) = kit.payload("ring", params = "[".repeat(17) + "]".repeat(17))
        assertEquals(Refusal.MALFORMED, kit.verifier.verify(CommandEnvelope(id2, p2, null), kit.env()).reason())
        // What the contract allows still passes.
        assertEquals("accepted", kit.verifier.verify(kit.simple("ring", """{"duration_s":5,"vibrate":false}"""), kit.env()).reason())
    }

    @Test
    fun replayProtectionSurvivesARestart() {
        val statePrefs = MemoryPrefs()
        val kit = CommandKit(statePrefs = statePrefs)
        val lock = kit.signed("lock")
        assertEquals("accepted", kit.verifier.verify(lock, kit.env()).reason())
        // "Restart": new objects on the same persisted preferences.
        val again = CommandKit(statePrefs = statePrefs)
        assertEquals(Refusal.REPLAY, again.verifier.verify(lock, again.env()).reason())
    }

    @Test
    fun unsignedTrafficCannotPushSignedIdsOutOfTheWindow() {
        val kit = CommandKit()
        val lock = kit.signed("lock")
        assertEquals("accepted", kit.verifier.verify(lock, kit.env()).reason())
        repeat(CommandStateStore.REPLAY_WINDOW + 10) { kit.verifier.verify(kit.simple("vibrate"), kit.env()) }
        assertEquals(Refusal.REPLAY, kit.verifier.verify(lock, kit.env()).reason())
        // The simple window itself is bounded to 500.
        val first = kit.simple("ring")
        assertEquals("accepted", kit.verifier.verify(first, kit.env()).reason())
        repeat(CommandStateStore.REPLAY_WINDOW) { kit.verifier.verify(kit.simple("vibrate"), kit.env()) }
        assertEquals("accepted", kit.verifier.verify(first, kit.env()).reason())
    }

    @Test
    fun fiveBadSignaturesWithinAnHourLockSensitiveCommandsOutForAnHour() {
        val statePrefs = MemoryPrefs()
        val kit = CommandKit(statePrefs = statePrefs)
        repeat(4) {
            assertEquals(Refusal.BAD_SIGNATURE, kit.verifier.verify(kit.signed("lock", key = ByteArray(32)), kit.env()).reason())
            kit.clock.advance(60_000)
        }
        assertEquals(Refusal.BAD_SIGNATURE, kit.verifier.verify(kit.signed("lock", key = ByteArray(32)), kit.env()).reason())
        // Now even a correctly signed command is refused, and the lock-out survives a restart.
        assertEquals(Refusal.LOCKED_OUT, kit.verifier.verify(kit.signed("lock"), kit.env()).reason())
        val restarted = CommandKit(statePrefs = statePrefs, clock = kit.clock)
        assertEquals(Refusal.LOCKED_OUT, restarted.verifier.verify(restarted.signed("wipe"), restarted.env(wipeAllowed = true)).reason())
        // Simple commands are not affected.
        assertEquals("accepted", restarted.verifier.verify(restarted.simple("ring"), restarted.env()).reason())
        kit.clock.advance(CommandStateStore.LOCKOUT_MS + 1)
        assertEquals("accepted", restarted.verifier.verify(restarted.signed("lock"), restarted.env()).reason())
    }

    @Test
    fun badSignaturesSpreadOverMoreThanAnHourDoNotLock() {
        val kit = CommandKit()
        repeat(8) {
            kit.verifier.verify(kit.signed("lock", key = ByteArray(32)), kit.env())
            kit.clock.advance(16 * 60_000)
        }
        assertEquals("accepted", kit.verifier.verify(kit.signed("lock"), kit.env()).reason())
    }

    @Test
    fun theKeyIsBoundToTheDeviceIdItWasDerivedFor() {
        val kit = CommandKit()
        assertTrue(kit.keys.isConfigured(CommandVector.DEVICE_ID))
        assertFalse(kit.keys.isConfigured("dev_renamed"))
        assertArrayEquals(CommandVector.key, kit.keys.key(CommandVector.DEVICE_ID))
        kit.keys.clear()
        assertFalse(kit.keys.isConfigured(CommandVector.DEVICE_ID))
        assertTrue(kit.box.destroyed)
    }

    @Test
    fun duplicateKeysAndControlCharactersAreRefused() {
        val kit = CommandKit()
        val ok = kit.env()
        // Duplicate key at the top level, in params, or hidden behind an escape: malformed, even when signed.
        val (id1, p1) = kit.payload("lock", """{"message":"a"}""")
        val dup = p1.replace("\"params\"", "\"type\":\"lock\",\"params\"")
        assertEquals(Refusal.MALFORMED, kit.verifier.verify(kit.sign(id1, dup), ok).reason())
        assertEquals(Refusal.MALFORMED, kit.verifier.verify(kit.signed("lock", """{"message":"a","message":"b"}"""), ok).reason())
        assertEquals(Refusal.MALFORMED, kit.verifier.verify(kit.signed("lock", """{"message":"a","\u006dessage":"b"}"""), ok).reason())
        assertEquals(Refusal.MALFORMED, kit.verifier.verify(kit.simple("ring", """{"duration_s":5,"duration_s":300}"""), ok).reason())
        // Nested objects with the same keys in different objects are fine.
        assertTrue(JsonDuplicateKeys.found("""{"a":{"x":1},"b":{"x":[{"x":1},{"x":2}]},"a":0}"""))
        assertFalse(JsonDuplicateKeys.found("""{"a":{"x":1},"b":{"x":[{"x":1},{"x":2}],"s":"\"a\":1,\"a\""}}"""))
        // Lock message: line feed allowed, any other control character refused (the server is not trusted).
        val withLf = kit.verifier.verify(kit.signed("lock", """{"message":"Perdu\nappelez-moi"}"""), ok) as Verification.Accepted
        assertEquals(CommandParams.Lock("Perdu\nappelez-moi"), withLf.command.params)
        assertEquals(Refusal.BAD_PARAMS, kit.verifier.verify(kit.signed("lock", """{"message":"a\tb"}"""), ok).reason())
        assertEquals(Refusal.BAD_PARAMS, kit.verifier.verify(kit.signed("lock", """{"message":"a\u0000b"}"""), ok).reason())
        assertEquals(Refusal.BAD_PARAMS, kit.verifier.verify(kit.signed("lock", """{"message":"a\u202Eb\u0085"}"""), ok).reason())
    }
}
