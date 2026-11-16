package io.github.erwsim.vigie.core.command

import io.github.erwsim.vigie.core.command.CommandVerifier.Verification
import io.github.erwsim.vigie.core.event.VigieJson
import io.github.erwsim.vigie.core.testing.CommandKit
import io.github.erwsim.vigie.core.testing.FakeClock
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.longOrNull
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Commands built and signed by the REAL console code (TypeScript, WebCrypto) are accepted by the real
 * verifier: `server/console/src/lib/fixtures/command-vectors.json` is produced by
 * `server/console/scripts/command-vectors.ts` and pinned on the console side by `commandVectors.test.ts`.
 * Hard cases, not only the contract vector: accents, emojis, quotes, line feeds, bidirectional text in the
 * lock message; non-ASCII, decomposed (NFD) or space-padded command codes.
 */
class ConsoleVectorsTest {
    private fun fixture(): File {
        var dir: File? = File("").absoluteFile
        while (dir != null) {
            val f = File(dir, "server/console/src/lib/fixtures/command-vectors.json")
            if (f.isFile) return f
            dir = dir.parentFile
        }
        throw AssertionError("server/console/src/lib/fixtures/command-vectors.json not found above ${File("").absolutePath}")
    }

    @Test
    fun everyCommandSignedByTheConsoleIsAcceptedWithItsExactContent() {
        val vectors = VigieJson.parseToJsonElement(fixture().readText(Charsets.UTF_8)) as JsonArray
        assertTrue("at least 12 vectors", vectors.size >= 12)
        val keys = HashMap<String, ByteArray>() // 600 000 iterations: once per code
        var signed = 0
        for (element in vectors) {
            val v = element.jsonObject
            val name = v["name"]!!.jsonPrimitive.content
            val deviceId = v["device_id"]!!.jsonPrimitive.content
            val type = v["type"]!!.jsonPrimitive.content
            val payload = v["payload"]!!.jsonPrimitive.content
            val code = (v["code"] as? JsonPrimitive)?.takeIf { it !is JsonNull }?.content
            val sig = (v["sig"] as? JsonPrimitive)?.takeIf { it !is JsonNull }?.content
            val now = v["now_ms"]!!.jsonPrimitive.longOrNull!!
            val id = (VigieJson.parseToJsonElement(payload) as JsonObject)["id"]!!.jsonPrimitive.content

            val kit = CommandKit(clock = FakeClock(now = now + 1_000), deviceId = deviceId, configureKey = false)
            if (code != null) {
                val key = keys.getOrPut("$deviceId\u0000$code") { CommandCrypto.deriveKey(code, deviceId) }
                assertEquals("$name: signature of the console", sig, CommandCrypto.sign(key, payload))
                kit.keys.save(deviceId, key.copyOf(), now)
                signed++
            }
            val verdict = kit.verifier.verify(CommandEnvelope(id, payload, sig), kit.env(wipeAllowed = true))
            assertTrue("$name: $verdict", verdict is Verification.Accepted)
            val command = (verdict as Verification.Accepted).command
            assertEquals(name, type, command.type)
            assertEquals(name, code != null, command.signatureVerified)
            val expect = v["expect"]!!.jsonObject
            when (val p = command.params) {
                is CommandParams.Lock -> {
                    val want = (expect["message"] as? JsonPrimitive)?.takeIf { it !is JsonNull }?.content
                    assertEquals(name, want, p.message)
                }
                is CommandParams.Ring -> {
                    assertEquals(name, expect["duration_s"]!!.jsonPrimitive.intOrNull, p.durationS)
                    assertEquals(name, expect["vibrate"]!!.jsonPrimitive.booleanOrNull, p.vibrate)
                }
                is CommandParams.Vibrate -> assertEquals(name, expect["duration_s"]!!.jsonPrimitive.intOrNull, p.durationS)
                CommandParams.None -> assertTrue(name, expect.isEmpty())
            }
            // One altered byte of the payload, or the signature of another vector, is refused.
            if (sig != null) {
                val altered = kit.verifier.verify(CommandEnvelope(id, payload.replace("\"v\":1", "\"v\":1 "), sig), kit.env(wipeAllowed = true))
                assertEquals(name, Refusal.BAD_SIGNATURE, (altered as Verification.Refused).reason)
            }
        }
        assertTrue("signed vectors: $signed", signed >= 9)
        assertNotNull(keys.keys.firstOrNull { k -> k.any { it.code > 0x7f } }) // a non-ASCII command code was exercised
    }
}
