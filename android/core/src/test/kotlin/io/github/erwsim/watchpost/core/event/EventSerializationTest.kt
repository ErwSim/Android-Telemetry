package io.github.erwsim.watchpost.core.event

import io.github.erwsim.watchpost.core.outbox.OutboxEntity
import io.github.erwsim.watchpost.core.upload.IngestTarget
import io.github.erwsim.watchpost.core.upload.UploadPayload
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import okhttp3.HttpUrl.Companion.toHttpUrl
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/** Contract §1 conformity of what is stored and sent. */
class EventSerializationTest {
    private val event = Event(
        id = "01JCQ8Z3K4M5N6P7Q8R9S0T1V2",
        ts = "2026-11-15T21:43:03.974Z",
        seq = 18234,
        bootId = "b7e1",
        elapsedMs = 86_400_123,
        type = "location.fix",
        sev = 0,
        data = eventData {
            put("lat", 48.8566)
            put("lon", 2.3522)
            put("acc_m", 4.5f)
            put("alt_m", null as Double?)
            put("provider", "gps")
            put("mock", false)
        },
    )

    @Test
    fun serializesExactlyTheContractFieldsInOrder() {
        val json = WatchpostJson.encodeToString(Event.serializer(), event)
        assertEquals(
            """{"id":"01JCQ8Z3K4M5N6P7Q8R9S0T1V2","ts":"2026-11-15T21:43:03.974Z","seq":18234,""" +
                """"boot_id":"b7e1","elapsed_ms":86400123,"type":"location.fix","sev":0,""" +
                """"data":{"lat":48.8566,"lon":2.3522,"acc_m":4.5,"provider":"gps","mock":false}}""",
            json,
        )
        assertFalse("no null anywhere", json.contains("null"))
        assertEquals(event, WatchpostJson.decodeFromString(Event.serializer(), json))
    }

    @Test
    fun nullValuesAreAbsentNotNull() {
        val data = eventData {
            put("a", null as String?)
            put("b", null as Number?)
            put("c", null as Boolean?)
            putStrings("d", null)
            putObject("e") { put("x", null as String?) }
            putMap("f", mapOf("k" to null, "l" to "v"))
            put("g", JsonNull)
        }
        assertEquals("""{"e":{},"f":{"l":"v"}}""", data.toString())
    }

    @Test
    fun stripNullsIsRecursive() {
        val raw = buildJsonObject {
            put("a", JsonNull)
            put("b", JsonArray(listOf(JsonNull, JsonPrimitive(1), buildJsonObject { put("c", JsonNull) })))
        }
        assertEquals("""{"b":[1,{}]}""", stripNulls(raw).toString())
    }

    @Test
    fun floatsUseTheirShortestDecimalForm() {
        assertEquals("""{"v":0.1,"w":12.3}""", eventData { put("v", 0.1f); put("w", 12.3f) }.toString())
    }

    @Test
    fun nonFiniteNumbersAreDropped() {
        assertEquals("{}", eventData { put("v", Double.NaN); put("w", Float.POSITIVE_INFINITY) }.toString())
    }

    @Test
    fun keysMustBeSnakeCase() {
        assertThrows(IllegalArgumentException::class.java) { eventData { put("camelCase", 1) } }
        assertThrows(IllegalArgumentException::class.java) { eventData { put("with-dash", 1) } }
    }

    @Test
    fun typeValidationFollowsTheContract() {
        listOf("agent.heartbeat", "net.wifi_scan", "security.log", "app.inventory.app").forEach {
            assertTrue(it, EventTypes.isValid(it))
        }
        listOf("Agent.started", "agent", "agent.", ".x", "net.wifi-scan", "net wifi", "").forEach {
            assertFalse(it, EventTypes.isValid(it))
        }
    }

    @Test
    fun timestampsAreRfc3339UtcWithMilliseconds() {
        assertEquals("2026-11-15T21:43:03.974Z", Rfc3339.format(1_794_778_983_974L))
        assertEquals("2026-11-15T21:43:03.000Z", Rfc3339.format(1_794_778_983_000L))
        assertEquals("1970-01-01T00:00:00.000Z", Rfc3339.format(0))
        assertEquals(1_794_778_983_974L, Rfc3339.parseOrNull("2026-11-15T21:43:03.974Z"))
    }

    @Test
    fun ulidsAreValidAndStrictlyIncreasing() {
        val gen = UlidGenerator()
        val ids = (0 until 2000).map { gen.next(1_794_778_983_974L + it / 100) }
        ids.forEach { assertTrue(it, UlidGenerator.isValid(it)) }
        assertEquals(ids.sorted(), ids)
        assertEquals(ids.size, ids.toSet().size)
        // Clock going backwards keeps ordering.
        val later = gen.next(1_000)
        assertTrue(later > ids.last())
        // Time prefix encodes the milliseconds (first 10 chars).
        val a = UlidGenerator().next(0)
        assertTrue(a.startsWith("0000000000"))
        assertNotEquals(UlidGenerator().next(5), UlidGenerator().next(5))
    }

    @Test
    fun uploadPayloadWrapsStoredEventsVerbatim() {
        val stored = WatchpostJson.encodeToString(Event.serializer(), event)
        val rows = listOf(OutboxEntity(event.seq, event.id, event.type, event.sev, 0, stored, stored.length))
        val target = IngestTarget("https://ingest.example.org".toHttpUrl(), "dev_8f3a", "tok", "1.0.0")
        val body = UploadPayload.json(target, rows, 1_794_779_100_000L)
        val parsed = WatchpostJson.parseToJsonElement(body).jsonObject
        assertEquals(listOf("device_id", "agent_version", "sent_at", "events"), parsed.keys.toList())
        assertEquals("dev_8f3a", parsed["device_id"]!!.jsonPrimitive.content)
        assertEquals("1.0.0", parsed["agent_version"]!!.jsonPrimitive.content)
        assertEquals("2026-11-15T21:45:00.000Z", parsed["sent_at"]!!.jsonPrimitive.content)
        val sent = parsed["events"]!!.jsonArray.single() as JsonObject
        assertEquals(18234L, sent["seq"]!!.jsonPrimitive.long)
        assertEquals(WatchpostJson.parseToJsonElement(stored), sent)
        assertEquals("https://ingest.example.org/api/v1/ingest", target.ingestUrl.toString())
        assertEquals("https://ingest.example.org/api/v1/ping", target.pingUrl.toString())
    }

    @Test
    fun ingestUrlKeepsAPathPrefix() {
        val target = IngestTarget("https://example.org/watchpost/".toHttpUrl(), "d", "t", "v")
        assertEquals("https://example.org/watchpost/api/v1/ingest", target.ingestUrl.toString())
    }
}
