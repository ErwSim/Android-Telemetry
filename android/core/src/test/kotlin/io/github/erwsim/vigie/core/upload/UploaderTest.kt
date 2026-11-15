package io.github.erwsim.vigie.core.upload

import io.github.erwsim.vigie.core.FakeClock
import io.github.erwsim.vigie.core.MemoryPrefs
import io.github.erwsim.vigie.core.event.Severity
import io.github.erwsim.vigie.core.event.UlidGenerator
import io.github.erwsim.vigie.core.event.VigieJson
import io.github.erwsim.vigie.core.event.eventData
import io.github.erwsim.vigie.core.openTestDatabase
import io.github.erwsim.vigie.core.outbox.Outbox
import io.github.erwsim.vigie.core.outbox.OutboxDatabase
import io.github.erwsim.vigie.core.outbox.PendingEvent
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import mockwebserver3.MockResponse
import mockwebserver3.MockWebServer
import mockwebserver3.RecordedRequest
import okhttp3.OkHttpClient
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.util.concurrent.TimeUnit
import java.util.zip.GZIPInputStream
import kotlin.random.Random

/** Contract §3 behaviour of the uploader against a real HTTP server (MockWebServer). */
class UploaderTest {
    @get:Rule
    val tmp = TemporaryFolder()

    private lateinit var db: OutboxDatabase
    private lateinit var outbox: Outbox
    private lateinit var server: MockWebServer
    private lateinit var target: IngestTarget
    private val client = OkHttpClient()
    private val clock = FakeClock()
    private val status = UploadStatusStore(MemoryPrefs())
    private val ulid = UlidGenerator()
    private var net = NetState(connected = true, metered = false)
    private var limits = UploadLimits(wifiOnlyLarge = true, largeThresholdBytes = 5L * 1024 * 1024)
    private var enrolled = true
    private lateinit var uploader: Uploader

    @Before
    fun setUp() {
        db = openTestDatabase(tmp.root)
        outbox = Outbox(db)
        server = MockWebServer()
        server.start()
        target = IngestTarget(server.url("/"), "dev_8f3a", "secret-token", "1.0.0")
        uploader = Uploader(
            outbox = outbox,
            target = { if (enrolled) client to target else null },
            statusStore = status,
            clock = clock,
            network = { net },
            limits = { limits },
            random = Random(42),
        )
    }

    @After
    fun tearDown() {
        server.close()
        db.close()
    }

    private fun fill(n: Int, sev: Int = Severity.INFO, payload: String = "on") = runBlocking {
        outbox.append(List(n) { PendingEvent(ulid.next(clock.now), clock.now, 1, "boot", "device.screen", sev, eventData { put("state", payload) }) })
    }

    private fun ack(accepted: Int, duplicates: Int = 0, rejected: List<String> = emptyList()) = MockResponse.Builder()
        .code(200)
        .addHeader("Content-Type", "application/json")
        .body(
            """{"accepted":$accepted,"duplicates":$duplicates,"rejected":[${rejected.joinToString { """{"id":"$it","reason":"invalid_type"}""" }}],"server_time":"2026-11-15T21:45:00.412Z"}""",
        )
        .build()

    private fun code(code: Int, vararg headers: Pair<String, String>) = MockResponse.Builder().code(code).apply {
        headers.forEach { addHeader(it.first, it.second) }
    }.build()

    private fun RecordedRequest.payload(): JsonObject {
        val raw = GZIPInputStream(body!!.toByteArray().inputStream()).readBytes().toString(Charsets.UTF_8)
        return VigieJson.parseToJsonElement(raw).jsonObject
    }

    private fun RecordedRequest.seqs(): List<Long> = payload()["events"]!!.jsonArray.map { it.jsonObject["seq"]!!.jsonPrimitive.long }

    private fun take(): RecordedRequest = server.takeRequest(5, TimeUnit.SECONDS)!!

    @Test
    fun sendsAGzippedAuthenticatedBatchAndDeletesOnAck() = runBlocking {
        fill(3)
        server.enqueue(ack(3))
        val outcome = uploader.run()
        assertEquals(UploadOutcome.Sent(3, moreLeft = false), outcome)
        val request = take()
        assertEquals("POST", request.method)
        assertEquals("/api/v1/ingest", request.url.encodedPath)
        assertEquals("Bearer secret-token", request.headers["Authorization"])
        assertEquals("gzip", request.headers["Content-Encoding"])
        assertTrue(request.headers["Content-Type"]!!.startsWith("application/json"))
        val payload = request.payload()
        assertEquals("dev_8f3a", payload["device_id"]!!.jsonPrimitive.content)
        assertEquals("1.0.0", payload["agent_version"]!!.jsonPrimitive.content)
        assertEquals(listOf(1L, 2L, 3L), request.seqs())
        assertEquals(0L, outbox.totals.value.count)
        assertEquals(clock.now, status.status.value.lastSuccessMs)
        assertNull(status.status.value.lastError)
    }

    @Test
    fun duplicatesAndRejectedAreRemovedToo() = runBlocking {
        fill(4)
        server.enqueue(ack(accepted = 1, duplicates = 2, rejected = listOf("x")))
        uploader.run()
        assertEquals(0L, outbox.totals.value.count)
        assertEquals(1L, status.status.value.rejectedTotal)
        assertEquals("invalid_type", status.status.value.lastRejectReason)
    }

    @Test
    fun inconsistentAckKeepsEverything() = runBlocking {
        fill(3)
        server.enqueue(ack(accepted = 2))
        val outcome = uploader.run()
        assertTrue(outcome is UploadOutcome.Retry && outcome.cause == RetryCause.PROTOCOL)
        assertEquals(3L, outbox.totals.value.count)
    }

    @Test
    fun unauthorizedKeepsEverythingAndWaits() = runBlocking {
        fill(3)
        server.enqueue(code(401))
        val outcome = uploader.run() as UploadOutcome.Retry
        assertEquals(RetryCause.AUTH, outcome.cause)
        assertTrue(outcome.atMs >= clock.now + 15 * 60_000)
        assertEquals(3L, outbox.totals.value.count)
        // Not due yet: no request at all.
        assertEquals(UploadOutcome.Deferred(outcome.atMs), uploader.run())
        assertEquals(1, server.requestCount)
    }

    @Test
    fun payloadTooLargeHalvesTheBatch() = runBlocking {
        fill(10)
        server.enqueue(code(413))
        server.enqueue(ack(5))
        server.enqueue(ack(5))
        assertEquals(UploadOutcome.Sent(10, moreLeft = false), uploader.run())
        assertEquals(10, take().seqs().size)
        assertEquals((1L..5L).toList(), take().seqs())
        assertEquals((6L..10L).toList(), take().seqs())
        assertEquals(0L, outbox.totals.value.count)
    }

    @Test
    fun singleEventRefusedAsTooLargeIsDroppedAndCounted() = runBlocking {
        fill(1)
        server.enqueue(code(413))
        uploader.run()
        assertEquals(0L, outbox.totals.value.count)
        assertEquals(1L, outbox.droppedTotal())
    }

    @Test
    fun rateLimitHonoursRetryAfter() = runBlocking {
        fill(2)
        server.enqueue(code(429, "Retry-After" to "120"))
        val outcome = uploader.run() as UploadOutcome.Retry
        assertEquals(RetryCause.RATE_LIMITED, outcome.cause)
        assertEquals(clock.now + 120_000, outcome.atMs)
        assertEquals(2L, outbox.totals.value.count)
    }

    @Test
    fun serverErrorsBackOffExponentiallyWithJitter() = runBlocking {
        fill(2)
        server.enqueue(code(503))
        server.enqueue(code(500))
        val first = uploader.run() as UploadOutcome.Retry
        assertEquals(RetryCause.SERVER, first.cause)
        assertTrue(first.atMs - clock.now in 30_000L..60_000L)
        val second = uploader.run(force = true) as UploadOutcome.Retry
        assertTrue(second.atMs - clock.now in 60_000L..120_000L)
        assertEquals(2, status.status.value.consecutiveFailures)
        assertEquals(2L, outbox.totals.value.count)
    }

    @Test
    fun networkFailureKeepsDataAndResumesWithoutDuplicates() = runBlocking {
        fill(7)
        server.close() // connection refused
        val outcome = uploader.run() as UploadOutcome.Retry
        assertEquals(RetryCause.NETWORK, outcome.cause)
        assertEquals(7L, outbox.totals.value.count)

        // Connectivity is back (new server instance), more events were buffered meanwhile.
        fill(3)
        server = MockWebServer().also { it.start() }
        target = IngestTarget(server.url("/"), "dev_8f3a", "secret-token", "1.0.0")
        server.enqueue(ack(10))
        assertEquals(UploadOutcome.Sent(10, moreLeft = false), uploader.run(force = true))
        assertEquals((1L..10L).toList(), take().seqs())
        assertEquals(0, status.status.value.consecutiveFailures)
    }

    @Test
    fun batchesHoldAtMost500Events() = runBlocking {
        fill(1200)
        server.enqueue(ack(500))
        server.enqueue(ack(500))
        server.enqueue(ack(200))
        assertEquals(UploadOutcome.Sent(1200, moreLeft = false), uploader.run())
        assertEquals(listOf(500, 500, 200), List(3) { take().seqs().size })
    }

    @Test
    fun compressedBatchesStayUnderOneMebibyte() = runBlocking {
        val random = Random(7)
        val alphabet = ('a'..'z') + ('A'..'Z') + ('0'..'9')
        repeat(500) {
            fill(1, payload = String(CharArray(4_000) { alphabet[random.nextInt(alphabet.size)] }))
        }
        // ~4 KB of incompressible text per event: 500 events are ~1.5 MiB once gzipped.
        server.enqueue(ack(250))
        server.enqueue(ack(250))
        val outcome = uploader.run()
        assertEquals(UploadOutcome.Sent(500, moreLeft = false), outcome)
        repeat(2) {
            val request = take()
            assertTrue("compressed ${request.bodySize}", request.bodySize <= Uploader.MAX_COMPRESSED_BYTES)
            assertEquals(250, request.seqs().size)
        }
    }

    @Test
    fun meteredNetworkWithLargeBacklogSendsOnlyHighSeverity() = runBlocking {
        fill(3)
        fill(1, sev = Severity.WARNING)
        fill(2)
        limits = UploadLimits(wifiOnlyLarge = true, largeThresholdBytes = 1)
        net = NetState(connected = true, metered = true)
        server.enqueue(ack(1))
        assertEquals(UploadOutcome.WaitingUnmetered(1), uploader.run())
        assertEquals(listOf(4L), take().seqs())
        assertEquals(5L, outbox.totals.value.count)

        net = NetState(connected = true, metered = false)
        server.enqueue(ack(5))
        assertEquals(UploadOutcome.Sent(5, moreLeft = false), uploader.run())
        assertEquals(listOf(1L, 2L, 3L, 5L, 6L), take().seqs())
    }

    @Test
    fun meteredNetworkWithSmallBacklogSendsEverything() = runBlocking {
        fill(3)
        net = NetState(connected = true, metered = true)
        server.enqueue(ack(3))
        assertEquals(UploadOutcome.Sent(3, moreLeft = false), uploader.run())
    }

    @Test
    fun notEnrolledSendsNothing() = runBlocking {
        enrolled = false
        fill(2)
        assertEquals(UploadOutcome.NotEnrolled, uploader.run())
        assertEquals(0, server.requestCount)
    }

    @Test
    fun retryAfterAcceptsSecondsAndHttpDates() {
        val now = 1_794_778_983_974L // 2026-11-15T21:43:03.974Z
        assertEquals(120_000L, Uploader.parseRetryAfter("120", now))
        assertEquals(0L, Uploader.parseRetryAfter("0", now))
        assertEquals(56_026L, Uploader.parseRetryAfter("Sun, 15 Nov 2026 21:44:00 GMT", now))
        assertEquals(0L, Uploader.parseRetryAfter("Sun, 15 Nov 2026 21:00:00 GMT", now))
        assertNull(Uploader.parseRetryAfter("soon", now))
        assertNull(Uploader.parseRetryAfter(null, now))
        assertNull(Uploader.parseRetryAfter("-5", now))
    }

    @Test
    fun backoffIsCappedAndJittered() {
        repeat(50) { n ->
            val d = uploader.backoffMs(RetryCause.NETWORK, n + 1)
            assertTrue(d in 15_000L..30 * 60_000L)
        }
        assertTrue(uploader.backoffMs(RetryCause.AUTH, 30) <= 6 * 3_600_000L)
    }
}
