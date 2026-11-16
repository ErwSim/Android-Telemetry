package io.github.erwsim.vigie.core.upload

import io.github.erwsim.vigie.core.testing.FakeClock
import io.github.erwsim.vigie.core.testing.MemoryPrefs
import io.github.erwsim.vigie.core.event.Severity
import io.github.erwsim.vigie.core.event.UlidGenerator
import io.github.erwsim.vigie.core.event.VigieJson
import io.github.erwsim.vigie.core.event.eventData
import io.github.erwsim.vigie.core.testing.openTestDatabase
import io.github.erwsim.vigie.core.outbox.Outbox
import io.github.erwsim.vigie.core.outbox.OutboxDatabase
import io.github.erwsim.vigie.core.outbox.PendingEvent
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import mockwebserver3.Dispatcher
import mockwebserver3.MockResponse
import mockwebserver3.MockWebServer
import mockwebserver3.RecordedRequest
import mockwebserver3.SocketEffect
import okhttp3.OkHttpClient
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.util.concurrent.CopyOnWriteArrayList
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
    private val client = OkHttpClient.Builder().retryOnConnectionFailure(false).build()
    private val clock = FakeClock()
    private val status = UploadStatusStore(MemoryPrefs())
    private val ulid = UlidGenerator()
    private var net = NetState(connected = true, metered = false)
    private var limits = UploadLimits(wifiOnlyLarge = true, largeThresholdBytes = 5L * 1024 * 1024)
    private var enrolled = true
    private lateinit var uploader: Uploader
    private val dropped = CopyOnWriteArrayList<DroppedEvent>()

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
            onDropped = { dropped += it },
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
    fun aBackoffLeftInTheFarFutureByAClockJumpDoesNotBlockUploads() = runBlocking {
        // The retry time is a wall-clock time. The clock was wrong (one year ahead) when a failure set it,
        // then got corrected: without a bound, nothing would be sent for a year.
        fill(2)
        clock.now += 365L * 86_400_000
        server.enqueue(code(503))
        assertTrue(uploader.run() is UploadOutcome.Retry)
        clock.now -= 365L * 86_400_000
        server.enqueue(ack(2))
        assertEquals(UploadOutcome.Sent(2, moreLeft = false), uploader.run())
        assertEquals(0L, outbox.totals.value.count)
    }

    @Test
    fun aRecentBackoffIsStillHonoured() = runBlocking {
        fill(1)
        server.enqueue(code(503))
        uploader.run()
        assertTrue(uploader.run() is UploadOutcome.Deferred)
        assertEquals(1, server.requestCount)
    }

    @Test
    fun anUnexpectedExceptionWhileSendingIsAFailureWithBackoffNotACrash() = runBlocking {
        // e.g. a Keystore or provider RuntimeException during the TLS handshake with the client key.
        fill(2)
        val broken = OkHttpClient.Builder().addInterceptor { throw IllegalStateException("keystore operation failed") }.build()
        val u = Uploader(outbox, { broken to target }, status, clock, { net }, { limits }, Random(42))
        val outcome = u.run()
        assertTrue(outcome.toString(), outcome is UploadOutcome.Retry)
        assertEquals(2L, outbox.totals.value.count)
        assertTrue(status.status.value.lastError!!.contains("keystore operation failed"))
        assertTrue(status.status.value.nextAttemptAtMs > clock.now)
    }

    @Test
    fun credentialsThatCannotBeLoadedAreAFailureWithBackoff() = runBlocking {
        fill(1)
        val u = Uploader(outbox, { throw java.security.KeyStoreException("no such entry") }, status, clock, { net }, { limits }, Random(42))
        val outcome = u.run()
        assertTrue(outcome.toString(), outcome is UploadOutcome.Retry && outcome.cause == RetryCause.AUTH)
        assertEquals(1L, outbox.totals.value.count)
        assertTrue(status.status.value.lastError!!.startsWith("credentials"))
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

    // ---- Poisoned batch (contract §3, 400): bisection ----

    /**
     * Server double: answers 400 to every batch containing a seq of [poison] (and to the empty probe
     * when [envelopeBroken]), 200 otherwise. [override] may force a response for a given request.
     */
    private inner class PoisonServer(
        val poison: Set<Long> = emptySet(),
        var envelopeBroken: Boolean = false,
        var override: (index: Int, seqs: List<Long>) -> MockResponse? = { _, _ -> null },
    ) : Dispatcher() {
        val requests = CopyOnWriteArrayList<List<Long>>()
        val acked = CopyOnWriteArrayList<Long>()

        override fun dispatch(request: RecordedRequest): MockResponse {
            val seqs = request.seqs()
            requests += seqs
            override(requests.size, seqs)?.let { return it }
            val bad = envelopeBroken || seqs.any { it in poison }
            if (bad) return code(400)
            acked += seqs
            return ack(seqs.size)
        }
    }

    private fun serve(poison: Set<Long> = emptySet(), envelopeBroken: Boolean = false, override: (Int, List<Long>) -> MockResponse? = { _, _ -> null }) =
        PoisonServer(poison, envelopeBroken, override).also { server.dispatcher = it }

    /** Runs the uploader (a new cycle each time, backoff ignored) until the buffer is empty; returns the number of runs. */
    private fun drain(maxRuns: Int = 20): Int = runBlocking {
        var runs = 0
        while (outbox.refreshTotals().count > 0 && runs < maxRuns) {
            uploader.run(force = true)
            runs++
        }
        runs
    }

    private fun assertOnlyHealthyDelivered(srv: PoisonServer, total: Int) {
        val healthy = (1L..total).filter { it !in srv.poison }
        assertEquals("every healthy event delivered once", healthy, srv.acked.sorted())
        assertEquals(srv.acked.size, srv.acked.toSet().size)
    }

    @Test
    fun aPoisonedEventInTheMiddleOfA500BatchIsIsolatedDroppedAndTheOthersSent() = runBlocking {
        fill(500)
        val srv = serve(poison = setOf(250L))
        assertEquals(UploadOutcome.Sent(499, moreLeft = false), uploader.run())
        assertEquals(0L, outbox.refreshTotals().count)
        assertEquals(1L, outbox.droppedTotal())
        assertOnlyHealthyDelivered(srv, 500)
        // About 2*log2(500) requests, plus the envelope probe: bounded, no storm.
        assertTrue("requests=${srv.requests.size}", srv.requests.size <= 30)
        // The poison was refused alone before being dropped.
        assertTrue(srv.requests.any { it == listOf(250L) })
        assertEquals(listOf(250L), dropped.map { it.seq })
        assertEquals("http_400", dropped.single().reason)
        assertEquals("device.screen", dropped.single().type)
    }

    @Test
    fun twoPoisonedEventsAreBothDroppedAndNothingElse() = runBlocking {
        fill(500)
        val srv = serve(poison = setOf(100L, 400L))
        assertEquals(UploadOutcome.Sent(498, moreLeft = false), uploader.run())
        assertEquals(0L, outbox.refreshTotals().count)
        assertEquals(2L, outbox.droppedTotal())
        assertOnlyHealthyDelivered(srv, 500)
        assertTrue("requests=${srv.requests.size}", srv.requests.size <= 55)
    }

    @Test
    fun anEntirelyPoisonedBatchIsDroppedWithABoundedNumberOfRequestsPerRun() = runBlocking {
        fill(64)
        val srv = serve(poison = (1L..64L).toSet())
        val first = uploader.run()
        // 2n-1 = 127 refusals are needed, a run stops at the cap with a normal backoff (no storm).
        assertTrue(first.toString(), first is UploadOutcome.Retry && first.cause == RetryCause.PROTOCOL)
        assertTrue("requests=${srv.requests.size}", srv.requests.size <= Uploader.MAX_REFUSALS_PER_RUN + 2)
        assertTrue(status.status.value.nextAttemptAtMs > clock.now)
        // Later cycles finish the job; nothing healthy exists, everything is dropped and counted.
        val runs = drain()
        assertTrue("runs=$runs", runs in 1..4)
        assertEquals(0L, outbox.refreshTotals().count)
        assertEquals(64L, outbox.droppedTotal())
        assertTrue("requests=${srv.requests.size}", srv.requests.size <= 4 * 64)
        assertTrue(srv.acked.isEmpty())
    }

    @Test
    fun anAbruptStopInTheMiddleOfTheBisectionLosesNothingAndResumes() = runBlocking {
        fill(100)
        // Requests: 1 batch (400), 2 probe, 3 [1-50] ok, 4 [51-100] 400, 5 [51-75] 400, 6 = the process dies.
        val srv = serve(poison = setOf(70L)) { index, _ ->
            if (index == 6) MockResponse.Builder().onResponseStart(SocketEffect.CloseSocket()).build() else null
        }
        val outcome = uploader.run()
        assertTrue(outcome.toString(), outcome is UploadOutcome.Retry && outcome.cause == RetryCause.NETWORK)
        assertEquals(50L, outbox.refreshTotals().count) // [1-50] was acknowledged and deleted, nothing else
        assertEquals(0L, outbox.droppedTotal())
        assertEquals((1L..50L).toList(), srv.acked.sorted())

        // New process: same database file, all in-memory state and the upload preferences are gone.
        db.close()
        db = openTestDatabase(tmp.root)
        outbox = Outbox(db)
        uploader = Uploader(outbox, { client to target }, UploadStatusStore(MemoryPrefs()), clock, { net }, { limits }, Random(1), onDropped = { dropped += it })
        val before = srv.requests.size
        drain()
        assertEquals(0L, outbox.refreshTotals().count)
        assertEquals(1L, outbox.droppedTotal())
        assertOnlyHealthyDelivered(srv, 100)
        assertTrue("requests after restart=${srv.requests.size - before}", srv.requests.size - before <= 25)
    }

    @Test
    fun aServerErrorIsTransientNotAPoisonedBatch() = runBlocking {
        fill(500)
        val srv = serve { index, _ -> if (index == 1) code(503) else null }
        val first = uploader.run() as UploadOutcome.Retry
        assertEquals(RetryCause.SERVER, first.cause)
        assertEquals(1, srv.requests.size)
        assertEquals(500L, outbox.refreshTotals().count)
        assertEquals(0L, outbox.droppedTotal())
        // The next cycle sends the same full batch, not a half.
        assertEquals(UploadOutcome.Sent(500, moreLeft = false), uploader.run(force = true))
        assertEquals(500, srv.requests[1].size)
    }

    @Test
    fun aServerErrorInTheMiddleOfABisectionKeepsEverythingAndTheBisectionResumesLater() = runBlocking {
        fill(100)
        // 1 batch (400), 2 probe, 3 [1-50] -> 503.
        val srv = serve(poison = setOf(30L)) { index, _ -> if (index == 3) code(503) else null }
        val outcome = uploader.run() as UploadOutcome.Retry
        assertEquals(RetryCause.SERVER, outcome.cause)
        assertEquals(100L, outbox.refreshTotals().count)
        assertEquals(0L, outbox.droppedTotal())
        assertTrue(dropped.isEmpty())
        drain()
        assertEquals(0L, outbox.refreshTotals().count)
        assertEquals(1L, outbox.droppedTotal())
        assertOnlyHealthyDelivered(srv, 100)
    }

    @Test
    fun a400ThatComesFromTheEnvelopeNotFromAnEventDeletesNothing() = runBlocking {
        // Every request is refused, including the one without any event: the fault is not in the events.
        fill(100)
        val srv = serve(envelopeBroken = true)
        val outcome = uploader.run() as UploadOutcome.Retry
        assertEquals(RetryCause.PROTOCOL, outcome.cause)
        assertEquals("http_400_envelope", status.status.value.lastError)
        assertEquals(2, srv.requests.size) // the batch, then the empty probe: no bisection, no storm
        assertEquals(100L, outbox.refreshTotals().count)
        assertEquals(0L, outbox.droppedTotal())
        // Same on later cycles (batch size and buffer unchanged, still nothing deleted).
        repeat(3) { uploader.run(force = true) }
        assertEquals(100L, outbox.refreshTotals().count)
        assertEquals(0L, outbox.droppedTotal())
        assertTrue(dropped.isEmpty())
    }

    @Test
    fun theBisectionDoesNotLeaveABadBatchSizeBehind() = runBlocking {
        fill(500)
        serve(poison = setOf(7L))
        uploader.run()
        fill(500)
        val srv = serve()
        assertEquals(UploadOutcome.Sent(500, moreLeft = false), uploader.run())
        assertTrue(srv.requests.size <= 3)
    }
}
