package io.github.erwsim.vigie.core.command

import io.github.erwsim.vigie.core.event.VigieJson
import io.github.erwsim.vigie.core.testing.CommandKit
import io.github.erwsim.vigie.core.testing.RecordingSink
import io.github.erwsim.vigie.core.upload.IngestTarget
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import mockwebserver3.Dispatcher
import mockwebserver3.MockResponse
import mockwebserver3.MockResponseBody
import mockwebserver3.MockWebServer
import mockwebserver3.RecordedRequest
import okhttp3.OkHttpClient
import okio.BufferedSink
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.random.Random

/** The channel client (contract §8) against a real HTTP server: SSE, polling, cuts, 401, results. */
class CommandChannelTest {
    private val kit = CommandKit()
    private val sink = RecordingSink()
    private val executed = CopyOnWriteArrayList<AcceptedCommand>()
    private val server = MockWebServer()
    private val fake = FakeServer()
    private val platform = FakePlatform()
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val client = OkHttpClient.Builder().retryOnConnectionFailure(false).build()

    @Volatile private var config = ChannelConfig(enabled = true, mode = ChannelMode.STREAM, pollIntervalMin = 5)
    @Volatile private var enrolled = true
    private lateinit var target: IngestTarget
    private lateinit var channel: CommandChannel

    @Before
    fun setUp() {
        server.dispatcher = fake
        server.start()
        target = IngestTarget(server.url("/"), kit.deviceId, "secret-token", "1.0.0")
        val processor = CommandProcessor(
            clock = kit.clock,
            verifier = kit.verifier,
            state = kit.state,
            sink = sink,
            environment = { kit.env(channelEnabled = config.enabled) },
            executors = {
                mapOf(
                    CommandTypes.RING to CommandExecutor { executed += it; ExecutionResult.executed() },
                    CommandTypes.LOCK to CommandExecutor { executed += it; ExecutionResult.executed() },
                )
            },
            hooks = object : CommandProcessor.Hooks {
                override suspend fun beforeIrreversible(timeoutMs: Long) = Unit
            },
        )
        channel = CommandChannel(
            scope = scope,
            clock = kit.clock,
            target = { if (enrolled) client to target else null },
            config = { config },
            processor = processor,
            state = kit.state,
            platform = platform,
            random = Random(7),
            streamReadTimeoutMs = 10_000,
        )
    }

    @After
    fun tearDown() {
        channel.stop()
        scope.cancel()
        fake.releaseAll()
        server.close()
    }

    private fun eventually(what: String, timeoutMs: Long = 10_000, condition: () -> Boolean) {
        val end = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < end) {
            if (condition()) return
            Thread.sleep(20)
        }
        throw AssertionError("timeout: $what (state=${channel.channelState.value}, requests=${fake.paths()})")
    }

    private fun sse(envelope: CommandEnvelope) = "event: command\ndata: ${kit.json(envelope)}\n\n"

    @Test
    fun streamDeliversCommandsAndTheResultIsPosted() {
        val ring = kit.simple("ring", """{"duration_s":30,"vibrate":false}""")
        fake.streams += StreamPlan(listOf(": keep-alive\n\n", sse(ring)), keepOpen = true)
        channel.start()
        eventually("connected") { channel.channelState.value.phase == ChannelPhase.CONNECTED }
        eventually("executed") { executed.size == 1 }
        assertEquals(CommandParams.Ring(30, false), executed.single().params)
        eventually("result posted") { fake.results.size == 1 }
        val (path, body) = fake.results.single()
        assertEquals("/api/v1/commands/${ring.id}/result", path)
        val json = VigieJson.parseToJsonElement(body).jsonObject
        assertEquals("executed", json["status"]!!.jsonPrimitive.content)
        assertEquals("ok", json["detail"]!!.jsonPrimitive.content)
        assertTrue(json["at"]!!.jsonPrimitive.content.endsWith("Z"))
        val stream = fake.requests.first { it.url.encodedPath == "/api/v1/commands/stream" }
        assertEquals("Bearer secret-token", stream.headers["Authorization"])
        assertEquals("text/event-stream", stream.headers["Accept"])
        // command.result emitted, with the contract's fields.
        val result = sink.of("command.result").single()
        assertEquals(setOf("command_id", "type", "status", "detail", "signed"), result.data.keys)
        assertEquals(0, result.sev)
        eventually("nothing pending") { kit.state.pendingResults().isEmpty() }
        // Still connected (no reconnection loop).
        assertEquals(1, fake.count("/api/v1/commands/stream"))
    }

    @Test
    fun aClosedStreamIsReopenedAfterAShortJitteredPause() {
        fake.streams += StreamPlan(listOf(sse(kit.simple("ring"))), keepOpen = false)
        fake.streams += StreamPlan(listOf(": keep-alive\n\n"), keepOpen = true)
        channel.start()
        eventually("first stream ended") { channel.channelState.value.phase == ChannelPhase.BACKOFF && executed.size == 1 }
        // The pause is in elapsedRealtime: nothing happens until it is over.
        Thread.sleep(200)
        assertEquals(1, fake.count("/api/v1/commands/stream"))
        kit.clock.advance(CommandChannel.RECONNECT_MIN_MS + CommandChannel.RECONNECT_JITTER_MS)
        channel.tick()
        eventually("reconnected") { fake.count("/api/v1/commands/stream") == 2 && channel.channelState.value.phase == ChannelPhase.CONNECTED }
    }

    @Test
    fun aStreamThatDiesAtOnceBacksOffExponentially() {
        repeat(3) { fake.streams += StreamPlan(emptyList(), keepOpen = false) }
        channel.start()
        eventually("first failure") { channel.channelState.value.phase == ChannelPhase.BACKOFF && channel.channelState.value.nextAttemptAtMs > kit.clock.now }
        val first = channel.channelState.value.nextAttemptAtMs - kit.clock.now
        assertTrue("first delay $first", first in CommandChannel.BACKOFF_BASE_MS / 2..CommandChannel.BACKOFF_BASE_MS)
        kit.clock.advance(first + 1)
        channel.tick()
        eventually("second failure") {
            fake.count("/api/v1/commands/stream") == 2 && channel.channelState.value.phase == ChannelPhase.BACKOFF &&
                channel.channelState.value.nextAttemptAtMs > kit.clock.now
        }
        val second = channel.channelState.value.nextAttemptAtMs - kit.clock.now
        assertTrue("second delay $second", second in CommandChannel.BACKOFF_BASE_MS..CommandChannel.BACKOFF_BASE_MS * 2)
    }

    @Test
    fun unauthorizedStopsTheChannelUntilTheConfigurationChanges() {
        fake.streamCode = 401
        channel.start()
        eventually("refused") { channel.channelState.value.phase == ChannelPhase.REFUSED }
        assertEquals("http_401", channel.channelState.value.lastError)
        repeat(5) {
            kit.clock.advance(3_600_000)
            channel.tick()
            channel.onNetworkAvailable()
            channel.onUploadCycle()
        }
        Thread.sleep(300)
        assertEquals("no retry after 401", 1, fake.requests.size)
        // New enrollment, or "Reconnecter": it tries again.
        fake.streamCode = 200
        fake.streams += StreamPlan(emptyList(), keepOpen = true)
        channel.onConfigChanged()
        eventually("reconnected") { channel.channelState.value.phase == ChannelPhase.CONNECTED }
    }

    @Test
    fun withoutNetworkNothingIsAttemptedUntilItComesBack() {
        platform.network = false
        channel.start()
        eventually("waiting") { channel.channelState.value.phase == ChannelPhase.WAITING_NETWORK }
        repeat(3) {
            kit.clock.advance(600_000)
            channel.tick()
        }
        Thread.sleep(300)
        assertEquals(0, fake.requests.size)
        fake.streams += StreamPlan(emptyList(), keepOpen = true)
        platform.network = true
        channel.onNetworkAvailable()
        eventually("connected") { channel.channelState.value.phase == ChannelPhase.CONNECTED }
    }

    @Test
    fun aNetworkCutEndsTheStreamAndTheNetworkCallbackReconnectsAtOnce() {
        fake.streams += StreamPlan(emptyList(), keepOpen = false)
        fake.streams += StreamPlan(emptyList(), keepOpen = true)
        platform.key = "wifi"
        channel.start()
        eventually("failed once") { channel.channelState.value.phase == ChannelPhase.BACKOFF }
        // No time passes: only the callback can bring it back before the backoff ends.
        platform.key = "cellular"
        channel.onNetworkAvailable()
        eventually("reconnected") { channel.channelState.value.phase == ChannelPhase.CONNECTED }
        assertEquals(2, fake.count("/api/v1/commands/stream"))
    }

    @Test
    fun aStaleStreamIsDroppedByTheWatchdogTick() {
        fake.streams += StreamPlan(emptyList(), keepOpen = true)
        fake.streams += StreamPlan(emptyList(), keepOpen = true)
        channel.start()
        eventually("connected") { channel.channelState.value.phase == ChannelPhase.CONNECTED }
        kit.clock.advance(CommandChannel.STALE_AFTER_MS + 1)
        channel.tick()
        eventually("second connection") { fake.count("/api/v1/commands/stream") == 2 }
        assertTrue("watchdog wake-up scheduled", platform.wakeups.isNotEmpty())
    }

    @Test
    fun pollModeFetchesPendingCommandsAtItsInterval() {
        config = config.copy(mode = ChannelMode.POLL, pollIntervalMin = 2)
        val lock = kit.signed("lock", """{"message":"Rendez-le moi"}""")
        fake.pollBody = """{"commands":[${kit.json(lock)}]}"""
        channel.start()
        eventually("polled and executed") { executed.size == 1 }
        assertEquals(CommandParams.Lock("Rendez-le moi"), executed.single().params)
        eventually("idle until the next poll") {
            channel.channelState.value.phase == ChannelPhase.POLL_IDLE && channel.channelState.value.nextAttemptAtMs - kit.clock.now == 2 * 60_000L
        }
        assertEquals(0, fake.count("/api/v1/commands/stream"))
        fake.pollBody = """{"commands":[]}"""
        kit.clock.advance(2 * 60_000L)
        channel.tick()
        eventually("second poll") { fake.count("/api/v1/commands") == 2 }
        // The sensitive command was posted as executed and recorded as signed.
        assertEquals(true, sink.of("command.result").single().data["signed"]!!.jsonPrimitive.content.toBoolean())
    }

    @Test
    fun anUploadTriggersAPollWhenTheStreamIsNotOpenAtMostOnceAMinute() {
        config = config.copy(mode = ChannelMode.POLL, pollIntervalMin = 15)
        channel.start()
        eventually("first poll") { fake.count("/api/v1/commands") == 1 && channel.channelState.value.phase == ChannelPhase.POLL_IDLE }
        channel.onUploadCycle()
        Thread.sleep(200)
        assertEquals(1, fake.count("/api/v1/commands"))
        kit.clock.advance(CommandChannel.MIN_POLL_SPACING_MS)
        channel.onUploadCycle()
        eventually("polled on upload") { fake.count("/api/v1/commands") == 2 }
    }

    @Test
    fun switchingFromStreamToPollClosesTheStream() {
        fake.streams += StreamPlan(emptyList(), keepOpen = true)
        channel.start()
        eventually("connected") { channel.channelState.value.phase == ChannelPhase.CONNECTED }
        config = config.copy(mode = ChannelMode.POLL)
        channel.onConfigChanged()
        eventually("polled") { fake.count("/api/v1/commands") == 1 }
        assertEquals(ChannelMode.POLL, channel.channelState.value.mode)
        config = config.copy(enabled = false)
        channel.onConfigChanged()
        eventually("off") { channel.channelState.value.phase == ChannelPhase.OFF }
    }

    @Test
    fun aResultIsKeptAndSentAgainAfterACut() {
        fake.resultCodes += -1 // connection dropped while posting
        fake.resultCodes += 503
        val ring = kit.simple("ring")
        fake.streams += StreamPlan(listOf(sse(ring)), keepOpen = true)
        channel.start()
        eventually("executed") { executed.size == 1 }
        eventually("first attempt failed") { fake.resultAttempts.get() == 1 }
        assertEquals(1, kit.state.pendingResults().size)
        // The stream goes stale and is reopened: the queued result is tried again first, then the server
        // delivers the same command again while its result is pending: it is not executed twice.
        fake.streams += StreamPlan(listOf(sse(ring)), keepOpen = true)
        kit.clock.advance(CommandChannel.BACKOFF_MAX_MS)
        channel.tick()
        eventually("second attempt and reconnection") { fake.resultAttempts.get() >= 2 && fake.count("/api/v1/commands/stream") == 2 }
        Thread.sleep(300)
        kit.clock.advance(CommandChannel.BACKOFF_MAX_MS)
        channel.flushResultsNow()
        eventually("result acknowledged") { kit.state.pendingResults().isEmpty() }
        assertEquals(1, executed.size)
        assertEquals(1, fake.results.size)
    }

    @Test
    fun aRedeliveredCommandWhoseResultIsPendingIsSkipped() {
        fake.resultCodes += 503
        fake.resultCodes += 503
        val ring = kit.simple("ring")
        config = config.copy(mode = ChannelMode.POLL, pollIntervalMin = 1)
        fake.pollBody = """{"commands":[${kit.json(ring)}]}"""
        channel.start()
        eventually("executed") { executed.size == 1 }
        kit.clock.advance(60_000)
        channel.tick()
        eventually("polled twice") { fake.count("/api/v1/commands") == 2 }
        Thread.sleep(200)
        assertEquals(1, executed.size)
        assertEquals(1, kit.state.history.value.size)
    }

    @Test
    fun unreadableDeliveriesAreTracedButNeverExecuted() {
        fake.streams += StreamPlan(
            listOf("event: command\ndata: {not json\n\n", "event: other\ndata: ${kit.json(kit.simple("ring"))}\n\n", "data: x\n\n"),
            keepOpen = true,
        )
        channel.start()
        eventually("traced") { sink.of("command.result").size == 1 }
        val e = sink.of("command.result").single()
        assertEquals("refused", e.data["status"]!!.jsonPrimitive.content)
        assertEquals("malformed", e.data["detail"]!!.jsonPrimitive.content)
        assertEquals("invalid", e.data["command_id"]!!.jsonPrimitive.content)
        Thread.sleep(200)
        assertEquals(0, executed.size)
        assertEquals(0, fake.results.size)
    }

    /**
     * Whatever the server sends must not end the channel: a stream event or a poll answer made of tens of
     * thousands of `[` is a plain unreadable delivery (traced `malformed`, or a failed poll), and the loop
     * goes on. (On this JVM the parser refuses such depths by itself; the depth check made before parsing
     * makes it independent of the stack size, see `JsonNesting`.)
     */
    @Test
    fun deeplyNestedJsonFromTheServerDoesNotKillTheChannel() {
        val deep = "[".repeat(30_000) + "]".repeat(30_000)
        val ring = kit.simple("ring")
        fake.streams += StreamPlan(listOf("event: command\ndata: $deep\n\n", sse(ring)), keepOpen = true)
        channel.start()
        eventually("the command that follows the hostile event is executed") { executed.size == 1 }
        assertTrue(channel.isRunning)
        assertEquals(listOf("malformed", "ok"), sink.of("command.result").map { it.data["detail"]!!.jsonPrimitive.content })

        // Same answer to a poll (up to 1 MiB is read): a failed attempt, the loop goes on.
        fake.pollBody = """{"commands":${"[".repeat(400_000)}${"]".repeat(400_000)}}"""
        config = config.copy(mode = ChannelMode.POLL)
        channel.onConfigChanged()
        eventually("poll answered and refused") { channel.channelState.value.lastError == "bad_response" }
        assertTrue(channel.isRunning)
    }

    // ------------------------------------------------------------------------------------ fakes

    private fun CommandChannel.flushResultsNow() = kotlinx.coroutines.runBlocking { flushResults(client to target, force = true) }

    class FakePlatform : ChannelPlatform {
        @Volatile var network = true
        @Volatile var key: String? = "wifi"
        val wakeups = CopyOnWriteArrayList<Long>()
        override fun isNetworkAvailable() = network
        override fun networkKey() = key
        override fun scheduleWakeup(atElapsedMs: Long) {
            wakeups += atElapsedMs
        }
        override fun cancelWakeup() = Unit
        override suspend fun <T> withWakeLock(timeoutMs: Long, block: suspend () -> T): T = block()
    }

    class StreamPlan(val chunks: List<String>, val keepOpen: Boolean)

    class StreamBody(private val plan: StreamPlan) : MockResponseBody {
        val release = CountDownLatch(1)
        override val contentLength: Long = -1L
        override fun writeTo(sink: BufferedSink) {
            for (c in plan.chunks) {
                sink.writeUtf8(c)
                sink.flush()
            }
            if (plan.keepOpen) release.await(30, TimeUnit.SECONDS)
        }
    }

    class FakeServer : Dispatcher() {
        val requests = CopyOnWriteArrayList<RecordedRequest>()
        val streams = ConcurrentLinkedQueue<StreamPlan>()
        private val bodies = CopyOnWriteArrayList<StreamBody>()
        @Volatile var streamCode = 200
        @Volatile var pollBody = """{"commands":[]}"""
        val resultCodes = ConcurrentLinkedQueue<Int>()
        val results = CopyOnWriteArrayList<Pair<String, String>>()
        val resultAttempts = java.util.concurrent.atomic.AtomicInteger()

        fun paths() = requests.map { "${it.method} ${it.url.encodedPath}" }
        fun count(path: String) = requests.count { it.method == "GET" && it.url.encodedPath == path }

        fun releaseAll() = bodies.forEach { it.release.countDown() }

        override fun dispatch(request: RecordedRequest): MockResponse {
            requests += request
            val path = request.url.encodedPath
            return when {
                path == "/api/v1/commands/stream" -> {
                    if (streamCode != 200) return MockResponse.Builder().code(streamCode).build()
                    val plan = streams.poll() ?: StreamPlan(emptyList(), keepOpen = false)
                    val body = StreamBody(plan).also { bodies += it }
                    MockResponse.Builder().code(200).addHeader("Content-Type", "text/event-stream").body(body)
                        // An ended stream closes the connection (as the server does); otherwise the client would wait for more.
                        .apply { if (!plan.keepOpen) onResponseEnd(mockwebserver3.SocketEffect.ShutdownConnection) }
                        .build()
                }
                path == "/api/v1/commands" ->
                    MockResponse.Builder().code(200).addHeader("Content-Type", "application/json").body(pollBody).build()
                path.startsWith("/api/v1/commands/") && path.endsWith("/result") -> {
                    resultAttempts.incrementAndGet()
                    when (val code = resultCodes.poll() ?: 204) {
                        -1 -> MockResponse.Builder().onResponseStart(mockwebserver3.SocketEffect.ShutdownConnection).build()
                        204 -> {
                            results += path to request.body!!.utf8()
                            MockResponse.Builder().code(204).build()
                        }
                        else -> MockResponse.Builder().code(code).build()
                    }
                }
                else -> MockResponse.Builder().code(404).build()
            }
        }
    }
}
