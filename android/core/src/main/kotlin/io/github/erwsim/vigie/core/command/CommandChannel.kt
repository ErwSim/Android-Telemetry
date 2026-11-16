package io.github.erwsim.vigie.core.command

import io.github.erwsim.vigie.core.event.AgentClock
import io.github.erwsim.vigie.core.event.Rfc3339
import io.github.erwsim.vigie.core.event.VigieJson
import io.github.erwsim.vigie.core.upload.IngestTarget
import io.github.erwsim.vigie.core.upload.Uploader
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import okhttp3.Call
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.io.IOException
import java.util.concurrent.TimeUnit
import kotlin.math.min
import kotlin.random.Random

/** Transport chosen in the settings (contract §8): permanent connection (SSE) or periodic polling. */
enum class ChannelMode(val wire: String) {
    STREAM("stream"),
    POLL("poll"),
    ;

    companion object {
        fun fromWire(s: String) = entries.firstOrNull { it.wire == s } ?: STREAM
    }
}

/** What the channel is doing, shown in the app and in the permanent notification. */
enum class ChannelPhase {
    /** Switched off in the app. */
    OFF,
    NOT_ENROLLED,

    /** No network: nothing is attempted until one comes back. */
    WAITING_NETWORK,
    CONNECTING,

    /** Stream open (SSE). */
    CONNECTED,

    /** Poll mode, between two polls. */
    POLL_IDLE,

    /** Waiting before the next attempt after a failure. */
    BACKOFF,

    /** 401/403: the server refuses this device. Stopped until re-enrollment or a manual reconnection. */
    REFUSED,

    /** 404/405: the server has no command channel (older collector). Long backoff. */
    UNSUPPORTED,
}

data class ChannelState(
    val phase: ChannelPhase = ChannelPhase.OFF,
    val mode: ChannelMode = ChannelMode.STREAM,
    /** Wall time of the last byte or answer from the server. */
    val lastContactMs: Long = 0,
    val lastError: String? = null,
    /** Wall time of the next attempt (backoff or next poll), 0 if none. */
    val nextAttemptAtMs: Long = 0,
)

/** Settings read at every turn of the loop (never written by the channel). */
data class ChannelConfig(val enabled: Boolean, val mode: ChannelMode, val pollIntervalMin: Int)

/** Android services used by the channel, faked in the JVM tests. */
interface ChannelPlatform {
    fun isNetworkAvailable(): Boolean

    /** Identity of the current default network (a stream opened on another network is dead). */
    fun networkKey(): String?

    /**
     * Wakes the channel ([CommandChannel.tick]) at [atElapsedMs] (`elapsedRealtime`), also in Doze
     * (inexact `setAndAllowWhileIdle`: at most about every 9 min in deep Doze). One pending wake-up at a time.
     */
    fun scheduleWakeup(atElapsedMs: Long)
    fun cancelWakeup()

    /** Runs [block] under a partial wake lock released after it or at [timeoutMs]. */
    suspend fun <T> withWakeLock(timeoutMs: Long, block: suspend () -> T): T
}

/**
 * Client of the command channel (contract §8), hosted by the foreground service.
 *
 * Sobriety (the main unknown, not measurable without the phone — see `ARCHITECTURE-CODE.md`):
 * - no permanent wake lock: the stream is a blocking read of an idle TCP connection; a wake lock is held
 *   only while a command is handled ([COMMAND_WAKELOCK_MS]) and around a poll;
 * - read timeout [STREAM_READ_TIMEOUT_MS] = 2.5 × the server's 120 s keep-alive (one lost keep-alive is
 *   tolerated). Timers stop while the CPU sleeps, so a stale connection is also detected by the
 *   [ChannelPlatform.scheduleWakeup] tick ([STALE_AFTER_MS] without a byte → reconnection);
 * - no reconnection loop: without network nothing is attempted until the network callback says it is
 *   back; failures back off exponentially with jitter ([BACKOFF_BASE_MS] → [BACKOFF_MAX_MS]); a stream
 *   that dies right after opening counts as a failure; 401/403 stops everything and is shown
 *   ([ChannelPhase.REFUSED]) until re-enrollment, a settings change or "Reconnecter";
 * - polling at each upload ([onUploadCycle]) when the stream is not open, at most once a minute.
 */
class CommandChannel(
    private val scope: CoroutineScope,
    private val clock: AgentClock,
    private val target: () -> Pair<OkHttpClient, IngestTarget>?,
    private val config: () -> ChannelConfig,
    private val processor: CommandProcessor,
    private val state: CommandStateStore,
    private val platform: ChannelPlatform,
    private val random: Random = Random.Default,
    private val streamReadTimeoutMs: Long = STREAM_READ_TIMEOUT_MS,
) {
    private enum class Kick { CONFIG, NETWORK, POLL_NOW, TICK }
    private enum class Cause { NETWORK, SERVER, RATE_LIMITED, UNSUPPORTED }

    private val _state = MutableStateFlow(ChannelState())
    val channelState: StateFlow<ChannelState> = _state.asStateFlow()

    private val kicks = Channel<Kick>(Channel.UNLIMITED)
    private val queue = Channel<CommandEnvelope?>(QUEUE_CAPACITY)
    private val resultsMutex = Mutex()

    private var loopJob: Job? = null
    private var workerJob: Job? = null

    @Volatile private var currentCall: Call? = null
    @Volatile private var streamNetworkKey: String? = null
    @Volatile private var lastByteElapsed = 0L
    @Volatile private var refused = false
    @Volatile private var nextAttemptElapsed = 0L
    @Volatile private var failures = 0
    @Volatile private var lastCause: Cause? = null
    @Volatile private var lastPollElapsed = Long.MIN_VALUE / 2
    @Volatile private var pollRequested = false
    @Volatile private var resultsRetryElapsed = 0L
    @Volatile private var resultFailures = 0
    private var streamClient: Pair<OkHttpClient, OkHttpClient>? = null

    val isRunning: Boolean get() = loopJob?.isActive == true

    @Synchronized
    fun start() {
        if (loopJob?.isActive == true) return
        workerJob = scope.launch { worker() }
        loopJob = scope.launch { loop() }
    }

    @Synchronized
    fun stop() {
        loopJob?.cancel()
        workerJob?.cancel()
        loopJob = null
        workerJob = null
        currentCall?.cancel()
        platform.cancelWakeup()
        _state.value = _state.value.copy(phase = ChannelPhase.OFF, nextAttemptAtMs = 0)
    }

    /** A setting, the enrollment or the user's "Reconnecter" changed things: start over at once. */
    fun onConfigChanged() {
        refused = false
        failures = 0
        nextAttemptElapsed = 0
        currentCall?.cancel()
        kicks.trySend(Kick.CONFIG)
    }

    /** Default network available (also called when it changes). */
    fun onNetworkAvailable() {
        val key = platform.networkKey()
        if (currentCall != null && _state.value.phase == ChannelPhase.CONNECTED && key != null && key != streamNetworkKey) {
            // The stream was opened on another network: its socket is dead even if no error shows yet.
            currentCall?.cancel()
        }
        if (lastCause == Cause.NETWORK) nextAttemptElapsed = 0
        kicks.trySend(Kick.NETWORK)
    }

    /** Called after each upload run: poll if the stream is not open (contract: "interroge à chaque envoi de lot"). */
    fun onUploadCycle() {
        flushSoon()
        if (_state.value.phase == ChannelPhase.CONNECTED) return
        if (lastCause == Cause.NETWORK) nextAttemptElapsed = 0
        pollRequested = true
        kicks.trySend(Kick.POLL_NOW)
    }

    /** Wake-up from [ChannelPlatform.scheduleWakeup] or the maintenance worker: re-check deadlines and staleness. */
    fun tick() {
        if (_state.value.phase == ChannelPhase.CONNECTED) {
            if (clock.elapsedRealtime() - lastByteElapsed > STALE_AFTER_MS) {
                currentCall?.cancel()
            } else {
                // Next watchdog check of the open stream (one pending alarm at a time).
                platform.scheduleWakeup(clock.elapsedRealtime() + WATCHDOG_INTERVAL_MS)
            }
        }
        flushSoon()
        kicks.trySend(Kick.TICK)
    }

    /** Results waiting while the loop is busy with an open stream: sent from here (backoff respected). */
    private fun flushSoon() {
        if (loopJob?.isActive != true || state.pendingResults().isEmpty()) return
        scope.launch {
            try {
                target()?.let { flushResults(it) }
            } catch (e: CancellationException) {
                throw e
            } catch (_: Exception) {
                // Next opportunity.
            }
        }
    }

    // ---------------------------------------------------------------------------------------- loop

    private suspend fun loop() {
        while (scope.isActive) {
            try {
                turn()
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                // Never let an unexpected error end the channel: back off and go on.
                fail(Cause.SERVER, "internal: ${e.javaClass.simpleName}", null)
                awaitKick(nextAttemptElapsed)
            }
        }
    }

    /** One turn of the loop: decide, then connect, poll or wait. */
    private suspend fun turn() {
        val cfg = config()
        setState { it.copy(mode = cfg.mode) }
        if (!cfg.enabled) {
            platform.cancelWakeup()
            setState { it.copy(phase = ChannelPhase.OFF, nextAttemptAtMs = 0, lastError = null) }
            awaitKick(null)
            return
        }
        val t = try {
            target()
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            fail(Cause.SERVER, "credentials: ${e.javaClass.simpleName}", null)
            awaitKick(nextAttemptElapsed)
            return
        }
        if (t == null) {
            setState { it.copy(phase = ChannelPhase.NOT_ENROLLED, nextAttemptAtMs = 0) }
            awaitKick(null)
            return
        }
        if (refused) {
            platform.cancelWakeup()
            setState { it.copy(phase = ChannelPhase.REFUSED, nextAttemptAtMs = 0) }
            awaitKick(null)
            return
        }
        if (!platform.isNetworkAvailable()) {
            platform.cancelWakeup()
            lastCause = Cause.NETWORK
            setState { it.copy(phase = ChannelPhase.WAITING_NETWORK, nextAttemptAtMs = 0) }
            awaitKick(null)
            return
        }
        val now = clock.elapsedRealtime()
        val pollDue = cfg.mode == ChannelMode.POLL && pollRequested && now - lastPollElapsed >= MIN_POLL_SPACING_MS
        if (now < nextAttemptElapsed && !pollDue) {
            platform.scheduleWakeup(nextAttemptElapsed)
            val phase = when {
                cfg.mode == ChannelMode.POLL && lastCause == null -> ChannelPhase.POLL_IDLE
                lastCause == Cause.UNSUPPORTED -> ChannelPhase.UNSUPPORTED
                else -> ChannelPhase.BACKOFF
            }
            setState { it.copy(phase = phase, nextAttemptAtMs = clock.nowMillis() + (nextAttemptElapsed - now)) }
            awaitKick(nextAttemptElapsed)
            return
        }
        pollRequested = false
        flushResults(t)
        if (refused) return
        when (cfg.mode) {
            ChannelMode.STREAM -> runStream(t)
            ChannelMode.POLL -> runPoll(t, cfg.pollIntervalMin)
        }
    }

    /** Waits for a kick, or until [deadlineElapsed] (null: no deadline). */
    private suspend fun awaitKick(deadlineElapsed: Long?) {
        if (deadlineElapsed == null) {
            kicks.receive()
        } else {
            val remaining = deadlineElapsed - clock.elapsedRealtime()
            if (remaining > 0) withTimeoutOrNull(remaining) { kicks.receive() }
        }
        // Several kicks may be pending: one turn of the loop answers them all.
        while (kicks.tryReceive().isSuccess) Unit
    }

    private fun backoffMs(cause: Cause, failures: Int): Long {
        val (base, cap) = when (cause) {
            Cause.NETWORK, Cause.SERVER -> BACKOFF_BASE_MS to BACKOFF_MAX_MS
            Cause.RATE_LIMITED -> 60_000L to 60 * 60_000L
            Cause.UNSUPPORTED -> UNSUPPORTED_RETRY_MS to UNSUPPORTED_RETRY_MS
        }
        val d = min(cap, base * (1L shl (failures - 1).coerceIn(0, 20)))
        return d / 2 + (random.nextDouble() * (d / 2)).toLong()
    }

    private fun fail(cause: Cause, error: String, retryAfterMs: Long?) {
        failures++
        lastCause = cause
        val delay = retryAfterMs?.coerceIn(1_000, MAX_RETRY_AFTER_MS) ?: backoffMs(cause, failures)
        nextAttemptElapsed = clock.elapsedRealtime() + delay
        setState { it.copy(phase = if (cause == Cause.UNSUPPORTED) ChannelPhase.UNSUPPORTED else ChannelPhase.BACKOFF, lastError = error) }
    }

    private fun refuse(code: Int) {
        refused = true
        lastCause = null
        setState { it.copy(phase = ChannelPhase.REFUSED, lastError = "http_$code", nextAttemptAtMs = 0) }
    }

    private fun contact() {
        lastByteElapsed = clock.elapsedRealtime()
        setState { it.copy(lastContactMs = clock.nowMillis()) }
    }

    private inline fun setState(transform: (ChannelState) -> ChannelState) {
        _state.value = transform(_state.value)
    }

    // -------------------------------------------------------------------------------------- stream

    private fun clientForStream(base: OkHttpClient): OkHttpClient {
        streamClient?.let { (b, s) -> if (b === base) return s }
        // Same TLS client (client certificate, pinned CA), longer read timeout, no overall call timeout.
        val s = base.newBuilder()
            .readTimeout(streamReadTimeoutMs, TimeUnit.MILLISECONDS)
            .callTimeout(0, TimeUnit.MILLISECONDS)
            .build()
        streamClient = base to s
        return s
    }

    private fun runStream(t: Pair<OkHttpClient, IngestTarget>) {
        val (base, tgt) = t
        val url = tgt.baseUrl.newBuilder().addPathSegments("api/v1/commands/stream").build()
        val request = Request.Builder().url(url)
            .header("Authorization", "Bearer ${tgt.token}")
            .header("Accept", "text/event-stream")
            .header("Cache-Control", "no-cache")
            .get().build()
        setState { it.copy(phase = ChannelPhase.CONNECTING) }
        platform.scheduleWakeup(clock.elapsedRealtime() + WATCHDOG_INTERVAL_MS)
        val call = clientForStream(base).newCall(request)
        currentCall = call
        streamNetworkKey = platform.networkKey()
        val openedAt = clock.elapsedRealtime()
        var delivered = false
        try {
            call.execute().use { response ->
                when (response.code) {
                    200 -> Unit
                    401, 403 -> return refuse(response.code)
                    404, 405 -> return fail(Cause.UNSUPPORTED, "http_${response.code}", null)
                    429 -> return fail(Cause.RATE_LIMITED, "http_429", Uploader.parseRetryAfter(response.header("Retry-After"), clock.nowMillis()))
                    else -> return fail(Cause.SERVER, "http_${response.code}", Uploader.parseRetryAfter(response.header("Retry-After"), clock.nowMillis()))
                }
                contact()
                setState { it.copy(phase = ChannelPhase.CONNECTED, lastError = null, nextAttemptAtMs = 0) }
                val source = response.body.source()
                val parser = SseParser { event, data ->
                    if (event == "command") {
                        delivered = true
                        enqueue(data)
                    }
                }
                while (true) {
                    val line = source.readUtf8Line() ?: break
                    contact()
                    if (line.length > MAX_LINE_CHARS) throw IOException("line too long")
                    parser.line(line)
                }
            }
            // Orderly end (server restart, connection replaced): reconnect, quickly if it had lived.
            endOfStream(openedAt, delivered, "stream_closed")
        } catch (e: IOException) {
            if (call.isCanceled()) {
                // We cancelled it (settings, network change, stale): start over without penalty.
                setState { it.copy(phase = ChannelPhase.CONNECTING) }
            } else if (clock.elapsedRealtime() - lastByteElapsed > streamReadTimeoutMs - 1_000 && lastByteElapsed >= openedAt) {
                endOfStream(openedAt, delivered, "read_timeout")
            } else if (lastByteElapsed >= openedAt) {
                endOfStream(openedAt, delivered, "network: ${e.message ?: e.javaClass.simpleName}")
            } else {
                fail(Cause.NETWORK, "network: ${e.message ?: e.javaClass.simpleName}", null)
            }
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            fail(Cause.NETWORK, "network: ${e.javaClass.simpleName}", null)
        } finally {
            currentCall = null
        }
    }

    private fun endOfStream(openedAt: Long, delivered: Boolean, error: String) {
        val lived = clock.elapsedRealtime() - openedAt
        if (lived >= HEALTHY_STREAM_MS || delivered) {
            failures = 0
            lastCause = Cause.NETWORK
            // Short, jittered pause so that a server restart is not met by every device at the same instant.
            nextAttemptElapsed = clock.elapsedRealtime() + RECONNECT_MIN_MS + (random.nextDouble() * RECONNECT_JITTER_MS).toLong()
            setState { it.copy(phase = ChannelPhase.BACKOFF, lastError = error) }
        } else {
            fail(Cause.NETWORK, error, null)
        }
    }

    // ---------------------------------------------------------------------------------------- poll

    private suspend fun runPoll(t: Pair<OkHttpClient, IngestTarget>, intervalMin: Int) {
        lastPollElapsed = clock.elapsedRealtime()
        setState { it.copy(phase = ChannelPhase.CONNECTING) }
        val ok = platform.withWakeLock(POLL_WAKELOCK_MS) { pollOnce(t) }
        if (ok) {
            failures = 0
            lastCause = null
            nextAttemptElapsed = clock.elapsedRealtime() + intervalMin.coerceIn(1, 15) * 60_000L
            setState { it.copy(phase = ChannelPhase.POLL_IDLE, lastError = null) }
        }
    }

    /** One `GET /api/v1/commands`; false when the attempt failed (state already updated). */
    private fun pollOnce(t: Pair<OkHttpClient, IngestTarget>): Boolean {
        val (client, tgt) = t
        val url = tgt.baseUrl.newBuilder().addPathSegments("api/v1/commands").build()
        val request = Request.Builder().url(url).header("Authorization", "Bearer ${tgt.token}").get().build()
        val call = client.newCall(request)
        currentCall = call
        try {
            call.execute().use { response ->
                when (response.code) {
                    200 -> Unit
                    401, 403 -> {
                        refuse(response.code)
                        return false
                    }
                    404, 405 -> {
                        fail(Cause.UNSUPPORTED, "http_${response.code}", null)
                        return false
                    }
                    429 -> {
                        fail(Cause.RATE_LIMITED, "http_429", Uploader.parseRetryAfter(response.header("Retry-After"), clock.nowMillis()))
                        return false
                    }
                    else -> {
                        fail(Cause.SERVER, "http_${response.code}", Uploader.parseRetryAfter(response.header("Retry-After"), clock.nowMillis()))
                        return false
                    }
                }
                contact()
                val body = response.body.source().let {
                    if (!it.request(MAX_POLL_BODY_BYTES + 1) || it.buffer.size <= MAX_POLL_BODY_BYTES) it.readUtf8() else throw IOException("poll answer too large")
                }
                val commands = try {
                    // Depth checked first: the parser recurses on nested arrays (see JsonNesting).
                    if (JsonNesting.deeperThan(body, JsonNesting.MAX_ENVELOPE_DEPTH)) null else (VigieJson.parseToJsonElement(body) as? JsonObject)?.get("commands") as? JsonArray
                } catch (_: Exception) {
                    null
                }
                if (commands == null) {
                    fail(Cause.SERVER, "bad_response", null)
                    return false
                }
                commands.take(QUEUE_CAPACITY).forEach { enqueue(it.toString()) }
                return true
            }
        } catch (e: IOException) {
            if (!call.isCanceled()) fail(Cause.NETWORK, "network: ${e.message ?: e.javaClass.simpleName}", null)
            return false
        } catch (e: Exception) {
            fail(Cause.NETWORK, "network: ${e.javaClass.simpleName}", null)
            return false
        } finally {
            currentCall = null
        }
    }

    // -------------------------------------------------------------------------------------- commands

    /** Raw JSON of one command object; parsed by the worker. Full queue: dropped (the server delivers it again). */
    private fun enqueue(json: String) {
        val envelope = try {
            // Depth checked first: the parser recurses on nested arrays (see JsonNesting).
            if (JsonNesting.deeperThan(json, JsonNesting.MAX_ENVELOPE_DEPTH)) null else processor.parseEnvelope(VigieJson.parseToJsonElement(json))
        } catch (_: Exception) {
            null
        }
        queue.trySend(envelope)
    }

    private suspend fun worker() {
        for (envelope in queue) {
            try {
                platform.withWakeLock(COMMAND_WAKELOCK_MS) {
                    if (envelope == null) processor.processUnreadable() else processor.process(envelope)
                    target()?.let { flushResults(it) }
                }
            } catch (e: CancellationException) {
                throw e
            } catch (_: Exception) {
                // One command never stops the channel.
            }
        }
    }

    /** Sends the queued results (oldest first). Network or server trouble: kept, retried later with backoff. */
    suspend fun flushResults(t: Pair<OkHttpClient, IngestTarget>, force: Boolean = false) = resultsMutex.withLock {
        if (!force && clock.elapsedRealtime() < resultsRetryElapsed) return@withLock
        for (result in state.pendingResults()) {
            if (!CommandVerifier.ULID.matches(result.id)) {
                state.removePendingResult(result.id)
                continue
            }
            when (val code = postResult(t, result)) {
                200, 201, 202, 204 -> {
                    state.removePendingResult(result.id)
                    resultFailures = 0
                    resultsRetryElapsed = 0
                }
                // The server does not know this command (purged, cancelled) or refuses the body: nothing more to say.
                400, 404, 409, 410, 422 -> state.removePendingResult(result.id)
                401, 403 -> {
                    refuse(code)
                    currentCall?.cancel()
                    return@withLock
                }
                else -> {
                    // Network error (-1), 429, 5xx: keep everything, try later.
                    state.bumpAttempts(result.id)
                    resultFailures++
                    resultsRetryElapsed = clock.elapsedRealtime() + backoffMs(Cause.SERVER, resultFailures)
                    platform.scheduleWakeup(resultsRetryElapsed)
                    return@withLock
                }
            }
        }
    }

    private fun postResult(t: Pair<OkHttpClient, IngestTarget>, result: PendingResult): Int {
        val (client, tgt) = t
        val url = tgt.baseUrl.newBuilder().addPathSegments("api/v1/commands").addPathSegment(result.id).addPathSegment("result").build()
        val body = buildJsonObject {
            put("status", result.status)
            put("detail", result.detail)
            put("at", Rfc3339.format(result.atMs))
        }.toString()
        val request = Request.Builder().url(url).header("Authorization", "Bearer ${tgt.token}").post(body.toRequestBody(JSON)).build()
        return try {
            client.newCall(request).execute().use { it.code }
        } catch (_: IOException) {
            -1
        } catch (_: Exception) {
            -1
        }
    }

    companion object {
        const val SERVER_KEEPALIVE_MS = 120_000L
        const val STREAM_READ_TIMEOUT_MS = 300_000L
        const val STALE_AFTER_MS = 300_000L
        const val WATCHDOG_INTERVAL_MS = 15 * 60_000L
        const val HEALTHY_STREAM_MS = 60_000L
        const val RECONNECT_MIN_MS = 2_000L
        const val RECONNECT_JITTER_MS = 8_000L
        const val BACKOFF_BASE_MS = 5_000L
        const val BACKOFF_MAX_MS = 15 * 60_000L
        const val UNSUPPORTED_RETRY_MS = 6 * 3_600_000L
        const val MAX_RETRY_AFTER_MS = 6 * 3_600_000L
        const val MIN_POLL_SPACING_MS = 60_000L
        const val COMMAND_WAKELOCK_MS = 120_000L
        const val POLL_WAKELOCK_MS = 60_000L
        const val QUEUE_CAPACITY = 32
        const val MAX_LINE_CHARS = 64 * 1024
        const val MAX_POLL_BODY_BYTES = 1024L * 1024
        private val JSON = "application/json".toMediaType()
    }
}

/**
 * Minimal Server-Sent Events parser (WHATWG): `event:` and `data:` fields, comments (`:`) ignored,
 * a blank line dispatches. Only what contract §8 uses; `id:` and `retry:` are ignored.
 */
class SseParser(private val onEvent: (event: String, data: String) -> Unit) {
    private var event: String? = null
    private val data = StringBuilder()
    private var hasData = false

    fun line(line: String) {
        if (line.isEmpty()) {
            if (hasData) onEvent(event ?: "message", data.toString())
            event = null
            data.setLength(0)
            hasData = false
            return
        }
        if (line.startsWith(":")) return
        val colon = line.indexOf(':')
        val field = if (colon < 0) line else line.substring(0, colon)
        var value = if (colon < 0) "" else line.substring(colon + 1)
        if (value.startsWith(" ")) value = value.substring(1)
        when (field) {
            "event" -> event = value
            "data" -> {
                if (hasData) data.append('\n')
                data.append(value)
                hasData = true
            }
        }
        if (data.length > CommandChannel.MAX_LINE_CHARS) {
            data.setLength(0)
            hasData = false
        }
    }
}
