package io.github.erwsim.watchpost.core.upload

import android.content.SharedPreferences
import io.github.erwsim.watchpost.core.event.AgentClock
import io.github.erwsim.watchpost.core.event.Rfc3339
import io.github.erwsim.watchpost.core.event.Severity
import io.github.erwsim.watchpost.core.event.WatchpostJson
import io.github.erwsim.watchpost.core.outbox.Outbox
import io.github.erwsim.watchpost.core.outbox.OutboxEntity
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.JsonPrimitive
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.time.ZonedDateTime
import java.time.format.DateTimeFormatter
import java.util.zip.GZIPOutputStream
import kotlin.math.min
import kotlin.random.Random

/** Current network as seen by the uploader. */
data class NetState(val connected: Boolean, val metered: Boolean)

/** Upload limits from the settings. */
data class UploadLimits(val wifiOnlyLarge: Boolean, val largeThresholdBytes: Long)

enum class RetryCause { NETWORK, SERVER, RATE_LIMITED, AUTH, PROTOCOL }

sealed class UploadOutcome {
    data object NotEnrolled : UploadOutcome()
    data class Sent(val events: Int, val moreLeft: Boolean) : UploadOutcome()
    data class Deferred(val untilMs: Long) : UploadOutcome()
    data class Retry(val atMs: Long, val cause: RetryCause, val sent: Int) : UploadOutcome()
    data class WaitingUnmetered(val sent: Int) : UploadOutcome()
}

/** An event deleted from the buffer because the server refuses it even alone (metadata only, no content). */
data class DroppedEvent(val seq: Long, val id: String, val type: String, val reason: String)

/** Persisted upload status (shown on the home screen, used by the heartbeat). */
data class UploadStatus(
    val lastSuccessMs: Long = 0,
    val lastAttemptMs: Long = 0,
    val lastError: String? = null,
    val consecutiveFailures: Int = 0,
    val nextAttemptAtMs: Long = 0,
    val batchSize: Int = Uploader.MAX_BATCH_EVENTS,
    val rejectedTotal: Long = 0,
    val lastRejectReason: String? = null,
)

class UploadStatusStore(private val prefs: SharedPreferences) {
    private val _status = MutableStateFlow(read())
    val status: StateFlow<UploadStatus> = _status.asStateFlow()

    private fun read() = UploadStatus(
        lastSuccessMs = prefs.getLong("last_success_ms", 0),
        lastAttemptMs = prefs.getLong("last_attempt_ms", 0),
        lastError = prefs.getString("last_error", null),
        consecutiveFailures = prefs.getInt("failures", 0),
        nextAttemptAtMs = prefs.getLong("next_attempt_ms", 0),
        batchSize = prefs.getInt("batch_size", Uploader.MAX_BATCH_EVENTS),
        rejectedTotal = prefs.getLong("rejected_total", 0),
        lastRejectReason = prefs.getString("last_reject_reason", null),
    )

    @Synchronized
    fun update(transform: (UploadStatus) -> UploadStatus) {
        val s = transform(_status.value)
        prefs.edit()
            .putLong("last_success_ms", s.lastSuccessMs)
            .putLong("last_attempt_ms", s.lastAttemptMs)
            .putString("last_error", s.lastError)
            .putInt("failures", s.consecutiveFailures)
            .putLong("next_attempt_ms", s.nextAttemptAtMs)
            .putInt("batch_size", s.batchSize)
            .putLong("rejected_total", s.rejectedTotal)
            .putString("last_reject_reason", s.lastRejectReason)
            .apply()
        _status.value = s
    }
}

/**
 * Sends the outbox to the enrolled server (contract §3).
 *
 * - batches of at most 500 events and 1 MiB gzip (8 MiB raw), oldest first;
 * - rows are deleted only after a 200 whose `accepted + duplicates + rejected` equals the batch size;
 * - 401/403: everything is kept, long backoff; 413: the batch is halved (a single event refused as
 *   too large is dropped and counted in `dropped_total`, otherwise it would block the queue forever);
 * - 400 (batch envelope unreadable, deterministic: a poisoned event would block the queue until the age
 *   purge): bisection, see [runLocked]. 5xx is never treated like 400: transient, backoff, nothing split;
 * - 429/5xx/network: exponential backoff with jitter, `Retry-After` honoured;
 * - "large volumes on Wi-Fi only": on a metered network with more than the threshold buffered,
 *   only `sev >= 2` events are sent, the rest waits for an unmetered network.
 */
class Uploader(
    private val outbox: Outbox,
    private val target: () -> Pair<OkHttpClient, IngestTarget>?,
    private val statusStore: UploadStatusStore,
    private val clock: AgentClock,
    private val network: () -> NetState,
    private val limits: () -> UploadLimits,
    private val random: Random = Random.Default,
    private val maxBatchesPerRun: Int = 40,
    /** Called for every event deleted because the server refuses it alone (at most [MAX_DROP_REPORTS_PER_RUN] per run). */
    private val onDropped: (DroppedEvent) -> Unit = {},
    /** Cap on 400/413 answers in one run (see [MAX_REFUSALS_PER_RUN]); a parameter so tests can lower it. */
    private val maxRefusalsPerRun: Int = MAX_REFUSALS_PER_RUN,
) {
    private val mutex = Mutex()

    @Volatile
    private var rerunRequested = false

    val isRunning: Boolean get() = mutex.isLocked

    /** Asks a running upload to look at the outbox once more before finishing. */
    fun requestRerun() {
        rerunRequested = true
    }

    suspend fun run(force: Boolean = false): UploadOutcome = mutex.withLock {
        withContext(Dispatchers.IO) { runLocked(force) }
    }

    private suspend fun runLocked(force: Boolean): UploadOutcome {
        val now = clock.nowMillis()
        val status = statusStore.status.value
        // The retry time is a wall-clock time: one further away than the longest possible delay was set
        // by a clock that has moved back since. It is ignored, otherwise nothing would be sent until the
        // clock catches up.
        val wait = status.nextAttemptAtMs - now
        if (!force && wait > 0 && wait <= MAX_RETRY_AFTER_MS) return UploadOutcome.Deferred(status.nextAttemptAtMs)
        val (client, tgt) = try {
            target()
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            // Keystore or stored enrollment unreadable: keep everything, say why, try again later.
            return fail(RetryCause.AUTH, "credentials: ${describe(e)}", null, 0)
        } ?: return UploadOutcome.NotEnrolled

        rerunRequested = false
        var sent = 0
        var batches = 0
        var batchSize = status.batchSize.coerceIn(1, MAX_BATCH_EVENTS)

        // Poisoned batch (400) bisection, all in this run and in memory: the only durable state is the
        // buffer itself (rows are deleted only after a 200 or when a single event is refused alone), so a
        // crash at any point just restarts the bisection of what is still buffered, with no loss.
        // - `suspects`: nested ranges, as the `seq` of their last event, of batches the server refused. While
        //   there is one, batches are bounded by the innermost, so the halves of a refused batch are sent
        //   separately and not mixed with the events that follow it. Depth <= log2(500).
        // - `bisectLimit`: size of the next batch after a 400 (half of the refused one).
        // Cost: about 2 * log2(batch) requests per faulty event (one refused, one accepted sibling per level).
        // - `envelopeOk`: the server accepted this device's envelope in this run (any 200, or the probe below).
        //   Without it a 400 may come from the envelope or the server, not from an event: nothing is deleted.
        val suspects = ArrayDeque<Long>()
        var bisectLimit: Int? = null
        var envelopeOk = false
        var refusals = 0
        var droppedReports = 0

        while (batches < maxBatchesPerRun) {
            val lim = limits()
            val net = network()
            val totals = outbox.totals.value
            val restricted = lim.wifiOnlyLarge && net.metered && totals.bytes > lim.largeThresholdBytes
            val minSev = if (restricted) Severity.WARNING else Severity.INFO

            var rows = outbox.batch(bisectLimit ?: batchSize, minSev, suspects.lastOrNull() ?: Long.MAX_VALUE)
            if (rows.isEmpty()) {
                if (suspects.isNotEmpty()) {
                    // Nothing left in the refused range (restricted by severity, or deleted meanwhile).
                    suspects.clear()
                    bisectLimit = null
                    continue
                }
                if (rerunRequested) {
                    rerunRequested = false
                    continue
                }
                return if (restricted && outbox.totals.value.count > 0) {
                    UploadOutcome.WaitingUnmetered(sent)
                } else {
                    UploadOutcome.Sent(sent, moreLeft = false)
                }
            }

            var payload = UploadPayload.build(tgt, rows, clock.nowMillis())
            while (!payload.fits() && rows.size > 1) {
                rows = rows.subList(0, rows.size / 2)
                payload = UploadPayload.build(tgt, rows, clock.nowMillis())
            }
            if (!payload.fits()) {
                dropRows(rows, "event_too_large_local", droppedReports++)
                continue
            }

            statusStore.update { it.copy(lastAttemptMs = clock.nowMillis()) }
            val response = when (val a = attempt(client, tgt, payload, sent)) {
                is Attempt.Failed -> return a.outcome
                is Attempt.Response -> a.result
            }

            when (response.code) {
                200 -> {
                    val ack = try {
                        WatchpostJson.decodeFromString(IngestResponse.serializer(), response.body)
                    } catch (e: Exception) {
                        return fail(RetryCause.PROTOCOL, "bad_response", null, sent)
                    }
                    val total = ack.accepted + ack.duplicates + ack.rejected.size
                    if (total != rows.size) {
                        return fail(RetryCause.PROTOCOL, "ack_mismatch $total/${rows.size}", null, sent)
                    }
                    outbox.remove(rows)
                    envelopeOk = true
                    sent += rows.size
                    batches++
                    val grown = if (rows.size == batchSize) min(MAX_BATCH_EVENTS, batchSize * 2) else batchSize
                    batchSize = grown
                    bisectLimit = null
                    popExhaustedRanges(suspects, rows.last().seq)
                    statusStore.update {
                        it.copy(
                            lastSuccessMs = clock.nowMillis(),
                            lastError = null,
                            consecutiveFailures = 0,
                            nextAttemptAtMs = 0,
                            batchSize = grown,
                            rejectedTotal = it.rejectedTotal + ack.rejected.size,
                            lastRejectReason = ack.rejected.lastOrNull()?.reason ?: it.lastRejectReason,
                        )
                    }
                }
                400 -> {
                    if (++refusals > maxRefusalsPerRun) {
                        return fail(RetryCause.PROTOCOL, "http_400", null, sent)
                    }
                    if (!envelopeOk) {
                        // First 400 of the run: is it the envelope or an event? A batch with no event carries
                        // the same envelope (device_id, agent_version, sent_at); the contract allows 0..500.
                        when (val probe = probeEnvelope(client, tgt, sent)) {
                            null -> envelopeOk = true
                            else -> return probe
                        }
                    }
                    if (rows.size > 1) {
                        if (suspects.lastOrNull() != rows.last().seq) suspects.addLast(rows.last().seq)
                        bisectLimit = (rows.size + 1) / 2
                        statusStore.update { it.copy(lastError = "http_400") }
                    } else {
                        dropRows(rows, "http_400", droppedReports++)
                        bisectLimit = null
                        popExhaustedRanges(suspects, rows.last().seq)
                    }
                }
                413 -> {
                    if (++refusals > maxRefusalsPerRun) {
                        return fail(RetryCause.PROTOCOL, "http_413", null, sent)
                    }
                    if (rows.size > 1) {
                        batchSize = maxOf(1, rows.size / 2)
                        statusStore.update { it.copy(batchSize = batchSize, lastError = "http_413") }
                    } else {
                        dropRows(rows, "http_413", droppedReports++)
                    }
                }
                else -> return failFor(response, sent)
            }
        }
        return UploadOutcome.Sent(sent, moreLeft = outbox.totals.value.count > 0)
    }

    /** Forgets the suspect ranges whose last event has just been sent or deleted. */
    private fun popExhaustedRanges(suspects: ArrayDeque<Long>, lastSeq: Long) {
        while (suspects.isNotEmpty() && lastSeq >= suspects.last()) suspects.removeLast()
    }

    private sealed class Attempt {
        class Response(val result: HttpResult) : Attempt()
        class Failed(val outcome: UploadOutcome) : Attempt()
    }

    private fun attempt(client: OkHttpClient, tgt: IngestTarget, payload: UploadPayload.Built, sent: Int): Attempt = try {
        Attempt.Response(post(client, tgt, payload))
    } catch (e: IOException) {
        Attempt.Failed(fail(RetryCause.NETWORK, "network: ${e.message ?: e.javaClass.simpleName}", null, sent))
    } catch (e: CancellationException) {
        throw e
    } catch (e: Exception) {
        // Not an I/O error (Keystore/provider failure while signing the TLS handshake, invalid
        // header…): same treatment, never an uncaught exception that would leave no trace.
        Attempt.Failed(fail(RetryCause.NETWORK, "network: ${describe(e)}", null, sent))
    }

    /** Outcome for the answers that always end the run (401/403, 429, 5xx, anything unexpected). */
    private fun failFor(response: HttpResult, sent: Int): UploadOutcome = when (response.code) {
        401, 403 -> fail(RetryCause.AUTH, "http_${response.code}", response.retryAfterMs, sent)
        429 -> fail(RetryCause.RATE_LIMITED, "http_429", response.retryAfterMs, sent)
        in 500..599 -> fail(RetryCause.SERVER, "http_${response.code}", response.retryAfterMs, sent)
        else -> fail(RetryCause.PROTOCOL, "http_${response.code}", response.retryAfterMs, sent)
    }

    /**
     * Sends a batch without events. Returns null when the server accepts it (the envelope is fine, so a 400
     * on events comes from the events), otherwise the outcome that ends the run: a 400 here means the
     * envelope or the server is at fault, and deleting events would lose healthy data.
     */
    private fun probeEnvelope(client: OkHttpClient, tgt: IngestTarget, sent: Int): UploadOutcome? {
        val payload = UploadPayload.build(tgt, emptyList(), clock.nowMillis())
        val response = when (val a = attempt(client, tgt, payload, sent)) {
            is Attempt.Failed -> return a.outcome
            is Attempt.Response -> a.result
        }
        if (response.code != 200) {
            return if (response.code == 400) {
                fail(RetryCause.PROTOCOL, "http_400_envelope", null, sent)
            } else {
                failFor(response, sent)
            }
        }
        val ack = try {
            WatchpostJson.decodeFromString(IngestResponse.serializer(), response.body)
        } catch (e: Exception) {
            return fail(RetryCause.PROTOCOL, "bad_response", null, sent)
        }
        val total = ack.accepted + ack.duplicates + ack.rejected.size
        return if (total == 0) null else fail(RetryCause.PROTOCOL, "ack_mismatch $total/0", null, sent)
    }

    /** Deletes events that cannot be sent (rows and `dropped_total` in one transaction) and traces them. */
    private suspend fun dropRows(rows: List<OutboxEntity>, reason: String, reportsSoFar: Int) {
        outbox.drop(rows)
        statusStore.update { it.copy(lastError = reason) }
        if (reportsSoFar < MAX_DROP_REPORTS_PER_RUN) {
            rows.forEach {
                try {
                    onDropped(DroppedEvent(it.seq, it.id, it.type, reason))
                } catch (e: CancellationException) {
                    throw e
                } catch (_: Exception) {
                    // Tracing must never keep the queue blocked.
                }
            }
        }
    }

    private fun describe(e: Exception) = "${e.javaClass.simpleName}: ${e.message.orEmpty()}".take(200)

    private fun fail(cause: RetryCause, error: String, retryAfterMs: Long?, sent: Int): UploadOutcome {
        val now = clock.nowMillis()
        var at = 0L
        statusStore.update {
            val failures = it.consecutiveFailures + 1
            val delay = retryAfterMs?.coerceIn(1_000, MAX_RETRY_AFTER_MS) ?: backoffMs(cause, failures)
            at = now + delay
            it.copy(lastError = error, consecutiveFailures = failures, nextAttemptAtMs = at)
        }
        return UploadOutcome.Retry(at, cause, sent)
    }

    /** Exponential backoff with jitter: a random value in [d/2, d], d = base·2^(n−1) capped. */
    internal fun backoffMs(cause: RetryCause, failures: Int): Long {
        val (base, cap) = when (cause) {
            RetryCause.NETWORK -> 30_000L to 30 * 60_000L
            RetryCause.SERVER, RetryCause.RATE_LIMITED -> 60_000L to 60 * 60_000L
            RetryCause.AUTH -> 30 * 60_000L to 6 * 3_600_000L
            RetryCause.PROTOCOL -> 5 * 60_000L to 6 * 3_600_000L
        }
        val exp = base * (1L shl (failures - 1).coerceIn(0, 20))
        val d = min(cap, exp)
        return d / 2 + (random.nextDouble() * (d / 2)).toLong()
    }

    private class HttpResult(val code: Int, val body: String, val retryAfterMs: Long?)

    private fun post(client: OkHttpClient, tgt: IngestTarget, payload: UploadPayload.Built): HttpResult {
        val request = Request.Builder()
            .url(tgt.ingestUrl)
            .header("Authorization", "Bearer ${tgt.token}")
            .header("Content-Encoding", "gzip")
            .post(payload.gzip.toRequestBody(JSON))
            .build()
        client.newCall(request).execute().use { response ->
            val body = if (response.code == 200) response.body.string() else ""
            return HttpResult(response.code, body, parseRetryAfter(response.header("Retry-After"), clock.nowMillis()))
        }
    }

    companion object {
        const val MAX_BATCH_EVENTS = 500
        const val MAX_COMPRESSED_BYTES = 1024 * 1024
        const val MAX_RAW_BYTES = 8 * 1024 * 1024
        const val MAX_RETRY_AFTER_MS = 24 * 3_600_000L

        /**
         * 400/413 answers tolerated in one run. Bisecting one faulty event of a 500-event batch costs about
         * 10 refusals, so a run handles a few; beyond that it ends with a normal PROTOCOL backoff and the
         * next cycle continues (no request storm, the bisection loses nothing by being cut).
         */
        const val MAX_REFUSALS_PER_RUN = 60
        const val MAX_DROP_REPORTS_PER_RUN = 5
        private val JSON = "application/json".toMediaType()

        /** `Retry-After` as delay-seconds or HTTP-date; null if absent or unparsable. */
        fun parseRetryAfter(value: String?, nowMs: Long): Long? {
            val v = value?.trim()?.takeIf { it.isNotEmpty() } ?: return null
            v.toLongOrNull()?.let { return if (it >= 0) it * 1000 else null }
            return try {
                val at = ZonedDateTime.parse(v, DateTimeFormatter.RFC_1123_DATE_TIME).toInstant().toEpochMilli()
                (at - nowMs).coerceAtLeast(0)
            } catch (_: Exception) {
                null
            }
        }
    }
}

/** Builds the `POST /api/v1/ingest` body from stored event JSON, without re-serializing events. */
object UploadPayload {
    class Built(val gzip: ByteArray, val rawSize: Int) {
        fun fits(): Boolean = gzip.size <= Uploader.MAX_COMPRESSED_BYTES && rawSize <= Uploader.MAX_RAW_BYTES
    }

    fun json(target: IngestTarget, rows: List<OutboxEntity>, sentAtMs: Long): String = buildString {
        append("{\"device_id\":").append(JsonPrimitive(target.deviceId).toString())
        append(",\"agent_version\":").append(JsonPrimitive(target.agentVersion).toString())
        append(",\"sent_at\":").append(JsonPrimitive(Rfc3339.format(sentAtMs)).toString())
        append(",\"events\":[")
        rows.forEachIndexed { i, row ->
            if (i > 0) append(',')
            append(row.json)
        }
        append("]}")
    }

    fun build(target: IngestTarget, rows: List<OutboxEntity>, sentAtMs: Long): Built {
        val raw = json(target, rows, sentAtMs).toByteArray(Charsets.UTF_8)
        val out = ByteArrayOutputStream(raw.size / 4 + 64)
        GZIPOutputStream(out).use { it.write(raw) }
        return Built(out.toByteArray(), raw.size)
    }
}
