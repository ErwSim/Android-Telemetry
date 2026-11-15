package io.github.erwsim.vigie.core.upload

import android.content.SharedPreferences
import io.github.erwsim.vigie.core.event.AgentClock
import io.github.erwsim.vigie.core.event.Rfc3339
import io.github.erwsim.vigie.core.event.Severity
import io.github.erwsim.vigie.core.event.VigieJson
import io.github.erwsim.vigie.core.outbox.Outbox
import io.github.erwsim.vigie.core.outbox.OutboxEntity
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
        val (client, tgt) = target() ?: return UploadOutcome.NotEnrolled
        val now = clock.nowMillis()
        val status = statusStore.status.value
        if (!force && status.nextAttemptAtMs > now) return UploadOutcome.Deferred(status.nextAttemptAtMs)

        rerunRequested = false
        var sent = 0
        var batches = 0
        var batchSize = status.batchSize.coerceIn(1, MAX_BATCH_EVENTS)
        while (batches < maxBatchesPerRun) {
            val lim = limits()
            val net = network()
            val totals = outbox.totals.value
            val restricted = lim.wifiOnlyLarge && net.metered && totals.bytes > lim.largeThresholdBytes
            val minSev = if (restricted) Severity.WARNING else Severity.INFO

            var rows = outbox.batch(batchSize, minSev)
            if (rows.isEmpty()) {
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
                dropOversized(rows, "event_too_large_local")
                continue
            }

            statusStore.update { it.copy(lastAttemptMs = clock.nowMillis()) }
            val response = try {
                post(client, tgt, payload)
            } catch (e: IOException) {
                return fail(RetryCause.NETWORK, "network: ${e.message ?: e.javaClass.simpleName}", null, sent)
            }

            when (response.code) {
                200 -> {
                    val ack = try {
                        VigieJson.decodeFromString(IngestResponse.serializer(), response.body)
                    } catch (e: Exception) {
                        return fail(RetryCause.PROTOCOL, "bad_response", null, sent)
                    }
                    val total = ack.accepted + ack.duplicates + ack.rejected.size
                    if (total != rows.size) {
                        return fail(RetryCause.PROTOCOL, "ack_mismatch $total/${rows.size}", null, sent)
                    }
                    outbox.remove(rows)
                    sent += rows.size
                    batches++
                    val grown = if (rows.size == batchSize) min(MAX_BATCH_EVENTS, batchSize * 2) else batchSize
                    batchSize = grown
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
                401, 403 -> return fail(RetryCause.AUTH, "http_${response.code}", response.retryAfterMs, sent)
                413 -> {
                    if (rows.size > 1) {
                        batchSize = maxOf(1, rows.size / 2)
                        statusStore.update { it.copy(batchSize = batchSize, lastError = "http_413") }
                    } else {
                        dropOversized(rows, "http_413")
                    }
                }
                429 -> return fail(RetryCause.RATE_LIMITED, "http_429", response.retryAfterMs, sent)
                in 500..599 -> return fail(RetryCause.SERVER, "http_${response.code}", response.retryAfterMs, sent)
                else -> return fail(RetryCause.PROTOCOL, "http_${response.code}", response.retryAfterMs, sent)
            }
        }
        return UploadOutcome.Sent(sent, moreLeft = outbox.totals.value.count > 0)
    }

    private suspend fun dropOversized(rows: List<OutboxEntity>, reason: String) {
        outbox.remove(rows)
        outbox.addDropped(rows.size.toLong())
        statusStore.update { it.copy(lastError = reason) }
    }

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
