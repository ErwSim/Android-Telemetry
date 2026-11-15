package io.github.erwsim.vigie.core.outbox

import androidx.room.withTransaction
import io.github.erwsim.vigie.core.event.Event
import io.github.erwsim.vigie.core.event.Rfc3339
import io.github.erwsim.vigie.core.event.VigieJson
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject

/** An event accepted by the sink but not yet written (no `seq` yet). */
data class PendingEvent(
    val id: String,
    val tsMs: Long,
    val elapsedMs: Long,
    val bootId: String,
    val type: String,
    val sev: Int,
    val data: JsonObject,
)

/** Result of a purge, used to build `agent.buffer_overflow`. */
data class PurgeReport(
    val dropped: Long,
    val oldestTsMs: Long,
    val newestTsMs: Long,
    val bytes: Long,
)

/**
 * Persistent offline buffer (contract §1/§3, ARCHITECTURE "Tampon hors-ligne").
 *
 * Guarantees:
 * - `seq` is assigned inside the same SQLite transaction as the insert and the counter update,
 *   so after any crash the counter and the rows agree: no duplicate and no reused `seq`.
 * - rows are deleted only by [remove] (after a server acknowledgement) or by purge.
 */
class Outbox(
    private val db: OutboxDatabase,
    private val json: Json = VigieJson,
) {
    private val dao = db.outboxDao()
    private val mutex = Mutex()
    private val _totals = MutableStateFlow(OutboxTotals(0, 0))
    private var initialized = false

    /** Cached count/bytes of buffered events (exact: maintained on every insert/delete). */
    val totals: StateFlow<OutboxTotals> = _totals.asStateFlow()

    private suspend fun ensureInit() {
        if (!initialized) {
            _totals.value = dao.totals()
            initialized = true
        }
    }

    /** Assigns sequence numbers and writes the events in one transaction. */
    suspend fun append(pending: List<PendingEvent>): List<Event> {
        if (pending.isEmpty()) return emptyList()
        return mutex.withLock {
            ensureInit()
            var addedBytes = 0L
            val events = db.withTransaction {
                val last = dao.counter(COUNTER_LAST_SEQ) ?: 0L
                val events = pending.mapIndexed { i, p ->
                    Event(
                        id = p.id,
                        ts = Rfc3339.format(p.tsMs),
                        seq = last + 1 + i,
                        bootId = p.bootId,
                        elapsedMs = p.elapsedMs,
                        type = p.type,
                        sev = p.sev,
                        data = p.data,
                    )
                }
                val rows = events.mapIndexed { i, e ->
                    val encoded = json.encodeToString(Event.serializer(), e)
                    val size = encoded.toByteArray(Charsets.UTF_8).size
                    addedBytes += size
                    OutboxEntity(e.seq, e.id, e.type, e.sev, pending[i].tsMs, encoded, size)
                }
                dao.insertAll(rows)
                dao.setCounter(CounterEntity(COUNTER_LAST_SEQ, last + events.size))
                events
            }
            _totals.value = OutboxTotals(_totals.value.count + events.size, _totals.value.bytes + addedBytes)
            events
        }
    }

    /** Oldest events first, optionally restricted to `sev >= minSev`. */
    suspend fun batch(limit: Int, minSev: Int = 0): List<OutboxEntity> = dao.oldest(limit, minSev)

    suspend fun countMinSev(minSev: Int): Long = dao.countMinSev(minSev)

    /** Most recent buffered events (local journal). */
    suspend fun newest(limit: Int): List<OutboxEntity> = dao.newest(limit)

    /** Deletes acknowledged rows. */
    suspend fun remove(rows: List<OutboxEntity>) {
        if (rows.isEmpty()) return
        mutex.withLock {
            ensureInit()
            var removedCount = 0L
            var removedBytes = 0L
            db.withTransaction {
                rows.chunked(CHUNK).forEach { chunk ->
                    val seqs = chunk.map { it.seq }
                    removedBytes += dao.sizeOf(seqs)
                    removedCount += dao.deleteSeqs(seqs)
                }
            }
            _totals.value = OutboxTotals(
                (_totals.value.count - removedCount).coerceAtLeast(0),
                (_totals.value.bytes - removedBytes).coerceAtLeast(0),
            )
        }
    }

    /**
     * Applies the age cap, then the size cap. The size cap removes the oldest events of the
     * lowest severity first, down to 90 % of [maxBytes] (hysteresis to avoid purging on every write).
     * Returns null when nothing was dropped.
     */
    suspend fun enforceLimits(maxBytes: Long, maxAgeMs: Long, nowMs: Long): PurgeReport? = mutex.withLock {
        var dropped = 0L
        var bytes = 0L
        var oldest = Long.MAX_VALUE
        var newest = Long.MIN_VALUE
        db.withTransaction {
            val cutoff = nowMs - maxAgeMs
            val aged = dao.olderThan(cutoff)
            if (aged.count > 0) {
                dao.deleteOlderThan(cutoff)
                dropped += aged.count
                bytes += aged.bytes
                aged.oldest?.let { oldest = minOf(oldest, it) }
                aged.newest?.let { newest = maxOf(newest, it) }
            }
            var current = dao.totals()
            if (current.bytes > maxBytes) {
                val target = maxBytes * 9 / 10
                var toFree = current.bytes - target
                val victims = ArrayList<Long>()
                var offset = 0
                while (toFree > 0) {
                    val page = dao.purgeCandidates(PAGE, offset)
                    if (page.isEmpty()) break
                    for (c in page) {
                        if (toFree <= 0) break
                        victims += c.seq
                        toFree -= c.sizeBytes
                        bytes += c.sizeBytes
                        oldest = minOf(oldest, c.tsMs)
                        newest = maxOf(newest, c.tsMs)
                    }
                    offset += page.size
                }
                victims.chunked(CHUNK).forEach { dao.deleteSeqs(it) }
                dropped += victims.size
                current = dao.totals()
            }
            if (dropped > 0) {
                val total = dao.counter(COUNTER_DROPPED) ?: 0L
                dao.setCounter(CounterEntity(COUNTER_DROPPED, total + dropped))
            }
            _totals.value = current
            initialized = true
        }
        if (dropped == 0L) null else PurgeReport(dropped, oldest, newest, bytes)
    }

    /** Oldest buffered timestamp (wall ms), for the periodic age check. */
    suspend fun oldestTsMs(): Long? = dao.oldestTs()

    /** Counts events dropped outside of a purge (e.g. a single event the server refuses as too large). */
    suspend fun addDropped(n: Long) {
        mutex.withLock {
            db.withTransaction {
                val total = dao.counter(COUNTER_DROPPED) ?: 0L
                dao.setCounter(CounterEntity(COUNTER_DROPPED, total + n))
            }
        }
    }

    suspend fun droppedTotal(): Long = dao.counter(COUNTER_DROPPED) ?: 0L

    suspend fun lastSeq(): Long = dao.counter(COUNTER_LAST_SEQ) ?: 0L

    /** Deletes every buffered event (unenrollment). The `seq` counter is kept: it never goes back. */
    suspend fun clear() {
        mutex.withLock {
            dao.clear()
            _totals.value = OutboxTotals(0, 0)
            initialized = true
        }
    }

    suspend fun refreshTotals(): OutboxTotals = mutex.withLock {
        dao.totals().also {
            _totals.value = it
            initialized = true
        }
    }

    private companion object {
        const val COUNTER_LAST_SEQ = "last_seq"
        const val COUNTER_DROPPED = "dropped_total"
        const val CHUNK = 500
        const val PAGE = 2000
    }
}
