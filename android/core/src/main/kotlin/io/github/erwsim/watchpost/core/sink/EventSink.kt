package io.github.erwsim.watchpost.core.sink

import io.github.erwsim.watchpost.core.event.EmptyData
import io.github.erwsim.watchpost.core.event.EventDataBuilder
import io.github.erwsim.watchpost.core.event.Severity
import io.github.erwsim.watchpost.core.event.eventData
import kotlinx.serialization.json.JsonObject

/**
 * The single API through which anything in the agent emits an event.
 *
 * The sink assigns `id` (ULID), `ts`, `boot_id`, `elapsed_ms` at call time and `seq` when the
 * event is persisted. `emit` never blocks on I/O: events are grouped in memory and written to
 * the outbox in one transaction (a few seconds later, immediately for `sev >= 2`).
 *
 * Events read after the fact (usage events, network and security logs: contract §2, event timestamps)
 * pass [originTsMs], the wall-clock time at which the system recorded them: it becomes `ts`, and
 * `elapsed_ms` is estimated for that instant (see [OriginTime]). `seq` always stays the emission
 * order, so `ts` is not monotonic in `seq`.
 *
 * `emit` is thread-safe and may be called from any thread.
 */
interface EventSink {
    /**
     * @param originTsMs wall-clock time (ms since the epoch) given by the system for an event read
     *   after the fact; null for an event observed now.
     * @throws IllegalArgumentException if [type] does not match the contract, [sev] is out of range
     *   or [originTsMs] is not a positive time.
     */
    fun emit(type: String, sev: Int = Severity.INFO, data: JsonObject = EmptyData, originTsMs: Long? = null)
}

/** Implemented by sinks that buffer in memory (shutdown paths force a write). */
interface FlushableSink {
    /** Writes pending events now; blocks the calling thread for at most [timeoutMs]. */
    fun flushBlocking(timeoutMs: Long = 2_000): Boolean
}

/** Convenience form: `sink.emit("device.screen") { put("state", "on") }`. */
inline fun EventSink.emit(type: String, sev: Int = Severity.INFO, originTsMs: Long? = null, block: EventDataBuilder.() -> Unit) =
    emit(type, sev, eventData(block), originTsMs)

/**
 * `ts` / `elapsed_ms` of an event whose time of origin is given by the system.
 *
 * `elapsed_ms` is `SystemClock.elapsedRealtime()` at the origin, estimated as
 * `elapsed_now - (now - origin)`, i.e. on the same boot reference as every other event of this
 * `boot_id` (`ts - elapsed_ms` stays the boot time). It is clamped to `[0, elapsed_now]`:
 * - an origin before the current boot (pre-reboot security logs, usage events of the previous
 *   boot) has no `elapsedRealtime` on this `boot_id`: `elapsed_ms = 0` marks it;
 * - an origin "in the future" (wall clock moved back meanwhile) gets the emission's `elapsed_ms`.
 */
object OriginTime {
    fun elapsedAt(originTsMs: Long, nowMs: Long, elapsedNowMs: Long): Long =
        (elapsedNowMs - (nowMs - originTsMs)).coerceIn(0L, elapsedNowMs.coerceAtLeast(0L))
}
