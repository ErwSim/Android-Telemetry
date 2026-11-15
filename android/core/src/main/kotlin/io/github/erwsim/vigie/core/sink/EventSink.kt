package io.github.erwsim.vigie.core.sink

import io.github.erwsim.vigie.core.event.EmptyData
import io.github.erwsim.vigie.core.event.EventDataBuilder
import io.github.erwsim.vigie.core.event.Severity
import io.github.erwsim.vigie.core.event.eventData
import kotlinx.serialization.json.JsonObject

/**
 * The single API through which anything in the agent emits an event.
 *
 * The sink assigns `id` (ULID), `ts`, `boot_id`, `elapsed_ms` at call time and `seq` when the
 * event is persisted. `emit` never blocks on I/O: events are grouped in memory and written to
 * the outbox in one transaction (a few seconds later, immediately for `sev >= 2`).
 *
 * `emit` is thread-safe and may be called from any thread.
 */
interface EventSink {
    /** @throws IllegalArgumentException if [type] does not match the contract or [sev] is out of range. */
    fun emit(type: String, sev: Int = Severity.INFO, data: JsonObject = EmptyData)
}

/** Implemented by sinks that buffer in memory (shutdown paths force a write). */
interface FlushableSink {
    /** Writes pending events now; blocks the calling thread for at most [timeoutMs]. */
    fun flushBlocking(timeoutMs: Long = 2_000): Boolean
}

/** Convenience form: `sink.emit("device.screen") { put("state", "on") }`. */
inline fun EventSink.emit(type: String, sev: Int = Severity.INFO, block: EventDataBuilder.() -> Unit) =
    emit(type, sev, eventData(block))
