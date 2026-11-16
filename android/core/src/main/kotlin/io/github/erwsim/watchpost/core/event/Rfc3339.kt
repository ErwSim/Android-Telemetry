package io.github.erwsim.watchpost.core.event

import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter

/** RFC 3339 UTC timestamps with exactly three fractional digits, e.g. `2026-11-15T21:43:03.974Z`. */
object Rfc3339 {
    private val FORMAT: DateTimeFormatter =
        DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'").withZone(ZoneOffset.UTC)

    fun format(epochMillis: Long): String = FORMAT.format(Instant.ofEpochMilli(epochMillis))

    fun parseOrNull(s: String): Long? = try {
        Instant.parse(s).toEpochMilli()
    } catch (_: Exception) {
        null
    }
}

/** Wall clock and monotonic clock, injectable for tests. */
interface AgentClock {
    fun nowMillis(): Long
    fun elapsedRealtime(): Long

    object System : AgentClock {
        override fun nowMillis(): Long = java.lang.System.currentTimeMillis()
        override fun elapsedRealtime(): Long = android.os.SystemClock.elapsedRealtime()
    }
}
