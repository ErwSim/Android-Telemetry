package io.github.erwsim.vigie.ui

import java.text.DateFormat
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.util.Date
import java.util.Locale

/** French display formats. */
object Format {
    private val FR = Locale.FRANCE
    private val CLOCK = DateTimeFormatter.ofPattern("HH:mm", FR)
    private val CLOCK_SECONDS = DateTimeFormatter.ofPattern("HH:mm:ss", FR)

    fun clock(epochMs: Long): String = CLOCK.format(Instant.ofEpochMilli(epochMs).atZone(ZoneId.systemDefault()))

    fun clockSeconds(epochMs: Long): String =
        CLOCK_SECONDS.format(Instant.ofEpochMilli(epochMs).atZone(ZoneId.systemDefault()))

    fun dateTime(epochMs: Long): String =
        DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT, FR).format(Date(epochMs))

    fun bytes(n: Long): String = when {
        n < 1024 -> "$n o"
        n < 1024 * 1024 -> String.format(FR, "%.1f Kio", n / 1024.0)
        n < 1024L * 1024 * 1024 -> String.format(FR, "%.1f Mio", n / (1024.0 * 1024))
        else -> String.format(FR, "%.2f Gio", n / (1024.0 * 1024 * 1024))
    }

    /** "il y a 3 min", "il y a 2 h"… */
    fun ago(epochMs: Long, nowMs: Long = System.currentTimeMillis()): String {
        val s = ((nowMs - epochMs) / 1000).coerceAtLeast(0)
        return when {
            s < 60 -> "il y a $s s"
            s < 3600 -> "il y a ${s / 60} min"
            s < 86_400 -> "il y a ${s / 3600} h"
            else -> "il y a ${s / 86_400} j"
        }
    }
}
