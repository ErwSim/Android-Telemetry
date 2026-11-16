package io.github.erwsim.watchpost.ui

import java.text.DateFormat
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.util.Date
import java.util.Locale

/** English display formats (24-hour clock, day before month). */
object Format {
    private val DISPLAY_LOCALE = Locale.UK
    private val CLOCK = DateTimeFormatter.ofPattern("HH:mm", DISPLAY_LOCALE)
    private val CLOCK_SECONDS = DateTimeFormatter.ofPattern("HH:mm:ss", DISPLAY_LOCALE)

    fun clock(epochMs: Long): String = CLOCK.format(Instant.ofEpochMilli(epochMs).atZone(ZoneId.systemDefault()))

    fun clockSeconds(epochMs: Long): String =
        CLOCK_SECONDS.format(Instant.ofEpochMilli(epochMs).atZone(ZoneId.systemDefault()))

    fun dateTime(epochMs: Long): String =
        DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT, DISPLAY_LOCALE).format(Date(epochMs))

    fun bytes(n: Long): String = when {
        n < 1024 -> "$n B"
        n < 1024 * 1024 -> String.format(DISPLAY_LOCALE, "%.1f KiB", n / 1024.0)
        n < 1024L * 1024 * 1024 -> String.format(DISPLAY_LOCALE, "%.1f MiB", n / (1024.0 * 1024))
        else -> String.format(DISPLAY_LOCALE, "%.2f GiB", n / (1024.0 * 1024 * 1024))
    }

    /** "3 min ago", "2 h ago"… */
    fun ago(epochMs: Long, nowMs: Long = System.currentTimeMillis()): String {
        val s = ((nowMs - epochMs) / 1000).coerceAtLeast(0)
        return when {
            s < 60 -> "$s s ago"
            s < 3600 -> "${s / 60} min ago"
            s < 86_400 -> "${s / 3600} h ago"
            else -> "${s / 86_400} d ago"
        }
    }
}
