package io.github.erwsim.vigie.notifier.protocol

/**
 * Decides which notification callbacks become `app.notification` events (companion side, before
 * the channel). Pure and deterministic (time is passed in); NOT thread-safe: one thread only.
 *
 * - never the agent's or the companion's own notifications, nor the ignored apps;
 * - never group summaries (each child is reported; the summary would double it);
 * - "persistent" notifications (ongoing, foreground service, media, progress, timer, call,
 *   navigation…): the first post and the removal only, none of their looping updates;
 * - other updates of a notification already reported: only if what it shows changed
 *   ([fingerprint]) and at least [minUpdateIntervalMs] after the previous report of that key;
 * - at most [maxPerApp] reports per app per [appWindowMs] (removals of a reported notification
 *   are not counted, so that every reported notification can be closed);
 * - a removal is reported only for a notification that was reported.
 *
 * Memory is bounded: [maxTracked] notifications (least recently seen forgotten first) and the
 * per-app windows of at most [maxTracked] apps. The fingerprint is a hash kept in memory only.
 */
class NoiseFilter(
    private val maxPerApp: Int = 20,
    private val appWindowMs: Long = 10 * 60_000L,
    private val minUpdateIntervalMs: Long = 30_000L,
    private val maxTracked: Int = 1_000,
) {
    enum class Verdict(val emit: Boolean) {
        EMIT(true),
        SELF(false),
        IGNORED(false),
        GROUP_SUMMARY(false),
        ONGOING_UPDATE(false),
        DUPLICATE(false),
        TOO_FREQUENT(false),
        RATE_LIMITED(false),
        NOT_REPORTED(false),
    }

    /** What the filter needs to know about one callback (no content: only its [fingerprint]). */
    data class Seen(
        val key: String,
        val packageName: String,
        val groupSummary: Boolean,
        val persistent: Boolean,
        val fingerprint: Long,
    )

    private class Tracked(var fingerprint: Long, var lastReportMs: Long, var reported: Boolean, var persistent: Boolean)

    private val tracked = object : LinkedHashMap<String, Tracked>(64, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, Tracked>?) = size > maxTracked
    }
    private val perApp = object : LinkedHashMap<String, ArrayDeque<Long>>(64, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, ArrayDeque<Long>>?) = size > maxTracked
    }

    fun onPosted(s: Seen, ignored: Set<String>, nowMs: Long): Verdict {
        common(s.packageName, s.groupSummary, ignored)?.let { return it }
        val t = tracked[s.key]
        if (t != null) {
            if (s.persistent) {
                t.persistent = true
                return Verdict.ONGOING_UPDATE
            }
            if (t.fingerprint == s.fingerprint && !t.persistent) return Verdict.DUPLICATE
            if (t.reported && nowMs - t.lastReportMs < minUpdateIntervalMs && !t.persistent) return Verdict.TOO_FREQUENT
        }
        if (!acquire(s.packageName, nowMs)) return Verdict.RATE_LIMITED
        if (t == null) {
            tracked[s.key] = Tracked(s.fingerprint, nowMs, reported = true, persistent = s.persistent)
        } else {
            // Includes the end of a persistent notification turned into a normal one ("Download complete").
            t.fingerprint = s.fingerprint
            t.lastReportMs = nowMs
            t.reported = true
            t.persistent = false
        }
        return Verdict.EMIT
    }

    fun onRemoved(key: String, packageName: String, groupSummary: Boolean, ignored: Set<String>): Verdict {
        val t = tracked.remove(key)
        common(packageName, groupSummary, ignored)?.let { return it }
        return if (t?.reported == true) Verdict.EMIT else Verdict.NOT_REPORTED
    }

    /**
     * Notifications already shown when the listener connects: remembered (so that their identical
     * updates are not reported as new) but not reported, and their removal is not reported either.
     */
    fun seed(s: Seen, nowMs: Long) {
        if (s.groupSummary || tracked.containsKey(s.key)) return
        tracked[s.key] = Tracked(s.fingerprint, nowMs, reported = false, persistent = s.persistent)
    }

    /** The report of [key] could not be delivered: forget it (its next update is handled as new). */
    fun deliveryFailed(key: String) {
        tracked.remove(key)
    }

    fun reset() {
        tracked.clear()
        perApp.clear()
    }

    fun trackedCount(): Int = tracked.size

    private fun common(packageName: String, groupSummary: Boolean, ignored: Set<String>): Verdict? = when {
        packageName in NotifierProtocol.SELF_PACKAGES -> Verdict.SELF
        packageName in ignored -> Verdict.IGNORED
        groupSummary -> Verdict.GROUP_SUMMARY
        else -> null
    }

    private fun acquire(packageName: String, nowMs: Long): Boolean {
        val times = perApp.getOrPut(packageName) { ArrayDeque() }
        while (times.isNotEmpty() && nowMs - times.first() >= appWindowMs) times.removeFirst()
        if (times.size >= maxPerApp) return false
        times.addLast(nowMs)
        return true
    }

    companion object {
        /** Categories whose notifications update in a loop (`Notification.CATEGORY_*` values). */
        val LOOPING_CATEGORIES = setOf(
            "transport", "progress", "stopwatch", "navigation", "call", "service", "workout", "location_sharing",
        )

        fun isPersistent(ongoing: Boolean, foregroundService: Boolean, category: String?): Boolean =
            ongoing || foregroundService || category in LOOPING_CATEGORIES

        /** What a notification shows, as a hash (in memory only; content is part of it so a new message counts as a change). */
        fun fingerprint(category: String?, channel: String?, importance: String?, ongoing: Boolean, title: String?, text: String?): Long =
            NotifierConfig.fnv1a64(listOf(category, channel, importance, ongoing.toString(), title, text).joinToString("\u0000") { it ?: "\u0001" })
    }
}
