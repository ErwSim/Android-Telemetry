package io.github.erwsim.vigie.collectors.ops

import android.Manifest
import androidx.core.content.edit
import io.github.erwsim.vigie.collectors.R
import io.github.erwsim.vigie.collectors.common.str
import io.github.erwsim.vigie.core.collector.Availability
import io.github.erwsim.vigie.core.collector.CollectReason
import io.github.erwsim.vigie.core.collector.Collector
import io.github.erwsim.vigie.core.collector.CollectorContext
import io.github.erwsim.vigie.core.collector.PeriodicSpec
import io.github.erwsim.vigie.core.event.Severity
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/** Thrown only to carry the French reason into `agent.collector_error` (reported once, see [AppOpsCollector]). */
class AppOpsUnavailableException(message: String) : Exception(message)

/**
 * EXPERIMENTAL, off by default: counts, per app and per sensitive operation (send SMS, read SMS, calls,
 * contacts, microphone, camera, location…), how many times the system let the app perform it during the last
 * hour, how many of those while the app was in the background, and how many the system REFUSED
 * (`rejected_count`, from `reject=` of the history: an app that tries to send SMS and is turned down is reported
 * even if nothing went through). The SMS that left unseen from the owner's
 * previous phone would have shown up here.
 *
 * Source: the history of `dumpsys appops --history --op OP` read through `Debug.dumpService` with the `DUMP`
 * and `PACKAGE_USAGE_STATS` permissions granted by ADB. The format is not an API ([AppOpsParser] documents
 * what is expected, from the AOSP sources); it was never observed on the Samsung.
 *
 * Sobriety: one reading per hour (10 history dumps, plus one state dump per op that was used, each bounded in
 * time and size), only the apps that used an op are reported, at most [AppOpsLogic.MAX_ITEMS] per hour. The
 * first reading is a baseline (no event): counts are differences between two readings.
 *
 * Failing cleanly: when the system refuses or the format is not recognised, the collector becomes
 * "indisponible" with the reason (persisted), emits ONE `agent.collector_error` (again only if the reason
 * changes) and tries again after [RETRY_AFTER_MS] at most: no loop.
 */
class AppOpsCollector(private val source: AppOpsDumpSource = DebugDumpSource) : Collector {
    override val id = "app_ops"
    override val titleRes = R.string.collector_app_ops_title
    override val descriptionRes = R.string.collector_app_ops_desc
    override val eventTypes = listOf(TYPE)
    override val defaultEnabled = false
    override val periodic = PeriodicSpec(intervalMinutes = 60, runAtStart = true)

    private val mutex = Mutex()

    override fun checkAvailability(ctx: CollectorContext): Availability {
        if (!ctx.capabilities.hasPermission(Manifest.permission.DUMP)) {
            return Availability.Unavailable(ctx.str(R.string.collector_app_ops_reason_dump))
        }
        if (!ctx.capabilities.hasPermission(Manifest.permission.PACKAGE_USAGE_STATS)) {
            return Availability.Unavailable(ctx.str(R.string.collector_app_ops_reason_usage_stats))
        }
        val reason = ctx.prefs.getString(K_FAIL_REASON, null)
        val at = ctx.prefs.getLong(K_FAIL_MS, 0)
        if (reason != null && ctx.clock.nowMillis() - at in 0 until RETRY_AFTER_MS) return Availability.Unavailable(reason)
        return Availability.Available
    }

    override suspend fun collectOnce(ctx: CollectorContext, reason: CollectReason) = mutex.withLock {
        val now = ctx.clock.nowMillis()
        val previous = AppOpsLogic.decode(ctx.prefs.getString(K_STATE, null))
        val deadline = ctx.clock.elapsedRealtime() + BUDGET_MS

        // 1. History of every op: the counts.
        val sums = LinkedHashMap<OpSpec, Map<String, OpCounts>>()
        val failures = LinkedHashMap<OpsFailure, String?>()
        for (op in AppOpsLogic.OPS) {
            if (ctx.clock.elapsedRealtime() > deadline) {
                failures.putIfAbsent(OpsFailure.TIMEOUT, null)
                continue
            }
            when (val d = source.dump(ctx, listOf("--history", "--op", op.dumpName), DUMP_TIMEOUT_MS, MAX_CHARS)) {
                is DumpResult.Failed -> failures.putIfAbsent(d.failure, d.detail)
                is DumpResult.Text -> when (val h = AppOpsParser.parseHistory(d.text, op.dumpName)) {
                    is HistoryResult.Failed -> failures.putIfAbsent(h.failure, h.detail)
                    is HistoryResult.Ok -> sums[op] = h.counts
                }
            }
        }
        if (sums.isEmpty()) {
            // Not one op could be read: format, permission or SELinux. Do not insist.
            val (failure, detail) = failures.entries.firstOrNull()?.let { it.key to it.value } ?: (OpsFailure.UNRECOGNIZED to null)
            markUnavailable(ctx, failure, detail, now)
            return@withLock
        }
        clearUnavailable(ctx)

        // 2. Differences with the previous reading (the first one is only a baseline).
        val usages = ArrayList<OpUsage>()
        val windows = HashMap<String, Pair<Long, Long>>() // op → from, to
        val newSums = (previous?.sums ?: emptyMap()).toMutableMap()
        val newAt = (previous?.atMs ?: emptyMap()).toMutableMap()
        for ((op, counts) in sums) {
            val before = previous?.sums?.get(op.wire)
            val at = previous?.atMs?.get(op.wire)
            if (before != null && at != null && now - at in 1..AppOpsLogic.MAX_WINDOW_MS) {
                val used = AppOpsLogic.deltas(op, before, counts, emptyMap())
                if (used.isNotEmpty()) {
                    val last = lastAccess(ctx, op, now)
                    usages += used.map { it.copy(lastTs = last[it.pkg]) }
                    windows[op.wire] = at to now
                }
            }
            newSums[op.wire] = counts
            newAt[op.wire] = now
        }

        // 3. One event (cut into parts if large) per window start; usually a single one.
        usages.groupBy { windows.getValue(it.op).first }.toSortedMap().forEach { (from, items) ->
            AppOpsLogic.events(from, now, items).forEach { ctx.sink.emit(TYPE, severity(items), it) }
        }
        ctx.prefs.edit { putString(K_STATE, AppOpsLogic.encode(OpsState(newSums, newAt))) }
    }

    /** Last access time per package of [op]: best effort, from the current-state dump (omitted if unreadable). */
    private suspend fun lastAccess(ctx: CollectorContext, op: OpSpec, now: Long): Map<String, Long> =
        when (val d = source.dump(ctx, listOf("--op", op.dumpName), STATE_TIMEOUT_MS, MAX_CHARS)) {
            is DumpResult.Text -> AppOpsParser.parseLastAccess(d.text, op.dumpName, now)
            is DumpResult.Failed -> emptyMap()
        }

    /** A refused SMS sending is a warning (someone tried despite the guard); a sending that went through is notable. */
    private fun severity(items: List<OpUsage>): Int = when {
        items.any { it.op == "send_sms" && it.rejectedCount > 0 } -> Severity.WARNING
        items.any { it.op == "send_sms" } -> Severity.NOTABLE
        else -> Severity.INFO
    }

    private fun markUnavailable(ctx: CollectorContext, failure: OpsFailure, detail: String?, now: Long) {
        val reason = ctx.str(reasonRes(failure))
        val firstTime = ctx.prefs.getString(K_FAIL_KIND, null) != failure.code
        ctx.prefs.edit {
            putString(K_FAIL_KIND, failure.code)
            putString(K_FAIL_REASON, reason)
            putLong(K_FAIL_MS, now)
        }
        if (firstTime) ctx.reportError(AppOpsUnavailableException(if (detail.isNullOrBlank()) "${failure.code}: $reason" else "${failure.code}: $reason [$detail]"), "app_ops")
    }

    private fun clearUnavailable(ctx: CollectorContext) {
        if (ctx.prefs.contains(K_FAIL_KIND)) {
            ctx.prefs.edit { remove(K_FAIL_KIND); remove(K_FAIL_REASON); remove(K_FAIL_MS) }
        }
    }

    companion object {
        const val TYPE = "app.ops"

        /** Retry delay after a failure (one attempt per period, one error event per distinct reason). */
        const val RETRY_AFTER_MS = 6 * 3_600_000L

        /** Per dump, per reading (10 history dumps and the state dumps), and size of one output. */
        const val DUMP_TIMEOUT_MS = 8_000L
        const val STATE_TIMEOUT_MS = 4_000L
        const val BUDGET_MS = 60_000L
        const val MAX_CHARS = 3 * 1024 * 1024

        private const val K_STATE = "ops_state"
        private const val K_FAIL_KIND = "fail_kind"
        private const val K_FAIL_REASON = "fail_reason"
        private const val K_FAIL_MS = "fail_ms"

        fun reasonRes(f: OpsFailure): Int = when (f) {
            OpsFailure.PERMISSION_DENIED -> R.string.collector_app_ops_reason_permission_denied
            OpsFailure.UNKNOWN_OPTION -> R.string.collector_app_ops_reason_unknown_option
            OpsFailure.EMPTY_OUTPUT -> R.string.collector_app_ops_reason_empty_output
            OpsFailure.NO_HISTORY -> R.string.collector_app_ops_reason_no_history
            OpsFailure.HISTORY_DISABLED -> R.string.collector_app_ops_reason_history_disabled
            OpsFailure.UNRECOGNIZED -> R.string.collector_app_ops_reason_unrecognized
            OpsFailure.TRUNCATED -> R.string.collector_app_ops_reason_truncated
            OpsFailure.TIMEOUT -> R.string.collector_app_ops_reason_timeout
            OpsFailure.DUMP_FAILED -> R.string.collector_app_ops_reason_dump_failed
        }
    }
}
