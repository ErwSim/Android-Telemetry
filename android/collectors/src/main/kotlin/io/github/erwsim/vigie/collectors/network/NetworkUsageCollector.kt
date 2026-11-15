package io.github.erwsim.vigie.collectors.network

import android.app.usage.NetworkStats
import android.app.usage.NetworkStatsManager
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.os.Process
import androidx.core.content.edit
import io.github.erwsim.vigie.collectors.R
import io.github.erwsim.vigie.collectors.common.hasUsageAccess
import io.github.erwsim.vigie.collectors.common.str
import io.github.erwsim.vigie.core.collector.Availability
import io.github.erwsim.vigie.core.collector.CollectReason
import io.github.erwsim.vigie.core.collector.Collector
import io.github.erwsim.vigie.core.collector.CollectorContext
import io.github.erwsim.vigie.core.collector.PeriodicSpec
import io.github.erwsim.vigie.core.event.Rfc3339
import io.github.erwsim.vigie.core.event.Severity
import io.github.erwsim.vigie.core.event.eventData
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.JsonObject

/**
 * `net.usage`: bytes received/sent per app and transport (Wi-Fi, mobile), one event per elapsed
 * hour, from `NetworkStatsManager.querySummary`. Needs "usage access" (PACKAGE_USAGE_STATS granted
 * by ADB or in Settings) or the Device Owner role. Hourly WorkManager job, two queries.
 *
 * The system stores these statistics in ~2 h buckets and splits a bucket pro rata when a query
 * covers part of it: hourly values are estimates (totals over a day are exact). Each query ends
 * at least 30 min in the past so that the system has written the counters.
 */
class NetworkUsageCollector : Collector {
    override val id = "net_usage"
    override val titleRes = R.string.collector_net_usage_title
    override val descriptionRes = R.string.collector_net_usage_desc
    override val eventTypes = listOf(TYPE)
    override val periodic = PeriodicSpec(intervalMinutes = 60, runAtStart = true)

    override fun checkAvailability(ctx: CollectorContext): Availability =
        if (ctx.hasUsageAccess() || ctx.capabilities.isDeviceOwner()) {
            Availability.Available
        } else {
            Availability.Unavailable(ctx.str(R.string.collectors_reason_usage_access))
        }

    @Suppress("DEPRECATION") // TYPE_WIFI/TYPE_MOBILE are still the networkType values of querySummary.
    override suspend fun collectOnce(ctx: CollectorContext, reason: CollectReason) {
        val nsm = ctx.appContext.getSystemService(NetworkStatsManager::class.java) ?: return
        val now = ctx.clock.nowMillis()
        val (from, to) = window(now, ctx.prefs.getLong("watermark_ms", 0)) ?: return
        val rows = withContext(Dispatchers.IO) {
            query(nsm, ConnectivityManager.TYPE_WIFI, "wifi", from, to) +
                query(nsm, ConnectivityManager.TYPE_MOBILE, "cellular", from, to)
        }
        val apps = aggregate(rows, MAX_APPS)
        val pm = ctx.appContext.packageManager
        ctx.prefs.edit { putLong("watermark_ms", to) }
        if (apps.isEmpty()) return
        val names = apps.map { it.uid }.distinct().associateWith { packageForUid(pm, it) }
        ctx.sink.emit(TYPE, Severity.INFO, data(from, to, apps, names))
    }

    private fun query(nsm: NetworkStatsManager, networkType: Int, transport: String, from: Long, to: Long): List<UsageRow> {
        val rows = ArrayList<UsageRow>()
        val stats: NetworkStats = try {
            nsm.querySummary(networkType, null, from, to)
        } catch (_: SecurityException) {
            return rows
        } catch (_: android.os.RemoteException) {
            return rows
        } ?: return rows
        stats.use { s ->
            val bucket = NetworkStats.Bucket()
            while (s.hasNextBucket()) {
                if (!s.getNextBucket(bucket)) break
                rows += UsageRow(bucket.uid, transport, bucket.rxBytes, bucket.txBytes)
            }
        }
        return rows
    }

    private fun packageForUid(pm: PackageManager?, uid: Int): String = when (uid) {
        NetworkStats.Bucket.UID_REMOVED -> "removed"
        NetworkStats.Bucket.UID_TETHERING -> "tethering"
        Process.ROOT_UID -> "root"
        Process.SYSTEM_UID -> "android"
        else -> try {
            pm?.getPackagesForUid(uid)?.minOrNull() ?: pm?.getNameForUid(uid)
        } catch (_: Exception) {
            null
        } ?: "uid_$uid"
    }

    data class UsageRow(val uid: Int, val transport: String, val rxBytes: Long, val txBytes: Long)

    companion object {
        const val TYPE = "net.usage"
        const val MAX_APPS = 100
        private const val HOUR = 3_600_000L
        private const val LAG = 30 * 60_000L
        private const val MAX_CATCH_UP = 24 * HOUR

        /**
         * Pure: next window to report, `[from, to)` on hour boundaries, ending at least 30 min ago,
         * starting at the last reported end (at most 24 h back). Null when nothing new.
         */
        fun window(nowMs: Long, watermarkMs: Long): Pair<Long, Long>? {
            val to = (nowMs - LAG) / HOUR * HOUR
            val from = when {
                watermarkMs <= 0 || watermarkMs > to -> to - HOUR // First run or clock moved back.
                else -> maxOf(watermarkMs, to - MAX_CATCH_UP)
            }
            return if (from < to) from to to else null
        }

        fun data(from: Long, to: Long, apps: List<UsageRow>, packages: Map<Int, String>): JsonObject = eventData {
            put("from", Rfc3339.format(from))
            put("to", Rfc3339.format(to))
            putObjects("apps", apps) { row ->
                put("package", packages[row.uid])
                put("uid", row.uid)
                put("rx_bytes", row.rxBytes)
                put("tx_bytes", row.txBytes)
                put("transport", row.transport)
            }
        }

        /** Pure: sums by uid and transport, drops zeros, keeps the [max] biggest. */
        fun aggregate(rows: List<UsageRow>, max: Int): List<UsageRow> = rows
            .groupBy { it.uid to it.transport }
            .map { (k, v) -> UsageRow(k.first, k.second, v.sumOf { it.rxBytes.coerceAtLeast(0) }, v.sumOf { it.txBytes.coerceAtLeast(0) }) }
            .filter { it.rxBytes + it.txBytes > 0 }
            .sortedWith(compareByDescending<UsageRow> { it.rxBytes + it.txBytes }.thenBy { it.uid }.thenBy { it.transport })
            .take(max)
    }
}
