package io.github.erwsim.vigie.collectors.network

import android.Manifest
import android.annotation.SuppressLint
import android.content.IntentFilter
import android.net.wifi.ScanResult
import android.net.wifi.WifiManager
import androidx.core.content.edit
import io.github.erwsim.vigie.collectors.R
import io.github.erwsim.vigie.core.collector.CollectReason
import io.github.erwsim.vigie.core.collector.Collector
import io.github.erwsim.vigie.core.collector.CollectorContext
import io.github.erwsim.vigie.core.collector.PeriodicSpec
import io.github.erwsim.vigie.core.collector.Requirement
import io.github.erwsim.vigie.core.event.Severity
import io.github.erwsim.vigie.core.event.eventData
import io.github.erwsim.vigie.core.settings.SettingKey
import io.github.erwsim.vigie.core.settings.SettingSpec
import kotlinx.serialization.json.JsonObject

/**
 * `net.wifi_scan` (optional, disabled by default: it records neighbours' SSIDs/BSSIDs).
 *
 * Passive by default: listens to SCAN_RESULTS_AVAILABLE_ACTION, i.e. to the scans the system and
 * other apps already run, at no radio cost. Optionally asks for one scan every N minutes (≥ 30,
 * through WorkManager); the platform throttles background scans to one per 30 minutes for all apps
 * anyway. At most one event per [MIN_INTERVAL] minutes, [MAX_APS] strongest access points.
 */
class WifiScanCollector : Collector {
    override val id = "wifi_scan"
    override val titleRes = R.string.collector_wifi_scan_title
    override val descriptionRes = R.string.collector_wifi_scan_desc
    override val eventTypes = listOf(TYPE)
    override val defaultEnabled = false
    override val requirements = listOf(Requirement.Permission(Manifest.permission.ACCESS_FINE_LOCATION))
    override val settings = listOf(
        SettingSpec.IntSpec(MIN_INTERVAL, R.string.setting_wifi_scan_min_interval, R.string.setting_wifi_scan_min_interval_summary, "min"),
        SettingSpec.IntSpec(ACTIVE_INTERVAL, R.string.setting_wifi_scan_active_interval, R.string.setting_wifi_scan_active_interval_summary, "min"),
    )
    override val periodic = PeriodicSpec(intervalMinutes = 30, runAtStart = false)

    override suspend fun start(ctx: CollectorContext) {
        val wm = ctx.appContext.getSystemService(WifiManager::class.java) ?: return
        ctx.registerReceiver(IntentFilter(WifiManager.SCAN_RESULTS_AVAILABLE_ACTION)) { intent ->
            if (!intent.getBooleanExtra(WifiManager.EXTRA_RESULTS_UPDATED, false)) return@registerReceiver
            val now = ctx.clock.elapsedRealtime()
            val last = ctx.prefs.getLong("last_emit_elapsed", Long.MIN_VALUE / 2)
            // elapsedRealtime restarts at boot: a "future" value means a reboot happened.
            if (now >= last && now - last < ctx.settings[MIN_INTERVAL] * 60_000L) return@registerReceiver
            val aps = scanResults(wm).map(::fromScanResult)
            val selected = selectAps(aps, MAX_APS)
            if (selected.isEmpty()) return@registerReceiver
            ctx.prefs.edit { putLong("last_emit_elapsed", now) }
            ctx.sink.emit(TYPE, Severity.INFO, data(selected))
        }
    }

    @SuppressLint("MissingPermission") // ACCESS_FINE_LOCATION is a requirement checked by the host.
    private fun scanResults(wm: WifiManager): List<ScanResult> = try {
        wm.scanResults.orEmpty()
    } catch (_: SecurityException) {
        emptyList() // Location switched off or permission just revoked.
    }

    /** Active scan request (WorkManager, every 30 min at best), only if enabled in the settings. */
    override suspend fun collectOnce(ctx: CollectorContext, reason: CollectReason) {
        val minutes = ctx.settings[ACTIVE_INTERVAL]
        if (minutes <= 0) return
        val now = ctx.clock.nowMillis()
        val last = ctx.prefs.getLong("last_active_scan_ms", 0)
        if (now - last in 0 until minutes.coerceAtLeast(30) * 60_000L - 60_000L) return
        val wm = ctx.appContext.getSystemService(WifiManager::class.java) ?: return
        ctx.prefs.edit { putLong("last_active_scan_ms", now) }
        @Suppress("DEPRECATION") // Still the only public way; throttled by the platform.
        wm.startScan()
    }

    data class Ap(val ssid: String?, val bssid: String?, val rssi: Int?, val freqMhz: Int?, val security: String?)

    companion object {
        const val TYPE = "net.wifi_scan"
        const val MAX_APS = 60
        val MIN_INTERVAL = SettingKey.IntKey("wifi_scan.min_interval_min", 15, 5, 240)
        val ACTIVE_INTERVAL = SettingKey.IntKey("wifi_scan.active_interval_min", 0, 0, 240)

        fun fromScanResult(r: ScanResult) = Ap(
            ssid = NetFormat.ssid(r.wifiSsid?.toString()),
            bssid = NetFormat.mac(r.BSSID),
            rssi = NetFormat.rssi(r.level),
            freqMhz = NetFormat.frequency(r.frequency),
            security = NetFormat.strongestSecurity(r.securityTypes),
        )

        fun data(aps: List<Ap>): JsonObject = eventData {
            putObjects("aps", aps) { ap ->
                put("ssid", ap.ssid)
                put("bssid", ap.bssid)
                put("rssi", ap.rssi)
                put("freq_mhz", ap.freqMhz)
                put("security", ap.security)
            }
        }

        /** Pure: drops entries without BSSID, de-duplicates by BSSID, keeps the [max] strongest. */
        fun selectAps(aps: List<Ap>, max: Int): List<Ap> = aps
            .filter { it.bssid != null }
            .groupBy { it.bssid }
            .map { (_, same) -> same.maxBy { it.rssi ?: -200 } }
            .sortedByDescending { it.rssi ?: -200 }
            .take(max)
    }
}
