package io.github.erwsim.vigie.collectors.network

import android.content.IntentFilter
import io.github.erwsim.vigie.collectors.R
import io.github.erwsim.vigie.collectors.common.changed
import io.github.erwsim.vigie.core.collector.Collector
import io.github.erwsim.vigie.core.collector.CollectorContext
import io.github.erwsim.vigie.core.event.Severity

/**
 * `net.hotspot`: Wi-Fi hotspot (tethering access point) switched on or off.
 *
 * There is no public API for the hotspot state: this listens to the system broadcast
 * `android.net.wifi.WIFI_AP_STATE_CHANGED` (sticky, public string, constants hidden), which apps
 * have used for years. Broadcast-driven, no cost. Only on/off is reported, never the clients.
 */
class HotspotCollector : Collector {
    override val id = "hotspot"
    override val titleRes = R.string.collector_hotspot_title
    override val descriptionRes = R.string.collector_hotspot_desc
    override val eventTypes = listOf(TYPE)

    override suspend fun start(ctx: CollectorContext) {
        ctx.registerReceiver(IntentFilter(ACTION_WIFI_AP_STATE_CHANGED)) { intent ->
            val enabled = enabledFromApState(intent.getIntExtra(EXTRA_WIFI_AP_STATE, -1)) ?: return@registerReceiver
            if (ctx.changed("enabled", enabled.toString())) {
                ctx.emit(TYPE, if (enabled) Severity.NOTABLE else Severity.INFO) { put("enabled", enabled) }
            }
        }
    }

    companion object {
        const val TYPE = "net.hotspot"
        const val ACTION_WIFI_AP_STATE_CHANGED = "android.net.wifi.WIFI_AP_STATE_CHANGED"
        const val EXTRA_WIFI_AP_STATE = "wifi_state"

        // WifiManager.WIFI_AP_STATE_* (hidden constants, stable since Android 4).
        private const val WIFI_AP_STATE_DISABLED = 11
        private const val WIFI_AP_STATE_ENABLED = 13

        /** Pure: final states only (enabling/disabling/failed are ignored). */
        fun enabledFromApState(state: Int): Boolean? = when (state) {
            WIFI_AP_STATE_ENABLED -> true
            WIFI_AP_STATE_DISABLED -> false
            else -> null
        }
    }
}
