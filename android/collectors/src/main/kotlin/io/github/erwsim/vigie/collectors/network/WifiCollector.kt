package io.github.erwsim.vigie.collectors.network

import android.Manifest
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.wifi.WifiInfo
import io.github.erwsim.vigie.collectors.R
import io.github.erwsim.vigie.collectors.common.RateLimiter
import io.github.erwsim.vigie.core.collector.Collector
import io.github.erwsim.vigie.core.collector.CollectorContext
import io.github.erwsim.vigie.core.collector.Requirement
import io.github.erwsim.vigie.core.event.EventDataBuilder

/**
 * `net.wifi` connected / disconnected, from a Wi-Fi NetworkCallback with
 * FLAG_INCLUDE_LOCATION_INFO (WifiInfo with SSID/BSSID; without precise location they are
 * redacted by the system and left absent). A new BSSID on the same network (roaming) is a new
 * `connected`. RSSI-only changes are ignored. No polling, no scan; at most 60 events per hour.
 */
class WifiCollector : Collector {
    override val id = "wifi"
    override val titleRes = R.string.collector_wifi_title
    override val descriptionRes = R.string.collector_wifi_desc
    override val eventTypes = listOf(TYPE)
    override val requirements = listOf(Requirement.Permission(Manifest.permission.ACCESS_FINE_LOCATION, optional = true))

    private val connected = HashMap<Network, WifiState>()
    private val limiter = RateLimiter(60, 3_600_000L)

    override suspend fun start(ctx: CollectorContext) {
        connected.clear()
        limiter.reset()
        val cm = ctx.appContext.getSystemService(ConnectivityManager::class.java) ?: return
        val request = NetworkRequest.Builder().addTransportType(NetworkCapabilities.TRANSPORT_WIFI).build()
        val callback = object : ConnectivityManager.NetworkCallback(FLAG_INCLUDE_LOCATION_INFO) {
            override fun onCapabilitiesChanged(n: Network, c: NetworkCapabilities) = ctx.guard("wifi caps") {
                val info = c.transportInfo as? WifiInfo ?: return@guard
                val state = fromInfo(info)
                val previous = connected[n]
                connected[n] = state
                if (!state.sameAccessPoint(previous)) emit(ctx, "connected", state)
            }

            override fun onLost(n: Network) = ctx.guard("wifi lost") {
                val previous = connected.remove(n) ?: return@guard
                emit(ctx, "disconnected", previous)
            }
        }
        cm.registerNetworkCallback(request, callback, ctx.handler)
        ctx.onStop { cm.unregisterNetworkCallback(callback) }
    }

    override suspend fun stop(ctx: CollectorContext) = connected.clear()

    private fun emit(ctx: CollectorContext, event: String, state: WifiState) {
        if (!limiter.tryAcquire(ctx.clock.elapsedRealtime())) return
        ctx.emit(TYPE) { state.writeTo(this, event) }
    }

    /** Pure, comparable Wi-Fi connection state. */
    data class WifiState(
        val ssid: String?,
        val bssid: String?,
        val rssi: Int?,
        val freqMhz: Int?,
        val security: String?,
        val standard: String?,
    ) {
        /** Same network and access point (RSSI and frequency changes do not count). */
        fun sameAccessPoint(other: WifiState?): Boolean = other != null && ssid == other.ssid && bssid == other.bssid

        fun writeTo(b: EventDataBuilder, event: String) {
            b.put("event", event)
            b.put("ssid", ssid)
            b.put("bssid", bssid)
            if (event == "connected") {
                b.put("rssi", rssi)
                b.put("freq_mhz", freqMhz)
                b.put("security", security)
                b.put("standard", standard)
            }
        }
    }

    companion object {
        const val TYPE = "net.wifi"

        fun fromInfo(info: WifiInfo) = WifiState(
            ssid = NetFormat.ssid(info.ssid),
            bssid = NetFormat.mac(info.bssid),
            rssi = NetFormat.rssi(info.rssi),
            freqMhz = NetFormat.frequency(info.frequency),
            security = NetFormat.securityName(info.currentSecurityType),
            standard = NetFormat.standardName(info.wifiStandard),
        )
    }
}
