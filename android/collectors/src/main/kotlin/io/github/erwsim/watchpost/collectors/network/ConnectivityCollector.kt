package io.github.erwsim.watchpost.collectors.network

import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import io.github.erwsim.watchpost.collectors.R
import io.github.erwsim.watchpost.collectors.common.RateLimiter
import io.github.erwsim.watchpost.core.collector.Collector
import io.github.erwsim.watchpost.core.collector.CollectorContext
import io.github.erwsim.watchpost.core.event.EventDataBuilder

/**
 * `net.connectivity`: the default network (transports, validated, metered, VPN, private DNS, DNS
 * servers, interface), from `registerDefaultNetworkCallback`. No polling; an event only when the
 * snapshot changes (signal strength and bandwidth updates are ignored), at most 60 per hour.
 * Needs only ACCESS_NETWORK_STATE (normal permission declared by `:core`).
 */
class ConnectivityCollector : Collector {
    override val id = "connectivity"
    override val titleRes = R.string.collector_connectivity_title
    override val descriptionRes = R.string.collector_connectivity_desc
    override val eventTypes = listOf(TYPE)

    // Collectors' thread state, reset at each start.
    private var network: Network? = null
    private var caps: NetworkCapabilities? = null
    private var links: LinkProperties? = null
    private var last: Snapshot? = null
    private val limiter = RateLimiter(60, 3_600_000L)

    override suspend fun start(ctx: CollectorContext) {
        network = null
        caps = null
        links = null
        last = null
        limiter.reset()
        val cm = ctx.appContext.getSystemService(ConnectivityManager::class.java) ?: return
        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onCapabilitiesChanged(n: Network, c: NetworkCapabilities) = ctx.guard("caps") {
                if (n != network) links = null
                network = n
                caps = c
                publish(ctx)
            }

            override fun onLinkPropertiesChanged(n: Network, l: LinkProperties) = ctx.guard("links") {
                if (n != network) caps = null
                network = n
                links = l
                publish(ctx)
            }

            override fun onLost(n: Network) = ctx.guard("lost") {
                if (n == network) {
                    network = null
                    caps = null
                    links = null
                    publish(ctx)
                }
            }
        }
        cm.registerDefaultNetworkCallback(callback, ctx.handler)
        ctx.onStop { cm.unregisterNetworkCallback(callback) }
        // No default network: the callback says nothing until one appears.
        if (cm.activeNetwork == null) publish(ctx)
    }

    override suspend fun stop(ctx: CollectorContext) {
        network = null
        caps = null
        links = null
    }

    private fun publish(ctx: CollectorContext) {
        val c = caps
        // Wait for the capabilities of a new network before reporting it.
        if (network != null && c == null) return
        val snapshot = if (c == null) Snapshot.NONE else snapshot(c, links)
        if (snapshot == last) return
        if (!limiter.tryAcquire(ctx.clock.elapsedRealtime())) return
        last = snapshot
        ctx.emit(TYPE) { snapshot.writeTo(this) }
    }

    private fun snapshot(c: NetworkCapabilities, l: LinkProperties?) = Snapshot(
        transports = NetFormat.transportNames(c::hasTransport),
        validated = c.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED),
        metered = !c.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED) &&
            !c.hasCapability(NetworkCapabilities.NET_CAPABILITY_TEMPORARILY_NOT_METERED),
        vpn = c.hasTransport(NetworkCapabilities.TRANSPORT_VPN),
        privateDnsActive = l?.isPrivateDnsActive,
        privateDnsServer = l?.privateDnsServerName,
        dnsServers = l?.dnsServers?.mapNotNull { it.hostAddress },
        iface = l?.interfaceName,
    )

    /** Pure, comparable view of the default network (what is emitted). */
    data class Snapshot(
        val transports: List<String>,
        val validated: Boolean,
        val metered: Boolean?,
        val vpn: Boolean?,
        val privateDnsActive: Boolean?,
        val privateDnsServer: String?,
        val dnsServers: List<String>?,
        val iface: String?,
    ) {
        fun writeTo(b: EventDataBuilder) {
            b.putStrings("transports", transports)
            b.put("validated", validated)
            b.put("metered", metered)
            b.put("vpn", vpn)
            b.put("private_dns_active", privateDnsActive)
            b.put("private_dns_server", privateDnsServer?.takeIf { it.isNotBlank() })
            b.putStrings("dns_servers", dnsServers)
            b.put("interface", iface)
        }

        companion object {
            /** No default network at all. */
            val NONE = Snapshot(emptyList(), false, null, null, null, null, null, null)
        }
    }

    companion object {
        const val TYPE = "net.connectivity"
    }
}
