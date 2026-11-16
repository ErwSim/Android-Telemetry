package io.github.erwsim.vigie.collectors

import io.github.erwsim.vigie.core.testing.Contract
import android.net.wifi.ScanResult
import android.net.wifi.WifiInfo
import io.github.erwsim.vigie.collectors.network.ConnectivityCollector
import io.github.erwsim.vigie.collectors.network.HotspotCollector
import io.github.erwsim.vigie.collectors.network.NetFormat
import io.github.erwsim.vigie.collectors.network.NetworkUsageCollector
import io.github.erwsim.vigie.collectors.network.NetworkUsageCollector.UsageRow
import io.github.erwsim.vigie.collectors.network.WifiCollector
import io.github.erwsim.vigie.collectors.network.WifiScanCollector
import io.github.erwsim.vigie.core.event.Rfc3339
import io.github.erwsim.vigie.core.event.eventData
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class NetworkCollectorsTest {
    @Test
    fun placeholdersBecomeAbsentFields() {
        assertEquals("Maison", NetFormat.ssid("\"Maison\""))
        assertNull(NetFormat.ssid("<unknown ssid>"))
        assertNull(NetFormat.ssid("\"\""))
        assertNull(NetFormat.ssid(null))
        assertEquals("e29c93", NetFormat.ssid("e29c93")) // Non-UTF-8 SSID: hex, kept as is.
        assertNull(NetFormat.mac("02:00:00:00:00:00"))
        assertNull(NetFormat.mac("not a mac"))
        assertEquals("aa:bb:cc:dd:ee:0f", NetFormat.mac("AA:BB:CC:DD:EE:0F"))
        assertNull(NetFormat.rssi(-127))
        assertEquals(-60, NetFormat.rssi(-60))
        assertNull(NetFormat.frequency(-1))
    }

    @Test
    fun securityAndStandardWords() {
        assertEquals("psk", NetFormat.securityName(WifiInfo.SECURITY_TYPE_PSK))
        assertEquals("sae", NetFormat.securityName(WifiInfo.SECURITY_TYPE_SAE))
        assertNull(NetFormat.securityName(WifiInfo.SECURITY_TYPE_UNKNOWN))
        assertEquals("sae", NetFormat.strongestSecurity(intArrayOf(WifiInfo.SECURITY_TYPE_PSK, WifiInfo.SECURITY_TYPE_SAE)))
        assertEquals("open", NetFormat.strongestSecurity(intArrayOf(WifiInfo.SECURITY_TYPE_OPEN)))
        assertNull(NetFormat.strongestSecurity(intArrayOf()))
        assertEquals("11ax", NetFormat.standardName(ScanResult.WIFI_STANDARD_11AX))
        assertEquals("11be", NetFormat.standardName(ScanResult.WIFI_STANDARD_11BE))
        assertNull(NetFormat.standardName(ScanResult.WIFI_STANDARD_UNKNOWN))
    }

    @Test
    fun connectivitySnapshotUsesContractFields() {
        val s = ConnectivityCollector.Snapshot(
            transports = listOf("wifi", "vpn"),
            validated = true,
            metered = false,
            vpn = true,
            privateDnsActive = true,
            privateDnsServer = "dns.exemple.fr",
            dnsServers = listOf("10.0.0.1", "fd00::1"),
            iface = "tun0",
        )
        val data = eventData { s.writeTo(this) }
        Contract.check("net.connectivity", data)
        assertEquals(8, data.size)
        assertEquals("\"tun0\"", data["interface"].toString())

        val none = eventData { ConnectivityCollector.Snapshot.NONE.writeTo(this) }
        Contract.check("net.connectivity", none)
        assertEquals(setOf("transports", "validated"), none.keys)
        assertEquals(0, (none["transports"] as JsonArray).size)
        // Equal snapshots are deduplicated by the collector.
        assertEquals(s, s.copy())
        assertFalse(s == s.copy(validated = false))
    }

    @Test
    fun wifiEventsAndRoaming() {
        val home = WifiCollector.WifiState("Maison", "aa:bb:cc:dd:ee:01", -55, 5180, "sae", "11ax")
        val connected = eventData { home.writeTo(this, "connected") }
        Contract.check("net.wifi", connected)
        assertEquals(7, connected.size)
        val disconnected = eventData { home.writeTo(this, "disconnected") }
        Contract.check("net.wifi", disconnected)
        assertEquals(setOf("event", "ssid", "bssid"), disconnected.keys)

        assertTrue(home.sameAccessPoint(home.copy(rssi = -70, freqMhz = 5200)))
        assertFalse(home.sameAccessPoint(home.copy(bssid = "aa:bb:cc:dd:ee:02"))) // Roaming = new "connected".
        assertFalse(home.sameAccessPoint(null))

        // Redacted SSID/BSSID (no location access): absent, never placeholders.
        val redacted = eventData { WifiCollector.WifiState(null, null, -60, 2412, "psk", null).writeTo(this, "connected") }
        assertFalse(redacted.containsKey("ssid") || redacted.containsKey("bssid") || redacted.containsKey("standard"))
    }

    @Test
    fun wifiScanSelectsStrongestUniqueAccessPoints() {
        val aps = listOf(
            WifiScanCollector.Ap("A", "aa:aa:aa:aa:aa:01", -80, 2412, "psk"),
            WifiScanCollector.Ap("A", "aa:aa:aa:aa:aa:01", -50, 2412, "psk"),
            WifiScanCollector.Ap("B", "aa:aa:aa:aa:aa:02", -60, 5180, "sae"),
            WifiScanCollector.Ap(null, null, -30, 2437, "open"),
            WifiScanCollector.Ap(null, "aa:aa:aa:aa:aa:03", -90, 2462, null),
        )
        val selected = WifiScanCollector.selectAps(aps, 2)
        assertEquals(listOf("aa:aa:aa:aa:aa:01", "aa:aa:aa:aa:aa:02"), selected.map { it.bssid })
        assertEquals(-50, selected.first().rssi)
        val data = WifiScanCollector.data(WifiScanCollector.selectAps(aps, 60))
        Contract.check("net.wifi_scan", data)
        val hidden = (data["aps"] as JsonArray)[2] as JsonObject
        assertEquals(setOf("bssid", "rssi", "freq_mhz"), hidden.keys)
        // 60 access points stay far below the 32 KiB event limit.
        val many = (1..200).map { WifiScanCollector.Ap("Réseau voisin numéro $it", "aa:bb:cc:dd:%02x:%02x".format(it / 256, it % 256), -40 - it % 50, 5180, "eap_wpa3_enterprise") }
        assertTrue(WifiScanCollector.data(WifiScanCollector.selectAps(many, WifiScanCollector.MAX_APS)).toString().length < 16_000)
    }

    @Test
    fun hotspotStates() {
        assertEquals(true, HotspotCollector.enabledFromApState(13))
        assertEquals(false, HotspotCollector.enabledFromApState(11))
        assertNull(HotspotCollector.enabledFromApState(12)) // Enabling.
        assertNull(HotspotCollector.enabledFromApState(14)) // Failed.
    }

    @Test
    fun usageWindowIsHourAlignedLaggedAndBounded() {
        val h = 3_600_000L
        val base = 1_763_240_400_000L // On an hour boundary ("21:00" below).
        // First run at 21:40 → [20:00, 21:00) (the last hour that ended ≥ 30 min ago).
        assertEquals(base - h to base, NetworkUsageCollector.window(base + 40 * 60_000, 0))
        // At 21:20 the 20:00-21:00 hour is not 30 min old yet: [19:00, 20:00).
        assertEquals(base - 2 * h to base - h, NetworkUsageCollector.window(base + 20 * 60_000, 0))
        // Already reported up to 21:00.
        assertNull(NetworkUsageCollector.window(base + 40 * 60_000, base))
        // Catch-up after 3 days off: at most 24 h.
        val (from, to) = NetworkUsageCollector.window(base + 40 * 60_000, base - 72 * h)!!
        assertEquals(24 * h, to - from)
        // Watermark in the future (clock moved back): restart with the last hour.
        assertEquals(base - h to base, NetworkUsageCollector.window(base + 40 * 60_000, base + 10 * h))
    }

    @Test
    fun usageAggregationAndContract() {
        val rows = listOf(
            UsageRow(10123, "wifi", 1000, 100),
            UsageRow(10123, "wifi", 500, 50), // Other bucket state (foreground/background).
            UsageRow(10123, "cellular", 10, 1),
            UsageRow(10200, "wifi", 0, 0),
            UsageRow(-4, "wifi", 99_999, 0), // Removed apps.
        )
        val apps = NetworkUsageCollector.aggregate(rows, 10)
        assertEquals(listOf(-4 to "wifi", 10123 to "wifi", 10123 to "cellular"), apps.map { it.uid to it.transport })
        assertEquals(1500L, apps[1].rxBytes)
        assertEquals(150L, apps[1].txBytes)
        assertEquals(2, NetworkUsageCollector.aggregate(rows, 2).size)

        val data = NetworkUsageCollector.data(0, 3_600_000, apps, mapOf(10123 to "org.example", -4 to "removed"))
        Contract.check("net.usage", data)
        assertEquals(Rfc3339.format(0), data["from"]!!.jsonPrimitive.content)
        val first = (data["apps"] as JsonArray)[0] as JsonObject
        assertEquals(setOf("package", "uid", "rx_bytes", "tx_bytes", "transport"), first.keys)
        // The cap (100 apps, worst-case sizes) stays well below 32 KiB.
        val big = (1..NetworkUsageCollector.MAX_APPS).map { UsageRow(10_000 + it, "wifi", 1L shl 40, 1L shl 40) }
        val bigData = NetworkUsageCollector.data(0, 1, big, big.associate { it.uid to "com.example.quite.long.package.name${it.uid}" })
        assertTrue(bigData.toString().length < 16_000)
    }
}
