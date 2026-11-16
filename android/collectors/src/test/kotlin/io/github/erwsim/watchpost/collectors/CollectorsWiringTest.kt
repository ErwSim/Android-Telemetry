package io.github.erwsim.watchpost.collectors

import io.github.erwsim.watchpost.core.testing.Contract
import android.Manifest
import io.github.erwsim.watchpost.collectors.apps.AppsCollector
import io.github.erwsim.watchpost.collectors.apps.ForegroundAppCollector
import io.github.erwsim.watchpost.collectors.apps.SpecialAccessCollector
import io.github.erwsim.watchpost.collectors.device.UsbCollector
import io.github.erwsim.watchpost.collectors.network.ConnectivityCollector
import io.github.erwsim.watchpost.collectors.network.HotspotCollector
import io.github.erwsim.watchpost.collectors.network.NetworkUsageCollector
import io.github.erwsim.watchpost.collectors.network.WifiCollector
import io.github.erwsim.watchpost.collectors.network.WifiScanCollector
import io.github.erwsim.watchpost.core.collector.CollectorRunState
import io.github.erwsim.watchpost.core.collector.Requirement
import io.github.erwsim.watchpost.core.event.EventTypes
import io.github.erwsim.watchpost.core.testing.CollectorHarness
import io.github.erwsim.watchpost.core.testing.TestContext
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.nio.file.Files

class CollectorsWiringTest {
    private val all = CollectorsModule.all(TestContext(Files.createTempDirectory("watchpost").toFile()))

    @Test
    fun everyCollectorIsDeclaredConsistently() {
        assertEquals(all.size, all.map { it.id }.toSet().size)
        all.forEach { c ->
            assertTrue(c.id, Regex("^[a-z0-9_]+$").matches(c.id))
            assertTrue(c.id, c.eventTypes.isNotEmpty())
            c.eventTypes.forEach { t ->
                assertTrue(t, EventTypes.isValid(t))
                // Every new type is in the contract catalogue (the reference collectors are checked elsewhere).
                if (c.id !in setOf("heartbeat", "device", "location")) assertTrue("$t not in contract", t in Contract.TYPES)
            }
            c.periodic?.let { assertTrue(c.id, it.intervalMinutes >= 15) }
            c.settings.forEach { s -> assertTrue("${c.id}: ${s.key.name}", s.key.name.startsWith(c.id.substringBefore('_')) || s.key.name.startsWith(c.id)) }
        }
        // No type is produced by two collectors.
        val types = all.flatMap { it.eventTypes }
        assertEquals(types.size, types.toSet().size)
        // Opt-in only for the collector recording third parties' networks and the experimental per-app usage counter.
        assertEquals(listOf("wifi_scan", "app_ops"), all.filterNot { it.defaultEnabled }.map { it.id })
    }

    @Test
    fun noForbiddenPermissionIsRequired() {
        val forbidden = setOf(
            Manifest.permission.READ_SMS, Manifest.permission.RECEIVE_SMS, Manifest.permission.READ_CALL_LOG,
            Manifest.permission.BIND_ACCESSIBILITY_SERVICE, Manifest.permission.BIND_NOTIFICATION_LISTENER_SERVICE,
            Manifest.permission.SYSTEM_ALERT_WINDOW, Manifest.permission.READ_CONTACTS,
        )
        all.flatMap { it.requirements }.filterIsInstance<Requirement.Permission>().forEach { assertFalse(it.name, it.name in forbidden) }
    }

    @Test
    fun collectorsStartOnTheJvmWithoutSystemServicesAndDegradeCleanly() {
        CollectorHarness(
            ConnectivityCollector(), WifiCollector(), WifiScanCollector(), HotspotCollector(), UsbCollector(),
            NetworkUsageCollector(), AppsCollector(), SpecialAccessCollector(), ForegroundAppCollector(),
        ).use { h ->
            h.startAll()
            listOf("connectivity", "wifi", "hotspot", "usb", "apps", "special_access").forEach {
                assertEquals(it, CollectorRunState.RUNNING, h.status(it).state)
            }
            // Optional precise location missing: wifi runs, degraded.
            assertEquals(listOf(Manifest.permission.ACCESS_FINE_LOCATION), h.status("wifi").missingPermissions)
            assertEquals(CollectorRunState.DISABLED, h.status("wifi_scan").state)
            // No usage access (no AppOpsManager on the JVM) and no Device Owner: unavailable with a reason.
            listOf("net_usage", "foreground").forEach {
                assertEquals(it, CollectorRunState.UNAVAILABLE, h.status(it).state)
                assertTrue(it, h.status(it).reason!!.isNotBlank())
            }
            assertTrue(h.scheduled.containsAll(listOf("+apps", "+special_access")))
            // Nothing to report without system services, and no collector error.
            assertTrue(h.events.toString(), h.events.none { it.type == EventTypes.AGENT_COLLECTOR_ERROR })
            h.events.forEach { Contract.check(it.type, it.data) }
        }
    }

    @Test
    fun usageCollectorBecomesAvailableAsDeviceOwner() {
        CollectorHarness(NetworkUsageCollector()).use { h ->
            h.deviceOwner = true
            h.startAll()
            assertEquals(CollectorRunState.RUNNING, h.status("net_usage").state)
            h.collectOnce("net_usage")
            assertTrue(h.events.none { it.type == EventTypes.AGENT_COLLECTOR_ERROR })
        }
    }
}
