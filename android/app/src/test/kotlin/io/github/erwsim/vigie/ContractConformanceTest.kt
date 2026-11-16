package io.github.erwsim.vigie

import android.app.admin.SecurityLog
import io.github.erwsim.vigie.collectors.CollectorsModule
import io.github.erwsim.vigie.collectors.apps.AppDetails
import io.github.erwsim.vigie.collectors.apps.AppInventoryLogic
import io.github.erwsim.vigie.collectors.apps.AppRecord
import io.github.erwsim.vigie.collectors.apps.ForegroundAppCollector
import io.github.erwsim.vigie.collectors.apps.ForegroundTracker
import io.github.erwsim.vigie.collectors.apps.PermissionChange
import io.github.erwsim.vigie.collectors.apps.SpecialAccessSnapshot
import io.github.erwsim.vigie.collectors.bluetooth.BleTrackerCollector
import io.github.erwsim.vigie.collectors.bluetooth.BluetoothCollector
import io.github.erwsim.vigie.collectors.bluetooth.TrackerDetector
import io.github.erwsim.vigie.collectors.cell.CellLogic
import io.github.erwsim.vigie.collectors.common.ScreenState
import io.github.erwsim.vigie.collectors.device.UsbLogic
import io.github.erwsim.vigie.collectors.network.ConnectivityCollector
import io.github.erwsim.vigie.collectors.network.NetworkUsageCollector
import io.github.erwsim.vigie.collectors.network.WifiCollector
import io.github.erwsim.vigie.collectors.network.WifiScanCollector
import io.github.erwsim.vigie.collectors.sensors.CameraCollector
import io.github.erwsim.vigie.collectors.sensors.MicState
import io.github.erwsim.vigie.collectors.sensors.MicrophoneCollector
import io.github.erwsim.vigie.core.collector.CollectReason
import io.github.erwsim.vigie.core.collector.Collector
import io.github.erwsim.vigie.core.event.EventTypes
import io.github.erwsim.vigie.core.event.Severity
import io.github.erwsim.vigie.core.event.eventData
import io.github.erwsim.vigie.core.sink.EventSink
import io.github.erwsim.vigie.core.testing.CollectorHarness
import io.github.erwsim.vigie.core.testing.Contract
import io.github.erwsim.vigie.core.testing.FakeClock
import io.github.erwsim.vigie.core.testing.MemoryPrefs
import io.github.erwsim.vigie.core.testing.TestContext
import io.github.erwsim.vigie.policy.PolicyModule
import io.github.erwsim.vigie.policy.engine.DevicePolicyGateway
import io.github.erwsim.vigie.policy.engine.PolicyCatalog
import io.github.erwsim.vigie.policy.engine.PolicyEngine
import io.github.erwsim.vigie.policy.engine.PolicyStore
import io.github.erwsim.vigie.policy.logs.NetRecord
import io.github.erwsim.vigie.policy.logs.NetworkLogProcessor
import io.github.erwsim.vigie.policy.logs.OwnerResolver
import io.github.erwsim.vigie.policy.logs.RawSecurityEvent
import io.github.erwsim.vigie.policy.logs.SecurityLogFilter
import io.github.erwsim.vigie.policy.logs.SecurityLogProcessor
import io.github.erwsim.vigie.policy.posture.CaCert
import io.github.erwsim.vigie.policy.posture.CaChange
import io.github.erwsim.vigie.policy.posture.PostureChange
import io.github.erwsim.vigie.policy.posture.PostureCollector
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.lang.reflect.Proxy
import java.nio.file.Files

/**
 * End-to-end conformity of what the APK emits with `docs/contrat/contrat.md` §2 and its "Précisions"
 * (single reference: [Contract], testFixtures of `:core`).
 *
 * Every collector of the APK (the `:collectors` and `:policy` entry points, wired as in
 * [VigieApplication]) produces its typical events through the same code paths as on the device:
 * its public data builders, its log processors, or the harness on the JVM. Each event type a
 * collector declares is either produced here or listed in [notOnTheJvm] with the reason.
 */
class ContractConformanceTest {
    private val context = TestContext(Files.createTempDirectory("vigie-contract").toFile())
    private val all: List<Collector> = CollectorsModule.all(context) + PolicyModule.collectors(context)

    /** Types emitted only from an Android callback or a system service absent on the JVM (checked by reading). */
    private val notOnTheJvm = mapOf(
        "device.inventory" to "Build, Environment and StatFs (null in the JVM stubs)",
        "device.storage" to "Environment and StatFs (null in the JVM stubs)",
        "device.boot" to "getprop after a real reboot",
        "device.shutdown" to "ACTION_SHUTDOWN broadcast",
        "device.screen" to "screen broadcasts",
        "device.battery" to "sticky ACTION_BATTERY_CHANGED",
        "device.power_save" to "PowerManager",
        "device.thermal" to "thermal listener",
        "device.time_changed" to "ACTION_TIME_CHANGED broadcast",
        "device.timezone_changed" to "ACTION_TIMEZONE_CHANGED broadcast",
        "device.airplane_mode" to "ACTION_AIRPLANE_MODE_CHANGED broadcast",
        "location.fix" to "LocationManager",
        "location.provider" to "LocationManager",
        "net.hotspot" to "hotspot broadcast",
        "net.nfc" to "NFC adapter broadcast",
    )

    private val emitted = HashMap<String, MutableList<Pair<String, JsonObject>>>() // producer -> (type, data)

    private fun sample(collector: String, type: String, data: JsonObject) {
        emitted.getOrPut(collector) { ArrayList() } += type to data
    }

    @Test
    fun theApkHasTheExpectedCollectorsAndOnlyContractTypes() {
        val ids = all.map { it.id }
        assertEquals(
            listOf(
                "heartbeat", "device", "usb", "location", "connectivity", "wifi", "wifi_scan", "hotspot", "nfc", "cell", "bluetooth",
                "ble_tracker", "net_usage", "apps", "special_access", "foreground", "camera", "microphone",
                "security_log", "network_log", "posture",
            ),
            ids,
        )
        assertEquals(ids.size, ids.toSet().size)
        for (c in all) {
            for (t in c.eventTypes) {
                assertTrue("${c.id}: $t", EventTypes.isValid(t))
                assertTrue("${c.id}: $t is not in the contract catalogue", t in Contract.TYPES)
            }
        }
    }

    @Test
    fun heartbeatListsEveryCollectorWithAContractState() {
        CollectorHarness(*all.toTypedArray()).use { h ->
            h.startAll()
            h.collectOnce("heartbeat")
            val beat = h.eventsOf(EventTypes.AGENT_HEARTBEAT).last().data
            Contract.check(EventTypes.AGENT_HEARTBEAT, beat)
            val states = (beat["collectors"] as JsonObject).mapValues { (it.value as JsonPrimitive).content }
            assertEquals(all.map { it.id }.toSet(), states.keys)
            assertTrue(states.toString(), states.values.all { it in Contract.COLLECTOR_STATES })
            // Not Device Owner on the JVM: the three :policy collectors wait for the role.
            listOf("security_log", "network_log").forEach { assertEquals(it, "unavailable", states[it]) }
            assertEquals("disabled", states["wifi_scan"]) // opt-in
            // Whatever ran on the JVM (heartbeat, inventory, storage, errors…) follows the contract.
            h.events.forEach { Contract.check(it.type, it.data) }
        }
    }

    @Test
    fun everyCollectorProducesContractEvents() {
        // ---- every collector started in the harness (JVM: no system service, defaults from the stubs)
        CollectorHarness(*all.toTypedArray()).use { h ->
            h.startAll()
            h.events.forEach { e -> sample("harness", e.type, e.data) }
        }
        // ---- :collectors, through the public data builders used by each collector
        sample("usb", "device.usb", UsbLogic.data(UsbLogic.Snapshot(UsbLogic.CableState(true, true, listOf("mtp", "adb")), UsbLogic.DeviceInfo(0x1050, 0x0407, 0, "Yubico", "YubiKey"), UsbLogic.AccessoryInfo("Acme", "Dock", "1.0"))))
        sample(
            "connectivity", "net.connectivity",
            eventData {
                ConnectivityCollector.Snapshot(listOf("wifi", "vpn"), true, false, true, true, "dns.exemple.fr", listOf("10.0.0.1"), "tun0").writeTo(this)
            },
        )
        sample("wifi", "net.wifi", eventData { WifiCollector.WifiState("Maison", "aa:bb:cc:dd:ee:01", -55, 5180, "sae", "11ax").writeTo(this, "connected") })
        sample("wifi_scan", "net.wifi_scan", WifiScanCollector.data(listOf(WifiScanCollector.Ap("Voisin", "aa:aa:aa:aa:aa:01", -70, 2412, "wpa2"))))
        val cell = CellLogic.snapshot(
            listOf(CellLogic.Registration(packetSwitched = true, circuitSwitched = true, tech = "lte", roaming = false)),
            CellLogic.ServingCell("lte", "208", "01", tac = 1234, ci = 56789L, pci = 101, band = 3, signalDbm = -95, operator = "Orange F"),
            roaming = false, operatorName = "Orange", operatorNumeric = "20801",
        )
        sample("cell", "net.cell", eventData { cell.writeTo(this, -95) })
        sample("cell", "net.cell_security", CellLogic.downgradeData("lte → gsm", cell))
        sample("bluetooth", "net.bluetooth", BluetoothCollector.stateData(true))
        sample("bluetooth", "net.bluetooth", BluetoothCollector.deviceData("connected", "Écouteurs", "aa:bb:cc:dd:ee:ff", "le"))
        sample("ble_tracker", "net.ble_tracker", BleTrackerCollector.alertData(TrackerDetector.Alert("aa:bb:cc:dd:ee:ff", "airtag", -70, 1_763_242_983_974L, 5)))
        val usage = NetworkUsageCollector.aggregate(listOf(NetworkUsageCollector.UsageRow(10123, "wifi", 1_000, 100)), 100)
        sample("net_usage", "net.usage", NetworkUsageCollector.data(1_763_240_400_000L, 1_763_244_000_000L, usage, mapOf(10123 to "org.example")))
        val record = AppRecord("org.example", "1.2", 12, "a".repeat(64), setOf("android.permission.CAMERA"), "com.android.vending")
        sample("apps", "app.installed", AppInventoryLogic.changeData(record))
        sample("apps", "app.updated", AppInventoryLogic.changeData(record))
        sample("apps", "app.removed", AppInventoryLogic.changeData(record))
        sample("apps", "app.permission_changed", AppInventoryLogic.permissionData(PermissionChange("org.example", "android.permission.CAMERA", true)))
        val item = AppInventoryLogic.inventoryItem(AppDetails("org.example", "Exemple", true, false, false, 36, 1_700_000_000_000L, 1_763_000_000_000L), record)
        AppInventoryLogic.inventoryParts(listOf(item), "01JCQ8Z3K4M5N6P7Q8R9S0T1V2", 16 * 1024).forEach { sample("apps", "app.inventory", it) }
        sample(
            "special_access", "app.special_access",
            eventData {
                SpecialAccessSnapshot(listOf("com.bank/.A11y"), null, listOf("io.github.erwsim.vigie/.policy.VigieAdminReceiver"), emptyList(), listOf("org.fdroid.fdroid"), listOf("io.github.erwsim.vigie"), listOf("com.wireguard.android"), mapOf("browser" to "org.mozilla.firefox")).writeTo(this)
            },
        )
        sample("foreground", "app.foreground", ForegroundAppCollector.data(ForegroundTracker.Change("resumed", "org.maps", "org.maps.Main")))
        sample("camera", "sensor.camera", CameraCollector.data("0", true, ScreenState(true, false), "org.cam"))
        sample("microphone", "sensor.microphone", MicrophoneCollector.data(MicState(true, "mic", false), ScreenState(false, true), null))

        // ---- :policy, through the processors and builders used by its collectors
        val t0 = 1_763_242_800_000L
        val resolver = OwnerResolver(uidOf = { 10150 }, packagesForUid = { emptyList() })
        NetworkLogProcessor.process(
            listOf(
                NetRecord.Dns("com.google.android.gms", t0, "app-measurement.com", listOf("142.250.1.1"), 1),
                NetRecord.Dns("com.google.android.gms", t0 + 1_000, "app-measurement.com", listOf("142.250.1.2"), 1),
                NetRecord.Connect("com.google.android.gms", t0 + 2_000, "142.250.1.1", 443),
            ),
            resolver, windowMs = 600_000, includeConnect = true,
        ).forEach {
            assertTrue("ts is the time of origin", it.tsMs in t0..t0 + 2_000)
            sample("network_log", it.type, it.data)
        }
        val nanos = t0 * 1_000_000
        SecurityLogProcessor.process(
            listOf(
                RawSecurityEvent(SecurityLog.TAG_ADB_SHELL_CMD, SecurityLog.LEVEL_INFO, 1, nanos, "pm list packages"),
                RawSecurityEvent(SecurityLog.TAG_APP_PROCESS_START, SecurityLog.LEVEL_INFO, 2, nanos + 1, arrayOf<Any>("com.whatsapp", 1L, 10201, 8841, "default", "ab".repeat(32))),
                RawSecurityEvent(SecurityLog.TAG_APP_PROCESS_START, SecurityLog.LEVEL_INFO, 3, nanos + 2, arrayOf<Any>("com.whatsapp", 2L, 10201, 8842, "default", "ab".repeat(32))),
                RawSecurityEvent(SecurityLog.TAG_KEYGUARD_DISMISS_AUTH_ATTEMPT, SecurityLog.LEVEL_WARNING, 4, nanos + 3, arrayOf<Any>(0, 1)),
                RawSecurityEvent(SecurityLog.TAG_REMOTE_LOCK, SecurityLog.LEVEL_INFO, 5, nanos + 4, arrayOf<Any>("com.admin", 0, 0)), // not in the table: argN
            ),
            SecurityLogFilter(), preReboot = true,
        ).forEach {
            assertEquals(t0, it.tsMs)
            sample("security_log", SecurityLogProcessor.TYPE, it.data)
        }
        val posture = linkedMapOf<String, Any?>(
            "security_patch" to "2026-10-01", "patch_age_days" to 45, "encrypted" to true, "lock_secure" to true, "adb_enabled" to false,
            "adb_wifi_enabled" to false, "dev_options" to true, "unknown_sources" to false, "private_dns_mode" to "hostname",
            "private_dns_host" to "dns.exemple.fr", "always_on_vpn" to false, "device_owner" to true, "verified_boot_state" to "green",
            "user_ca_certs" to listOf("cd".repeat(32)), "play_protect" to null, "usb_data_signaling" to true,
        )
        sample("posture", "security.posture", PostureCollector.postureData(posture))
        sample("posture", "security.posture_change", PostureCollector.changeData(PostureChange("adb_enabled", "false", "true", Severity.WARNING)))
        sample("posture", "security.ca_cert", PostureCollector.caCertData(CaChange("added", CaCert("cd".repeat(32), "CN=Proxy"))))
        sample("posture", "security.keyguard", PostureCollector.keyguardData(false, 3))

        // security.policy: the policy engine's journal (also used for the base agent's actions).
        val policyEvents = ArrayList<JsonObject>()
        val engine = PolicyEngine(
            gateway = Proxy.newProxyInstance(javaClass.classLoader, arrayOf(DevicePolicyGateway::class.java)) { _, _, _ ->
                throw UnsupportedOperationException("not needed")
            } as DevicePolicyGateway,
            store = PolicyStore(MemoryPrefs()),
            catalog = PolicyCatalog.parse("""{"version":1,"updated":"2026-11-15","source":"test"}"""),
            probe = { _, _ -> throw UnsupportedOperationException() },
            clock = FakeClock(),
            sink = {
                object : EventSink {
                    override fun emit(type: String, sev: Int, data: JsonObject, originTsMs: Long?) {
                        assertEquals("security.policy", type)
                        policyEvents += data
                    }
                }
            },
            dnsHost = { null },
        )
        engine.logAction("permission_granted", "android.permission.ACCESS_FINE_LOCATION", null, true, null)
        engine.logAction("force_stop_protection", "enabled", null, false, "aucun effet constaté")
        engine.logAction("device_owner_cleared", PolicyEngine.OWNER_TARGET, null, true, null)
        engine.logAction("package_disabled", "com.samsung.android.rubin.app", "balanced", true, null)
        assertEquals(4, policyEvents.size)
        policyEvents.forEach { sample("policy_engine", "security.policy", it) }

        // ---- every sample follows the contract, and every declared type is covered
        for ((_, events) in emitted) events.forEach { (type, data) -> Contract.check(type, data) }
        val produced = emitted.values.flatten().map { it.first }.toSet()
        for (c in all) {
            val missing = c.eventTypes.filter { it !in produced && it !in notOnTheJvm }
            assertTrue("${c.id}: no sample for $missing", missing.isEmpty())
        }
    }

    @Test
    fun heartbeatCollectorReportsTheRealHostStates() {
        CollectorHarness(*all.toTypedArray()).use { h ->
            h.granted += "android.permission.ACCESS_FINE_LOCATION"
            h.startAll()
            h.collectOnce("heartbeat", CollectReason.MANUAL)
            val states = (h.eventsOf(EventTypes.AGENT_HEARTBEAT).last().data["collectors"] as JsonObject)
                .mapValues { (it.value as JsonPrimitive).content }
            all.forEach { c -> assertEquals(c.id, h.status(c.id).state.wire, states[c.id]) }
        }
    }
}
