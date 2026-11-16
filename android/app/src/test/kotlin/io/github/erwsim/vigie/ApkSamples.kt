package io.github.erwsim.vigie

import android.app.admin.SecurityLog
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
import io.github.erwsim.vigie.collectors.location.LocationCollector
import io.github.erwsim.vigie.collectors.network.ConnectivityCollector
import io.github.erwsim.vigie.collectors.network.NetworkUsageCollector
import io.github.erwsim.vigie.collectors.network.WifiCollector
import io.github.erwsim.vigie.collectors.network.WifiScanCollector
import io.github.erwsim.vigie.collectors.sensors.CameraCollector
import io.github.erwsim.vigie.collectors.sensors.MicState
import io.github.erwsim.vigie.collectors.sensors.MicrophoneCollector
import io.github.erwsim.vigie.core.collector.Collector
import io.github.erwsim.vigie.core.event.Severity
import io.github.erwsim.vigie.core.event.eventData
import io.github.erwsim.vigie.core.sink.EventSink
import io.github.erwsim.vigie.core.testing.CollectorHarness
import io.github.erwsim.vigie.core.testing.FakeClock
import io.github.erwsim.vigie.core.testing.MemoryPrefs
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
import java.lang.reflect.Proxy

/**
 * Typical events of every collector of the APK, produced by the same code as on the device: the
 * collectors' public data builders, the log processors, the policy engine, or the harness on the
 * JVM. Shared by [ContractConformanceTest] (shape against the contract) and [CrossServerTest]
 * (acceptance by the real collector).
 *
 * @param t0 wall-clock time of the samples (origin time of the log entries).
 */
class ApkSamples(private val all: List<Collector>, private val t0: Long = 1_763_242_800_000L) {
    /** [originTsMs]: time of origin for events read after the fact (becomes `ts`), else null. */
    data class Sample(val producer: String, val type: String, val data: JsonObject, val sev: Int = Severity.INFO, val originTsMs: Long? = null)

    private val out = ArrayList<Sample>()

    private fun sample(collector: String, type: String, data: JsonObject, sev: Int = Severity.INFO, originTsMs: Long? = null) {
        out += Sample(collector, type, data, sev, originTsMs)
    }

    fun produce(): List<Sample> {
        out.clear()
        // ---- every collector started in the harness (JVM: no system service, defaults from the stubs)
        CollectorHarness(*all.toTypedArray()).use { h ->
            h.startAll()
            h.collectOnce("heartbeat")
            h.events.forEach { e -> sample("harness", e.type, e.data, e.sev) }
        }
        // ---- :collectors, through the public data builders used by each collector
        sample("usb", "device.usb", UsbLogic.data(UsbLogic.Snapshot(UsbLogic.CableState(true, true, listOf("mtp", "adb")), UsbLogic.DeviceInfo(0x1050, 0x0407, 0, "Yubico", "YubiKey"), UsbLogic.AccessoryInfo("Acme", "Dock", "1.0"))))
        sample("location", "location.fix", LocationCollector.fixData(48.8566, 2.3522, 12.5f, 35.0, 1.4f, 90f, "gps", false, t0))
        sample("location", "location.fix", LocationCollector.fixData(48.8570, 2.3530, 30f, null, null, null, "passive", false, t0 + 60_000))
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
        sample("cell", "net.cell_security", CellLogic.downgradeData("lte → gsm", cell), Severity.WARNING)
        sample("bluetooth", "net.bluetooth", BluetoothCollector.stateData(true))
        sample("bluetooth", "net.bluetooth", BluetoothCollector.deviceData("connected", "Écouteurs", "aa:bb:cc:dd:ee:ff", "le"))
        sample("ble_tracker", "net.ble_tracker", BleTrackerCollector.alertData(TrackerDetector.Alert("aa:bb:cc:dd:ee:ff", "airtag", -70, t0, 5)), Severity.WARNING)
        val hour = t0 / 3_600_000 * 3_600_000
        val usage = NetworkUsageCollector.aggregate(
            listOf(
                NetworkUsageCollector.UsageRow(10123, "wifi", 1_000, 100),
                NetworkUsageCollector.UsageRow(10123, "wifi", 500, 50),
                NetworkUsageCollector.UsageRow(10150, "cellular", 70_000, 3_000),
            ),
            100,
        )
        sample("net_usage", "net.usage", NetworkUsageCollector.data(hour - 3_600_000, hour, usage, mapOf(10123 to "org.example", 10150 to "com.google.android.gms")))
        val record = AppRecord("org.example", "1.2", 12, "a".repeat(64), setOf("android.permission.CAMERA"), "com.android.vending")
        sample("apps", "app.installed", AppInventoryLogic.changeData(record), AppInventoryLogic.changeSeverity("app.installed", record, false))
        sample("apps", "app.updated", AppInventoryLogic.changeData(record))
        sample("apps", "app.removed", AppInventoryLogic.changeData(record), Severity.NOTABLE)
        sample("apps", "app.permission_changed", AppInventoryLogic.permissionData(PermissionChange("org.example", "android.permission.CAMERA", true)))
        // A phone-sized inventory: several parts sharing one inventory id.
        val items = (1..INVENTORY_APPS).map { i ->
            val r = AppRecord(
                "org.example.app%03d".format(i), "1.$i", i.toLong(), "%064x".format(i), setOf("android.permission.CAMERA", "android.permission.ACCESS_FINE_LOCATION"),
                if (i % 3 == 0) null else "com.android.vending", system = i % 5 == 0,
            )
            AppInventoryLogic.inventoryItem(AppDetails(r.pkg, "Application n° $i", true, i % 50 == 0, i % 40 == 0, 36, t0 - 86_400_000L * i, t0 - 3_600_000L * i), r)
        }
        AppInventoryLogic.inventoryParts(items, INVENTORY_ID, 16 * 1024).forEach { sample("apps", "app.inventory", it) }
        sample(
            "special_access", "app.special_access",
            eventData {
                SpecialAccessSnapshot(listOf("com.bank/.A11y"), null, listOf("io.github.erwsim.vigie/.policy.VigieAdminReceiver"), emptyList(), listOf("org.fdroid.fdroid"), listOf("io.github.erwsim.vigie"), listOf("com.wireguard.android"), mapOf("browser" to "org.mozilla.firefox")).writeTo(this)
            },
        )
        sample("foreground", "app.foreground", ForegroundAppCollector.data(ForegroundTracker.Change("resumed", "org.maps", "org.maps.Main")), originTsMs = t0 - 90_000)
        sample("camera", "sensor.camera", CameraCollector.data("0", true, ScreenState(true, false), "org.cam"))
        sample("microphone", "sensor.microphone", MicrophoneCollector.data(MicState(true, "mic", false), ScreenState(false, true), null), Severity.NOTABLE)

        // ---- :policy, through the processors and builders used by its collectors
        val resolver = OwnerResolver(uidOf = { 10150 }, packagesForUid = { emptyList() })
        NetworkLogProcessor.process(
            listOf(
                NetRecord.Dns("com.google.android.gms", t0, "app-measurement.com", listOf("142.250.1.1"), 1),
                NetRecord.Dns("com.google.android.gms", t0 + 1_000, "app-measurement.com", listOf("142.250.1.2"), 1),
                NetRecord.Dns("com.google.android.gms", t0 + 1_500, "app-measurement.com", listOf("142.250.1.2"), 1),
                NetRecord.Dns("org.example", t0 + 1_700, "exemple.org", listOf("203.0.113.9"), 1),
                NetRecord.Connect("com.google.android.gms", t0 + 2_000, "142.250.1.1", 443),
                NetRecord.Connect("com.google.android.gms", t0 + 2_100, "142.250.1.1", 443),
            ),
            resolver, windowMs = 600_000, includeConnect = true,
        ).forEach {
            check(it.tsMs in t0..t0 + 2_100) { "ts is the time of origin" }
            sample("network_log", it.type, it.data, originTsMs = it.tsMs)
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
            check(it.tsMs == t0) { "ts is the time of origin" }
            sample("security_log", SecurityLogProcessor.TYPE, it.data, it.sev, originTsMs = it.tsMs)
        }
        // Two successive snapshots: ADB off, then on (the collector derives the changes from snapshots).
        sample("posture", "security.posture", PostureCollector.postureData(POSTURE + ("adb_enabled" to false)))
        sample("posture", "security.posture", PostureCollector.postureData(POSTURE), Severity.WARNING)
        sample("posture", "security.posture_change", PostureCollector.changeData(PostureChange("adb_enabled", "false", "true", Severity.WARNING)), Severity.WARNING)
        sample("posture", "security.ca_cert", PostureCollector.caCertData(CaChange("added", CaCert("cd".repeat(32), "CN=Proxy"))), Severity.WARNING)
        sample("posture", "security.keyguard", PostureCollector.keyguardData(false, 3), Severity.WARNING)

        // security.policy: the policy engine's journal (also used for the base agent's actions).
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
                        check(type == "security.policy")
                        sample("policy_engine", type, data, sev)
                    }
                }
            },
            dnsHost = { null },
        )
        engine.logAction("permission_granted", "android.permission.ACCESS_FINE_LOCATION", null, true, null)
        engine.logAction("force_stop_protection", "enabled", null, false, "aucun effet constaté")
        engine.logAction("device_owner_cleared", PolicyEngine.OWNER_TARGET, null, true, null)
        engine.logAction("package_disabled", "com.samsung.android.rubin.app", "balanced", true, null)
        return out.toList()
    }

    companion object {
        const val INVENTORY_APPS = 420
        const val INVENTORY_ID = "01JCQ8Z3K4M5N6P7Q8R9S0T1V2"

        val POSTURE = linkedMapOf<String, Any?>(
            "security_patch" to "2026-10-01", "patch_age_days" to 45, "encrypted" to true, "lock_secure" to true, "adb_enabled" to true,
            "adb_wifi_enabled" to false, "dev_options" to true, "unknown_sources" to false, "private_dns_mode" to "hostname",
            "private_dns_host" to "dns.exemple.fr", "always_on_vpn" to false, "device_owner" to true, "verified_boot_state" to "green",
            "user_ca_certs" to listOf("cd".repeat(32)), "play_protect" to null, "usb_data_signaling" to true,
        )
    }
}
