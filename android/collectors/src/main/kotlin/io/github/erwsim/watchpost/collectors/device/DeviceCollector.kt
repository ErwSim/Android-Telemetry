package io.github.erwsim.watchpost.collectors.device

import android.app.ActivityManager
import android.content.Intent
import android.content.IntentFilter
import android.os.BatteryManager
import android.os.Build
import android.os.Environment
import android.os.PowerManager
import android.os.StatFs
import io.github.erwsim.watchpost.collectors.R
import io.github.erwsim.watchpost.core.capability.SystemProps
import io.github.erwsim.watchpost.core.collector.CollectReason
import io.github.erwsim.watchpost.core.collector.Collector
import io.github.erwsim.watchpost.core.collector.CollectorContext
import io.github.erwsim.watchpost.core.collector.PeriodicSpec
import io.github.erwsim.watchpost.core.event.Severity
import io.github.erwsim.watchpost.core.event.eventData
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.JsonObject

/**
 * `device.*` events: screen, battery, power save, boot/shutdown, inventory, storage, time and time
 * zone changes, airplane mode, thermal status. Broadcast-driven (no polling) except the daily
 * inventory/storage snapshot.
 */
class DeviceCollector : Collector {
    override val id = "device"
    override val titleRes = R.string.collector_device_title
    override val descriptionRes = R.string.collector_device_desc
    override val eventTypes = listOf(
        "device.inventory", "device.boot", "device.shutdown", "device.screen", "device.battery",
        "device.power_save", "device.storage", "device.thermal", "device.time_changed",
        "device.timezone_changed", "device.airplane_mode",
    )
    override val periodic = PeriodicSpec(intervalMinutes = 24 * 60, runAtStart = true)

    // State below is only touched on the collectors' thread.
    private var lastBattery: BatterySnapshot? = null
    private var clockOffsetMs = 0L
    private var lastThermal = -1

    override suspend fun start(ctx: CollectorContext) {
        reportBootOnce(ctx)
        clockOffsetMs = ctx.clock.nowMillis() - ctx.clock.elapsedRealtime()

        ctx.registerReceiver(
            IntentFilter().apply {
                addAction(Intent.ACTION_SCREEN_ON)
                addAction(Intent.ACTION_SCREEN_OFF)
                addAction(Intent.ACTION_USER_PRESENT)
            },
        ) { intent ->
            val state = when (intent.action) {
                Intent.ACTION_SCREEN_ON -> "on"
                Intent.ACTION_SCREEN_OFF -> "off"
                else -> "unlocked"
            }
            ctx.emit("device.screen") { put("state", state) }
        }

        // Sticky: delivers the current state right away, then every change.
        ctx.registerReceiver(IntentFilter(Intent.ACTION_BATTERY_CHANGED)) { onBattery(ctx, it) }

        val power = ctx.appContext.getSystemService(PowerManager::class.java)
        if (power != null) {
            emitIfChanged(ctx, "power_save", power.isPowerSaveMode.toString()) {
                ctx.emit("device.power_save") { put("enabled", power.isPowerSaveMode) }
            }
            ctx.registerReceiver(IntentFilter(PowerManager.ACTION_POWER_SAVE_MODE_CHANGED)) {
                ctx.prefs.edit().putString("last_power_save", power.isPowerSaveMode.toString()).apply()
                ctx.emit("device.power_save") { put("enabled", power.isPowerSaveMode) }
            }
            val thermalListener = PowerManager.OnThermalStatusChangedListener { status ->
                ctx.guard("thermal") {
                    if (status != lastThermal) {
                        lastThermal = status
                        ctx.emit("device.thermal", if (status >= PowerManager.THERMAL_STATUS_SEVERE) Severity.WARNING else Severity.INFO) {
                            put("status", thermalName(status))
                        }
                    }
                }
            }
            power.addThermalStatusListener(ctx.executor, thermalListener)
            ctx.onStop { power.removeThermalStatusListener(thermalListener) }
        }

        ctx.registerReceiver(
            IntentFilter().apply {
                addAction(Intent.ACTION_SHUTDOWN)
                addAction(ACTION_REBOOT)
            },
        ) { intent ->
            ctx.emit("device.shutdown", Severity.NOTABLE) {
                put("reason", if (intent.action == ACTION_REBOOT) "reboot" else "shutdown")
            }
            // The process may die within seconds: write now.
            ctx.flushBlocking(3_000)
        }

        ctx.registerReceiver(IntentFilter(Intent.ACTION_TIME_CHANGED)) {
            val newOffset = ctx.clock.nowMillis() - ctx.clock.elapsedRealtime()
            val delta = newOffset - clockOffsetMs
            clockOffsetMs = newOffset
            val sev = if (kotlin.math.abs(delta) > 60_000) Severity.NOTABLE else Severity.INFO
            ctx.emit("device.time_changed", sev) { put("delta_ms", delta) }
        }
        ctx.registerReceiver(IntentFilter(Intent.ACTION_TIMEZONE_CHANGED)) { intent ->
            ctx.emit("device.timezone_changed") {
                put("tz", intent.getStringExtra(Intent.EXTRA_TIMEZONE) ?: java.util.TimeZone.getDefault().id)
            }
        }
        ctx.registerReceiver(IntentFilter(Intent.ACTION_AIRPLANE_MODE_CHANGED)) { intent ->
            ctx.emit("device.airplane_mode") { put("enabled", intent.getBooleanExtra("state", false)) }
        }
    }

    override suspend fun stop(ctx: CollectorContext) {
        lastBattery = null
        lastThermal = -1
    }

    override suspend fun collectOnce(ctx: CollectorContext, reason: CollectReason) {
        val inventory = withContext(ctx.io) { inventory(ctx) }
        val signature = inventory.toString().hashCode().toString()
        val lastSignature = ctx.prefs.getString("inventory_signature", null)
        val lastMs = ctx.prefs.getLong("inventory_ms", 0)
        val due = reason == CollectReason.PERIODIC ||
            ctx.boot.isNewBoot || ctx.boot.isFirstRun ||
            signature != lastSignature ||
            ctx.clock.nowMillis() - lastMs > 20 * 3_600_000L
        if (due) {
            ctx.sink.emit("device.inventory", Severity.INFO, inventory)
            ctx.prefs.edit().putString("inventory_signature", signature).putLong("inventory_ms", ctx.clock.nowMillis()).apply()
        }
        val stat = withContext(ctx.io) { StatFs(Environment.getDataDirectory().path) }
        ctx.emit("device.storage") {
            put("free_bytes", stat.availableBytes)
            put("total_bytes", stat.totalBytes)
        }
    }

    private suspend fun reportBootOnce(ctx: CollectorContext) {
        if (!ctx.boot.isNewBoot) return
        if (ctx.prefs.getString("boot_reported", null) == ctx.boot.bootId) return
        val reason = withContext(ctx.io) {
            SystemProps.get("sys.boot.reason") ?: SystemProps.get("ro.boot.bootreason")
        } ?: "unknown"
        ctx.emit("device.boot", Severity.NOTABLE) { put("reason", reason) }
        ctx.prefs.edit().putString("boot_reported", ctx.boot.bootId).apply()
    }

    private fun onBattery(ctx: CollectorContext, intent: Intent) {
        val level = intent.getIntExtra(BatteryManager.EXTRA_LEVEL, -1)
        val scale = intent.getIntExtra(BatteryManager.EXTRA_SCALE, 100)
        val snapshot = BatterySnapshot(
            pct = if (level >= 0 && scale > 0) level * 100 / scale else null,
            plugged = pluggedName(intent.getIntExtra(BatteryManager.EXTRA_PLUGGED, 0)),
            status = statusName(intent.getIntExtra(BatteryManager.EXTRA_STATUS, BatteryManager.BATTERY_STATUS_UNKNOWN)),
            health = healthName(intent.getIntExtra(BatteryManager.EXTRA_HEALTH, BatteryManager.BATTERY_HEALTH_UNKNOWN)),
        )
        // Temperature alone changes constantly: it is reported but does not trigger an event.
        if (snapshot == lastBattery) return
        lastBattery = snapshot
        val temperature = intent.getIntExtra(BatteryManager.EXTRA_TEMPERATURE, Int.MIN_VALUE)
        ctx.emit("device.battery") {
            put("pct", snapshot.pct)
            put("plugged", snapshot.plugged)
            put("status", snapshot.status)
            if (temperature != Int.MIN_VALUE) put("temperature_c", temperature / 10.0)
            put("health", snapshot.health)
        }
    }

    private inline fun emitIfChanged(ctx: CollectorContext, key: String, value: String, emit: () -> Unit) {
        if (ctx.prefs.getString("last_$key", null) != value) {
            ctx.prefs.edit().putString("last_$key", value).apply()
            emit()
        }
    }

    private fun inventory(ctx: CollectorContext): JsonObject {
        val am = ctx.appContext.getSystemService(ActivityManager::class.java)
        val memory = ActivityManager.MemoryInfo().also { am?.getMemoryInfo(it) }
        val stat = StatFs(Environment.getDataDirectory().path)
        return eventData {
            put("manufacturer", Build.MANUFACTURER)
            put("model", Build.MODEL)
            put("android_release", Build.VERSION.RELEASE)
            put("sdk_int", Build.VERSION.SDK_INT)
            put("security_patch", Build.VERSION.SECURITY_PATCH)
            put("build_fingerprint", Build.FINGERPRINT)
            put("one_ui", SystemProps.oneUiVersion())
            put("kernel", System.getProperty("os.version"))
            put("bootloader", Build.BOOTLOADER)
            put("verified_boot_state", SystemProps.get("ro.boot.verifiedbootstate"))
            put("total_storage_bytes", stat.totalBytes)
            put("total_ram_bytes", memory.totalMem.takeIf { it > 0 })
        }
    }

    private data class BatterySnapshot(val pct: Int?, val plugged: String, val status: String, val health: String)

    internal companion object {
        /** Protected system broadcast sent on reboot by some builds (no public constant). */
        const val ACTION_REBOOT = "android.intent.action.REBOOT"

        fun pluggedName(plugged: Int): String = when {
            plugged == 0 -> "none"
            plugged and BatteryManager.BATTERY_PLUGGED_WIRELESS != 0 -> "wireless"
            plugged and BatteryManager.BATTERY_PLUGGED_USB != 0 -> "usb"
            // AC and dock (mains powered) are both reported as "ac", the contract has no "dock".
            else -> "ac"
        }

        fun statusName(status: Int): String = when (status) {
            BatteryManager.BATTERY_STATUS_CHARGING -> "charging"
            BatteryManager.BATTERY_STATUS_DISCHARGING -> "discharging"
            BatteryManager.BATTERY_STATUS_FULL -> "full"
            BatteryManager.BATTERY_STATUS_NOT_CHARGING -> "not_charging"
            else -> "unknown"
        }

        fun healthName(health: Int): String = when (health) {
            BatteryManager.BATTERY_HEALTH_GOOD -> "good"
            BatteryManager.BATTERY_HEALTH_OVERHEAT -> "overheat"
            BatteryManager.BATTERY_HEALTH_DEAD -> "dead"
            BatteryManager.BATTERY_HEALTH_OVER_VOLTAGE -> "over_voltage"
            BatteryManager.BATTERY_HEALTH_UNSPECIFIED_FAILURE -> "failure"
            BatteryManager.BATTERY_HEALTH_COLD -> "cold"
            else -> "unknown"
        }

        fun thermalName(status: Int): String = when (status) {
            PowerManager.THERMAL_STATUS_NONE -> "none"
            PowerManager.THERMAL_STATUS_LIGHT -> "light"
            PowerManager.THERMAL_STATUS_MODERATE -> "moderate"
            PowerManager.THERMAL_STATUS_SEVERE -> "severe"
            PowerManager.THERMAL_STATUS_CRITICAL -> "critical"
            PowerManager.THERMAL_STATUS_EMERGENCY -> "emergency"
            PowerManager.THERMAL_STATUS_SHUTDOWN -> "shutdown"
            else -> "unknown"
        }
    }
}
