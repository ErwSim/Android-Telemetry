package io.github.erwsim.vigie.collectors.device

import android.content.Intent
import android.content.IntentFilter
import android.hardware.usb.UsbAccessory
import android.hardware.usb.UsbDevice
import android.hardware.usb.UsbManager
import io.github.erwsim.vigie.collectors.R
import io.github.erwsim.vigie.collectors.common.RateLimiter
import io.github.erwsim.vigie.core.collector.Collector
import io.github.erwsim.vigie.core.collector.CollectorContext
import io.github.erwsim.vigie.core.event.Severity
import io.github.erwsim.vigie.core.event.eventData
import kotlinx.serialization.json.JsonObject

/**
 * `device.usb`: USB cable state (connected to a host, configured, active functions such as `mtp`,
 * `ptp`, `rndis`, `midi`, `adb`) and USB devices/accessories plugged into the phone.
 *
 * The cable state comes from the sticky system broadcast `android.hardware.usb.action.USB_STATE`
 * (public string, constant hidden), widely used by apps; devices and accessories from the public
 * attach/detach broadcasts and `UsbManager` lists (no permission needed to list them). An event
 * only when the state changes, at most 60 per hour. Broadcast-driven, no cost.
 */
class UsbCollector : Collector {
    override val id = "usb"
    override val titleRes = R.string.collector_usb_title
    override val descriptionRes = R.string.collector_usb_desc
    override val eventTypes = listOf(TYPE)

    private var cable = UsbLogic.CableState(connected = false, configured = false, functions = emptyList())
    private var last: UsbLogic.Snapshot? = null
    private val limiter = RateLimiter(60, 3_600_000L)

    override suspend fun start(ctx: CollectorContext) {
        last = null
        cable = UsbLogic.CableState(connected = false, configured = false, functions = emptyList())
        limiter.reset()
        val usb = ctx.appContext.getSystemService(UsbManager::class.java) ?: return
        ctx.registerReceiver(IntentFilter(ACTION_USB_STATE)) { intent ->
            cable = UsbLogic.cableState { key -> intent.getBooleanExtra(key, false) }
            publish(ctx, usb)
        }
        ctx.registerReceiver(
            IntentFilter().apply {
                addAction(UsbManager.ACTION_USB_DEVICE_ATTACHED)
                addAction(UsbManager.ACTION_USB_DEVICE_DETACHED)
                addAction(UsbManager.ACTION_USB_ACCESSORY_ATTACHED)
                addAction(UsbManager.ACTION_USB_ACCESSORY_DETACHED)
            },
        ) { publish(ctx, usb) }
        publish(ctx, usb)
    }

    override suspend fun stop(ctx: CollectorContext) {
        last = null
    }

    private fun publish(ctx: CollectorContext, usb: UsbManager) {
        val device = try {
            usb.deviceList?.values?.minByOrNull { it.deviceId }?.let(::deviceInfo)
        } catch (_: Exception) {
            null
        }
        val accessory = try {
            usb.accessoryList?.firstOrNull()?.let(::accessoryInfo)
        } catch (_: Exception) {
            null
        }
        val snapshot = UsbLogic.Snapshot(cable, device, accessory)
        val previous = last
        if (snapshot == previous) return
        // The first state after start is only reported if something is plugged in.
        if (previous == null && !snapshot.anythingConnected) {
            last = snapshot
            return
        }
        if (!limiter.tryAcquire(ctx.clock.elapsedRealtime())) return
        last = snapshot
        val sev = if (UsbLogic.isNotable(previous, snapshot)) Severity.NOTABLE else Severity.INFO
        ctx.sink.emit(TYPE, sev, UsbLogic.data(snapshot))
    }

    private fun deviceInfo(d: UsbDevice) = UsbLogic.DeviceInfo(
        vendorId = d.vendorId,
        productId = d.productId,
        deviceClass = d.deviceClass,
        manufacturer = safe { d.manufacturerName },
        product = safe { d.productName },
    )

    private fun accessoryInfo(a: UsbAccessory) = UsbLogic.AccessoryInfo(
        manufacturer = safe { a.manufacturer },
        model = safe { a.model },
        version = safe { a.version },
    )

    private inline fun safe(block: () -> String?): String? = try {
        block()?.trim()?.takeIf { it.isNotEmpty() }?.take(100)
    } catch (_: Exception) {
        null
    }

    companion object {
        const val TYPE = "device.usb"
        /** UsbManager.ACTION_USB_STATE (hidden constant, stable public string). */
        const val ACTION_USB_STATE = "android.hardware.usb.action.USB_STATE"
    }
}

/** Pure USB state logic. */
object UsbLogic {
    /** Boolean extras of USB_STATE naming a function (UsbManager.USB_FUNCTION_*). */
    val FUNCTIONS = listOf("mtp", "ptp", "rndis", "midi", "accessory", "audio_source", "adb", "ncm", "uvc")

    data class CableState(val connected: Boolean, val configured: Boolean, val functions: List<String>)

    data class DeviceInfo(val vendorId: Int, val productId: Int, val deviceClass: Int, val manufacturer: String?, val product: String?)

    data class AccessoryInfo(val manufacturer: String?, val model: String?, val version: String?)

    data class Snapshot(val cable: CableState, val device: DeviceInfo?, val accessory: AccessoryInfo?) {
        val anythingConnected: Boolean get() = cable.connected || device != null || accessory != null
    }

    /** Parses USB_STATE extras (`connected`, `configured`, one boolean per active function). */
    fun cableState(extra: (String) -> Boolean): CableState {
        val connected = extra("connected")
        return CableState(
            connected = connected,
            configured = extra("configured"),
            functions = if (connected) FUNCTIONS.filter(extra) else emptyList(),
        )
    }

    /** `device.usb` data. */
    fun data(s: Snapshot): JsonObject = eventData {
        put("connected", s.cable.connected || s.device != null)
        put("configured", s.cable.configured)
        putStrings("functions", s.cable.functions)
        s.accessory?.let { a ->
            putObject("accessory") {
                put("manufacturer", a.manufacturer)
                put("model", a.model)
                put("version", a.version)
            }
        }
        s.device?.let { d ->
            putObject("device") {
                put("vendor_id", d.vendorId)
                put("product_id", d.productId)
                put("device_class", d.deviceClass)
                put("manufacturer", d.manufacturer)
                put("product", d.product)
            }
        }
    }

    /** ADB newly active, or a device/accessory newly plugged into the phone. */
    fun isNotable(previous: Snapshot?, now: Snapshot): Boolean =
        ("adb" in now.cable.functions && "adb" !in previous?.cable?.functions.orEmpty()) ||
            (now.device != null && now.device != previous?.device) ||
            (now.accessory != null && now.accessory != previous?.accessory)
}
