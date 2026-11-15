package io.github.erwsim.vigie.collectors.bluetooth

import android.Manifest
import android.annotation.SuppressLint
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothManager
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import io.github.erwsim.vigie.collectors.R
import io.github.erwsim.vigie.collectors.common.RateLimiter
import io.github.erwsim.vigie.collectors.common.changed
import io.github.erwsim.vigie.collectors.network.NetFormat
import io.github.erwsim.vigie.core.collector.Collector
import io.github.erwsim.vigie.core.collector.CollectorContext
import io.github.erwsim.vigie.core.collector.Requirement
import io.github.erwsim.vigie.core.event.Severity
import io.github.erwsim.vigie.core.event.eventData
import kotlinx.serialization.json.JsonObject

/**
 * `net.bluetooth`: adapter on/off (`event = state`) and device connections/disconnections (ACL
 * link, `connected`/`disconnected` with name, address and type). Broadcast-driven, no scan.
 * Without BLUETOOTH_CONNECT ("Nearby devices"), only the on/off state is available. Repeated
 * identical events for the same device are dropped; at most 120 events per hour.
 */
class BluetoothCollector : Collector {
    override val id = "bluetooth"
    override val titleRes = R.string.collector_bluetooth_title
    override val descriptionRes = R.string.collector_bluetooth_desc
    override val eventTypes = listOf(TYPE)
    override val requirements = listOf(
        Requirement.SystemFeature(PackageManager.FEATURE_BLUETOOTH),
        Requirement.Permission(Manifest.permission.BLUETOOTH_CONNECT, optional = true),
    )

    private val lastByAddress = HashMap<String, String>()
    private val limiter = RateLimiter(120, 3_600_000L)

    override suspend fun start(ctx: CollectorContext) {
        lastByAddress.clear()
        limiter.reset()
        val adapter = ctx.appContext.getSystemService(BluetoothManager::class.java)?.adapter ?: return
        reportState(ctx, adapter.isEnabled)
        ctx.registerReceiver(IntentFilter(BluetoothAdapter.ACTION_STATE_CHANGED)) { intent ->
            when (intent.getIntExtra(BluetoothAdapter.EXTRA_STATE, -1)) {
                BluetoothAdapter.STATE_ON -> reportState(ctx, true)
                BluetoothAdapter.STATE_OFF -> {
                    lastByAddress.clear()
                    reportState(ctx, false)
                }
            }
        }
        if (ctx.capabilities.hasPermission(Manifest.permission.BLUETOOTH_CONNECT)) {
            ctx.registerReceiver(
                IntentFilter().apply {
                    addAction(BluetoothDevice.ACTION_ACL_CONNECTED)
                    addAction(BluetoothDevice.ACTION_ACL_DISCONNECTED)
                },
            ) { intent -> onAcl(ctx, intent) }
        }
    }

    override suspend fun stop(ctx: CollectorContext) = lastByAddress.clear()

    private fun reportState(ctx: CollectorContext, enabled: Boolean) {
        if (!ctx.changed("enabled", enabled.toString())) return
        ctx.sink.emit(TYPE, Severity.INFO, stateData(enabled))
    }

    @SuppressLint("MissingPermission") // Receiver registered only with BLUETOOTH_CONNECT.
    private fun onAcl(ctx: CollectorContext, intent: Intent) {
        val device = intent.getParcelableExtra(BluetoothDevice.EXTRA_DEVICE, BluetoothDevice::class.java) ?: return
        val event = if (intent.action == BluetoothDevice.ACTION_ACL_CONNECTED) "connected" else "disconnected"
        val address = NetFormat.mac(device.address) ?: return
        if (lastByAddress[address] == event) return
        lastByAddress[address] = event
        if (!limiter.tryAcquire(ctx.clock.elapsedRealtime())) return
        val name = try {
            device.name
        } catch (_: SecurityException) {
            null
        }
        val type = try {
            typeName(device.type)
        } catch (_: SecurityException) {
            null
        }
        ctx.sink.emit(TYPE, Severity.INFO, deviceData(event, name, address, type))
    }

    companion object {
        const val TYPE = "net.bluetooth"

        fun stateData(enabled: Boolean): JsonObject = eventData {
            put("event", "state")
            put("enabled", enabled)
        }

        fun deviceData(event: String, name: String?, address: String, type: String?): JsonObject = eventData {
            put("event", event)
            put("name", name?.trim()?.takeIf { it.isNotEmpty() }?.take(100))
            put("address", address)
            put("type", type)
        }

        fun typeName(type: Int): String? = when (type) {
            BluetoothDevice.DEVICE_TYPE_CLASSIC -> "classic"
            BluetoothDevice.DEVICE_TYPE_LE -> "le"
            BluetoothDevice.DEVICE_TYPE_DUAL -> "dual"
            else -> null
        }
    }
}
