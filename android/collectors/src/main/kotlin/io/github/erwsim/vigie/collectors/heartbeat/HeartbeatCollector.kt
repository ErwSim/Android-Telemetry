package io.github.erwsim.vigie.collectors.heartbeat

import android.os.BatteryManager
import io.github.erwsim.vigie.collectors.R
import io.github.erwsim.vigie.core.collector.CollectReason
import io.github.erwsim.vigie.core.collector.Collector
import io.github.erwsim.vigie.core.collector.CollectorContext
import io.github.erwsim.vigie.core.collector.PeriodicSpec
import io.github.erwsim.vigie.core.event.EventTypes
import io.github.erwsim.vigie.core.event.Rfc3339
import kotlinx.coroutines.withContext

/** `agent.heartbeat` every 15 minutes (contract §2), through WorkManager so it survives Doze. */
class HeartbeatCollector : Collector {
    override val id = "heartbeat"
    override val titleRes = R.string.collector_heartbeat_title
    override val descriptionRes = R.string.collector_heartbeat_desc
    override val eventTypes = listOf(EventTypes.AGENT_HEARTBEAT)
    override val periodic = PeriodicSpec(intervalMinutes = 15, runAtStart = true)

    override suspend fun collectOnce(ctx: CollectorContext, reason: CollectReason) {
        val battery = ctx.appContext.getSystemService(BatteryManager::class.java)
        val pct = battery?.getIntProperty(BatteryManager.BATTERY_PROPERTY_CAPACITY)?.takeIf { it in 0..100 }
        val status = ctx.status
        val dropped = withContext(ctx.io) { status.droppedTotal() }
        val deviceOwner = status.isDeviceOwner()
        ctx.emit(EventTypes.AGENT_HEARTBEAT) {
            put("battery_pct", pct)
            put("charging", battery?.isCharging)
            put("uptime_ms", ctx.clock.elapsedRealtime())
            put("queue_depth", status.queueDepth())
            put("queue_bytes", status.queueBytes())
            put("dropped_total", dropped)
            put("device_owner", deviceOwner)
            putMap("collectors", status.collectorStates().mapValues { it.value.wire })
            put("last_upload_ts", status.lastUploadMs()?.let(Rfc3339::format))
        }
    }
}
