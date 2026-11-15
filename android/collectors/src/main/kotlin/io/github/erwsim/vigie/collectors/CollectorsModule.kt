package io.github.erwsim.vigie.collectors

import android.content.Context
import io.github.erwsim.vigie.collectors.device.DeviceCollector
import io.github.erwsim.vigie.collectors.heartbeat.HeartbeatCollector
import io.github.erwsim.vigie.collectors.location.LocationCollector
import io.github.erwsim.vigie.core.collector.Collector

/**
 * Entry point of the `:collectors` module: every collector that needs no Device Owner privilege.
 * To add one: create its class in its own package and add it to this list (only this file changes).
 * The order is the display order in the app.
 */
object CollectorsModule {
    @Suppress("UNUSED_PARAMETER")
    fun all(context: Context): List<Collector> = listOf(
        HeartbeatCollector(),
        DeviceCollector(),
        LocationCollector(),
    )
}
