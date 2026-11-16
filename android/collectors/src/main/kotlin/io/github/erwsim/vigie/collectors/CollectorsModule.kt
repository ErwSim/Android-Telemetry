package io.github.erwsim.vigie.collectors

import android.content.Context
import io.github.erwsim.vigie.collectors.apps.AppsCollector
import io.github.erwsim.vigie.collectors.apps.ForegroundAppCollector
import io.github.erwsim.vigie.collectors.apps.SpecialAccessCollector
import io.github.erwsim.vigie.collectors.bluetooth.BleTrackerCollector
import io.github.erwsim.vigie.collectors.bluetooth.BluetoothCollector
import io.github.erwsim.vigie.collectors.cell.CellCollector
import io.github.erwsim.vigie.collectors.device.DeviceCollector
import io.github.erwsim.vigie.collectors.device.UsbCollector
import io.github.erwsim.vigie.collectors.heartbeat.HeartbeatCollector
import io.github.erwsim.vigie.collectors.location.LocationCollector
import io.github.erwsim.vigie.collectors.network.ConnectivityCollector
import io.github.erwsim.vigie.collectors.network.HotspotCollector
import io.github.erwsim.vigie.collectors.network.NetworkUsageCollector
import io.github.erwsim.vigie.collectors.network.NfcCollector
import io.github.erwsim.vigie.collectors.network.WifiCollector
import io.github.erwsim.vigie.collectors.network.WifiScanCollector
import io.github.erwsim.vigie.collectors.notifications.NotificationsCollector
import io.github.erwsim.vigie.collectors.sensors.CameraCollector
import io.github.erwsim.vigie.collectors.sensors.MicrophoneCollector
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
        UsbCollector(),
        LocationCollector(),
        ConnectivityCollector(),
        WifiCollector(),
        WifiScanCollector(),
        HotspotCollector(),
        NfcCollector(),
        CellCollector(),
        BluetoothCollector(),
        BleTrackerCollector(),
        NetworkUsageCollector(),
        AppsCollector(),
        SpecialAccessCollector(),
        ForegroundAppCollector(),
        NotificationsCollector(),
        CameraCollector(),
        MicrophoneCollector(),
    )
}
