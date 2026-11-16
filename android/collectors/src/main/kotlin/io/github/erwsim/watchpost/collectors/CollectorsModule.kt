package io.github.erwsim.watchpost.collectors

import android.content.Context
import io.github.erwsim.watchpost.collectors.apps.AppsCollector
import io.github.erwsim.watchpost.collectors.apps.ForegroundAppCollector
import io.github.erwsim.watchpost.collectors.apps.SpecialAccessCollector
import io.github.erwsim.watchpost.collectors.bluetooth.BleTrackerCollector
import io.github.erwsim.watchpost.collectors.bluetooth.BluetoothCollector
import io.github.erwsim.watchpost.collectors.cell.CellCollector
import io.github.erwsim.watchpost.collectors.device.DeviceCollector
import io.github.erwsim.watchpost.collectors.device.UsbCollector
import io.github.erwsim.watchpost.collectors.heartbeat.HeartbeatCollector
import io.github.erwsim.watchpost.collectors.location.LocationCollector
import io.github.erwsim.watchpost.collectors.network.ConnectivityCollector
import io.github.erwsim.watchpost.collectors.network.HotspotCollector
import io.github.erwsim.watchpost.collectors.network.NetworkUsageCollector
import io.github.erwsim.watchpost.collectors.network.NfcCollector
import io.github.erwsim.watchpost.collectors.network.WifiCollector
import io.github.erwsim.watchpost.collectors.network.WifiScanCollector
import io.github.erwsim.watchpost.collectors.notifications.NotificationsCollector
import io.github.erwsim.watchpost.collectors.ops.AppOpsCollector
import io.github.erwsim.watchpost.collectors.risk.AppRiskCollector
import io.github.erwsim.watchpost.collectors.roles.AppRoleCollector
import io.github.erwsim.watchpost.collectors.sensors.CameraCollector
import io.github.erwsim.watchpost.collectors.sensors.MicrophoneCollector
import io.github.erwsim.watchpost.core.collector.Collector

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
        AppRiskCollector(),
        AppRoleCollector(),
        AppOpsCollector(),
        ForegroundAppCollector(),
        NotificationsCollector(),
        CameraCollector(),
        MicrophoneCollector(),
    )
}
