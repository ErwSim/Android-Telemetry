package io.github.erwsim.vigie.collectors.bluetooth

import android.Manifest
import android.annotation.SuppressLint
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothManager
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanFilter
import android.bluetooth.le.ScanResult
import android.bluetooth.le.ScanSettings
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.location.LocationManager
import android.os.ParcelUuid
import io.github.erwsim.vigie.collectors.R
import io.github.erwsim.vigie.collectors.network.NetFormat
import io.github.erwsim.vigie.core.collector.Collector
import io.github.erwsim.vigie.core.collector.CollectorContext
import io.github.erwsim.vigie.core.collector.Requirement
import io.github.erwsim.vigie.core.event.Rfc3339
import io.github.erwsim.vigie.core.event.Severity
import io.github.erwsim.vigie.core.event.eventData
import io.github.erwsim.vigie.core.settings.SettingKey
import io.github.erwsim.vigie.core.settings.SettingSpec
import kotlinx.serialization.json.JsonObject

/**
 * `net.ble_tracker` (sev 2): an item tracker (AirTag, SmartTag, Tile, Google Find My Device)
 * that keeps being seen while the phone moves. See [TrackerSignatures] and [TrackerDetector].
 *
 * Energy: one continuous `SCAN_MODE_LOW_POWER` scan (radio duty cycle ~10 %) with hardware
 * `ScanFilter`s on tracker signatures only (mandatory for scans to keep running screen off; the
 * application processor only wakes up for matching advertisements) and, when the controller
 * supports it, batched results every 60 s. Positions come from the passive location cache (no
 * GPS request). Only while Bluetooth is on.
 */
class BleTrackerCollector : Collector {
    override val id = "ble_tracker"
    override val titleRes = R.string.collector_ble_tracker_title
    override val descriptionRes = R.string.collector_ble_tracker_desc
    override val eventTypes = listOf(TYPE)
    override val requirements = listOf(
        Requirement.SystemFeature(PackageManager.FEATURE_BLUETOOTH_LE),
        Requirement.Permission(Manifest.permission.BLUETOOTH_SCAN),
        Requirement.Permission(Manifest.permission.ACCESS_FINE_LOCATION),
    )
    override val settings = listOf(
        SettingSpec.IntSpec(MIN_DURATION, R.string.setting_ble_tracker_duration, R.string.setting_ble_tracker_duration_summary, "min"),
        SettingSpec.IntSpec(MIN_DISTANCE, R.string.setting_ble_tracker_distance, R.string.setting_ble_tracker_distance_summary, "m"),
    )

    // Collectors' thread state, reset at each start.
    private var detector = TrackerDetector()
    private var scanning = false
    private var lastPositionLookup = Long.MIN_VALUE / 2
    private var lastPosition: TrackerDetector.Position? = null

    @SuppressLint("MissingPermission") // BLUETOOTH_SCAN and ACCESS_FINE_LOCATION are requirements.
    override suspend fun start(ctx: CollectorContext) {
        detector = TrackerDetector(
            minDurationMs = ctx.settings[MIN_DURATION] * 60_000L,
            minDistanceM = ctx.settings[MIN_DISTANCE].toDouble(),
        )
        scanning = false
        lastPosition = null
        lastPositionLookup = Long.MIN_VALUE / 2
        val adapter = ctx.appContext.getSystemService(BluetoothManager::class.java)?.adapter ?: return

        val callback = object : ScanCallback() {
            override fun onScanResult(callbackType: Int, result: ScanResult) {
                ctx.handler.post { ctx.guard("ble result") { onResult(ctx, result) } }
            }

            override fun onBatchScanResults(results: MutableList<ScanResult>) {
                val copy = results.toList()
                ctx.handler.post { ctx.guard("ble batch") { copy.forEach { onResult(ctx, it) } } }
            }

            override fun onScanFailed(errorCode: Int) {
                ctx.handler.post {
                    scanning = false
                    ctx.reportError(IllegalStateException("BLE scan failed: $errorCode"), "ble scan")
                }
            }
        }

        fun startScan() {
            if (scanning || !adapter.isEnabled) return
            val scanner = adapter.bluetoothLeScanner ?: return
            val settings = ScanSettings.Builder()
                .setScanMode(ScanSettings.SCAN_MODE_LOW_POWER)
                .setCallbackType(ScanSettings.CALLBACK_TYPE_ALL_MATCHES)
                .apply { if (adapter.isOffloadedScanBatchingSupported) setReportDelay(BATCH_DELAY_MS) }
                .build()
            scanner.startScan(filters(), settings, callback)
            scanning = true
        }

        fun stopScan() {
            if (!scanning) return
            scanning = false
            try {
                adapter.bluetoothLeScanner?.stopScan(callback)
            } catch (_: IllegalStateException) {
                // Adapter already off: the scan is gone.
            }
        }

        // Bluetooth broadcasts may come from the Bluetooth stack's own uid: exported (protected broadcast).
        ctx.registerReceiver(IntentFilter(BluetoothAdapter.ACTION_STATE_CHANGED), exported = true) { intent ->
            when (intent.getIntExtra(BluetoothAdapter.EXTRA_STATE, -1)) {
                BluetoothAdapter.STATE_ON -> startScan()
                BluetoothAdapter.STATE_TURNING_OFF, BluetoothAdapter.STATE_OFF -> stopScan()
            }
        }
        ctx.onStop { stopScan() }
        startScan()
    }

    // `scanning` is left as is: the cleanup registered in start (run after stop) stops the scan.
    override suspend fun stop(ctx: CollectorContext) = detector.clear()

    private fun onResult(ctx: CollectorContext, result: ScanResult) {
        val kind = TrackerSignatures.classify(result.scanRecord?.bytes) ?: return
        val address = NetFormat.mac(result.device?.address) ?: return
        val alert = detector.onSighting(
            address = address,
            kind = kind,
            rssi = result.rssi.takeIf { it in -127..20 },
            wallMs = ctx.clock.nowMillis(),
            elapsedMs = ctx.clock.elapsedRealtime(),
            position = position(ctx),
        ) ?: return
        ctx.sink.emit(TYPE, Severity.WARNING, alertData(alert))
    }

    /** Last known position from the passive cache, if recent (looked up at most every 30 s). */
    @SuppressLint("MissingPermission")
    private fun position(ctx: CollectorContext): TrackerDetector.Position? {
        val now = ctx.clock.elapsedRealtime()
        if (now - lastPositionLookup < 30_000) return lastPosition
        lastPositionLookup = now
        val lm = ctx.appContext.getSystemService(LocationManager::class.java) ?: return null
        val fix = try {
            listOf(LocationManager.PASSIVE_PROVIDER, LocationManager.GPS_PROVIDER)
                .mapNotNull { lm.getLastKnownLocation(it) }
                .maxByOrNull { it.elapsedRealtimeNanos }
        } catch (_: SecurityException) {
            null
        }
        lastPosition = fix?.takeIf { now - it.elapsedRealtimeNanos / 1_000_000 < MAX_FIX_AGE_MS }
            ?.let { TrackerDetector.Position(it.latitude, it.longitude) }
        return lastPosition
    }

    private fun filters(): List<ScanFilter> {
        fun uuid(short: Int) = ParcelUuid.fromString(TrackerSignatures.uuid16(short))
        return listOf(
            ScanFilter.Builder().setManufacturerData(
                TrackerSignatures.APPLE_COMPANY_ID,
                byteArrayOf(TrackerSignatures.APPLE_FIND_MY_TYPE.toByte(), TrackerSignatures.APPLE_FIND_MY_SEPARATED_LENGTH.toByte()),
                byteArrayOf(0xFF.toByte(), 0xFF.toByte()),
            ).build(),
            ScanFilter.Builder().setServiceData(uuid(TrackerSignatures.UUID_SAMSUNG_SMARTTAG), ByteArray(0)).build(),
            ScanFilter.Builder().setServiceUuid(uuid(TrackerSignatures.UUID_TILE)).build(),
            ScanFilter.Builder().setServiceData(uuid(TrackerSignatures.UUID_TILE), ByteArray(0)).build(),
            ScanFilter.Builder().setServiceUuid(uuid(TrackerSignatures.UUID_TILE_ALT)).build(),
            ScanFilter.Builder().setServiceData(
                uuid(TrackerSignatures.UUID_GOOGLE_FMDN),
                byteArrayOf(TrackerSignatures.FMDN_UNWANTED_TRACKING_FRAME.toByte()),
                byteArrayOf(0xFF.toByte()),
            ).build(),
        )
    }

    companion object {
        const val TYPE = "net.ble_tracker"

        fun alertData(alert: TrackerDetector.Alert): JsonObject = eventData {
            put("address", alert.address)
            put("kind", alert.kind)
            put("rssi", alert.rssi)
            put("first_seen", Rfc3339.format(alert.firstSeenWallMs))
            put("sightings", alert.sightings)
        }
        private const val BATCH_DELAY_MS = 60_000L
        private const val MAX_FIX_AGE_MS = 15 * 60_000L
        val MIN_DURATION = SettingKey.IntKey("ble_tracker.min_duration_min", 30, 10, 240)
        val MIN_DISTANCE = SettingKey.IntKey("ble_tracker.min_distance_m", 500, 100, 20_000)
    }
}
