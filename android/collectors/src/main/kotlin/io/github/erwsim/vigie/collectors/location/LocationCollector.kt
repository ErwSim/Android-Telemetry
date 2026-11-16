package io.github.erwsim.vigie.collectors.location

import android.Manifest
import android.annotation.SuppressLint
import android.hardware.Sensor
import android.hardware.SensorManager
import android.hardware.TriggerEvent
import android.hardware.TriggerEventListener
import android.location.Location
import android.location.LocationListener
import android.location.LocationManager
import android.location.LocationRequest
import io.github.erwsim.vigie.collectors.R
import io.github.erwsim.vigie.core.collector.Availability
import io.github.erwsim.vigie.core.collector.Collector
import io.github.erwsim.vigie.core.collector.CollectorContext
import io.github.erwsim.vigie.core.collector.Requirement
import io.github.erwsim.vigie.core.event.Rfc3339
import io.github.erwsim.vigie.core.event.Severity
import io.github.erwsim.vigie.core.event.eventData
import io.github.erwsim.vigie.core.settings.SettingKey
import io.github.erwsim.vigie.core.settings.SettingSpec
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.serialization.json.JsonObject

/**
 * `location.fix` / `location.provider` from `GPS_PROVIDER` and `PASSIVE_PROVIDER` only
 * (the "network" and "fused" providers are implemented by Google Play services on GMS devices).
 *
 * Energy: GPS is requested at [MOVING_INTERVAL] while moving and at [STATIONARY_INTERVAL] once
 * stationary (the platform duty-cycles the GNSS chip for long intervals); in stationary mode the
 * low-power significant-motion sensor brings back the fast cadence as soon as the device moves.
 * Passive fixes cost nothing: they are the ones other apps requested.
 */
class LocationCollector : Collector {
    override val id = "location"
    override val titleRes = R.string.collector_location_title
    override val descriptionRes = R.string.collector_location_desc
    override val eventTypes = listOf("location.fix", "location.provider")
    override val requirements = listOf(
        Requirement.Permission(Manifest.permission.ACCESS_FINE_LOCATION),
        // Covered by the location foreground service type; granted automatically when Device Owner.
        Requirement.Permission(Manifest.permission.ACCESS_BACKGROUND_LOCATION, optional = true),
    )
    override val settings = listOf(
        SettingSpec.IntSpec(MOVING_INTERVAL, R.string.setting_location_moving_interval, R.string.setting_location_moving_interval_summary, "s"),
        SettingSpec.IntSpec(STATIONARY_INTERVAL, R.string.setting_location_stationary_interval, R.string.setting_location_stationary_interval_summary, "s"),
        SettingSpec.BoolSpec(PASSIVE, R.string.setting_location_passive, R.string.setting_location_passive_summary),
        SettingSpec.IntSpec(PASSIVE_MIN_INTERVAL, R.string.setting_location_passive_interval, null, "s"),
    )

    // Collector-thread state, reset at each start.
    private var manager: LocationManager? = null
    private var tracker = MotionTracker()
    private var gpsListener: LocationListener? = null
    private var currentMode: MotionTracker.Mode? = null
    private var lastGpsFixTime = 0L
    private var lastEmitElapsed = Long.MIN_VALUE / 2
    private var trigger: TriggerEventListener? = null

    override fun checkAvailability(ctx: CollectorContext): Availability {
        val lm = ctx.appContext.getSystemService(LocationManager::class.java)
        return if (lm != null && lm.allProviders.contains(LocationManager.GPS_PROVIDER)) {
            Availability.Available
        } else {
            Availability.Unavailable(ctx.appContext.getString(R.string.collector_location_no_gps))
        }
    }

    @SuppressLint("MissingPermission") // ACCESS_FINE_LOCATION is a requirement checked by the host.
    override suspend fun start(ctx: CollectorContext) {
        val lm = ctx.appContext.getSystemService(LocationManager::class.java) ?: return
        manager = lm
        tracker = MotionTracker(startedAtElapsedMs = ctx.clock.elapsedRealtime())
        currentMode = null
        lastGpsFixTime = 0
        lastEmitElapsed = Long.MIN_VALUE / 2

        val gps = object : LocationListener {
            override fun onLocationChanged(location: Location) = onFix(ctx, location, passive = false)
            override fun onProviderEnabled(provider: String) = providerChanged(ctx, provider, true)
            override fun onProviderDisabled(provider: String) = providerChanged(ctx, provider, false)
        }
        gpsListener = gps
        requestGps(ctx, MotionTracker.Mode.MOVING)
        ctx.onStop { lm.removeUpdates(gps) }

        if (ctx.settings[PASSIVE]) {
            val passive = LocationListener { location -> onFix(ctx, location, passive = true) }
            val minMs = ctx.settings[PASSIVE_MIN_INTERVAL] * 1000L
            lm.requestLocationUpdates(
                LocationManager.PASSIVE_PROVIDER,
                LocationRequest.Builder(LocationRequest.PASSIVE_INTERVAL).setMinUpdateIntervalMillis(minMs).build(),
                ctx.executor,
                passive,
            )
            ctx.onStop { lm.removeUpdates(passive) }
        }
        ctx.onStop { disarmMotionTrigger(ctx) }

        // No fix at all (indoors): give up the fast cadence instead of letting the GNSS receiver search
        // minute after minute. One cheap check per minute on the collectors' thread (no wake-up alarm).
        ctx.scope.launch {
            while (isActive) {
                delay(NO_FIX_CHECK_MS)
                if (manager != null && currentMode == MotionTracker.Mode.MOVING) {
                    val mode = tracker.onNoFix(ctx.clock.elapsedRealtime())
                    if (mode != currentMode) requestGps(ctx, mode)
                }
            }
        }

        providerChanged(ctx, LocationManager.GPS_PROVIDER, lm.isProviderEnabled(LocationManager.GPS_PROVIDER), onlyIfChanged = true)
    }

    override suspend fun stop(ctx: CollectorContext) {
        manager = null
        gpsListener = null
        currentMode = null
    }

    private fun onFix(ctx: CollectorContext, location: Location, passive: Boolean) {
        val now = ctx.clock.elapsedRealtime()
        if (passive) {
            // Our own GPS fixes are also delivered to the passive listener.
            if (location.provider == LocationManager.GPS_PROVIDER && location.time == lastGpsFixTime) return
            if (now - lastEmitElapsed < ctx.settings[PASSIVE_MIN_INTERVAL] * 1000L) return
        } else {
            lastGpsFixTime = location.time
        }
        lastEmitElapsed = now
        val mock = location.isMock
        ctx.sink.emit(
            "location.fix",
            if (mock) Severity.NOTABLE else Severity.INFO,
            fixData(
                lat = location.latitude,
                lon = location.longitude,
                accuracyM = if (location.hasAccuracy()) location.accuracy else null,
                altitudeM = if (location.hasAltitude()) location.altitude else null,
                speedMps = if (location.hasSpeed()) location.speed else null,
                bearingDeg = if (location.hasBearing()) location.bearing else null,
                provider = location.provider ?: if (passive) LocationManager.PASSIVE_PROVIDER else LocationManager.GPS_PROVIDER,
                mock = mock,
                fixTimeMs = location.time,
            ),
        )
        val mode = tracker.onFix(
            location.latitude,
            location.longitude,
            if (location.hasAccuracy()) location.accuracy else null,
            if (location.hasSpeed()) location.speed else null,
            now,
        )
        if (mode != currentMode) requestGps(ctx, mode)
    }

    @SuppressLint("MissingPermission")
    private fun requestGps(ctx: CollectorContext, mode: MotionTracker.Mode) {
        val lm = manager ?: return
        val listener = gpsListener ?: return
        val seconds = if (mode == MotionTracker.Mode.MOVING) ctx.settings[MOVING_INTERVAL] else ctx.settings[STATIONARY_INTERVAL]
        val intervalMs = seconds * 1000L
        lm.removeUpdates(listener)
        lm.requestLocationUpdates(
            LocationManager.GPS_PROVIDER,
            LocationRequest.Builder(intervalMs)
                .setQuality(LocationRequest.QUALITY_HIGH_ACCURACY)
                .setMinUpdateIntervalMillis(intervalMs)
                .build(),
            ctx.executor,
            listener,
        )
        currentMode = mode
        if (mode == MotionTracker.Mode.STATIONARY) armMotionTrigger(ctx) else disarmMotionTrigger(ctx)
    }

    private fun armMotionTrigger(ctx: CollectorContext) {
        if (trigger != null) return
        val sm = ctx.appContext.getSystemService(SensorManager::class.java) ?: return
        val sensor = sm.getDefaultSensor(Sensor.TYPE_SIGNIFICANT_MOTION) ?: return
        val listener = object : TriggerEventListener() {
            override fun onTrigger(event: TriggerEvent?) {
                // Delivered on the main thread: hop to the collectors' thread.
                ctx.handler.post {
                    ctx.guard("significant_motion") {
                        trigger = null
                        if (manager != null) requestGps(ctx, tracker.onSignificantMotion(ctx.clock.elapsedRealtime()))
                    }
                }
            }
        }
        if (sm.requestTriggerSensor(listener, sensor)) trigger = listener
    }

    private fun disarmMotionTrigger(ctx: CollectorContext) {
        val listener = trigger ?: return
        trigger = null
        val sm = ctx.appContext.getSystemService(SensorManager::class.java) ?: return
        sm.getDefaultSensor(Sensor.TYPE_SIGNIFICANT_MOTION)?.let { sm.cancelTriggerSensor(listener, it) }
    }

    private fun providerChanged(ctx: CollectorContext, provider: String, enabled: Boolean, onlyIfChanged: Boolean = false) {
        if (provider != LocationManager.GPS_PROVIDER) return
        val key = "provider_$provider"
        val previous = if (ctx.prefs.contains(key)) ctx.prefs.getBoolean(key, true) else null
        ctx.prefs.edit().putBoolean(key, enabled).apply()
        if (onlyIfChanged && previous == enabled) return
        ctx.emit("location.provider", if (enabled) Severity.INFO else Severity.NOTABLE) {
            put("provider", provider)
            put("enabled", enabled)
        }
    }

    companion object {
        private const val NO_FIX_CHECK_MS = 60_000L

        /** `location.fix` data (contract §2). */
        fun fixData(
            lat: Double,
            lon: Double,
            accuracyM: Float?,
            altitudeM: Double?,
            speedMps: Float?,
            bearingDeg: Float?,
            provider: String,
            mock: Boolean,
            fixTimeMs: Long,
        ): JsonObject = eventData {
            put("lat", lat)
            put("lon", lon)
            put("acc_m", accuracyM)
            put("alt_m", altitudeM)
            put("speed_mps", speedMps)
            put("bearing_deg", bearingDeg)
            put("provider", provider)
            put("mock", mock)
            put("fix_ts", Rfc3339.format(fixTimeMs))
        }

        val MOVING_INTERVAL = SettingKey.IntKey("location.moving_interval_s", 60, 10, 3_600)
        val STATIONARY_INTERVAL = SettingKey.IntKey("location.stationary_interval_s", 900, 60, 7_200)
        val PASSIVE = SettingKey.BoolKey("location.passive", true)
        val PASSIVE_MIN_INTERVAL = SettingKey.IntKey("location.passive_min_interval_s", 30, 0, 3_600)
    }
}
