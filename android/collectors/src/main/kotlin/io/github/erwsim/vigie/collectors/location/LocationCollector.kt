package io.github.erwsim.vigie.collectors.location

import android.Manifest
import android.annotation.SuppressLint
import android.content.IntentFilter
import android.hardware.Sensor
import android.hardware.SensorManager
import android.hardware.TriggerEvent
import android.hardware.TriggerEventListener
import android.location.Location
import android.location.LocationListener
import android.location.LocationManager
import android.location.LocationRequest
import android.os.CancellationSignal
import io.github.erwsim.vigie.collectors.R
import io.github.erwsim.vigie.core.collector.Availability
import io.github.erwsim.vigie.core.collector.Collector
import io.github.erwsim.vigie.core.collector.CollectorContext
import io.github.erwsim.vigie.core.collector.Requirement
import io.github.erwsim.vigie.core.command.LocateOutcome
import io.github.erwsim.vigie.core.command.OnDemandLocator
import io.github.erwsim.vigie.core.event.Rfc3339
import io.github.erwsim.vigie.core.event.Severity
import io.github.erwsim.vigie.core.event.eventData
import io.github.erwsim.vigie.core.settings.SettingKey
import io.github.erwsim.vigie.core.settings.SettingSpec
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.serialization.json.JsonObject

/**
 * `location.fix` / `location.provider`. Providers according to the `location.mode` setting
 * (contract §10, see [LocationModes]): `gps` (default: GPS + passive, no Google service), `gps_network`
 * (adds the network provider) or `fused` (fused provider). The network and fused providers are
 * implemented by Google Play services on a GMS phone: the app says what is then sent to Google.
 * `location.fix.provider` is the provider that really produced each fix.
 *
 * Energy: the active providers are requested at [MOVING_INTERVAL] while moving and at
 * [STATIONARY_INTERVAL] once stationary (the platform duty-cycles the GNSS chip for long intervals); in
 * stationary mode the low-power significant-motion sensor brings back the fast cadence as soon as the
 * device moves. Passive fixes cost nothing: they are the ones other apps requested.
 *
 * Also the [OnDemandLocator] of the `locate` remote command: one precise fix through the same providers
 * and the same emission path (same `provider` and `mock` handling).
 */
class LocationCollector : Collector, OnDemandLocator {
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
        SettingSpec.ChoiceSpec(
            MODE,
            R.string.setting_location_mode,
            R.string.setting_location_mode_summary,
            options = listOf(
                SettingSpec.ChoiceSpec.Option(LocationModes.GPS, R.string.location_mode_gps, R.string.location_mode_gps_desc),
                SettingSpec.ChoiceSpec.Option(LocationModes.GPS_NETWORK, R.string.location_mode_gps_network, R.string.location_mode_gps_network_desc),
                SettingSpec.ChoiceSpec.Option(LocationModes.FUSED, R.string.location_mode_fused, R.string.location_mode_fused_desc),
            ),
        ),
        SettingSpec.IntSpec(MOVING_INTERVAL, R.string.setting_location_moving_interval, R.string.setting_location_moving_interval_summary, "s"),
        SettingSpec.IntSpec(STATIONARY_INTERVAL, R.string.setting_location_stationary_interval, R.string.setting_location_stationary_interval_summary, "s"),
        SettingSpec.BoolSpec(PASSIVE, R.string.setting_location_passive, R.string.setting_location_passive_summary),
        SettingSpec.IntSpec(PASSIVE_MIN_INTERVAL, R.string.setting_location_passive_interval, null, "s"),
    )

    // Collector-thread state, reset at each start.
    @Volatile private var context: CollectorContext? = null
    private var manager: LocationManager? = null
    private var tracker = MotionTracker()
    private val listeners = LinkedHashMap<String, LocationListener>()
    private var plan = LocationModes.Plan(emptyList(), false)
    private var currentMode: MotionTracker.Mode? = null
    private val lastFixTime = HashMap<String, Long>()
    private var lastGpsEmitElapsed: Long? = null
    private var lastEmitElapsed = Long.MIN_VALUE / 2
    private var trigger: TriggerEventListener? = null

    override fun checkAvailability(ctx: CollectorContext): Availability {
        val lm = ctx.appContext.getSystemService(LocationManager::class.java)
        val mode = ctx.settings[MODE]
        val any = lm != null && (LocationModes.wanted(mode) + LocationModes.P_GPS).any { lm.allProviders.contains(it) }
        return if (any) Availability.Available else Availability.Unavailable(ctx.appContext.getString(R.string.collector_location_no_gps))
    }

    @SuppressLint("MissingPermission") // ACCESS_FINE_LOCATION is a requirement checked by the host.
    override suspend fun start(ctx: CollectorContext) {
        val lm = ctx.appContext.getSystemService(LocationManager::class.java) ?: return
        manager = lm
        context = ctx
        tracker = MotionTracker(startedAtElapsedMs = ctx.clock.elapsedRealtime())
        listeners.clear()
        plan = LocationModes.Plan(emptyList(), false)
        currentMode = null
        lastFixTime.clear()
        lastGpsEmitElapsed = null
        lastEmitElapsed = Long.MIN_VALUE / 2

        requestUpdates(ctx, MotionTracker.Mode.MOVING)
        ctx.onStop { removeAll(lm) }

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

        // A provider switched on or off (Location settings, "Google location accuracy"): report it and re-plan.
        ctx.registerReceiver(IntentFilter(LocationManager.PROVIDERS_CHANGED_ACTION)) { intent ->
            val name = intent.getStringExtra(LocationManager.EXTRA_PROVIDER_NAME)
            if (name != null) providerChanged(ctx, name, lm.isProviderEnabled(name), onlyIfChanged = true)
            replanIfNeeded(ctx)
        }

        // No fix at all (indoors): give up the fast cadence instead of letting the GNSS receiver search
        // minute after minute. One cheap check per minute on the collectors' thread (no wake-up alarm).
        ctx.scope.launch {
            while (isActive) {
                delay(NO_FIX_CHECK_MS)
                if (manager != null && currentMode == MotionTracker.Mode.MOVING) {
                    val mode = tracker.onNoFix(ctx.clock.elapsedRealtime())
                    if (mode != currentMode) requestUpdates(ctx, mode)
                }
                if (plan.fallback) replanIfNeeded(ctx)
            }
        }

        for (p in (LocationModes.wanted(ctx.settings[MODE]) + LocationModes.P_GPS).distinct()) {
            if (lm.allProviders.contains(p)) providerChanged(ctx, p, lm.isProviderEnabled(p), onlyIfChanged = true)
        }
    }

    override suspend fun stop(ctx: CollectorContext) {
        manager = null
        context = null
        listeners.clear()
        currentMode = null
    }

    private fun removeAll(lm: LocationManager) {
        listeners.values.forEach { lm.removeUpdates(it) }
        listeners.clear()
    }

    private fun currentPlan(ctx: CollectorContext, lm: LocationManager): LocationModes.Plan = LocationModes.plan(
        ctx.settings[MODE],
        exists = { lm.allProviders.contains(it) },
        enabled = { lm.isProviderEnabled(it) },
    )

    private fun replanIfNeeded(ctx: CollectorContext) {
        val lm = manager ?: return
        if (currentPlan(ctx, lm) != plan) requestUpdates(ctx, currentMode ?: MotionTracker.Mode.MOVING)
    }

    private fun intervalMs(ctx: CollectorContext, mode: MotionTracker.Mode?): Long =
        (if (mode == MotionTracker.Mode.STATIONARY) ctx.settings[STATIONARY_INTERVAL] else ctx.settings[MOVING_INTERVAL]) * 1000L

    @SuppressLint("MissingPermission")
    private fun requestUpdates(ctx: CollectorContext, mode: MotionTracker.Mode) {
        val lm = manager ?: return
        removeAll(lm)
        plan = currentPlan(ctx, lm)
        val intervalMs = intervalMs(ctx, mode)
        for (provider in plan.providers) {
            val listener = object : LocationListener {
                override fun onLocationChanged(location: Location) = onFix(ctx, location, passive = false)
                override fun onProviderEnabled(provider: String) = providerChanged(ctx, provider, true)
                override fun onProviderDisabled(provider: String) {
                    providerChanged(ctx, provider, false)
                    replanIfNeeded(ctx)
                }
            }
            lm.requestLocationUpdates(
                provider,
                LocationRequest.Builder(intervalMs)
                    .setQuality(LocationModes.quality(provider))
                    .setMinUpdateIntervalMillis(intervalMs)
                    .build(),
                ctx.executor,
                listener,
            )
            listeners[provider] = listener
        }
        currentMode = mode
        if (mode == MotionTracker.Mode.STATIONARY) armMotionTrigger(ctx) else disarmMotionTrigger(ctx)
    }

    private fun onFix(ctx: CollectorContext, location: Location, passive: Boolean, onDemand: Boolean = false) {
        val now = ctx.clock.elapsedRealtime()
        val provider = location.provider
        if (passive) {
            // Our own fixes are also delivered to the passive listener.
            if (provider != null && lastFixTime[provider] == location.time) return
            if (now - lastEmitElapsed < ctx.settings[PASSIVE_MIN_INTERVAL] * 1000L) return
        } else {
            if (!onDemand && !LocationModes.keepFix(provider, now, lastGpsEmitElapsed, intervalMs(ctx, currentMode))) return
            provider?.let { lastFixTime[it] = location.time }
            if (provider == LocationManager.GPS_PROVIDER) lastGpsEmitElapsed = now
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
                provider = provider ?: if (passive) LocationManager.PASSIVE_PROVIDER else plan.providers.firstOrNull() ?: LocationManager.GPS_PROVIDER,
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
        if (mode != currentMode && manager != null) requestUpdates(ctx, mode)
    }

    /**
     * `locate` command: a current fix from every provider of the mode's plan (`getCurrentLocation`,
     * high accuracy, at most [timeoutMs]); each fix is emitted as it comes (network first, then GPS in
     * `gps_network`). Runs on the collectors' thread; cancelled if the collector stops.
     */
    @SuppressLint("MissingPermission")
    override suspend fun locateNow(timeoutMs: Long): LocateOutcome {
        val ctx = context ?: return LocateOutcome.Unavailable("location_unavailable")
        val job = ctx.scope.async {
            val lm = manager ?: return@async LocateOutcome.Unavailable("location_unavailable")
            val providers = currentPlan(ctx, lm).providers
            if (providers.isEmpty()) return@async LocateOutcome.Unavailable("provider_disabled")
            val answered = HashSet<String>()
            var best: Location? = null
            val done = CompletableDeferred<Unit>()
            val signal = CancellationSignal()
            for (provider in providers) {
                lm.getCurrentLocation(
                    provider,
                    LocationRequest.Builder(0)
                        .setQuality(LocationRequest.QUALITY_HIGH_ACCURACY)
                        .setDurationMillis(timeoutMs)
                        .build(),
                    signal,
                    ctx.executor,
                ) { location ->
                    ctx.guard("locate") {
                        answered += provider
                        if (location != null && manager != null) {
                            onFix(ctx, location, passive = false, onDemand = true)
                            val b = best
                            if (b == null || (location.hasAccuracy() && (!b.hasAccuracy() || location.accuracy < b.accuracy))) best = location
                        }
                        if (LocationModes.locateDone(providers, answered)) done.complete(Unit)
                    }
                }
            }
            withTimeoutOrNull(timeoutMs) { done.await() }
            signal.cancel()
            best?.let { LocateOutcome.Fixed(it.provider ?: providers.first(), if (it.hasAccuracy()) it.accuracy else null) }
                ?: LocateOutcome.NoFix
        }
        return try {
            job.await()
        } catch (e: kotlinx.coroutines.CancellationException) {
            // The collector stopped meanwhile (switched off, permission withdrawn).
            if (context == null) LocateOutcome.Unavailable("location_unavailable") else throw e
        }
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
                        if (manager != null) requestUpdates(ctx, tracker.onSignificantMotion(ctx.clock.elapsedRealtime()))
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

    /** `location.provider` for the providers the current mode can use (and GPS), on change only. */
    private fun providerChanged(ctx: CollectorContext, provider: String, enabled: Boolean, onlyIfChanged: Boolean = false) {
        if (provider !in (LocationModes.wanted(ctx.settings[MODE]) + LocationModes.P_GPS)) return
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

        /** Contract §10: `gps` (default), `gps_network`, `fused`. */
        val MODE = SettingKey.ChoiceKey("location.mode", LocationModes.GPS, LocationModes.ALL)
        val MOVING_INTERVAL = SettingKey.IntKey("location.moving_interval_s", 60, 10, 3_600)
        val STATIONARY_INTERVAL = SettingKey.IntKey("location.stationary_interval_s", 900, 60, 7_200)
        val PASSIVE = SettingKey.BoolKey("location.passive", true)
        val PASSIVE_MIN_INTERVAL = SettingKey.IntKey("location.passive_min_interval_s", 30, 0, 3_600)
    }
}
