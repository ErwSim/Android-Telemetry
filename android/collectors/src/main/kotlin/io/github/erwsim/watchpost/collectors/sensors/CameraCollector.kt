package io.github.erwsim.watchpost.collectors.sensors

import android.content.pm.PackageManager
import android.hardware.camera2.CameraManager
import io.github.erwsim.watchpost.collectors.R
import io.github.erwsim.watchpost.collectors.common.RateLimiter
import io.github.erwsim.watchpost.collectors.common.ScreenState
import io.github.erwsim.watchpost.core.collector.Collector
import io.github.erwsim.watchpost.core.collector.CollectorContext
import io.github.erwsim.watchpost.core.collector.Requirement
import io.github.erwsim.watchpost.core.event.Severity
import io.github.erwsim.watchpost.core.event.eventData
import io.github.erwsim.watchpost.core.settings.SettingKey
import io.github.erwsim.watchpost.core.settings.SettingSpec
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.serialization.json.JsonObject

/**
 * `sensor.camera`: a camera is opened/closed by any app (`CameraManager.AvailabilityCallback`,
 * no permission), with `screen_on` and `locked`. The public API does not say which app: `package`
 * is only set by the experimental DUMP attribution ([AppOpsDump], off by default). Callback only,
 * no cost; at most 120 events per hour (face unlock opens the front camera at each attempt).
 */
class CameraCollector : Collector {
    override val id = "camera"
    override val titleRes = R.string.collector_camera_title
    override val descriptionRes = R.string.collector_camera_desc
    override val eventTypes = listOf(TYPE)
    override val requirements = listOf(Requirement.SystemFeature(PackageManager.FEATURE_CAMERA_ANY))
    override val settings = listOf(SettingSpec.BoolSpec(ATTRIBUTION, R.string.setting_sensor_attribution, R.string.setting_sensor_attribution_summary, experimental = true))

    private val tracker = CameraStateTracker()
    private val limiter = RateLimiter(120, 3_600_000L)

    override suspend fun start(ctx: CollectorContext) {
        tracker.reset()
        limiter.reset()
        if (ctx.settings[ATTRIBUTION]) AppOpsDump.reportIfUnavailable(ctx, "camera attribution")
        val cm = ctx.appContext.getSystemService(CameraManager::class.java) ?: return
        val callback = object : CameraManager.AvailabilityCallback() {
            override fun onCameraAvailable(cameraId: String) = ctx.guard("camera") { on(ctx, cameraId, inUse = false) }
            override fun onCameraUnavailable(cameraId: String) = ctx.guard("camera") { on(ctx, cameraId, inUse = true) }
            override fun onCameraRemoved(cameraId: String) = ctx.guard("camera") { tracker.onRemoved(cameraId) }
        }
        cm.registerAvailabilityCallback(ctx.executor, callback)
        ctx.onStop { cm.unregisterAvailabilityCallback(callback) }
    }

    override suspend fun stop(ctx: CollectorContext) = tracker.reset()

    private fun on(ctx: CollectorContext, cameraId: String, inUse: Boolean) {
        val report = tracker.onAvailability(cameraId, inUse) ?: return
        if (!limiter.tryAcquire(ctx.clock.elapsedRealtime())) return
        val screen = ScreenState.read(ctx)
        if (report && ctx.settings[ATTRIBUTION] && AppOpsDump.available(ctx)) {
            ctx.scope.launch {
                delay(ATTRIBUTION_DELAY_MS) // Let the app's startOp be recorded.
                emit(ctx, cameraId, report, screen, AppOpsDump.runningPackage(ctx, "CAMERA"))
            }
        } else {
            emit(ctx, cameraId, report, screen, null)
        }
    }

    private fun emit(ctx: CollectorContext, cameraId: String, inUse: Boolean, screen: ScreenState, pkg: String?) {
        val sev = if (inUse && screen.screenOn == false) Severity.NOTABLE else Severity.INFO
        ctx.sink.emit(TYPE, sev, data(cameraId, inUse, screen, pkg))
    }

    companion object {
        const val TYPE = "sensor.camera"
        const val ATTRIBUTION_DELAY_MS = 500L
        val ATTRIBUTION = SettingKey.BoolKey("camera.attribution_dump", false)

        fun data(cameraId: String, inUse: Boolean, screen: ScreenState, pkg: String?): JsonObject = eventData {
            put("camera_id", cameraId)
            put("in_use", inUse)
            put("package", pkg)
            screen.writeTo(this)
        }
    }
}
