package io.github.erwsim.watchpost.collectors.sensors

import android.content.pm.PackageManager
import android.media.AudioManager
import android.media.AudioRecordingConfiguration
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
 * `sensor.microphone`: recording starts/stops in any app (`AudioManager.AudioRecordingCallback`,
 * no permission), with the audio source, whether the system silences the client, `screen_on`
 * and `locked`. The public API hides the recording app: `package` is only set by the
 * experimental DUMP attribution ([AppOpsDump], off by default). Callback only; an event only when
 * the state changes, at most 120 per hour.
 */
class MicrophoneCollector : Collector {
    override val id = "microphone"
    override val titleRes = R.string.collector_microphone_title
    override val descriptionRes = R.string.collector_microphone_desc
    override val eventTypes = listOf(TYPE)
    override val requirements = listOf(Requirement.SystemFeature(PackageManager.FEATURE_MICROPHONE))
    override val settings = listOf(SettingSpec.BoolSpec(ATTRIBUTION, R.string.setting_sensor_attribution, R.string.setting_sensor_attribution_summary, experimental = true))

    private var last = MicState.IDLE
    private val limiter = RateLimiter(120, 3_600_000L)

    override suspend fun start(ctx: CollectorContext) {
        last = MicState.IDLE
        limiter.reset()
        if (ctx.settings[ATTRIBUTION]) AppOpsDump.reportIfUnavailable(ctx, "microphone attribution")
        val am = ctx.appContext.getSystemService(AudioManager::class.java) ?: return
        val callback = object : AudioManager.AudioRecordingCallback() {
            override fun onRecordingConfigChanged(configs: MutableList<AudioRecordingConfiguration>?) =
                ctx.guard("microphone") { on(ctx, configs.orEmpty()) }
        }
        am.registerAudioRecordingCallback(callback, ctx.handler)
        ctx.onStop { am.unregisterAudioRecordingCallback(callback) }
        on(ctx, am.activeRecordingConfigurations.orEmpty())
    }

    override suspend fun stop(ctx: CollectorContext) {
        last = MicState.IDLE
    }

    private fun on(ctx: CollectorContext, configs: List<AudioRecordingConfiguration>) {
        val state = MicState.from(configs.map { Recording(it.clientAudioSource, it.isClientSilenced) })
        if (state == last) return
        if (!limiter.tryAcquire(ctx.clock.elapsedRealtime())) return
        val startedRecording = state.recording && !last.recording
        last = state
        val screen = ScreenState.read(ctx)
        if (startedRecording && ctx.settings[ATTRIBUTION] && AppOpsDump.available(ctx)) {
            ctx.scope.launch {
                delay(CameraCollector.ATTRIBUTION_DELAY_MS)
                emit(ctx, state, screen, AppOpsDump.runningPackage(ctx, "RECORD_AUDIO"))
            }
        } else {
            emit(ctx, state, screen, null)
        }
    }

    private fun emit(ctx: CollectorContext, state: MicState, screen: ScreenState, pkg: String?) {
        val sev = if (state.recording && state.silenced != true && screen.screenOn == false) Severity.NOTABLE else Severity.INFO
        ctx.sink.emit(TYPE, sev, data(state, screen, pkg))
    }

    companion object {
        const val TYPE = "sensor.microphone"
        val ATTRIBUTION = SettingKey.BoolKey("microphone.attribution_dump", false)

        fun data(state: MicState, screen: ScreenState, pkg: String?): JsonObject = eventData {
            put("recording", state.recording)
            put("source", state.source)
            put("package", pkg)
            put("silenced", state.silenced)
            screen.writeTo(this)
        }
    }
}
