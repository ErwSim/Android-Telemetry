package io.github.erwsim.watchpost.collectors.sensors

import android.media.MediaRecorder

/**
 * Pure camera state: AvailabilityCallback reports every camera as available right after
 * registration; only real transitions (and a camera already in use at start) are reported.
 */
class CameraStateTracker {
    private val inUse = HashMap<String, Boolean>()

    /** Returns the new "in use" value to report, or null if nothing to report. */
    fun onAvailability(cameraId: String, nowInUse: Boolean): Boolean? {
        val previous = inUse.put(cameraId, nowInUse)
        return when {
            previous == null -> if (nowInUse) true else null
            previous != nowInUse -> nowInUse
            else -> null
        }
    }

    fun onRemoved(cameraId: String) {
        inUse.remove(cameraId)
    }

    fun reset() = inUse.clear()
}

/** One active recording as seen by other apps (AudioRecordingConfiguration, anonymised). */
data class Recording(val clientSource: Int, val silenced: Boolean)

/** What `sensor.microphone` reports; compared to emit only on change. */
data class MicState(val recording: Boolean, val source: String?, val silenced: Boolean?) {
    companion object {
        val IDLE = MicState(false, null, null)

        /**
         * Reduces the active recordings: `source` of the first non-silenced one (else the first),
         * `silenced` true only if every active recording is silenced by the system.
         */
        fun from(recordings: List<Recording>): MicState {
            if (recordings.isEmpty()) return IDLE
            val main = recordings.firstOrNull { !it.silenced } ?: recordings.first()
            return MicState(true, sourceName(main.clientSource), recordings.all { it.silenced })
        }

        fun sourceName(source: Int): String = when (source) {
            MediaRecorder.AudioSource.DEFAULT -> "default"
            MediaRecorder.AudioSource.MIC -> "mic"
            MediaRecorder.AudioSource.VOICE_UPLINK -> "voice_uplink"
            MediaRecorder.AudioSource.VOICE_DOWNLINK -> "voice_downlink"
            MediaRecorder.AudioSource.VOICE_CALL -> "voice_call"
            MediaRecorder.AudioSource.CAMCORDER -> "camcorder"
            MediaRecorder.AudioSource.VOICE_RECOGNITION -> "voice_recognition"
            MediaRecorder.AudioSource.VOICE_COMMUNICATION -> "voice_communication"
            MediaRecorder.AudioSource.REMOTE_SUBMIX -> "remote_submix"
            MediaRecorder.AudioSource.UNPROCESSED -> "unprocessed"
            MediaRecorder.AudioSource.VOICE_PERFORMANCE -> "voice_performance"
            HOTWORD -> "hotword"
            else -> "source_$source"
        }

        /** MediaRecorder.AudioSource.HOTWORD (system API constant). */
        private const val HOTWORD = 1999
    }
}
