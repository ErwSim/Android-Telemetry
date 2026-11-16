package io.github.erwsim.vigie.service

import android.app.Notification
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.media.AudioAttributes
import android.media.AudioManager
import android.media.MediaPlayer
import android.media.RingtoneManager
import android.media.ToneGenerator
import android.net.Uri
import android.os.Handler
import android.os.Looper
import android.os.PowerManager
import android.os.VibrationAttributes
import android.os.VibrationEffect
import android.os.Vibrator
import android.os.VibratorManager
import android.util.Log
import io.github.erwsim.vigie.R
import io.github.erwsim.vigie.core.command.AcceptedCommand
import io.github.erwsim.vigie.core.command.CommandExecutor
import io.github.erwsim.vigie.core.command.CommandParams
import io.github.erwsim.vigie.core.command.ExecutionResult
import io.github.erwsim.vigie.ui.MainActivity

/**
 * `ring`, `vibrate` and `stop_ring` (contract §8), without Device Owner.
 *
 * Sound: audio usage `USAGE_ALARM` on the alarm stream, raised to its maximum for the duration and put
 * back afterwards. The alarm stream is not muted by the ringer's silent or vibrate mode. "Ne pas
 * déranger" is another matter: Android lets alarms through by default, but if the owner's DND mode
 * mutes alarms ("Silence total", or alarms switched off in the mode), the sound stays muted. An app
 * targeting Android 15+ can no longer turn the user's DND off (its `setInterruptionFilter` only drives
 * its own rule), and being Device Owner gives no DND right: this limit is reported in `detail`
 * (`dnd_alarms_muted`) and documented.
 *
 * Stop: the "Arrêter" action of a high-importance notification (also its tap and its dismissal),
 * `stop_ring`, or the end of `duration_s`. A wake lock is held only while ringing (≤ 300 s + margin).
 */
class RingController(private val context: Context) {
    private val main = Handler(Looper.getMainLooper())
    private val lock = Any()
    private var player: MediaPlayer? = null
    private var tone: ToneGenerator? = null
    private var savedAlarmVolume: Int? = null
    private var vibrating = false
    private var wakeLock: PowerManager.WakeLock? = null
    private val stopTask = Runnable { stop() }

    val isRinging: Boolean get() = synchronized(lock) { player != null || tone != null || vibrating }

    /** Starts ringing (replacing a ring in progress). Returns the `detail` of the result. */
    fun ring(durationS: Int, vibrate: Boolean): String = synchronized(lock) {
        stopLocked()
        acquireWakeLock(durationS * 1000L + 10_000)
        val am = context.getSystemService(AudioManager::class.java)
        if (am != null) {
            try {
                savedAlarmVolume = am.getStreamVolume(AudioManager.STREAM_ALARM)
                am.setStreamVolume(AudioManager.STREAM_ALARM, am.getStreamMaxVolume(AudioManager.STREAM_ALARM), 0)
            } catch (e: Exception) {
                // SecurityException when the change would affect DND: the current alarm volume stays.
                Log.w(TAG, "alarm volume unchanged", e)
                savedAlarmVolume = null
            }
        }
        val sound = startSound()
        if (vibrate) startVibration(longArrayOf(0, 1_000, 500))
        AgentNotifications.showRinging(context)
        main.removeCallbacks(stopTask)
        main.postDelayed(stopTask, durationS * 1000L)
        when {
            !sound -> "no_sound" + if (vibrate) "_vibrating" else ""
            dndMutesAlarms() -> "dnd_alarms_muted"
            else -> "ok"
        }
    }

    /** Vibration only (`vibrate`). */
    fun vibrate(durationS: Int): String = synchronized(lock) {
        stopLocked()
        acquireWakeLock(durationS * 1000L + 10_000)
        val ok = startVibration(longArrayOf(0, 800, 400))
        AgentNotifications.showRinging(context)
        main.removeCallbacks(stopTask)
        main.postDelayed(stopTask, durationS * 1000L)
        if (ok) "ok" else "no_vibrator"
    }

    /** Stops sound and vibration, puts the alarm volume back. Returns true if something was ringing. */
    fun stop(): Boolean = synchronized(lock) { stopLocked() }

    private fun stopLocked(): Boolean {
        val was = player != null || tone != null || vibrating
        main.removeCallbacks(stopTask)
        player?.let {
            try {
                it.stop()
            } catch (_: Exception) {
            }
            it.release()
        }
        player = null
        tone?.release()
        tone = null
        if (vibrating) vibrator()?.cancel()
        vibrating = false
        savedAlarmVolume?.let { v ->
            try {
                context.getSystemService(AudioManager::class.java)?.setStreamVolume(AudioManager.STREAM_ALARM, v, 0)
            } catch (e: Exception) {
                Log.w(TAG, "alarm volume not restored", e)
            }
        }
        savedAlarmVolume = null
        AgentNotifications.cancelRinging(context)
        wakeLock?.let { if (it.isHeld) it.release() }
        wakeLock = null
        return was
    }

    private fun startSound(): Boolean {
        val attributes = AudioAttributes.Builder()
            .setUsage(AudioAttributes.USAGE_ALARM)
            .setContentType(AudioAttributes.CONTENT_TYPE_SONIFICATION)
            .build()
        val uri: Uri? = RingtoneManager.getActualDefaultRingtoneUri(context, RingtoneManager.TYPE_ALARM)
            ?: RingtoneManager.getActualDefaultRingtoneUri(context, RingtoneManager.TYPE_RINGTONE)
            ?: RingtoneManager.getDefaultUri(RingtoneManager.TYPE_ALARM)
        if (uri != null) {
            try {
                player = MediaPlayer().apply {
                    setAudioAttributes(attributes)
                    setDataSource(context, uri)
                    isLooping = true
                    prepare()
                    start()
                }
                return true
            } catch (e: Exception) {
                Log.w(TAG, "alarm sound unavailable, falling back to a tone", e)
                player?.release()
                player = null
            }
        }
        return try {
            tone = ToneGenerator(AudioManager.STREAM_ALARM, ToneGenerator.MAX_VOLUME).also {
                it.startTone(ToneGenerator.TONE_CDMA_ALERT_CALL_GUARD, -1)
            }
            true
        } catch (e: Exception) {
            Log.w(TAG, "no tone either", e)
            false
        }
    }

    private fun vibrator(): Vibrator? = context.getSystemService(VibratorManager::class.java)?.defaultVibrator

    private fun startVibration(pattern: LongArray): Boolean {
        val v = vibrator()?.takeIf { it.hasVibrator() } ?: return false
        return try {
            v.vibrate(VibrationEffect.createWaveform(pattern, 1), VibrationAttributes.createForUsage(VibrationAttributes.USAGE_ALARM))
            vibrating = true
            true
        } catch (e: Exception) {
            Log.w(TAG, "vibration refused", e)
            false
        }
    }

    /** Best effort: DND currently mutes alarms (total silence, or a priority mode without alarms). */
    private fun dndMutesAlarms(): Boolean = try {
        val nm = context.getSystemService(NotificationManager::class.java)
        when (nm?.currentInterruptionFilter) {
            NotificationManager.INTERRUPTION_FILTER_NONE -> true
            NotificationManager.INTERRUPTION_FILTER_PRIORITY ->
                nm.notificationPolicy.priorityCategories and NotificationManager.Policy.PRIORITY_CATEGORY_ALARMS == 0
            else -> false
        }
    } catch (_: Exception) {
        false
    }

    private fun acquireWakeLock(timeoutMs: Long) {
        wakeLock = context.getSystemService(PowerManager::class.java)
            ?.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "vigie:ring")
            ?.apply {
                setReferenceCounted(false)
                acquire(timeoutMs)
            }
    }

    companion object {
        private const val TAG = "VigieRing"
    }
}

/** "Arrêter la sonnerie" from the notification (action, tap or dismissal). Not exported. */
class RingStopReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action == ACTION) RemoteAlerts.controller(context).stop()
    }

    companion object {
        const val ACTION = "io.github.erwsim.vigie.action.STOP_RING"

        fun pendingIntent(context: Context): PendingIntent = PendingIntent.getBroadcast(
            context,
            1,
            Intent(context, RingStopReceiver::class.java).setAction(ACTION),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
    }
}

/** Executors registered by the app for the commands that need no Device Owner. */
object RemoteAlerts {
    @Volatile
    private var instance: RingController? = null

    fun controller(context: Context): RingController = instance ?: synchronized(this) {
        instance ?: RingController(context.applicationContext).also { instance = it }
    }

    fun ring(context: Context) = CommandExecutor { command: AcceptedCommand ->
        val p = command.params as? CommandParams.Ring ?: return@CommandExecutor ExecutionResult.failed("bad_params")
        ExecutionResult.executed(onMain { controller(context).ring(p.durationS, p.vibrate) })
    }

    fun vibrate(context: Context) = CommandExecutor { command: AcceptedCommand ->
        val p = command.params as? CommandParams.Vibrate ?: return@CommandExecutor ExecutionResult.failed("bad_params")
        ExecutionResult.executed(onMain { controller(context).vibrate(p.durationS) })
    }

    fun stopRing(context: Context) = CommandExecutor {
        ExecutionResult.executed(if (onMain { controller(context).stop() }) "stopped" else "not_ringing")
    }

    /** MediaPlayer and the stop timer live on the main thread. */
    private suspend fun <T> onMain(block: () -> T): T =
        kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.Main) { block() }
}

/** Notification builders of the remote commands (channels created in [AgentNotifications.createChannel]). */
internal object RemoteNotifications {
    fun ringing(context: Context): Notification {
        val stop = RingStopReceiver.pendingIntent(context)
        return Notification.Builder(context, AgentNotifications.CHANNEL_ALERT)
            .setSmallIcon(R.drawable.ic_stat_vigie)
            .setContentTitle(context.getString(R.string.cmd_notif_ringing_title))
            .setContentText(context.getString(R.string.cmd_notif_ringing_text))
            .setCategory(Notification.CATEGORY_ALARM)
            .setVisibility(Notification.VISIBILITY_PUBLIC)
            .setOngoing(true)
            .setContentIntent(stop)
            .setDeleteIntent(stop)
            .addAction(Notification.Action.Builder(null, context.getString(R.string.cmd_notif_stop), stop).build())
            .build()
    }

    fun processed(context: Context, text: String): Notification {
        val open = PendingIntent.getActivity(
            context,
            2,
            Intent(context, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        return Notification.Builder(context, AgentNotifications.CHANNEL_COMMANDS)
            .setSmallIcon(R.drawable.ic_stat_vigie)
            .setContentTitle(context.getString(R.string.cmd_notif_processed_title))
            .setContentText(text)
            .setStyle(Notification.BigTextStyle().bigText(text))
            .setCategory(Notification.CATEGORY_STATUS)
            .setContentIntent(open)
            .setAutoCancel(true)
            .build()
    }
}
