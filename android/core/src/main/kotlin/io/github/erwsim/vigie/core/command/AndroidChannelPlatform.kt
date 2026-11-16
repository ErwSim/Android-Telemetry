package io.github.erwsim.vigie.core.command

import android.app.AlarmManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.PowerManager
import io.github.erwsim.vigie.core.Agent

/**
 * Android side of [ChannelPlatform]:
 * - network state from `ConnectivityManager` (default network with `NET_CAPABILITY_INTERNET`);
 * - wake-ups by `AlarmManager.setAndAllowWhileIdle(ELAPSED_REALTIME_WAKEUP)`: inexact, no special
 *   permission, delivered in Doze but at most about once per 9 minutes per app there;
 * - partial wake locks with a timeout (never held permanently).
 */
class AndroidChannelPlatform(private val context: Context) : ChannelPlatform {
    override fun isNetworkAvailable(): Boolean {
        val cm = context.getSystemService(ConnectivityManager::class.java) ?: return true
        val caps = cm.getNetworkCapabilities(cm.activeNetwork) ?: return false
        return caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
    }

    override fun networkKey(): String? = try {
        context.getSystemService(ConnectivityManager::class.java)?.activeNetwork?.toString()
    } catch (_: Exception) {
        null
    }

    private fun pendingIntent(): PendingIntent = PendingIntent.getBroadcast(
        context,
        0,
        Intent(context, CommandAlarmReceiver::class.java).setAction(CommandAlarmReceiver.ACTION),
        PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
    )

    override fun scheduleWakeup(atElapsedMs: Long) {
        try {
            context.getSystemService(AlarmManager::class.java)
                ?.setAndAllowWhileIdle(AlarmManager.ELAPSED_REALTIME_WAKEUP, atElapsedMs, pendingIntent())
        } catch (_: Exception) {
            // Alarm limit reached: the maintenance worker (15 min) also ticks the channel.
        }
    }

    override fun cancelWakeup() {
        try {
            context.getSystemService(AlarmManager::class.java)?.cancel(pendingIntent())
        } catch (_: Exception) {
        }
    }

    override suspend fun <T> withWakeLock(timeoutMs: Long, block: suspend () -> T): T {
        val wl = context.getSystemService(PowerManager::class.java)
            ?.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "vigie:commands")
            ?.apply {
                setReferenceCounted(false)
                acquire(timeoutMs)
            }
        try {
            return block()
        } finally {
            try {
                if (wl?.isHeld == true) wl.release()
            } catch (_: Exception) {
            }
        }
    }
}

/** Wake-up of the command channel (non exported: only this app's own alarm can send it). */
class CommandAlarmReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != ACTION) return
        val channel = Agent.getOrNull()?.commands?.channel ?: return
        // The alarm keeps the CPU awake only during onReceive: a bounded wake lock covers the reconnection
        // or poll it triggers (released by its timeout, never held longer).
        try {
            context.getSystemService(PowerManager::class.java)
                ?.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "vigie:commands_tick")
                ?.apply { setReferenceCounted(false) }
                ?.acquire(TICK_WAKELOCK_MS)
        } catch (_: Exception) {
        }
        channel.tick()
    }

    companion object {
        const val ACTION = "io.github.erwsim.vigie.action.COMMAND_TICK"
        private const val TICK_WAKELOCK_MS = 30_000L
    }
}
