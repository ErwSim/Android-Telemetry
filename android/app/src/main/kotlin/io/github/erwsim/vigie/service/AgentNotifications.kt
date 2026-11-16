package io.github.erwsim.vigie.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import io.github.erwsim.vigie.R
import io.github.erwsim.vigie.core.Agent
import io.github.erwsim.vigie.core.command.ChannelPhase
import io.github.erwsim.vigie.core.command.CommandHistoryEntry
import io.github.erwsim.vigie.core.command.CommandSettings
import io.github.erwsim.vigie.ui.CommandLabels
import io.github.erwsim.vigie.ui.Format
import io.github.erwsim.vigie.ui.MainActivity

/** The permanent notification: always visible while the agent collects (no stealth). */
object AgentNotifications {
    const val CHANNEL_ID = "vigie_agent"
    const val NOTIFICATION_ID = 1

    /** Remote `ring`/`vibrate` in progress (high importance: heads-up, lock screen, "Arrêter"). */
    const val CHANNEL_ALERT = "vigie_commands_alert"

    /** One notification per processed remote command: a command never goes unnoticed on the phone. */
    const val CHANNEL_COMMANDS = "vigie_commands"
    private const val RING_NOTIFICATION_ID = 2
    private const val COMMAND_NOTIFICATION_ID = 3

    fun createChannel(context: Context) {
        val channel = NotificationChannel(
            CHANNEL_ID,
            context.getString(R.string.notif_channel_name),
            NotificationManager.IMPORTANCE_LOW,
        ).apply {
            description = context.getString(R.string.notif_channel_description)
            setShowBadge(false)
        }
        val alert = NotificationChannel(
            CHANNEL_ALERT,
            context.getString(R.string.cmd_channel_alert_name),
            NotificationManager.IMPORTANCE_HIGH,
        ).apply {
            description = context.getString(R.string.cmd_channel_alert_description)
            // The sound comes from the ringing itself (alarm stream); the notification stays silent.
            setSound(null, null)
            lockscreenVisibility = Notification.VISIBILITY_PUBLIC
        }
        val commands = NotificationChannel(
            CHANNEL_COMMANDS,
            context.getString(R.string.cmd_channel_name),
            NotificationManager.IMPORTANCE_DEFAULT,
        ).apply { description = context.getString(R.string.cmd_channel_description) }
        context.getSystemService(NotificationManager::class.java)?.createNotificationChannels(listOf(channel, alert, commands))
    }

    fun showRinging(context: Context) {
        try {
            context.getSystemService(NotificationManager::class.java)?.notify(RING_NOTIFICATION_ID, RemoteNotifications.ringing(context))
        } catch (_: Exception) {
            // Notifications refused: the ring still stops by stop_ring or at its end.
        }
    }

    fun cancelRinging(context: Context) {
        context.getSystemService(NotificationManager::class.java)?.cancel(RING_NOTIFICATION_ID)
    }

    /** "Commande à distance : Localiser — exécutée (10:42)". */
    fun commandProcessed(context: Context, entry: CommandHistoryEntry) {
        val text = context.getString(
            R.string.cmd_notif_processed_text,
            context.getString(CommandLabels.type(entry.type)),
            context.getString(CommandLabels.status(entry.status)),
            Format.clock(entry.atMs),
        ) + (CommandLabels.detail(context, entry.status, entry.detail)?.let { " — $it" } ?: "")
        try {
            context.getSystemService(NotificationManager::class.java)?.notify(COMMAND_NOTIFICATION_ID, RemoteNotifications.processed(context, text))
        } catch (_: Exception) {
        }
    }

    fun text(context: Context, agent: Agent): String {
        val totals = agent.outbox.totals.value
        val pending = context.resources.getQuantityString(R.plurals.notif_pending, totals.count.toInt().coerceAtMost(Int.MAX_VALUE), totals.count)
        val upload = if (agent.enrollment.state.value == null) {
            context.getString(R.string.notif_not_enrolled)
        } else {
            val last = agent.uploadStatus.status.value.lastSuccessMs
            if (last > 0) context.getString(R.string.notif_last_upload, Format.clock(last)) else context.getString(R.string.notif_never_uploaded)
        }
        // Honest about the remote channel: when it is on, the permanent notification says so.
        val commands = if (agent.settings[CommandSettings.ENABLED]) {
            val phase = agent.commands.channel.channelState.value.phase
            " · " + context.getString(
                R.string.notif_commands,
                context.getString(if (phase == ChannelPhase.CONNECTED || phase == ChannelPhase.POLL_IDLE) R.string.notif_commands_listening else CommandLabels.phase(phase)),
            )
        } else {
            ""
        }
        return "$pending · $upload$commands"
    }

    fun build(context: Context, text: String): Notification {
        val open = PendingIntent.getActivity(
            context,
            0,
            Intent(context, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        return Notification.Builder(context, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_stat_vigie)
            .setContentTitle(context.getString(R.string.notif_title))
            .setContentText(text)
            .setStyle(Notification.BigTextStyle().bigText(text))
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setShowWhen(false)
            .setCategory(Notification.CATEGORY_SERVICE)
            .setForegroundServiceBehavior(Notification.FOREGROUND_SERVICE_IMMEDIATE)
            .setContentIntent(open)
            .build()
    }
}
