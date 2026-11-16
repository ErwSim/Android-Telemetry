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
import io.github.erwsim.vigie.policy.engine.CapabilityGuards
import io.github.erwsim.vigie.policy.engine.GuardKey
import io.github.erwsim.vigie.policy.engine.GuardNotice
import io.github.erwsim.vigie.ui.Apps
import io.github.erwsim.vigie.ui.CommandLabels
import io.github.erwsim.vigie.ui.Format
import io.github.erwsim.vigie.ui.MainActivity
import io.github.erwsim.vigie.ui.Screen

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

    /** What a capability guard did on its own (quarantine, role change): never silent (contract §11.1). */
    const val CHANNEL_GUARDS = "vigie_guards"

    /** One notification per package (ids from this base, by package hash), so that several stay visible. */
    private const val GUARD_NOTIFICATION_BASE = 1000

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
        val guards = NotificationChannel(
            CHANNEL_GUARDS,
            context.getString(R.string.guard_channel_name),
            NotificationManager.IMPORTANCE_DEFAULT,
        ).apply { description = context.getString(R.string.guard_channel_description) }
        context.getSystemService(NotificationManager::class.java)?.createNotificationChannels(listOf(channel, alert, commands, guards))
    }

    /** Notification for a [GuardNotice]: tapping it opens the quarantine screen (or the policy screen). */
    fun guardNotice(context: Context, notice: GuardNotice) {
        // The name is chosen by the app: the package name always goes with it.
        fun label(pkg: String) = Apps.label(context, pkg).let { if (it == pkg) pkg else "$it ($pkg)" }
        fun perms(list: List<String>) = list.joinToString { CapabilityGuards.short(it) }
        fun guardTitle(key: GuardKey) = context.getString(
            when (key) {
                GuardKey.SMS -> R.string.guard_sms_title
                GuardKey.CALLS -> R.string.guard_calls_title
                GuardKey.ACCESSIBILITY -> R.string.guard_accessibility_title
                GuardKey.INPUT_METHODS -> R.string.guard_input_methods_title
                GuardKey.QUARANTINE -> R.string.guard_quarantine_title
            },
        )
        val (pkg, title, text, screen) = when (notice) {
            is GuardNotice.Quarantined -> listOf(
                notice.pkg,
                context.getString(R.string.guard_notif_quarantined_title),
                if (notice.denied.isEmpty()) {
                    context.getString(R.string.guard_notif_quarantined_nothing, label(notice.pkg))
                } else {
                    context.getString(R.string.guard_notif_quarantined_text, label(notice.pkg), perms(notice.denied))
                },
                Screen.Quarantine.name,
            )
            is GuardNotice.RoleHolder -> listOf(
                notice.pkg,
                context.getString(R.string.guard_notif_role_title),
                if (notice.joined) {
                    context.getString(
                        R.string.guard_notif_role_text, label(notice.pkg), notice.role, guardTitle(notice.key),
                        if (notice.lifted.isEmpty()) "" else context.getString(R.string.guard_notif_role_lifted, perms(notice.lifted)),
                    )
                } else {
                    context.getString(R.string.guard_notif_role_spared, label(notice.pkg), notice.role, guardTitle(notice.key), perms(notice.lifted))
                },
                Screen.Policy.name,
            )
            is GuardNotice.Released -> listOf(
                notice.pkg,
                context.getString(R.string.guard_notif_released_title),
                context.getString(R.string.guard_notif_released_text, label(notice.pkg), notice.reason),
                Screen.Quarantine.name,
            )
        }
        val open = PendingIntent.getActivity(
            context,
            pkg.hashCode(),
            Intent(context, MainActivity::class.java).putExtra(MainActivity.EXTRA_OPEN, screen)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val notification = Notification.Builder(context, CHANNEL_GUARDS)
            .setSmallIcon(R.drawable.ic_stat_vigie)
            .setContentTitle(title)
            .setContentText(text)
            .setStyle(Notification.BigTextStyle().bigText(text))
            .setContentIntent(open)
            .setAutoCancel(true)
            .build()
        try {
            context.getSystemService(NotificationManager::class.java)?.notify(GUARD_NOTIFICATION_BASE + (pkg.hashCode() and 0xFFFF), notification)
        } catch (_: Exception) {
            // Notifications refused: the journal and security.policy still say it.
        }
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
