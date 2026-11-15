package io.github.erwsim.vigie.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import io.github.erwsim.vigie.R
import io.github.erwsim.vigie.core.Agent
import io.github.erwsim.vigie.ui.Format
import io.github.erwsim.vigie.ui.MainActivity

/** The permanent notification: always visible while the agent collects (no stealth). */
object AgentNotifications {
    const val CHANNEL_ID = "vigie_agent"
    const val NOTIFICATION_ID = 1

    fun createChannel(context: Context) {
        val channel = NotificationChannel(
            CHANNEL_ID,
            context.getString(R.string.notif_channel_name),
            NotificationManager.IMPORTANCE_LOW,
        ).apply {
            description = context.getString(R.string.notif_channel_description)
            setShowBadge(false)
        }
        context.getSystemService(NotificationManager::class.java)?.createNotificationChannel(channel)
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
        return "$pending · $upload"
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
