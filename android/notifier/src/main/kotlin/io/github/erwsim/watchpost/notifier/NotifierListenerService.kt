package io.github.erwsim.watchpost.notifier

import android.app.Notification
import android.content.ComponentName
import android.service.notification.NotificationListenerService
import android.service.notification.StatusBarNotification
import io.github.erwsim.watchpost.notifier.protocol.Importance
import io.github.erwsim.watchpost.notifier.protocol.Limits
import io.github.erwsim.watchpost.notifier.protocol.TextBounds

/**
 * The project's only `NotificationListenerService`. Bound by the system once the user has granted
 * notification access (Settings, or `adb shell cmd notification allow_listener`). Callbacks run on
 * the main thread: they only read the notification and hand it to [Relay]. Nothing is logged and
 * nothing is written to disk.
 */
class NotifierListenerService : NotificationListenerService() {
    override fun onCreate() {
        super.onCreate()
        Relay.init(this)
    }

    override fun onListenerConnected() {
        Relay.init(this)
        val active = try {
            activeNotifications.orEmpty().mapNotNull { read(it, currentRanking) }
        } catch (_: Exception) {
            emptyList() // SecurityException if the listener is no longer allowed
        }
        Relay.onConnected(active)
    }

    override fun onListenerDisconnected() {
        Relay.onDisconnected()
        // Ask the system to bind again (ignored if the user withdrew the access).
        try {
            requestRebind(ComponentName(this, NotifierListenerService::class.java))
        } catch (_: Exception) {
            // Not allowed any more: nothing to do.
        }
    }

    override fun onNotificationPosted(sbn: StatusBarNotification?, rankingMap: RankingMap?) {
        read(sbn ?: return, rankingMap)?.let(Relay::onPosted)
    }

    override fun onNotificationRemoved(sbn: StatusBarNotification?, rankingMap: RankingMap?, reason: Int) {
        read(sbn ?: return, rankingMap, withContent = false)?.let(Relay::onRemoved)
    }

    private fun read(sbn: StatusBarNotification, rankingMap: RankingMap?, withContent: Boolean = true): RawNotification? = try {
        val n = sbn.notification
        val extras = n.extras
        val importance = rankingMap?.let { map ->
            val r = Ranking()
            if (map.getRanking(sbn.key, r)) Importance.name(r.importance) else null
        }
        RawNotification(
            key = sbn.key,
            packageName = sbn.packageName,
            category = TextBounds.clean(n.category, Limits.MAX_CATEGORY_CODE_POINTS),
            channel = TextBounds.clean(n.channelId, Limits.MAX_CHANNEL_CODE_POINTS),
            ongoing = sbn.isOngoing,
            foregroundService = (n.flags and Notification.FLAG_FOREGROUND_SERVICE) != 0,
            groupSummary = (n.flags and Notification.FLAG_GROUP_SUMMARY) != 0,
            importance = importance,
            // Read in any case (in memory only): a changed text marks a new message of the same
            // notification. They leave this process only if the agent's settings allow content.
            title = if (withContent) {
                TextBounds.precut(
                    extras?.getCharSequence(Notification.EXTRA_TITLE)
                        ?: extras?.getCharSequence(Notification.EXTRA_TITLE_BIG)
                        ?: extras?.getCharSequence(Notification.EXTRA_CONVERSATION_TITLE),
                )
            } else {
                null
            },
            text = if (withContent) {
                TextBounds.precut(extras?.getCharSequence(Notification.EXTRA_TEXT) ?: extras?.getCharSequence(Notification.EXTRA_BIG_TEXT))
            } else {
                null
            },
        )
    } catch (_: Exception) {
        null // malformed extras (BadParcelableException…): skipped
    }
}
