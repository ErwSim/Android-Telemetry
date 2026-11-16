package io.github.erwsim.watchpost.collectors.notifications

import android.content.Context
import android.content.pm.PackageManager
import androidx.core.app.NotificationManagerCompat
import io.github.erwsim.watchpost.collectors.R
import io.github.erwsim.watchpost.collectors.common.str
import io.github.erwsim.watchpost.core.collector.Availability
import io.github.erwsim.watchpost.core.collector.Collector
import io.github.erwsim.watchpost.core.collector.CollectorContext
import io.github.erwsim.watchpost.core.settings.SettingKey
import io.github.erwsim.watchpost.core.settings.SettingSpec
import io.github.erwsim.watchpost.notifier.protocol.NotifierProtocol

/**
 * `app.notification` (contract §10), relayed by the separate, optional companion APK
 * `io.github.erwsim.watchpost.notifier` — this APK contains no `NotificationListenerService`
 * (principle 4, Play Protect). The companion filters BEFORE the local channel: with content off
 * (default) the title and text never leave its process; codes of 4 to 8 digits are masked (on by
 * default); apps excluded from content and ignored apps are package lists stored here (edited on
 * the companion's screen, see [NotificationsConfigStore]).
 *
 * Events arrive through [NotificationsProvider] (binder thread) and are emitted with this
 * collector's context while it runs ([NotificationsBridge]). Unavailable, with the reason, while the
 * companion is not installed, is signed by another key, or has no notification access.
 *
 * Start and stop (including a change of one of its settings, which restarts it) tell the companion
 * to read the settings again ([NotifierProtocol.ACTION_CONFIG_CHANGED]).
 */
class NotificationsCollector : Collector {
    override val id = ID
    override val titleRes = R.string.collector_notifications_title
    override val descriptionRes = R.string.collector_notifications_desc
    override val eventTypes = listOf(NotificationEvents.TYPE)
    override val settings = listOf(
        SettingSpec.BoolSpec(CONTENT, R.string.setting_notifications_content, R.string.setting_notifications_content_summary),
        SettingSpec.BoolSpec(REDACT_CODES, R.string.setting_notifications_redact, R.string.setting_notifications_redact_summary),
    )

    override fun checkAvailability(ctx: CollectorContext): Availability {
        val problem = CompanionCheck.evaluate(
            installed = CompanionCheck.isInstalled(ctx.appContext),
            sameKey = CompanionCheck.isSameKey(ctx.appContext),
            listenerEnabled = CompanionCheck.isListenerEnabled(ctx.appContext),
            reportedConnected = NotificationsBridge.companionConnected,
        ) ?: return Availability.Available
        return Availability.Unavailable(
            ctx.str(
                when (problem) {
                    CompanionCheck.Problem.NOT_INSTALLED -> R.string.collector_notifications_reason_not_installed
                    CompanionCheck.Problem.OTHER_KEY -> R.string.collector_notifications_reason_other_key
                    CompanionCheck.Problem.NO_ACCESS -> R.string.collector_notifications_reason_no_access
                },
            ),
        )
    }

    override suspend fun start(ctx: CollectorContext) {
        NotificationsBridge.attach(ctx)
        ctx.onStop { NotificationsBridge.detach(ctx) }
        NotificationsBridge.notifyCompanion(ctx.appContext)
    }

    override suspend fun stop(ctx: CollectorContext) {
        NotificationsBridge.detach(ctx)
        NotificationsBridge.notifyCompanion(ctx.appContext)
    }

    companion object {
        const val ID = "notifications"

        /** "Contenu des notifications": title and text (off by default, contract §10). */
        val CONTENT = SettingKey.BoolKey("notifications.content", false)

        /** Masking of 4-to-8-digit codes (on by default). */
        val REDACT_CODES = SettingKey.BoolKey("notifications.redact_codes", true)
    }
}

/** Is the companion there, signed by our key, and allowed to read notifications? */
object CompanionCheck {
    enum class Problem { NOT_INSTALLED, OTHER_KEY, NO_ACCESS }

    /**
     * [listenerEnabled] null = the secure setting could not be read; [reportedConnected] = what the
     * companion itself said through the channel since this process started (null: nothing yet).
     */
    fun evaluate(installed: Boolean, sameKey: Boolean, listenerEnabled: Boolean?, reportedConnected: Boolean?): Problem? = when {
        !installed -> Problem.NOT_INSTALLED
        !sameKey -> Problem.OTHER_KEY
        listenerEnabled == false && reportedConnected != true -> Problem.NO_ACCESS
        else -> null
    }

    fun isInstalled(context: Context): Boolean = try {
        context.packageManager.getPackageInfo(NotifierProtocol.NOTIFIER_PACKAGE, PackageManager.PackageInfoFlags.of(0))
        true
    } catch (_: Exception) {
        false // NameNotFoundException, or no PackageManager (JVM tests)
    }

    fun isSameKey(context: Context): Boolean = try {
        context.packageManager.checkSignatures(context.packageName, NotifierProtocol.NOTIFIER_PACKAGE) == PackageManager.SIGNATURE_MATCH
    } catch (_: Exception) {
        false
    }

    /** Secure setting `enabled_notification_listeners` (read as AndroidX does); null if unreadable. */
    fun isListenerEnabled(context: Context): Boolean? = try {
        NotifierProtocol.NOTIFIER_PACKAGE in NotificationManagerCompat.getEnabledListenerPackages(context)
    } catch (_: Exception) {
        null
    }
}
