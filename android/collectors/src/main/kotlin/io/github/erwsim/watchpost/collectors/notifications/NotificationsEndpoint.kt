package io.github.erwsim.watchpost.collectors.notifications

import io.github.erwsim.watchpost.collectors.common.RateLimiter
import io.github.erwsim.watchpost.core.settings.AgentSettings
import io.github.erwsim.watchpost.notifier.protocol.ContentPolicy
import io.github.erwsim.watchpost.notifier.protocol.NotificationPayload
import io.github.erwsim.watchpost.notifier.protocol.NotifierProtocol as P
import io.github.erwsim.watchpost.notifier.protocol.ValueReader

/**
 * Agent side of the channel, independent of Android (the provider only converts bundles), so that
 * it is tested on the JVM. Called on binder threads: thread-safe.
 *
 * Order of the checks for every call: caller (permission + same signing key + companion package,
 * done by the provider) → protocol version → agent initialised → global rate limit → method.
 * A `post` is decoded with strict bounds ([NotificationPayload.decode]), refused unless the agent
 * accepts (agent running, collector enabled), then the content rule is applied AGAIN here with the
 * current settings: if content was switched off (or the app excluded) after the companion read the
 * settings, title and text are dropped before anything is recorded.
 */
class NotificationsEndpoint(
    /** null while the agent is not initialised yet (provider called during the process start). */
    private val settings: () -> AgentSettings?,
    /** Records one event; false if nothing could take it. */
    private val emit: (NotificationPayload) -> Boolean,
    private val elapsedMs: () -> Long,
    private val onCompanionStatus: (Boolean) -> Unit = {},
    private val onListsChanged: () -> Unit = {},
    maxCallsPerMinute: Int = MAX_CALLS_PER_MINUTE,
) {
    private val limiter = RateLimiter(maxCallsPerMinute, 60_000L)

    fun handle(method: String, extras: ValueReader, callerIsCompanion: Boolean): Map<String, Any?> {
        if (!callerIsCompanion) return status(P.STATUS_DENIED)
        if (extras.int(P.KEY_PROTOCOL) != P.VERSION) return status(P.STATUS_PROTOCOL_MISMATCH)
        val s = settings() ?: return status(P.STATUS_STARTING)
        if (!synchronized(limiter) { limiter.tryAcquire(elapsedMs()) }) return status(P.STATUS_RATE_LIMITED)
        val store = NotificationsConfigStore(s)
        return when (method) {
            P.METHOD_CONFIG -> store.config().toValues()
            P.METHOD_POST -> post(store, extras)
            P.METHOD_STATUS -> {
                val connected = extras.bool(P.KEY_LISTENER_CONNECTED) ?: return status(P.STATUS_INVALID)
                onCompanionStatus(connected)
                status(P.STATUS_OK) + (P.KEY_CONFIG_VERSION to store.config().version)
            }
            P.METHOD_SET_LISTS -> setLists(store, extras)
            else -> status(P.STATUS_INVALID)
        }
    }

    private fun post(store: NotificationsConfigStore, extras: ValueReader): Map<String, Any?> {
        val config = store.config()
        val withVersion = { st: String -> status(st) + (P.KEY_CONFIG_VERSION to config.version) }
        val payload = when (val d = NotificationPayload.decode(extras)) {
            is NotificationPayload.Decoded.Invalid -> return withVersion(P.STATUS_INVALID)
            is NotificationPayload.Decoded.Valid -> d.payload
        }
        if (!config.accepting) return withVersion(P.STATUS_NOT_ACCEPTING)
        if (payload.packageName in config.ignored) return withVersion(P.STATUS_OK) // nothing recorded
        val content = ContentPolicy.apply(payload.packageName, payload.title, payload.text, config, alreadyRedacted = payload.redacted == true)
        val final = payload.copy(title = content.title, text = content.text, redacted = content.redacted)
        return withVersion(if (emit(final)) P.STATUS_OK else P.STATUS_NOT_ACCEPTING)
    }

    private fun setLists(store: NotificationsConfigStore, extras: ValueReader): Map<String, Any?> {
        val reset = extras.bool(P.KEY_RESET) == true
        val (changed, rejected) = store.setLists(extras.strings(P.KEY_CONTENT_EXCLUDED), extras.strings(P.KEY_IGNORED), reset)
        if (changed) onListsChanged()
        return store.config().toValues() + (P.KEY_REJECTED to rejected)
    }

    companion object {
        /** Every method together; the companion sends far less (at most 20 reports per app per 10 min). */
        const val MAX_CALLS_PER_MINUTE = 300

        fun status(s: String): Map<String, Any?> = mapOf(P.KEY_PROTOCOL to P.VERSION, P.KEY_STATUS to s)
    }
}

/**
 * Agent-side caller check, on top of the provider's `android:permission`: the calling uid must be
 * the companion's package, the attributed calling package must be that package, the caller must
 * hold the permission, and its signing key must be the agent's own.
 */
object CallerCheck {
    fun isCompanion(callingPackage: String?, packagesForUid: Array<String>?, holdsPermission: Boolean, sameSigningKey: Boolean): Boolean =
        holdsPermission && sameSigningKey &&
            callingPackage == P.NOTIFIER_PACKAGE &&
            packagesForUid?.contains(P.NOTIFIER_PACKAGE) == true
}
