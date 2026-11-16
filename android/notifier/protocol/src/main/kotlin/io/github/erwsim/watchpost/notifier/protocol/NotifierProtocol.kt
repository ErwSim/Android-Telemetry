package io.github.erwsim.watchpost.notifier.protocol

/**
 * Local channel between the companion APK (`io.github.erwsim.watchpost.notifier`, the only
 * `NotificationListenerService` of the project) and the agent (`io.github.erwsim.watchpost`).
 *
 * Mechanism: a `ContentProvider` exported by the agent and called with `ContentResolver.call`
 * (synchronous, starts the agent's process if needed, no background-service start involved).
 * It is protected by [PERMISSION] (protection level `signature`, declared by BOTH APKs so that the
 * install order does not matter) and the agent also checks that the caller is the companion and is
 * signed by its own key. In the other direction the agent only sends [ACTION_CONFIG_CHANGED] to the
 * companion's receiver, protected by the same permission: it carries nothing, the companion then
 * reads the settings again.
 *
 * Every call carries [KEY_PROTOCOL]; a different version is refused ([STATUS_PROTOCOL_MISMATCH]).
 */
object NotifierProtocol {
    const val VERSION = 1

    const val AGENT_PACKAGE = "io.github.erwsim.watchpost"
    const val NOTIFIER_PACKAGE = "io.github.erwsim.watchpost.notifier"
    const val LISTENER_CLASS = "io.github.erwsim.watchpost.notifier.NotifierListenerService"

    /** Signature-level permission declared by both APKs (same key, so no install conflict). */
    const val PERMISSION = "io.github.erwsim.watchpost.permission.NOTIFICATION_RELAY"

    /** Authority of the agent's provider (fixed: the companion must know it). */
    const val AUTHORITY = "io.github.erwsim.watchpost.notifications"

    /** Agent → companion, explicit (package-targeted) broadcast: "settings changed, read them again". */
    const val ACTION_CONFIG_CHANGED = "io.github.erwsim.watchpost.notifier.action.CONFIG_CHANGED"

    /** Packages whose notifications are never relayed (the agent's own, the companion's own). */
    val SELF_PACKAGES: Set<String> = setOf(AGENT_PACKAGE, NOTIFIER_PACKAGE)

    // ---- methods of ContentResolver.call
    /** Returns the settings the companion applies (see [NotifierConfig]). */
    const val METHOD_CONFIG = "config"

    /** Delivers one notification event ([NotificationPayload]); returns a status and the config version. */
    const val METHOD_POST = "post"

    /** Companion state: listener connected or not (the agent re-evaluates the collector's availability). */
    const val METHOD_STATUS = "status"

    /** Replaces the package lists stored by the agent (edited on the companion's screen). */
    const val METHOD_SET_LISTS = "set_lists"

    // ---- common keys
    const val KEY_PROTOCOL = "protocol"
    const val KEY_STATUS = "status"
    const val KEY_CONFIG_VERSION = "config_version"

    // ---- config keys
    const val KEY_ACCEPTING = "accepting"
    const val KEY_CONTENT = "content"
    const val KEY_REDACT = "redact"
    const val KEY_CONTENT_EXCLUDED = "content_excluded"
    const val KEY_IGNORED = "ignored"

    // ---- status call
    const val KEY_LISTENER_CONNECTED = "listener_connected"

    // ---- set_lists call
    const val KEY_RESET = "reset"
    const val KEY_REJECTED = "rejected"

    // ---- payload keys (wire names = contract field names)
    const val KEY_PACKAGE = "package"
    const val KEY_EVENT = "event"
    const val KEY_CATEGORY = "category"
    const val KEY_CHANNEL = "channel"
    const val KEY_ONGOING = "ongoing"
    const val KEY_IMPORTANCE = "importance"
    const val KEY_TITLE = "title"
    const val KEY_TEXT = "text"
    const val KEY_REDACTED = "redacted"

    // ---- statuses
    const val STATUS_OK = "ok"

    /** The agent is stopped or the `notifications` collector is disabled: nothing is recorded. */
    const val STATUS_NOT_ACCEPTING = "not_accepting"

    /** The agent's process is still starting (its `Application.onCreate` has not finished). */
    const val STATUS_STARTING = "starting"
    const val STATUS_INVALID = "invalid"
    const val STATUS_RATE_LIMITED = "rate_limited"
    const val STATUS_DENIED = "denied"
    const val STATUS_PROTOCOL_MISMATCH = "protocol_mismatch"

    const val EVENT_POSTED = "posted"
    const val EVENT_REMOVED = "removed"
}

/** Size bounds applied by the companion before sending AND checked again by the agent. */
object Limits {
    /** Contract §10: `title` and `text` are at most 512 characters (Unicode code points). */
    const val MAX_CONTENT_CODE_POINTS = 512

    /** Read from the notification before masking and truncation (bounds the work on huge texts). */
    const val MAX_RAW_CHARS = 4_096
    const val MAX_PACKAGE_CHARS = 255
    const val MAX_CATEGORY_CODE_POINTS = 64
    const val MAX_CHANNEL_CODE_POINTS = 128

    /** Entries of each package list. */
    const val MAX_LIST_ENTRIES = 500

    /** Keys of one call's extras (a hostile bundle with thousands of keys is refused). */
    const val MAX_KEYS = 32
}
