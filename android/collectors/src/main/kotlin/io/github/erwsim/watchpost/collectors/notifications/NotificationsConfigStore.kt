package io.github.erwsim.watchpost.collectors.notifications

import androidx.core.content.edit
import io.github.erwsim.watchpost.core.event.EventTypes
import io.github.erwsim.watchpost.core.settings.AgentSettings
import io.github.erwsim.watchpost.core.settings.CoreSettings
import io.github.erwsim.watchpost.core.sink.emit
import io.github.erwsim.watchpost.notifier.protocol.NotifierConfig
import io.github.erwsim.watchpost.notifier.protocol.PackageLists

/**
 * The notification settings kept by the agent. The two switches are ordinary collector settings
 * (Collecteurs › Notifications); the two package lists have no generic editor in the agent's UI
 * (the settings framework has integer, boolean and choice settings only): they are stored in the
 * agent's settings file under [KEY_CONTENT_EXCLUDED] / [KEY_IGNORED] (absent = default list),
 * edited on the companion's screen through the channel, and every change emits
 * `agent.config_changed` like any other setting.
 */
class NotificationsConfigStore(private val settings: AgentSettings) {
    /** The agent runs and the collector is enabled. */
    fun accepting(): Boolean =
        settings[CoreSettings.AGENT_ENABLED] &&
            settings[settings.collectorEnabledKey(NotificationsCollector.ID, default = true)]

    fun contentExcluded(): List<String> = read(KEY_CONTENT_EXCLUDED, PackageLists.DEFAULT_CONTENT_EXCLUDED)

    fun ignored(): List<String> = read(KEY_IGNORED, PackageLists.DEFAULT_IGNORED)

    fun config(): NotifierConfig = NotifierConfig(
        accepting = accepting(),
        contentEnabled = settings[NotificationsCollector.CONTENT],
        redactCodes = settings[NotificationsCollector.REDACT_CODES],
        contentExcluded = contentExcluded().toSet(),
        ignored = ignored().toSet(),
    )

    /**
     * Replaces the lists given (null = unchanged), or restores both defaults when [reset]. Invalid
     * entries are refused and returned. Returns true if anything changed.
     */
    @Synchronized
    fun setLists(contentExcluded: List<String>?, ignored: List<String>?, reset: Boolean): Pair<Boolean, List<String>> {
        val rejected = ArrayList<String>()
        var changed = false
        fun apply(key: String, values: List<String>?, defaults: List<String>) {
            val old = read(key, defaults)
            val new = if (reset) {
                defaults
            } else {
                val parsed = PackageLists.parse(values ?: return)
                rejected += parsed.rejected
                parsed.packages
            }
            settings.raw.edit { if (reset) remove(key) else putString(key, PackageLists.joinForStorage(new)) }
            if (old != new) {
                changed = true
                settings.sink?.emit(EventTypes.AGENT_CONFIG_CHANGED) {
                    put("key", key)
                    put("old", summary(old))
                    put("new", summary(new))
                }
            }
        }
        apply(KEY_CONTENT_EXCLUDED, contentExcluded, PackageLists.DEFAULT_CONTENT_EXCLUDED)
        apply(KEY_IGNORED, ignored, PackageLists.DEFAULT_IGNORED)
        return changed to rejected
    }

    private fun read(key: String, defaults: List<String>): List<String> =
        settings.raw.getString(key, null)?.let(PackageLists::splitStored) ?: defaults

    companion object {
        const val KEY_CONTENT_EXCLUDED = "notifications.content_excluded_packages"
        const val KEY_IGNORED = "notifications.ignored_packages"
        private const val MAX_SUMMARY = 1_000

        /** Value of `agent.config_changed.old/new` for a list: package names separated by commas, bounded. */
        fun summary(list: List<String>): String {
            val s = list.joinToString(",")
            return if (s.length <= MAX_SUMMARY) s else s.take(MAX_SUMMARY - 1) + "…"
        }
    }
}
