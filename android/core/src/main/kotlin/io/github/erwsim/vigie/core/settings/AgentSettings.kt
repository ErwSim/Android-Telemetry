package io.github.erwsim.vigie.core.settings

import android.content.SharedPreferences
import androidx.annotation.StringRes
import io.github.erwsim.vigie.core.event.EventTypes
import io.github.erwsim.vigie.core.sink.EventSink
import io.github.erwsim.vigie.core.sink.emit
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.asSharedFlow

/** A typed setting. Names are dotted lowercase, prefixed by the owner (`buffer.`, `location.`…). */
sealed class SettingKey<T : Any>(val name: String, val default: T) {
    class IntKey(name: String, default: Int, val min: Int, val max: Int) : SettingKey<Int>(name, default)
    class BoolKey(name: String, default: Boolean) : SettingKey<Boolean>(name, default)
}

/**
 * How a setting is shown in the generic settings UI. Collectors list theirs in
 * [io.github.erwsim.vigie.core.collector.Collector.settings]; the app renders them without
 * knowing the collector.
 */
sealed class SettingSpec(open val key: SettingKey<*>, @StringRes open val titleRes: Int, @StringRes open val summaryRes: Int?) {
    data class IntSpec(
        override val key: SettingKey.IntKey,
        @StringRes override val titleRes: Int,
        @StringRes override val summaryRes: Int? = null,
        /** Unit suffix shown after the value, e.g. "s", "min", "Mo". */
        val unit: String = "",
    ) : SettingSpec(key, titleRes, summaryRes)

    data class BoolSpec(
        override val key: SettingKey.BoolKey,
        @StringRes override val titleRes: Int,
        @StringRes override val summaryRes: Int? = null,
    ) : SettingSpec(key, titleRes, summaryRes)
}

/**
 * Local settings (SharedPreferences). Every change made through [set] emits
 * `agent.config_changed` (`key`, `old`, `new`) and is broadcast on [changes].
 * Nothing here can be changed by the server (one-way flow).
 */
class AgentSettings(private val prefs: SharedPreferences) {
    @Volatile
    var sink: EventSink? = null

    private val _changes = MutableSharedFlow<String>(extraBufferCapacity = 64)

    /** Names of keys changed through [set]. */
    val changes: SharedFlow<String> = _changes.asSharedFlow()

    operator fun get(key: SettingKey.IntKey): Int =
        prefs.getInt(key.name, key.default).coerceIn(key.min, key.max)

    operator fun get(key: SettingKey.BoolKey): Boolean = prefs.getBoolean(key.name, key.default)

    fun set(key: SettingKey.IntKey, value: Int) {
        val clamped = value.coerceIn(key.min, key.max)
        val old = get(key)
        if (old == clamped && prefs.contains(key.name)) return
        prefs.edit().putInt(key.name, clamped).apply()
        changed(key.name, old.toString(), clamped.toString(), old != clamped)
    }

    fun set(key: SettingKey.BoolKey, value: Boolean) {
        val old = get(key)
        if (old == value && prefs.contains(key.name)) return
        prefs.edit().putBoolean(key.name, value).apply()
        changed(key.name, old.toString(), value.toString(), old != value)
    }

    fun collectorEnabledKey(collectorId: String, default: Boolean) =
        SettingKey.BoolKey("collector.$collectorId.enabled", default)

    private fun changed(name: String, old: String, new: String, reallyChanged: Boolean) {
        if (!reallyChanged) return
        sink?.emit(EventTypes.AGENT_CONFIG_CHANGED) {
            put("key", name)
            put("old", old)
            put("new", new)
        }
        _changes.tryEmit(name)
    }

    /** Raw access for internal state that is not a user setting (no event emitted). */
    val raw: SharedPreferences get() = prefs
}

/** Core settings shown in the "Réglages" screen. */
object CoreSettings {
    val AGENT_ENABLED = SettingKey.BoolKey("agent.enabled", true)
    val BUFFER_MAX_MB = SettingKey.IntKey("buffer.max_mb", 200, 10, 2_000)
    val BUFFER_MAX_AGE_DAYS = SettingKey.IntKey("buffer.max_age_days", 30, 1, 365)
    val UPLOAD_INTERVAL_MIN = SettingKey.IntKey("upload.interval_min", 15, 15, 360)
    val WIFI_ONLY_LARGE = SettingKey.BoolKey("upload.wifi_only_large", true)
    val LARGE_THRESHOLD_MB = SettingKey.IntKey("upload.large_threshold_mb", 5, 1, 200)
}
