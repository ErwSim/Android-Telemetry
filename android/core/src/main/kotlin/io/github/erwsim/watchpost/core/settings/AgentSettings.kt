package io.github.erwsim.watchpost.core.settings

import android.content.SharedPreferences
import androidx.annotation.StringRes
import io.github.erwsim.watchpost.core.event.EventTypes
import io.github.erwsim.watchpost.core.sink.EventSink
import io.github.erwsim.watchpost.core.sink.emit
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.asSharedFlow

/** A typed setting. Names are dotted lowercase, prefixed by the component that owns them (`buffer.`, `location.`…). */
sealed class SettingKey<T : Any>(val name: String, val default: T) {
    class IntKey(name: String, default: Int, val min: Int, val max: Int) : SettingKey<Int>(name, default)
    class BoolKey(name: String, default: Boolean) : SettingKey<Boolean>(name, default)

    /** One value of a closed list of strings (stored as is; an unknown stored value reads as [default]). */
    class ChoiceKey(name: String, default: String, val values: List<String>) : SettingKey<String>(name, default) {
        init {
            require(default in values) { "default $default not in $values" }
        }
    }

    /**
     * A set of Android package names (exception lists of the guards, exclusion lists…). Stored as one
     * sorted, newline-separated string; a stored entry that is not a valid package name is dropped on
     * read and never written; at most [maxSize] entries (the extra ones are refused, not truncated).
     */
    class PackageListKey(name: String, default: Set<String> = emptySet(), val maxSize: Int = 500) : SettingKey<Set<String>>(name, default) {
        init {
            require(default.all(PackageNames::isValid)) { "invalid package in default $default" }
        }
    }
}

/** Android package names (`applicationId` rules: at least two segments, each starting with a letter). */
object PackageNames {
    private val PATTERN = Regex("^[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z][A-Za-z0-9_]*)+$")
    const val MAX_LENGTH = 255

    fun isValid(name: String): Boolean = name.length <= MAX_LENGTH && PATTERN.matches(name)

    /** Stored form: sorted, one per line (stable, so that `agent.config_changed` only reports real changes). */
    fun encode(packages: Set<String>): String = packages.sorted().joinToString("\n")

    /** Lenient: blank and invalid lines are dropped. */
    fun decode(text: String?): Set<String> =
        text?.split('\n', ',')?.map { it.trim() }?.filter { isValid(it) }?.toSortedSet() ?: emptySet()
}

/**
 * How a setting is shown in the generic settings UI. Collectors list theirs in
 * [io.github.erwsim.watchpost.core.collector.Collector.settings]; the app renders them without
 * knowing the collector.
 */
sealed class SettingSpec(
    open val key: SettingKey<*>,
    @StringRes open val titleRes: Int,
    @StringRes open val summaryRes: Int?,
    /** Shown with an "Experimental" mark (unstable platform behaviour, best effort). */
    open val experimental: Boolean,
) {
    data class IntSpec(
        override val key: SettingKey.IntKey,
        @StringRes override val titleRes: Int,
        @StringRes override val summaryRes: Int? = null,
        /** Unit suffix shown after the value, e.g. "s", "min", "Mo". */
        val unit: String = "",
        override val experimental: Boolean = false,
    ) : SettingSpec(key, titleRes, summaryRes, experimental)

    data class BoolSpec(
        override val key: SettingKey.BoolKey,
        @StringRes override val titleRes: Int,
        @StringRes override val summaryRes: Int? = null,
        override val experimental: Boolean = false,
    ) : SettingSpec(key, titleRes, summaryRes, experimental)

    /**
     * A set of installed applications, edited with a picker (name and icon). [candidates] narrows the
     * picker (e.g. the packages that provide an accessibility service); null lists every installed app.
     * Packages of the set that are no longer installed stay listed (marked absent) until removed.
     */
    data class PackageListSpec(
        override val key: SettingKey.PackageListKey,
        @StringRes override val titleRes: Int,
        @StringRes override val summaryRes: Int? = null,
        val candidates: ((android.content.Context) -> Collection<String>)? = null,
        /** Packages that cannot be removed from the set here (always exempt anyway): shown as locked. */
        val locked: ((android.content.Context) -> Collection<String>)? = null,
        override val experimental: Boolean = false,
    ) : SettingSpec(key, titleRes, summaryRes, experimental)

    /** A closed list of choices, each with its label and an explanation shown under it. */
    data class ChoiceSpec(
        override val key: SettingKey.ChoiceKey,
        @StringRes override val titleRes: Int,
        @StringRes override val summaryRes: Int? = null,
        val options: List<Option>,
        override val experimental: Boolean = false,
    ) : SettingSpec(key, titleRes, summaryRes, experimental) {
        data class Option(val value: String, @StringRes val labelRes: Int, @StringRes val descriptionRes: Int? = null)
    }
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

    operator fun get(key: SettingKey.ChoiceKey): String =
        prefs.getString(key.name, null)?.takeIf { it in key.values } ?: key.default

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

    /** A value outside [SettingKey.ChoiceKey.values] is ignored (never stored). */
    fun set(key: SettingKey.ChoiceKey, value: String) {
        if (value !in key.values) return
        val old = get(key)
        if (old == value && prefs.contains(key.name)) return
        prefs.edit().putString(key.name, value).apply()
        changed(key.name, old, value, old != value)
    }

    operator fun get(key: SettingKey.PackageListKey): Set<String> =
        if (prefs.contains(key.name)) PackageNames.decode(prefs.getString(key.name, null)).take(key.maxSize).toSortedSet() else key.default

    /** Whether the user ever saved this list (a never-saved list reads as its default). */
    fun isSet(key: SettingKey<*>): Boolean = prefs.contains(key.name)

    /**
     * Replaces the list. Returns false (nothing written) if an entry is not a valid package name or
     * the set is larger than [SettingKey.PackageListKey.maxSize].
     */
    fun set(key: SettingKey.PackageListKey, value: Set<String>): Boolean {
        if (value.size > key.maxSize || !value.all(PackageNames::isValid)) return false
        val old = get(key)
        val new = value.toSortedSet()
        if (old == new && prefs.contains(key.name)) return true
        prefs.edit().putString(key.name, PackageNames.encode(new)).apply()
        changed(key.name, old.sorted().joinToString(","), new.joinToString(","), old != new)
        return true
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

/** Core settings shown in the "Settings" screen. */
object CoreSettings {
    val AGENT_ENABLED = SettingKey.BoolKey("agent.enabled", true)
    val BUFFER_MAX_MB = SettingKey.IntKey("buffer.max_mb", 200, 10, 2_000)
    val BUFFER_MAX_AGE_DAYS = SettingKey.IntKey("buffer.max_age_days", 30, 1, 365)
    val UPLOAD_INTERVAL_MIN = SettingKey.IntKey("upload.interval_min", 15, 15, 360)
    val WIFI_ONLY_LARGE = SettingKey.BoolKey("upload.wifi_only_large", true)
    val LARGE_THRESHOLD_MB = SettingKey.IntKey("upload.large_threshold_mb", 5, 1, 200)
}
