package io.github.erwsim.watchpost.notifier.protocol

import android.os.Bundle

/**
 * Typed, defensive read access to the extras of a call. A value of the wrong type reads as absent:
 * a hostile caller cannot make the reader throw. [MapValues] is the JVM-testable implementation,
 * [BundleValues] the one used on the device.
 */
interface ValueReader {
    fun keyCount(): Int
    fun string(key: String): String?
    fun bool(key: String): Boolean?
    fun int(key: String): Int?
    fun long(key: String): Long?
    fun strings(key: String): List<String>?
}

class MapValues(private val map: Map<String, Any?>) : ValueReader {
    override fun keyCount() = map.size
    override fun string(key: String) = map[key] as? String
    override fun bool(key: String) = map[key] as? Boolean
    override fun int(key: String) = map[key] as? Int
    override fun long(key: String) = map[key] as? Long

    override fun strings(key: String): List<String>? = when (val v = map[key]) {
        is Array<*> -> if (v.all { it is String }) v.map { it as String } else null
        is List<*> -> if (v.all { it is String }) v.map { it as String } else null
        else -> null
    }
}

/**
 * Reads a [Bundle] received over binder. Every access is guarded: unparcelling a hostile bundle
 * (unknown Parcelable class, truncated data) throws, and that must read as "absent", not crash
 * the binder thread. Typed getters never return a value of another type.
 */
class BundleValues(private val b: Bundle?) : ValueReader {
    private inline fun <T> safe(key: String, read: (Bundle) -> T?): T? = try {
        if (b != null && b.containsKey(key)) read(b) else null
    } catch (_: RuntimeException) {
        null
    }

    override fun keyCount(): Int = try {
        b?.size() ?: 0
    } catch (_: RuntimeException) {
        Int.MAX_VALUE
    }

    override fun string(key: String) = safe(key) { it.getString(key) }
    override fun bool(key: String) = safe(key) { bundle -> bundle.getBoolean(key, false).takeIf { v -> v == bundle.getBoolean(key, true) } }
    override fun int(key: String) = safe(key) { bundle -> bundle.getInt(key, 0).takeIf { v -> v == bundle.getInt(key, 1) } }
    override fun long(key: String) = safe(key) { bundle -> bundle.getLong(key, 0L).takeIf { v -> v == bundle.getLong(key, 1L) } }
    override fun strings(key: String) = safe(key) { bundle -> bundle.getStringArray(key)?.toList()?.takeIf { l -> l.size <= Limits.MAX_LIST_ENTRIES * 4 } }
}

/** Builds a [Bundle] from String, Boolean, Int, Long and List<String> values (null values are skipped). */
fun bundleOf(values: Map<String, Any?>): Bundle {
    val b = Bundle(values.size)
    for ((k, v) in values) {
        when (v) {
            null -> Unit
            is String -> b.putString(k, v)
            is Boolean -> b.putBoolean(k, v)
            is Int -> b.putInt(k, v)
            is Long -> b.putLong(k, v)
            is List<*> -> b.putStringArray(k, v.map { it as String }.toTypedArray())
            else -> throw IllegalArgumentException("unsupported value type for $k")
        }
    }
    return b
}
