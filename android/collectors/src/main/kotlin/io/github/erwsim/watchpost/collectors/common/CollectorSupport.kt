package io.github.erwsim.watchpost.collectors.common

import android.Manifest
import android.app.AppOpsManager
import android.app.KeyguardManager
import android.os.PowerManager
import android.os.Process
import androidx.core.content.edit
import io.github.erwsim.watchpost.core.collector.CollectorContext
import io.github.erwsim.watchpost.core.event.EventDataBuilder

/** Sliding-window rate limiter (pure, not thread-safe: use it on the collectors' thread). */
class RateLimiter(private val maxEvents: Int, private val windowMs: Long) {
    private val times = ArrayDeque<Long>()

    /** True if one more event is allowed at [nowMs] (and records it). */
    fun tryAcquire(nowMs: Long): Boolean {
        while (times.isNotEmpty() && nowMs - times.first() >= windowMs) times.removeFirst()
        if (times.size >= maxEvents) return false
        times.addLast(nowMs)
        return true
    }

    fun reset() = times.clear()
}

/** English string of this module, never null (JVM stubs return null). */
fun CollectorContext.str(id: Int, vararg args: Any): String =
    (
        try {
            if (args.isEmpty()) appContext.getString(id) else appContext.getString(id, *args)
        } catch (_: Exception) {
            null
        }
        ) ?: "unavailable"

/** Lowercase SHA-256 hex digest. */
fun sha256Hex(bytes: ByteArray): String =
    java.security.MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }

/**
 * "Usage access" (app-op GET_USAGE_STATS): granted either in Settings (mode allowed) or by
 * `adb shell pm grant … PACKAGE_USAGE_STATS` (mode default + permission granted).
 */
fun CollectorContext.hasUsageAccess(): Boolean = try {
    val ops = appContext.getSystemService(AppOpsManager::class.java)
    when (ops?.unsafeCheckOpNoThrow(AppOpsManager.OPSTR_GET_USAGE_STATS, Process.myUid(), appContext.packageName)) {
        AppOpsManager.MODE_ALLOWED -> true
        AppOpsManager.MODE_DEFAULT -> capabilities.hasPermission(Manifest.permission.PACKAGE_USAGE_STATS)
        else -> false
    }
} catch (_: Exception) {
    false
}

/** `screen_on` and `locked` at the time of a `sensor.*` event (contract precision); null if unknown. */
data class ScreenState(val screenOn: Boolean?, val locked: Boolean?) {
    fun writeTo(b: EventDataBuilder) {
        b.put("screen_on", screenOn)
        b.put("locked", locked)
    }

    companion object {
        fun read(ctx: CollectorContext): ScreenState {
            val screenOn = try {
                ctx.appContext.getSystemService(PowerManager::class.java)?.isInteractive
            } catch (_: Exception) {
                null
            }
            val locked = try {
                ctx.appContext.getSystemService(KeyguardManager::class.java)?.isKeyguardLocked
            } catch (_: Exception) {
                null
            }
            return ScreenState(screenOn, locked)
        }
    }
}

/**
 * Persisted "emit only on change" helper: returns true (and stores [value]) when [value] differs
 * from the last one stored under [key] in the collector's private preferences.
 */
fun CollectorContext.changed(key: String, value: String): Boolean {
    if (prefs.getString("last_$key", null) == value) return false
    prefs.edit { putString("last_$key", value) }
    return true
}
