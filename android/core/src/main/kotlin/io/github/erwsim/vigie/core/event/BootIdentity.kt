package io.github.erwsim.vigie.core.event

import android.annotation.SuppressLint
import android.content.SharedPreferences
import java.security.SecureRandom

/**
 * Per-boot random identifier (contract §1 `boot_id`).
 *
 * A new boot is detected when `Settings.Global.BOOT_COUNT` changes, or, if that counter is not
 * readable, when the estimated boot wall time (`now - elapsedRealtime`) moved by more than a
 * minute or `elapsedRealtime` went backwards. Computed once per process.
 */
@SuppressLint("ApplySharedPref") // commit(): the boot id must be on disk before events of this boot are written.
class BootIdentity(
    private val prefs: SharedPreferences,
    private val clock: AgentClock,
    private val bootCount: () -> Int?,
    private val random: SecureRandom = SecureRandom(),
) {
    /** The boot id of the current boot. */
    val bootId: String

    /** True when this process is the first agent process of this boot (and not the first run ever). */
    val isNewBoot: Boolean

    /** True when no boot id was ever stored (fresh install or cleared data). */
    val isFirstRun: Boolean

    init {
        val now = clock.nowMillis()
        val elapsed = clock.elapsedRealtime()
        val bootWall = now - elapsed
        val currentCount = bootCount()
        val storedId = prefs.getString(KEY_ID, null)
        val storedCount = prefs.getInt(KEY_COUNT, -1)
        val storedBootWall = prefs.getLong(KEY_BOOT_WALL, Long.MIN_VALUE)
        val storedElapsed = prefs.getLong(KEY_LAST_ELAPSED, -1)

        val changed = when {
            storedId == null -> true
            currentCount != null && storedCount >= 0 -> currentCount != storedCount
            elapsed < storedElapsed -> true
            else -> kotlin.math.abs(bootWall - storedBootWall) > BOOT_WALL_TOLERANCE_MS
        }
        isFirstRun = storedId == null
        isNewBoot = changed && !isFirstRun
        bootId = if (changed) newId() else storedId!!
        prefs.edit()
            .putString(KEY_ID, bootId)
            .putInt(KEY_COUNT, currentCount ?: -1)
            .putLong(KEY_BOOT_WALL, bootWall)
            .putLong(KEY_LAST_ELAPSED, elapsed)
            .commit()
    }

    private fun newId(): String {
        val bytes = ByteArray(16)
        random.nextBytes(bytes)
        return bytes.joinToString("") { "%02x".format(it) }
    }

    private companion object {
        const val KEY_ID = "boot_id"
        const val KEY_COUNT = "boot_count"
        const val KEY_BOOT_WALL = "boot_wall_ms"
        const val KEY_LAST_ELAPSED = "last_elapsed_ms"
        const val BOOT_WALL_TOLERANCE_MS = 60_000L
    }
}
