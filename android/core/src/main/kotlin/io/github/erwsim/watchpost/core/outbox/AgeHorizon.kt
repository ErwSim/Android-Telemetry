package io.github.erwsim.watchpost.core.outbox

import android.content.SharedPreferences
import io.github.erwsim.watchpost.core.event.AgentClock

/**
 * The "now" used by the age purge, so that a wall clock that jumps (user, bad NTP, tampering) cannot
 * purge the whole buffer in one pass.
 *
 * Without it, `cutoff = wall_now - max_age` and a wall clock set 31 days ahead makes every buffered
 * event "older than 30 days": the whole buffer is deleted at the next maintenance (15 min). That is
 * also the cheapest way to erase evidence.
 *
 * The horizon is an estimate of the true time that moves FORWARD at most [CATCH_UP_FACTOR] times as
 * fast as the monotonic clock (`elapsedRealtime`, which nobody can set), never ahead of the wall clock:
 *
 *     horizon = min(wall_now, previous_horizon + CATCH_UP_FACTOR * elapsed_since_previous + slack)
 *
 * - normal operation: the wall clock follows the elapsed time, so horizon == wall clock;
 * - wall clock jumps FORWARD: the horizon only moves at twice the real speed. A real 30-day retention
 *   is honoured (nothing is purged early in one pass), and a clock that stays wrong ages events at most
 *   twice as fast, which is the bound of what the age purge can do for a wrong clock;
 * - wall clock jumps BACK: the horizon follows it at once (`min`), so events written after the jump
 *   (stamped with the wrong, older time) are not seen as "30 days old" and purged. Older events are kept
 *   longer than the retention until the clock is right again (the size cap still applies);
 * - once the wall clock is right again the horizon catches up at twice the real speed;
 * - reboot (`boot_id` changes, no monotonic reference between the two boots): the horizon may move
 *   forward by at most [REBOOT_ALLOWANCE_MS] over the last stored value, whatever the wall clock says.
 *
 * Not covered, by design: see the "Known limits" of the age horizon in ARCHITECTURE-CODE.md.
 */
class AgeHorizon(
    private val prefs: SharedPreferences,
    private val clock: AgentClock,
    private val bootId: String,
) {
    /** Returns the reference time (epoch ms) for the age purge and stores the new horizon. */
    @Synchronized
    fun reference(wallNowMs: Long): Long {
        val elapsed = clock.elapsedRealtime()
        val storedHorizon = prefs.getLong(KEY_HORIZON, NONE)
        val storedElapsed = prefs.getLong(KEY_ELAPSED, NONE)
        val storedBoot = prefs.getString(KEY_BOOT, null)
        val horizon = when {
            storedHorizon == NONE -> wallNowMs
            storedBoot == bootId && storedElapsed != NONE && elapsed >= storedElapsed -> {
                val maxAdvance = CATCH_UP_FACTOR * (elapsed - storedElapsed) + SLACK_MS
                minOf(wallNowMs, storedHorizon + maxAdvance)
            }
            else -> minOf(wallNowMs, storedHorizon + REBOOT_ALLOWANCE_MS)
        }
        prefs.edit()
            .putLong(KEY_HORIZON, horizon)
            .putLong(KEY_ELAPSED, elapsed)
            .putString(KEY_BOOT, bootId)
            .apply()
        return horizon
    }

    companion object {
        const val CATCH_UP_FACTOR = 2L
        const val SLACK_MS = 60_000L
        const val REBOOT_ALLOWANCE_MS = 2 * 86_400_000L
        private const val NONE = Long.MIN_VALUE
        private const val KEY_HORIZON = "horizon_ms"
        private const val KEY_ELAPSED = "elapsed_ms"
        private const val KEY_BOOT = "boot_id"
    }
}
