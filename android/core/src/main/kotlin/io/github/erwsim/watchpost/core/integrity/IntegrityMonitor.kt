package io.github.erwsim.watchpost.core.integrity

import android.annotation.SuppressLint
import android.app.ActivityManager
import android.app.ApplicationExitInfo
import android.content.Context
import android.content.SharedPreferences
import io.github.erwsim.watchpost.core.capability.Capabilities
import io.github.erwsim.watchpost.core.event.AgentClock
import io.github.erwsim.watchpost.core.event.EventTypes
import io.github.erwsim.watchpost.core.event.Rfc3339
import io.github.erwsim.watchpost.core.event.Severity
import io.github.erwsim.watchpost.core.sink.EventSink
import io.github.erwsim.watchpost.core.sink.emit

/**
 * Detects tampering signals available without system privileges and emits `agent.tamper` (sev 3):
 * - `permission_revoked`: a runtime permission the agent had is no longer granted;
 * - `device_owner_lost`: the app was Device Owner and is not anymore;
 * - `force_stop`: the previous process was killed by a user request (Settings "Force stop",
 *   clear data…) according to `ApplicationExitInfo`.
 * Admin deactivation is reported by the `:policy` DeviceAdminReceiver through [onAdminDisabled].
 *
 * A voluntary Device Owner removal (Politique screen, ADB rescue) is announced beforehand with
 * [expectOwnershipLoss]: the loss that follows within the window is then not tampering (the
 * `:policy` module reports it as `security.policy` `device_owner_cleared`). The announcement is
 * persisted (the check may run in a later process) and cancelled if the removal fails.
 */
class IntegrityMonitor(
    private val context: Context,
    private val prefs: SharedPreferences,
    private val capabilities: Capabilities,
    private val sink: EventSink,
    private val clock: AgentClock = AgentClock.System,
) {
    @Synchronized
    fun checkPermissionsAndOwnership() {
        val declared = capabilities.declaredRuntimePermissions()
        val granted = declared.filter(capabilities::hasPermission).toSet()
        val previous = prefs.getStringSet(K_GRANTED, null)
        if (previous != null) {
            for (p in previous.sorted()) {
                if (p in declared && p !in granted) tamper("permission_revoked", p)
            }
        }
        prefs.edit().putStringSet(K_GRANTED, granted).apply()

        val isOwner = capabilities.isDeviceOwner()
        if (prefs.getBoolean(K_WAS_OWNER, false) && !isOwner) {
            if (!isOwnershipLossExpected()) tamper("device_owner_lost", context.packageName)
            prefs.edit().remove(K_EXPECT_LOSS_UNTIL).apply()
        }
        prefs.edit().putBoolean(K_WAS_OWNER, isOwner).apply()
    }

    /**
     * Announces that the app itself is about to give up the Device Owner role (called right before
     * `clearDeviceOwnerApp`). The loss observed within [windowMs] is not reported as `agent.tamper`
     * (`device_owner_lost`, `admin_disabled`).
     */
    @SuppressLint("ApplySharedPref") // commit(): must be on disk before the role (and maybe the process) goes away.
    @Synchronized
    fun expectOwnershipLoss(windowMs: Long = DEFAULT_EXPECT_WINDOW_MS) {
        prefs.edit().putLong(K_EXPECT_LOSS_UNTIL, clock.nowMillis() + windowMs).commit()
    }

    /** The announced removal did not happen (still Device Owner): a later loss is tampering again. */
    @Synchronized
    fun cancelOwnershipLossExpectation() {
        prefs.edit().remove(K_EXPECT_LOSS_UNTIL).apply()
    }

    @Synchronized
    fun isOwnershipLossExpected(): Boolean {
        val until = prefs.getLong(K_EXPECT_LOSS_UNTIL, 0L)
        val now = clock.nowMillis()
        // An announcement far in the future (clock moved back) is not trusted beyond its window.
        return until > 0 && now <= until && until - now <= MAX_EXPECT_WINDOW_MS
    }

    /** `DeviceAdminReceiver.onDisabled`: tampering unless the removal was announced. */
    fun onAdminDisabled(detail: String) {
        if (!isOwnershipLossExpected()) tamper("admin_disabled", detail)
    }

    /** Inspects process exits since the last check. Called once per agent start. */
    @Synchronized
    fun checkExitReasons() {
        val am = context.getSystemService(ActivityManager::class.java) ?: return
        val lastChecked = prefs.getLong(K_EXIT_CHECKED, 0)
        val exits = try {
            am.getHistoricalProcessExitReasons(context.packageName, 0, 16)
        } catch (_: Exception) {
            return
        }
        var newest = lastChecked
        for (exit in exits.sortedBy { it.timestamp }) {
            if (exit.timestamp <= lastChecked) continue
            newest = maxOf(newest, exit.timestamp)
            if (lastChecked == 0L) continue // first run: only record the baseline
            if (exit.reason == ApplicationExitInfo.REASON_USER_REQUESTED) {
                tamper("force_stop", "${Rfc3339.format(exit.timestamp)} ${exit.description.orEmpty()}".trim())
            }
        }
        prefs.edit().putLong(K_EXIT_CHECKED, maxOf(newest, 1L)).apply()
    }

    fun tamper(kind: String, detail: String) {
        sink.emit(EventTypes.AGENT_TAMPER, Severity.CRITICAL) {
            put("kind", kind)
            put("detail", detail)
        }
    }

    private companion object {
        const val K_GRANTED = "granted_permissions"
        const val K_WAS_OWNER = "was_device_owner"
        const val K_EXIT_CHECKED = "exit_reasons_checked_ms"
        const val K_EXPECT_LOSS_UNTIL = "expect_owner_loss_until_ms"
        const val DEFAULT_EXPECT_WINDOW_MS = 5 * 60_000L
        const val MAX_EXPECT_WINDOW_MS = 30 * 60_000L
    }
}
