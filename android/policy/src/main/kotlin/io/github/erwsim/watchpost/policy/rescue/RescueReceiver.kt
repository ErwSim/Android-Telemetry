package io.github.erwsim.watchpost.policy.rescue

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import io.github.erwsim.watchpost.policy.PolicyModule
import io.github.erwsim.watchpost.policy.engine.ItemKind
import io.github.erwsim.watchpost.policy.engine.PackageMethod
import io.github.erwsim.watchpost.policy.engine.PolicyEngine
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread

/**
 * Rescue without the user interface: "Restore everything" (and optionally "Remove Device Owner")
 * triggered from ADB by `scripts/rescue-revert.sh` / `.ps1`:
 *
 *     adb shell am broadcast --include-stopped-packages -a io.github.erwsim.watchpost.action.RESCUE_REVERT_ALL \
 *         -n io.github.erwsim.watchpost/io.github.erwsim.watchpost.policy.rescue.RescueReceiver \
 *         [--ez sweep true] [--ez remove_owner true [--ez force true]]
 *
 * - `sweep`: besides the recorded changes, restores everything the catalog can have changed
 *   ([PolicyEngine.sweepCatalog]): for a state that cannot be trusted any more. Done automatically
 *   when the persisted state was unreadable.
 * - `remove_owner`: then gives up the Device Owner role, but only if everything was undone. `force`
 *   gives it up even if something could not be undone (what remains is listed in the answer).
 *
 * Protection: the receiver is exported but requires the sender to hold
 * `android.permission.FORCE_STOP_PACKAGES` (manifest `android:permission`). Its protection level is
 * `signature|privileged` (0x12 in the android-37 framework manifest), without the `development`,
 * `appop` or `role` flags: no third-party app can obtain it, not even through `pm grant`. It is
 * held by apps signed with the platform key or privileged and allow-listed by the manufacturer, and
 * by the ADB shell (`com.android.shell` declares it for `am force-stop`; AOSP
 * `packages/Shell/AndroidManifest.xml`). The only effect is undoing Watchpost's own changes; it never
 * applies anything.
 *
 * Limits: the app is not direct-boot aware (its state is in credential-encrypted storage), so the
 * rescue only works after the first unlock following a reboot; and it needs the app process to
 * start (`Application.onCreate` tolerates a broken agent for that reason). If the app cannot start
 * at all, the last resort is `dpm remove-active-admin` (testOnly builds only).
 *
 * The result is returned to `am broadcast` (ordered broadcast result): code [RESULT_OK],
 * [RESULT_PARTIAL], [RESULT_NOT_OWNER] or [RESULT_TIMEOUT], and a one-line summary. When Watchpost is no
 * longer Device Owner it cannot undo anything itself: the summary then lists the packages it had
 * hidden or suspended so that the script can check them.
 */
class RescueReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != ACTION) return
        val removeOwner = intent.getBooleanExtra(EXTRA_REMOVE_OWNER, false)
        val force = intent.getBooleanExtra(EXTRA_FORCE, false)
        val sweep = intent.getBooleanExtra(EXTRA_SWEEP, false)
        val pending = goAsync()
        val done = CountDownLatch(1)
        var code = RESULT_TIMEOUT
        var summary = "timed out: the operation continues in the background, run the script again to see the result"
        val app = context.applicationContext
        thread(name = "watchpost-rescue") {
            try {
                val engine = PolicyModule.engine(app)
                if (!engine.isDeviceOwner()) {
                    code = RESULT_NOT_OWNER
                    summary = "not_device_owner ${leftovers(engine)}".trim()
                } else {
                    var report = engine.revertAll()
                    if (sweep) report += engine.sweepCatalog()
                    // Never give up the role over something that could not be undone, unless asked to:
                    // once the role is gone, nobody may be able to show a hidden package again.
                    if (removeOwner && (report.allOk || force)) report += engine.removeDeviceOwner(force)
                    code = if (report.allOk) RESULT_OK else RESULT_PARTIAL
                    summary = (
                        "reverted=${report.succeeded.size} failed=${report.failed.size}" +
                            (if (removeOwner) " device_owner=${engine.isDeviceOwner()}" else "") +
                            report.failed.joinToString(prefix = " | ", separator = " | ").takeIf { report.failed.isNotEmpty() }.orEmpty()
                        ).replace('\n', ' ').take(MAX_SUMMARY)
                    if (!engine.isDeviceOwner()) summary += " ${leftovers(engine)}".trimEnd()
                }
            } catch (e: Exception) {
                code = RESULT_PARTIAL
                summary = "error ${e.javaClass.simpleName}: ${e.message.orEmpty()}".take(MAX_SUMMARY)
            } finally {
                done.countDown()
            }
        }
        // Background broadcasts must finish within ~60 s; answer before, the work goes on anyway.
        thread(name = "watchpost-rescue-result") {
            // The latch publishes code/summary written by the worker (happens-before).
            done.await(TIMEOUT_S, TimeUnit.SECONDS)
            pending.setResult(code, summary, null)
            pending.finish()
        }
    }

    /** What still needs an ADB command when Watchpost cannot act any more. */
    private fun leftovers(engine: PolicyEngine): String {
        val records = engine.state().records
        val hidden = records.filter { it.kind == ItemKind.PACKAGE && it.method == PackageMethod.HIDE }.map { it.target }
        val suspended = records.filter { it.kind == ItemKind.PACKAGE && it.method == PackageMethod.SUSPEND }.map { it.target }
        return buildString {
            if (hidden.isNotEmpty()) append("hidden=").append(hidden.joinToString(",")).append(' ')
            if (suspended.isNotEmpty()) append("suspended=").append(suspended.joinToString(",")).append(' ')
            val others = records.count { it.kind != ItemKind.PACKAGE }
            if (others > 0) append("other_items=").append(others)
        }.trim()
    }

    companion object {
        const val ACTION = "io.github.erwsim.watchpost.action.RESCUE_REVERT_ALL"
        const val EXTRA_REMOVE_OWNER = "remove_owner"
        const val EXTRA_FORCE = "force"
        const val EXTRA_SWEEP = "sweep"
        const val RESULT_OK = 1
        const val RESULT_PARTIAL = 2
        const val RESULT_NOT_OWNER = 3
        const val RESULT_TIMEOUT = 4
        private const val TIMEOUT_S = 45L
        private const val MAX_SUMMARY = 3_000
    }
}
