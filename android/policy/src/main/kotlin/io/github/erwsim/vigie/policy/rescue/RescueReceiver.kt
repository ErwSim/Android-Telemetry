package io.github.erwsim.vigie.policy.rescue

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import io.github.erwsim.vigie.policy.PolicyModule
import io.github.erwsim.vigie.policy.engine.ItemKind
import io.github.erwsim.vigie.policy.engine.PackageMethod
import io.github.erwsim.vigie.policy.engine.PolicyEngine
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread

/**
 * Rescue without the user interface: "Tout rétablir" (and optionally "Retirer le Device Owner")
 * triggered from ADB by `scripts/rescue-revert.sh` / `.ps1`:
 *
 *     adb shell am broadcast --include-stopped-packages -a io.github.erwsim.vigie.action.RESCUE_REVERT_ALL \
 *         -n io.github.erwsim.vigie/io.github.erwsim.vigie.policy.rescue.RescueReceiver [--ez remove_owner true]
 *
 * Protection: the receiver is exported but requires the sender to hold
 * `android.permission.FORCE_STOP_PACKAGES` (manifest `android:permission`). Its protection level is
 * `signature|privileged` (checked in the android-37 framework manifest), without the `development`
 * or `appop` flags: no third-party app can ever obtain it, not even through `pm grant`. Only the
 * system and the ADB shell (`com.android.shell` holds it for `am force-stop`) can deliver this
 * broadcast. The only effect is undoing Vigie's own changes; it never applies anything.
 *
 * The result is returned to `am broadcast` (ordered broadcast result): code [RESULT_OK],
 * [RESULT_PARTIAL], [RESULT_NOT_OWNER] or [RESULT_TIMEOUT], and a one-line summary. When Vigie is no
 * longer Device Owner it cannot undo anything itself: the summary then lists the packages it had
 * hidden or suspended so that the script can restore them with `pm unhide` / `pm unsuspend`.
 */
class RescueReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != ACTION) return
        val removeOwner = intent.getBooleanExtra(EXTRA_REMOVE_OWNER, false)
        val pending = goAsync()
        val done = CountDownLatch(1)
        var code = RESULT_TIMEOUT
        var summary = "délai dépassé : l'opération continue en arrière-plan, relancez le script pour voir le résultat"
        val app = context.applicationContext
        thread(name = "vigie-rescue") {
            try {
                val engine = PolicyModule.engine(app)
                if (!engine.isDeviceOwner()) {
                    code = RESULT_NOT_OWNER
                    summary = "not_device_owner ${leftovers(engine)}".trim()
                } else {
                    var report = engine.revertAll()
                    if (removeOwner) report += engine.removeDeviceOwner(force = true)
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
        thread(name = "vigie-rescue-result") {
            // The latch publishes code/summary written by the worker (happens-before).
            done.await(TIMEOUT_S, TimeUnit.SECONDS)
            pending.setResult(code, summary, null)
            pending.finish()
        }
    }

    /** What still needs an ADB command when Vigie cannot act any more. */
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
        const val ACTION = "io.github.erwsim.vigie.action.RESCUE_REVERT_ALL"
        const val EXTRA_REMOVE_OWNER = "remove_owner"
        const val RESULT_OK = 1
        const val RESULT_PARTIAL = 2
        const val RESULT_NOT_OWNER = 3
        const val RESULT_TIMEOUT = 4
        private const val TIMEOUT_S = 45L
        private const val MAX_SUMMARY = 3_000
    }
}
