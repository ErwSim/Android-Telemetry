package io.github.erwsim.vigie.collectors.apps

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.provider.Settings
import android.provider.Telephony
import android.telecom.TelecomManager
import androidx.core.net.toUri

/**
 * Default apps ("roles") readable WITHOUT a system privilege. Single reader shared by
 * `app.special_access` (`default_apps`: the current state) and `app.role` (the changes), so that the
 * two events can never contradict each other for the same reading.
 *
 * What the platform lets a third-party app (including a Device Owner) read, checked against
 * `android.jar` of API 37:
 * - `RoleManager` only offers `isRoleAvailable`, `isRoleHeld` (for the caller itself) and
 *   `createRequestRoleIntent`: `getRoleHolders` is a system API (permission `OBSERVE_ROLE_HOLDERS`,
 *   signature level). A Device Owner has no more right here;
 * - SMS: `Telephony.Sms.getDefaultSmsPackage` (public); dialer: `TelecomManager.getDefaultDialerPackage`
 *   (public); browser and home: the app that resolves the default intent (`MATCH_DEFAULT_ONLY`);
 * - keyboard: secure setting `default_input_method` (public constant);
 * - assistant, autofill: secure settings `assistant` and `autofill_service`, which are hidden keys:
 *   readable on some builds only, omitted when the system refuses;
 * - call screening, call redirection, emergency, notes, wallet: no public getter for another app.
 *   Omitted, never guessed.
 */
object DefaultApps {
    /** The roles reported, in a stable order. */
    val ROLES = listOf("sms", "dialer", "browser", "home", "assistant", "keyboard", "autofill")

    /** Role → package, only for the roles that are set AND readable. */
    fun read(context: Context, pm: PackageManager): Map<String, String> {
        fun resolve(intent: Intent): String? = try {
            pm.resolveActivity(intent, PackageManager.ResolveInfoFlags.of(PackageManager.MATCH_DEFAULT_ONLY.toLong()))
                ?.activityInfo?.packageName?.takeIf { it != "android" } // "android" = chooser, no default.
        } catch (_: Exception) {
            null
        }
        fun secureComponentPackage(key: String): String? = try {
            Settings.Secure.getString(context.contentResolver, key)?.let(::packageOfComponent)
        } catch (_: Exception) {
            null
        }
        return linkedMapOf(
            "browser" to resolve(Intent(Intent.ACTION_VIEW, "https://example.org".toUri()).addCategory(Intent.CATEGORY_BROWSABLE)),
            "home" to resolve(Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_HOME)),
            "dialer" to try {
                context.getSystemService(TelecomManager::class.java)?.defaultDialerPackage
            } catch (_: Exception) {
                null
            },
            "sms" to try {
                Telephony.Sms.getDefaultSmsPackage(context)
            } catch (_: Exception) {
                null
            },
            "keyboard" to secureComponentPackage(Settings.Secure.DEFAULT_INPUT_METHOD),
            "assistant" to secureComponentPackage("assistant"),
            "autofill" to secureComponentPackage("autofill_service"),
        ).mapNotNull { (role, pkg) -> pkg?.takeIf { it.isNotBlank() }?.let { role to it } }.toMap()
    }

    /** `pkg/cls` (flattened component) or a bare package name → package; null if empty. */
    fun packageOfComponent(raw: String): String? =
        (ComponentName.unflattenFromString(raw)?.packageName ?: raw.substringBefore('/')).takeIf { it.isNotBlank() }
}
