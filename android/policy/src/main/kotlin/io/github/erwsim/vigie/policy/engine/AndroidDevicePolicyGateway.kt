package io.github.erwsim.vigie.policy.engine

import android.Manifest
import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.UserManager
import android.provider.Settings
import android.provider.Telephony
import android.telecom.TelecomManager
import android.view.inputmethod.InputMethodManager
import io.github.erwsim.vigie.policy.VigieAdminReceiver

/**
 * [DevicePolicyGateway] on the real `DevicePolicyManager`. Signatures checked against the
 * android-37.0 SDK. Every call may throw `SecurityException` (not Device Owner, unaffiliated user,
 * OEM restriction): the engine catches and reads the state back.
 */
class AndroidDevicePolicyGateway(private val context: Context) : DevicePolicyGateway {
    private val dpm: DevicePolicyManager get() = checkNotNull(context.getSystemService(DevicePolicyManager::class.java)) { "no DevicePolicyManager" }
    private val pm: PackageManager get() = context.packageManager
    private val admin: ComponentName get() = ComponentName(context, VigieAdminReceiver::class.java)

    override fun isDeviceOwner(): Boolean = dpm.isDeviceOwnerApp(context.packageName)

    override fun protectedPackages(): Set<String> {
        val out = HashSet<String>()
        out += context.packageName
        fun add(block: () -> String?) {
            try {
                block()?.let(out::add)
            } catch (_: Exception) {
                // Best effort: the static deny list still applies.
            }
        }
        // Default launcher (home) and every app able to be the home screen.
        add { pm.resolveActivity(Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_HOME), PackageManager.MATCH_DEFAULT_ONLY)?.activityInfo?.packageName }
        try {
            pm.queryIntentActivities(Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_HOME), 0).forEach { out += it.activityInfo.packageName }
        } catch (_: Exception) {
        }
        add { context.getSystemService(TelecomManager::class.java)?.defaultDialerPackage }
        add { context.getSystemService(TelecomManager::class.java)?.systemDialerPackage }
        add { Telephony.Sms.getDefaultSmsPackage(context) }
        // Every enabled keyboard (one of them is the only way to type the PIN).
        try {
            context.getSystemService(InputMethodManager::class.java)?.enabledInputMethodList?.forEach { out += it.packageName }
        } catch (_: Exception) {
        }
        // Package installers and active device admins (Find My Mobile…).
        try {
            pm.queryIntentActivities(Intent(Intent.ACTION_INSTALL_PACKAGE).setDataAndType(android.net.Uri.parse("file:///x.apk"), "application/vnd.android.package-archive"), 0)
                .forEach { out += it.activityInfo.packageName }
        } catch (_: Exception) {
        }
        try {
            dpm.activeAdmins?.forEach { out += it.packageName }
        } catch (_: Exception) {
        }
        // Current always-on VPN (hiding it could cut the network in lockdown mode).
        add { dpm.getAlwaysOnVpnPackage(admin) }
        return out
    }

    override fun isInstalled(pkg: String): Boolean = try {
        pm.getPackageInfo(pkg, PackageManager.PackageInfoFlags.of(PackageManager.MATCH_UNINSTALLED_PACKAGES.toLong()))
        true
    } catch (_: PackageManager.NameNotFoundException) {
        false
    }

    override fun isHidden(pkg: String): Boolean = dpm.isApplicationHidden(admin, pkg)

    override fun setHidden(pkg: String, hidden: Boolean): Boolean = dpm.setApplicationHidden(admin, pkg, hidden)

    override fun isSuspended(pkg: String): Boolean = dpm.isPackageSuspended(admin, pkg)

    override fun setSuspended(pkg: String, suspended: Boolean): Boolean =
        dpm.setPackagesSuspended(admin, arrayOf(pkg), suspended).isEmpty()

    override fun requestsPermission(pkg: String, permission: String): Boolean = try {
        pm.getPackageInfo(pkg, PackageManager.PackageInfoFlags.of(PackageManager.GET_PERMISSIONS.toLong()))
            .requestedPermissions?.contains(permission) == true
    } catch (_: PackageManager.NameNotFoundException) {
        false
    }

    override fun isPermissionGranted(pkg: String, permission: String): Boolean =
        pm.checkPermission(permission, pkg) == PackageManager.PERMISSION_GRANTED

    override fun permissionGrantState(pkg: String, permission: String): Int = dpm.getPermissionGrantState(admin, pkg, permission)

    override fun setPermissionGrantState(pkg: String, permission: String, state: Int): Boolean =
        dpm.setPermissionGrantState(admin, pkg, permission, state)

    override fun hasRestriction(key: String): Boolean = dpm.getUserRestrictions(admin).getBoolean(key, false)

    override fun addRestriction(key: String) = dpm.addUserRestriction(admin, key)

    override fun clearRestriction(key: String) = dpm.clearUserRestriction(admin, key)

    override fun privateDnsMode(): Int = dpm.getGlobalPrivateDnsMode(admin)

    override fun privateDnsHost(): String? = dpm.getGlobalPrivateDnsHost(admin)

    override fun setPrivateDnsSpecifiedHost(host: String): Int = dpm.setGlobalPrivateDnsModeSpecifiedHost(admin, host)

    override fun setPrivateDnsOpportunistic(): Int = dpm.setGlobalPrivateDnsModeOpportunistic(admin)

    /** No dedicated API: `private_dns_mode` is in the Device Owner global settings allowlist (API 29+). */
    override fun setPrivateDnsOff() = dpm.setGlobalSetting(admin, KEY_PRIVATE_DNS_MODE, "off")

    override fun canWriteSecureSettings(): Boolean =
        context.checkSelfPermission(Manifest.permission.WRITE_SECURE_SETTINGS) == PackageManager.PERMISSION_GRANTED

    override fun readSetting(namespace: String, key: String): String? = when (namespace) {
        "global" -> Settings.Global.getString(context.contentResolver, key)
        "secure" -> Settings.Secure.getString(context.contentResolver, key)
        else -> throw IllegalArgumentException(namespace)
    }

    override fun writeSetting(namespace: String, key: String, value: String?): Boolean = when (namespace) {
        "global" -> Settings.Global.putString(context.contentResolver, key, value)
        "secure" -> Settings.Secure.putString(context.contentResolver, key, value)
        else -> throw IllegalArgumentException(namespace)
    }

    override fun isBackupServiceEnabled(): Boolean = dpm.isBackupServiceEnabled(admin)

    override fun setBackupServiceEnabled(enabled: Boolean) = dpm.setBackupServiceEnabled(admin, enabled)

    override fun alwaysOnVpnPackage(): String? = dpm.getAlwaysOnVpnPackage(admin)

    override fun isAlwaysOnVpnLockdown(): Boolean = dpm.isAlwaysOnVpnLockdownEnabled(admin)

    override fun setAlwaysOnVpn(pkg: String?, lockdown: Boolean) = dpm.setAlwaysOnVpnPackage(admin, pkg, lockdown)

    override fun isNetworkLoggingEnabled(): Boolean = dpm.isNetworkLoggingEnabled(admin)

    override fun setNetworkLoggingEnabled(enabled: Boolean) = dpm.setNetworkLoggingEnabled(admin, enabled)

    override fun isSecurityLoggingEnabled(): Boolean = dpm.isSecurityLoggingEnabled(admin)

    override fun setSecurityLoggingEnabled(enabled: Boolean) = dpm.setSecurityLoggingEnabled(admin, enabled)

    override fun clearUserControlDisabledPackages() = dpm.setUserControlDisabledPackages(admin, emptyList())

    @Suppress("DEPRECATION") // Deprecated but the only self-service way out; works on Android 16/17 (research §2.3).
    override fun clearDeviceOwner() = dpm.clearDeviceOwnerApp(context.packageName)

    /** Installed apps that declare a `VpnService` (candidates for the always-on VPN). */
    fun vpnApps(): List<String> = try {
        pm.queryIntentServices(Intent(VPN_SERVICE_ACTION), 0)
            .filter { it.serviceInfo.permission == Manifest.permission.BIND_VPN_SERVICE }
            .map { it.serviceInfo.packageName }
            .filter { it != context.packageName }
            .distinct().sorted()
    } catch (_: Exception) {
        emptyList()
    }

    /** Whether the user can see/affect these restrictions at all (sanity for the screen). */
    fun hasUserRestriction(key: String): Boolean = try {
        context.getSystemService(UserManager::class.java)?.hasUserRestriction(key) == true
    } catch (_: Exception) {
        false
    }

    companion object {
        const val KEY_PRIVATE_DNS_MODE = "private_dns_mode"
        const val VPN_SERVICE_ACTION = "android.net.VpnService"
    }
}
