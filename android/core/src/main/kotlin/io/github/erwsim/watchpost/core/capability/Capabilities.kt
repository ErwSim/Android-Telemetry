package io.github.erwsim.watchpost.core.capability

import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import android.content.pm.PackageManager
import android.content.pm.PermissionInfo
import android.os.PowerManager

/** "What am I allowed to do right now?" helpers. All checks are cheap and side-effect free. */
open class Capabilities(private val context: Context) {
    private val dpm: DevicePolicyManager? get() = context.getSystemService(DevicePolicyManager::class.java)

    open fun isDeviceOwner(): Boolean = try {
        dpm?.isDeviceOwnerApp(context.packageName) == true
    } catch (_: Exception) {
        false
    }

    /** Our active device-admin component (the `:policy` receiver), if the admin is active. */
    fun adminComponent(): ComponentName? = try {
        dpm?.activeAdmins?.firstOrNull { it.packageName == context.packageName }
    } catch (_: Exception) {
        null
    }

    open fun hasPermission(permission: String): Boolean =
        context.checkSelfPermission(permission) == PackageManager.PERMISSION_GRANTED

    fun missing(permissions: Collection<String>): List<String> = permissions.filterNot(::hasPermission)

    /** False when the feature is absent or the package manager cannot answer. */
    open fun hasSystemFeature(feature: String): Boolean = try {
        context.packageManager?.hasSystemFeature(feature) == true
    } catch (_: Exception) {
        false
    }

    fun isIgnoringBatteryOptimizations(): Boolean =
        context.getSystemService(PowerManager::class.java)?.isIgnoringBatteryOptimizations(context.packageName) == true

    /** Runtime ("dangerous") permissions requested by the merged manifest of the APK. */
    open fun declaredRuntimePermissions(): List<String> {
        val pm = context.packageManager
        val requested = try {
            pm.getPackageInfo(context.packageName, PackageManager.PackageInfoFlags.of(PackageManager.GET_PERMISSIONS.toLong()))
                .requestedPermissions?.toList().orEmpty()
        } catch (_: Exception) {
            emptyList()
        }
        return requested.filter { name ->
            try {
                val info = pm.getPermissionInfo(name, 0)
                info.protection == PermissionInfo.PROTECTION_DANGEROUS
            } catch (_: PackageManager.NameNotFoundException) {
                false // Permission unknown on this OS version.
            }
        }
    }
}
