package io.github.erwsim.vigie.collectors.apps

import android.content.pm.PackageInfo
import android.content.pm.PackageManager

/** PackageManager readings shared by the collectors of the `apps` package (one implementation). */
object PackageSupport {
    /** Package that installed [pkg] (`InstallSourceInfo`), null if unknown or unreadable. */
    fun installerOf(pm: PackageManager, pkg: String): String? = try {
        pm.getInstallSourceInfo(pkg).installingPackageName
    } catch (_: Exception) {
        null
    }

    /** True if [permission] is requested by [info] AND currently granted (install-time or runtime). */
    fun isGranted(info: PackageInfo, permission: String): Boolean {
        val i = info.requestedPermissions?.indexOf(permission) ?: return false
        val flags = info.requestedPermissionsFlags ?: return false
        return i in flags.indices && flags[i] and PackageInfo.REQUESTED_PERMISSION_GRANTED != 0
    }

    fun requests(info: PackageInfo, permission: String): Boolean = info.requestedPermissions?.contains(permission) == true
}
