package io.github.erwsim.vigie.policy

import android.Manifest
import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import io.github.erwsim.vigie.core.capability.Capabilities

/** Minimal Device Owner operations of this lot. Every call is a no-op when not Device Owner. */
class DeviceOwnerManager(
    private val context: Context,
    private val capabilities: Capabilities,
) {
    private val dpm: DevicePolicyManager? get() = context.getSystemService(DevicePolicyManager::class.java)

    val admin: ComponentName get() = ComponentName(context, VigieAdminReceiver::class.java)

    fun isDeviceOwner(): Boolean = capabilities.isDeviceOwner()

    data class GrantResult(val permission: String, val granted: Boolean, val error: String? = null)

    /**
     * Grants to Vigie itself every runtime permission declared by the merged manifest (so a
     * collector added in another module gets its permissions without code here). Foreground
     * location is granted before background location. The grant state is then put back to
     * DEFAULT: the permission stays granted but remains under the user's control (reversible);
     * a later revocation is reported as `agent.tamper`.
     */
    fun selfGrantRuntimePermissions(): List<GrantResult> {
        val dpm = dpm ?: return emptyList()
        if (!isDeviceOwner()) return emptyList()
        val pending = capabilities.declaredRuntimePermissions()
            .filterNot(capabilities::hasPermission)
            .sortedBy { if (it == Manifest.permission.ACCESS_BACKGROUND_LOCATION) 1 else 0 }
        return pending.map { permission ->
            try {
                val ok = dpm.setPermissionGrantState(
                    admin, context.packageName, permission, DevicePolicyManager.PERMISSION_GRANT_STATE_GRANTED,
                )
                if (ok) {
                    dpm.setPermissionGrantState(
                        admin, context.packageName, permission, DevicePolicyManager.PERMISSION_GRANT_STATE_DEFAULT,
                    )
                }
                GrantResult(permission, ok && capabilities.hasPermission(permission))
            } catch (e: Exception) {
                GrantResult(permission, false, e.toString())
            }
        }
    }

    /** `setUserControlDisabledPackages`: blocks "Force stop"/"Clear data" and exempts from standby buckets. */
    fun setForceStopProtection(enabled: Boolean): Boolean {
        val dpm = dpm ?: return false
        if (!isDeviceOwner()) return false
        return try {
            dpm.setUserControlDisabledPackages(admin, if (enabled) listOf(context.packageName) else emptyList())
            true
        } catch (_: Exception) {
            false
        }
    }

    fun isForceStopProtected(): Boolean = try {
        isDeviceOwner() && dpm?.getUserControlDisabledPackages(admin)?.contains(context.packageName) == true
    } catch (_: Exception) {
        false
    }
}
