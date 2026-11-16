package io.github.erwsim.vigie.policy

import android.app.admin.DeviceAdminReceiver
import android.app.admin.DevicePolicyManager
import android.content.Context
import android.content.Intent
import android.os.UserHandle
import io.github.erwsim.vigie.core.Agent

/**
 * Device admin receiver, promoted to Device Owner by ADB (`dpm set-device-owner`).
 * Runs on the main thread: keep every callback short and delegate to [PolicyModule].
 * Password callbacks need `<watch-login />` in `res/xml/device_admin.xml`.
 */
class VigieAdminReceiver : DeviceAdminReceiver() {
    override fun onEnabled(context: Context, intent: Intent) {
        Agent.getOrNull()?.let { agent ->
            agent.integrity.checkPermissionsAndOwnership()
            PolicyModule.onOwnerEnabled(agent)
            agent.host.reconcile()
        }
    }

    override fun onDisableRequested(context: Context, intent: Intent): CharSequence {
        Agent.getOrNull()?.let { agent ->
            agent.integrity.tamper("admin_disable_requested", context.packageName)
            agent.sink.flushBlocking(1_000)
        }
        return context.getString(R.string.policy_disable_warning)
    }

    override fun onDisabled(context: Context, intent: Intent) {
        Agent.getOrNull()?.let { agent ->
            // Not tampering when the app removed its own role (announced by PolicyEngine.removeDeviceOwner).
            agent.integrity.onAdminDisabled(context.packageName)
            agent.sink.flushBlocking(1_000)
            agent.host.reconcile()
        }
    }

    override fun onNetworkLogsAvailable(context: Context, intent: Intent, batchToken: Long, networkLogsCount: Int) {
        PolicyModule.onNetworkLogsAvailable(context, batchToken, networkLogsCount)
    }

    override fun onSecurityLogsAvailable(context: Context, intent: Intent) {
        PolicyModule.onSecurityLogsAvailable(context)
    }

    override fun onPasswordFailed(context: Context, intent: Intent, user: UserHandle) {
        PolicyModule.onPasswordFailed(failedAttempts(context))
    }

    override fun onPasswordSucceeded(context: Context, intent: Intent, user: UserHandle) {
        PolicyModule.onPasswordSucceeded(failedAttempts(context))
    }

    override fun onPasswordChanged(context: Context, intent: Intent, user: UserHandle) {
        PolicyModule.onPasswordChanged()
    }

    /** Failed attempts since the last successful unlock (needs the watch-login policy); null if refused. */
    private fun failedAttempts(context: Context): Int? = try {
        context.getSystemService(DevicePolicyManager::class.java)?.currentFailedPasswordAttempts
    } catch (_: Exception) {
        null
    }
}
