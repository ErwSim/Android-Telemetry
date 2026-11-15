package io.github.erwsim.vigie.policy

import android.app.admin.DeviceAdminReceiver
import android.content.Context
import android.content.Intent
import io.github.erwsim.vigie.core.Agent

/**
 * Device admin receiver, promoted to Device Owner by ADB (`dpm set-device-owner`).
 * Runs on the main thread: keep every callback short and delegate to [PolicyModule].
 */
class VigieAdminReceiver : DeviceAdminReceiver() {
    override fun onEnabled(context: Context, intent: Intent) {
        Agent.getOrNull()?.let { agent ->
            agent.integrity.checkPermissionsAndOwnership()
            PolicyModule.onAgentStarted(agent)
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
            agent.integrity.tamper("admin_disabled", context.packageName)
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
}
