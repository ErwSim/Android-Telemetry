package io.github.erwsim.vigie.policy

import android.content.Context
import android.util.Log
import io.github.erwsim.vigie.core.Agent
import io.github.erwsim.vigie.core.collector.Collector
import io.github.erwsim.vigie.core.settings.SettingKey
import io.github.erwsim.vigie.core.settings.SettingSpec
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch

/**
 * Entry point of the `:policy` module (everything that requires Device Owner).
 *
 * Extension points for the next lot:
 * - [collectors]: Device Owner collectors (network logs, security logs, posture…), each declaring
 *   `Requirement.DeviceOwner`;
 * - [onNetworkLogsAvailable] / [onSecurityLogsAvailable]: called by [VigieAdminReceiver];
 * - [settings]: policy settings rendered in the app's settings screen;
 * - the app's "Politique" screen (`app/.../ui/PolicyScreen.kt`) is a placeholder to replace.
 */
object PolicyModule {
    private const val TAG = "VigiePolicy"

    val FORCE_STOP_PROTECTION = SettingKey.BoolKey("policy.force_stop_protection", true)

    val settings: List<SettingSpec> = listOf(
        SettingSpec.BoolSpec(FORCE_STOP_PROTECTION, R.string.setting_force_stop_protection, R.string.setting_force_stop_protection_summary),
    )

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    @Suppress("UNUSED_PARAMETER")
    fun collectors(context: Context): List<Collector> = emptyList()

    fun deviceOwner(agent: Agent) = DeviceOwnerManager(agent.context, agent.capabilities)

    /** Called once from `Application.onCreate`, after `Agent.init`. */
    fun install(agent: Agent) {
        scope.launch {
            agent.settings.changes.collect { key ->
                if (key == FORCE_STOP_PROTECTION.name) applyForceStopProtection(agent)
            }
        }
    }

    /** Called at each agent (service) start, on Device Owner activation and by the maintenance worker. */
    fun onAgentStarted(agent: Agent) {
        val manager = deviceOwner(agent)
        if (!manager.isDeviceOwner()) return
        val results = manager.selfGrantRuntimePermissions()
        results.filter { !it.granted }.forEach { Log.w(TAG, "self-grant failed: ${it.permission} ${it.error.orEmpty()}") }
        if (results.any { it.granted }) {
            agent.integrity.checkPermissionsAndOwnership()
            agent.host.reconcile()
        }
        applyForceStopProtection(agent)
    }

    private fun applyForceStopProtection(agent: Agent) {
        val manager = deviceOwner(agent)
        val wanted = agent.settings[FORCE_STOP_PROTECTION]
        if (manager.isDeviceOwner() && manager.isForceStopProtected() != wanted) {
            if (!manager.setForceStopProtection(wanted)) Log.w(TAG, "setUserControlDisabledPackages failed")
        }
    }

    /** Device Owner network logging batch ready (next lot: retrieve, emit `net.dns` / `net.connect`). */
    @Suppress("UNUSED_PARAMETER")
    fun onNetworkLogsAvailable(context: Context, batchToken: Long, count: Int) {
        Log.i(TAG, "network logs available ($count), not collected in this version")
    }

    /** Device Owner security logs ready (next lot: retrieve, emit `security.log`). */
    @Suppress("UNUSED_PARAMETER")
    fun onSecurityLogsAvailable(context: Context) {
        Log.i(TAG, "security logs available, not collected in this version")
    }
}
