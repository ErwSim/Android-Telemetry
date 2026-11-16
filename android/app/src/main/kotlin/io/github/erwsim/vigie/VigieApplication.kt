package io.github.erwsim.vigie

import android.app.Application
import android.util.Log
import io.github.erwsim.vigie.collectors.CollectorsModule
import io.github.erwsim.vigie.core.Agent
import io.github.erwsim.vigie.core.command.CommandTypes
import io.github.erwsim.vigie.core.settings.CoreSettings
import io.github.erwsim.vigie.policy.PolicyModule
import io.github.erwsim.vigie.service.AgentNotifications
import io.github.erwsim.vigie.service.AgentService
import io.github.erwsim.vigie.service.RemoteAlerts

/**
 * Wires the modules together: every collector comes from a module entry point, so adding a
 * collector never touches this file.
 *
 * Nothing here may crash the process: the ADB rescue (`RescueReceiver`, "Tout rétablir" without the
 * interface) runs in this process and only needs the policy engine, which does not depend on the
 * agent. A start-up step that fails is logged, kept in [startupError] (shown by the activity) and
 * skipped; if the agent itself cannot be built, the app only offers the rescue.
 */
class VigieApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        val agent = step("agent") {
            Agent.init(this) { context -> CollectorsModule.all(context) + PolicyModule.collectors(context) }
        } ?: return
        step("policy") { PolicyModule.install(agent) }
        step("notification channel") { AgentNotifications.createChannel(this) }
        // What a guard does on its own (quarantine, role change) is always shown (contract §11.1).
        PolicyModule.guardNoticeListener = { notice -> AgentNotifications.guardNotice(this, notice) }
        step("remote commands") {
            // ring / vibrate / stop_ring need no Device Owner; lock / wipe are registered by PolicyModule.install.
            agent.commands.register(CommandTypes.RING, RemoteAlerts.ring(this))
            agent.commands.register(CommandTypes.VIBRATE, RemoteAlerts.vibrate(this))
            agent.commands.register(CommandTypes.STOP_RING, RemoteAlerts.stopRing(this))
            agent.onCommandProcessed = { entry -> AgentNotifications.commandProcessed(this, entry) }
        }
        agent.maintenanceHook = {
            PolicyModule.onAgentStarted(agent)
            if (agent.settings[CoreSettings.AGENT_ENABLED] && !AgentService.running.value) {
                AgentService.start(this, AgentService.REASON_WATCHDOG)
            }
        }
        step("background work") { agent.ensureBackgroundWork() }
        // Any start of the process (notifications companion calling its provider, command alarm, worker…)
        // brings the agent service back at once if it should run, instead of at the next maintenance pass.
        // Allowed from the background for a Device Owner; otherwise refused and logged by AgentService.start.
        // Checked a little later so that a boot, update or app start keeps its own reason in agent.started.
        step("service watchdog") {
            android.os.Handler(mainLooper).postDelayed({
                try {
                    if (agent.settings[CoreSettings.AGENT_ENABLED] && !AgentService.running.value && !AgentService.startRequested) {
                        AgentService.start(this, AgentService.REASON_WATCHDOG)
                    }
                } catch (e: Exception) {
                    Log.w(TAG, "service watchdog failed", e)
                }
            }, WATCHDOG_DELAY_MS)
        }
    }

    private inline fun <T> step(name: String, block: () -> T): T? = try {
        block()
    } catch (e: Exception) {
        Log.e(TAG, "start-up step failed: $name", e)
        if (startupError == null) startupError = "$name : ${e.javaClass.simpleName} ${e.message.orEmpty()}".trim()
        null
    }

    companion object {
        private const val TAG = "Vigie"
        private const val WATCHDOG_DELAY_MS = 3_000L

        /** First start-up failure of this process, null when everything started. */
        @Volatile
        var startupError: String? = null
            private set
    }
}
