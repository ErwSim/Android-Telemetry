package io.github.erwsim.vigie

import android.app.Application
import io.github.erwsim.vigie.collectors.CollectorsModule
import io.github.erwsim.vigie.core.Agent
import io.github.erwsim.vigie.core.settings.CoreSettings
import io.github.erwsim.vigie.policy.PolicyModule
import io.github.erwsim.vigie.service.AgentNotifications
import io.github.erwsim.vigie.service.AgentService

/**
 * Wires the modules together: every collector comes from a module entry point, so adding a
 * collector never touches this file.
 */
class VigieApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        val agent = Agent.init(this) { context ->
            CollectorsModule.all(context) + PolicyModule.collectors(context)
        }
        PolicyModule.install(agent)
        AgentNotifications.createChannel(this)
        agent.maintenanceHook = {
            PolicyModule.onAgentStarted(agent)
            if (agent.settings[CoreSettings.AGENT_ENABLED] && !AgentService.running.value) {
                AgentService.start(this, AgentService.REASON_WATCHDOG)
            }
        }
        agent.ensureBackgroundWork()
    }
}
