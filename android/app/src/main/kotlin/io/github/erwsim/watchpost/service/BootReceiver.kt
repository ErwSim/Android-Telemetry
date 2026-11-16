package io.github.erwsim.watchpost.service

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import io.github.erwsim.watchpost.core.Agent
import io.github.erwsim.watchpost.core.settings.CoreSettings

/**
 * Starts the agent after boot and after an update of the app. `BOOT_COMPLETED` is allowed to
 * start `location`/`specialUse` foreground services. Direct Boot (before the first unlock) is not
 * used: the buffer and the enrollment live in credential-encrypted storage.
 */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val reason = when (intent.action) {
            Intent.ACTION_BOOT_COMPLETED -> AgentService.REASON_BOOT
            Intent.ACTION_MY_PACKAGE_REPLACED -> AgentService.REASON_UPDATE
            else -> return
        }
        val agent = Agent.getOrNull() ?: return
        agent.ensureBackgroundWork()
        if (agent.settings[CoreSettings.AGENT_ENABLED]) AgentService.start(context, reason)
    }
}
