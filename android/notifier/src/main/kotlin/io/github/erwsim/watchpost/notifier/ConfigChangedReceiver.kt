package io.github.erwsim.watchpost.notifier

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import io.github.erwsim.watchpost.notifier.protocol.NotifierProtocol

/**
 * "The notification settings changed" from the agent (its sender must hold the signature
 * permission). Carries nothing: the settings are read again from the agent before the next report.
 */
class ConfigChangedReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action == NotifierProtocol.ACTION_CONFIG_CHANGED) Relay.invalidateConfig()
    }
}
