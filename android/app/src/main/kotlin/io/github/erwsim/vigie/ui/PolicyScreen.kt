package io.github.erwsim.vigie.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import io.github.erwsim.vigie.R
import io.github.erwsim.vigie.core.Agent
import io.github.erwsim.vigie.policy.PolicyModule

/**
 * Placeholder for the policy screen of the `:policy` module (private DNS, package profiles,
 * restrictions, "undo everything"). The next lot replaces the body of this composable.
 */
@Composable
fun PolicyScreen(agent: Agent, resumeTick: Int, modifier: Modifier) {
    val manager = remember { PolicyModule.deviceOwner(agent) }
    val deviceOwner = remember(resumeTick) { manager.isDeviceOwner() }
    val protected = remember(resumeTick) { manager.isForceStopProtected() }
    Column(
        modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        SectionCard(stringResource(R.string.screen_policy)) {
            StatusLine(
                stringResource(R.string.home_device_owner),
                stringResource(if (deviceOwner) R.string.yes else R.string.no),
                if (deviceOwner) Tone.OK else Tone.WARN,
            )
            StatusLine(
                stringResource(R.string.home_force_stop_protection),
                stringResource(if (protected) R.string.state_active else R.string.state_inactive),
            )
            Text(stringResource(R.string.policy_placeholder), style = MaterialTheme.typography.bodyMedium)
        }
        SectionCard(stringResource(R.string.policy_removal_title)) {
            Text(stringResource(R.string.policy_removal), style = MaterialTheme.typography.bodySmall)
        }
    }
}
