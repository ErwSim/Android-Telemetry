package io.github.erwsim.vigie.ui

import android.Manifest
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import io.github.erwsim.vigie.R
import io.github.erwsim.vigie.core.Agent
import io.github.erwsim.vigie.core.collector.CollectorHost
import io.github.erwsim.vigie.core.collector.CollectorRunState
import io.github.erwsim.vigie.core.collector.Requirement
import io.github.erwsim.vigie.service.AgentService

/**
 * Every collector of every module (`:collectors` then `:policy`, in their entry-point order) with
 * its switch, its state (and why it is unavailable), what it collects, its own settings, and marks
 * for "off by default", "Device Owner required" and experimental settings.
 */
@Composable
fun CollectorsScreen(agent: Agent, resumeTick: Int, modifier: Modifier) {
    val context = LocalContext.current
    val statuses by agent.host.statuses.collectAsStateWithLifecycle()
    var localTick by remember { mutableIntStateOf(0) }
    val tick = resumeTick + localTick
    LaunchedEffect(Unit) { agent.settings.changes.collect { localTick++ } }
    val launcher = rememberLauncherForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) {
        localTick++
        agent.integrity.checkPermissionsAndOwnership()
        agent.host.reconcile()
        AgentService.refresh(context)
    }

    LazyColumn(
        modifier.fillMaxSize(),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        item {
            Text(stringResource(R.string.collectors_intro), style = MaterialTheme.typography.bodyMedium)
        }
        items(agent.host.collectors, key = { it.id }) { collector ->
            val status = statuses[collector.id]
            val enabled = remember(tick, status) { agent.host.isEnabled(collector) }
            val missing = remember(tick, status) {
                collector.requirements.filterIsInstance<Requirement.Permission>()
                    .map { it.name }
                    .filterNot(agent.capabilities::hasPermission)
            }
            SectionCard(stringResource(collector.titleRes)) {
                val marks = buildList {
                    if (!collector.defaultEnabled) add(stringResource(R.string.collectors_default_off))
                    if (collector.requirements.any { it is Requirement.DeviceOwner }) add(stringResource(R.string.collectors_requires_owner))
                    if (collector.settings.any { it.experimental }) add(stringResource(R.string.collectors_has_experimental))
                }
                if (marks.isNotEmpty()) {
                    Text(marks.joinToString(" · "), color = toneColor(Tone.WARN), style = MaterialTheme.typography.labelMedium)
                }
                Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                    val (label, tone) = when (status?.state) {
                        CollectorRunState.RUNNING -> stringResource(R.string.state_running) to Tone.OK
                        CollectorRunState.UNAVAILABLE -> stringResource(R.string.state_unavailable) to Tone.ERROR
                        else -> stringResource(if (enabled) R.string.state_waiting else R.string.state_disabled) to Tone.NEUTRAL
                    }
                    Text(label, color = toneColor(tone), style = MaterialTheme.typography.labelLarge, modifier = Modifier.weight(1f))
                    Switch(checked = enabled, onCheckedChange = {
                        agent.host.setEnabled(collector.id, it)
                        localTick++
                    })
                }
                status?.reason?.let { Text(it, color = toneColor(Tone.ERROR), style = MaterialTheme.typography.bodySmall) }
                Text(stringResource(collector.descriptionRes), style = MaterialTheme.typography.bodyMedium)
                Column {
                    Text(stringResource(R.string.collectors_event_types), style = MaterialTheme.typography.labelMedium)
                    Text(
                        collector.eventTypes.joinToString(", "),
                        style = MaterialTheme.typography.bodySmall,
                        fontFamily = FontFamily.Monospace,
                    )
                }
                if (missing.isNotEmpty()) {
                    Text(
                        stringResource(R.string.collectors_missing, missing.joinToString { CollectorHost.shortName(it) }),
                        style = MaterialTheme.typography.bodySmall,
                    )
                    // Background location must be requested on its own, after foreground location.
                    val foreground = missing - Manifest.permission.ACCESS_BACKGROUND_LOCATION
                    OutlinedButton(onClick = {
                        launcher.launch((foreground.ifEmpty { missing }).toTypedArray())
                    }) { Text(stringResource(R.string.action_grant)) }
                }
                status?.lastError?.let {
                    Text(stringResource(R.string.collectors_last_error, it), style = MaterialTheme.typography.bodySmall, color = toneColor(Tone.WARN))
                }
                if (collector.settings.isNotEmpty()) {
                    HorizontalDivider()
                    Text(stringResource(R.string.collectors_settings), style = MaterialTheme.typography.labelMedium)
                    // A change restarts the collector (CollectorHost) and emits agent.config_changed.
                    collector.settings.forEach { SettingRow(agent.settings, it, tick) }
                }
            }
        }
    }
}
