package io.github.erwsim.vigie.ui

import android.Manifest
import android.annotation.SuppressLint
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.provider.Settings
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import io.github.erwsim.vigie.R
import io.github.erwsim.vigie.core.Agent
import io.github.erwsim.vigie.core.collector.CollectorRunState
import io.github.erwsim.vigie.core.settings.CoreSettings
import io.github.erwsim.vigie.policy.PolicyModule
import io.github.erwsim.vigie.service.AgentService

/** Honest overview: what runs, what is pending, what is wrong. */
@Composable
fun HomeScreen(agent: Agent, resumeTick: Int, modifier: Modifier, navigate: (Screen) -> Unit) {
    val context = LocalContext.current
    val running by AgentService.running.collectAsStateWithLifecycle()
    val totals by agent.outbox.totals.collectAsStateWithLifecycle()
    val upload by agent.uploadStatus.status.collectAsStateWithLifecycle()
    val enrollment by agent.enrollment.state.collectAsStateWithLifecycle()
    val statuses by agent.host.statuses.collectAsStateWithLifecycle()
    val writeError by agent.sink.lastWriteError.collectAsStateWithLifecycle()
    var localTick by remember { mutableIntStateOf(0) }
    val tick = resumeTick + localTick
    var enabled by remember(tick) { mutableStateOf(agent.settings[CoreSettings.AGENT_ENABLED]) }
    val deviceOwner = remember(tick) { agent.capabilities.isDeviceOwner() }
    val forceStopProtected = remember(tick) { PolicyModule.deviceOwner(agent).isForceStopProtected() }
    val notificationsGranted = remember(tick) {
        context.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED
    }
    val batteryExempt = remember(tick) { agent.capabilities.isIgnoringBatteryOptimizations() }
    val notificationLauncher = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { localTick++ }

    Column(
        modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        SectionCard(stringResource(R.string.home_agent_title)) {
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Text(stringResource(R.string.home_agent_switch), Modifier.weight(1f))
                Switch(checked = enabled, onCheckedChange = { on ->
                    enabled = on
                    agent.settings.set(CoreSettings.AGENT_ENABLED, on)
                    if (on) AgentService.start(context, AgentService.REASON_APP) else AgentService.stop(context)
                })
            }
            StatusLine(
                stringResource(R.string.home_service),
                stringResource(if (running) R.string.state_running else R.string.state_stopped),
                if (running) Tone.OK else Tone.ERROR,
            )
            val active = statuses.values.count { it.state == CollectorRunState.RUNNING }
            StatusLine(stringResource(R.string.home_collectors_active), "$active / ${statuses.size}", if (active > 0) Tone.OK else Tone.WARN)
            StatusLine(stringResource(R.string.home_pending), "${totals.count} (${Format.bytes(totals.bytes)})")
        }

        SectionCard(stringResource(R.string.home_server_title)) {
            val e = enrollment
            if (e == null) {
                Text(stringResource(R.string.home_not_enrolled), style = MaterialTheme.typography.bodyMedium)
                Button(onClick = { navigate(Screen.Enrollment) }) { Text(stringResource(R.string.action_enroll)) }
            } else {
                StatusLine(stringResource(R.string.home_server), Uri.parse(e.ingestUrl).host ?: e.ingestUrl)
                StatusLine(stringResource(R.string.home_device), e.deviceName ?: e.deviceId)
                StatusLine(
                    stringResource(R.string.home_last_upload),
                    if (upload.lastSuccessMs > 0) Format.ago(upload.lastSuccessMs) else stringResource(R.string.never),
                    if (upload.lastSuccessMs > 0) Tone.OK else Tone.WARN,
                )
                upload.lastError?.let { StatusLine(stringResource(R.string.home_last_error), it, Tone.ERROR) }
                if (upload.nextAttemptAtMs > System.currentTimeMillis()) {
                    StatusLine(stringResource(R.string.home_next_attempt), Format.clock(upload.nextAttemptAtMs), Tone.WARN)
                }
                if (upload.rejectedTotal > 0) {
                    StatusLine(
                        stringResource(R.string.home_rejected),
                        "${upload.rejectedTotal} (${upload.lastRejectReason.orEmpty()})",
                        Tone.WARN,
                    )
                }
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(onClick = { agent.requestUpload(force = true) }) { Text(stringResource(R.string.action_upload_now)) }
                    OutlinedButton(onClick = { navigate(Screen.Enrollment) }) { Text(stringResource(R.string.action_details)) }
                }
            }
        }

        SectionCard(stringResource(R.string.home_owner_title)) {
            StatusLine(
                stringResource(R.string.home_device_owner),
                stringResource(if (deviceOwner) R.string.yes else R.string.no),
                if (deviceOwner) Tone.OK else Tone.WARN,
            )
            if (deviceOwner) {
                StatusLine(
                    stringResource(R.string.home_force_stop_protection),
                    stringResource(if (forceStopProtected) R.string.state_active else R.string.state_inactive),
                    if (forceStopProtected) Tone.OK else Tone.WARN,
                )
            } else {
                Text(stringResource(R.string.home_degraded_mode), style = MaterialTheme.typography.bodySmall)
            }
            OutlinedButton(onClick = { navigate(Screen.Policy) }) { Text(stringResource(R.string.screen_policy)) }
        }

        SectionCard(stringResource(R.string.home_system_title)) {
            StatusLine(
                stringResource(R.string.home_notifications),
                stringResource(if (notificationsGranted) R.string.state_allowed else R.string.state_denied),
                if (notificationsGranted) Tone.OK else Tone.ERROR,
            )
            if (!notificationsGranted) {
                OutlinedButton(onClick = { notificationLauncher.launch(Manifest.permission.POST_NOTIFICATIONS) }) {
                    Text(stringResource(R.string.action_allow))
                }
            }
            StatusLine(
                stringResource(R.string.home_battery_optimization),
                stringResource(if (batteryExempt) R.string.battery_exempt else R.string.battery_optimized),
                if (batteryExempt) Tone.OK else Tone.WARN,
            )
            if (!batteryExempt) {
                OutlinedButton(onClick = { requestBatteryExemption(context) }) { Text(stringResource(R.string.action_battery_exempt)) }
            }
            Text(stringResource(R.string.home_samsung_sleep_hint), style = MaterialTheme.typography.bodySmall)
        }

        val problems = statuses.mapNotNull { (id, s) -> s.lastError?.let { "$id : $it" } } + listOfNotNull(writeError)
        if (problems.isNotEmpty()) {
            SectionCard(stringResource(R.string.home_errors_title)) {
                problems.forEach { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error) }
            }
        }

        SectionCard(stringResource(R.string.home_transparency_title)) {
            Text(stringResource(R.string.home_transparency), style = MaterialTheme.typography.bodySmall)
        }
    }
}

@SuppressLint("BatteryLife") // Personal agent that must run 24/7: the exemption is explained to the owner.
private fun requestBatteryExemption(context: android.content.Context) {
    try {
        context.startActivity(
            Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS, Uri.parse("package:${context.packageName}")),
        )
    } catch (_: Exception) {
        context.startActivity(Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS))
    }
}
