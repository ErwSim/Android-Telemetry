package io.github.erwsim.watchpost.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import io.github.erwsim.watchpost.R
import io.github.erwsim.watchpost.core.Agent
import io.github.erwsim.watchpost.core.command.ChannelMode
import io.github.erwsim.watchpost.core.command.ChannelPhase
import io.github.erwsim.watchpost.core.command.CommandSettings
import io.github.erwsim.watchpost.core.command.RemoteCommands
import io.github.erwsim.watchpost.core.settings.SettingSpec
import io.github.erwsim.watchpost.policy.PolicyModule
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

private val modeSpec = SettingSpec.ChoiceSpec(
    CommandSettings.MODE,
    R.string.cmd_mode,
    R.string.cmd_mode_summary,
    options = listOf(
        SettingSpec.ChoiceSpec.Option(ChannelMode.STREAM.wire, R.string.cmd_mode_stream, R.string.cmd_mode_stream_desc),
        SettingSpec.ChoiceSpec.Option(ChannelMode.POLL.wire, R.string.cmd_mode_poll, R.string.cmd_mode_poll_desc),
    ),
)
private val pollSpec = SettingSpec.IntSpec(CommandSettings.POLL_INTERVAL_MIN, R.string.cmd_poll_interval, null, "min")
private val enabledSpec = SettingSpec.BoolSpec(CommandSettings.ENABLED, R.string.cmd_enabled, R.string.cmd_enabled_summary)

/**
 * "Remote commands": channel switch and mode, connection state, command passphrase, remote wipe
 * permission (explicit confirmation), lock-screen message, local history. Everything here is local:
 * no command can change any of it.
 */
@Composable
fun CommandsScreen(agent: Agent, resumeTick: Int, modifier: Modifier) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var changeTick by remember { mutableIntStateOf(0) }
    LaunchedEffect(Unit) { agent.settings.changes.collect { changeTick++ } }
    var localTick by remember { mutableIntStateOf(0) }
    val tick = resumeTick + changeTick + localTick
    val channel by agent.commands.channel.channelState.collectAsStateWithLifecycle()
    val history by agent.commands.state.history.collectAsStateWithLifecycle()
    val enrollment by agent.enrollment.state.collectAsStateWithLifecycle()
    val keyDevice by agent.commands.keys.configuredFor.collectAsStateWithLifecycle()
    val enabled = remember(tick) { agent.settings[CommandSettings.ENABLED] }
    val mode = remember(tick) { agent.settings[CommandSettings.MODE] }
    val wipeAllowed = remember(tick) { agent.settings[CommandSettings.ALLOW_WIPE] }
    val deviceOwner = remember(tick) { agent.capabilities.isDeviceOwner() }
    val lockMessage = remember(tick) { if (deviceOwner) PolicyModule.lockScreenMessage(agent) else null }
    val codeConfigured = enrollment != null && keyDevice == enrollment?.deviceId

    Column(
        modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text(stringResource(R.string.cmd_intro), style = MaterialTheme.typography.bodyMedium)

        SectionCard(stringResource(R.string.cmd_section_channel)) {
            SettingRow(agent.settings, enabledSpec, tick)
            if (enabled) {
                SettingRow(agent.settings, modeSpec, tick)
                if (mode == ChannelMode.POLL.wire) SettingRow(agent.settings, pollSpec, tick)
            }
            val ok = channel.phase == ChannelPhase.CONNECTED || channel.phase == ChannelPhase.POLL_IDLE
            StatusLine(
                stringResource(R.string.cmd_state),
                stringResource(CommandLabels.phase(channel.phase)),
                when {
                    !enabled -> Tone.NEUTRAL
                    ok -> Tone.OK
                    channel.phase == ChannelPhase.REFUSED || channel.phase == ChannelPhase.UNSUPPORTED -> Tone.ERROR
                    else -> Tone.WARN
                },
            )
            if (enabled) {
                if (channel.lastContactMs > 0) StatusLine(stringResource(R.string.cmd_last_contact), Format.ago(channel.lastContactMs))
                channel.lastError?.let { StatusLine(stringResource(R.string.cmd_last_error), it, Tone.WARN) }
                if (channel.nextAttemptAtMs > System.currentTimeMillis()) {
                    StatusLine(stringResource(R.string.cmd_next_attempt), Format.clock(channel.nextAttemptAtMs))
                }
                OutlinedButton(onClick = { agent.commands.channel.onConfigChanged() }) { Text(stringResource(R.string.cmd_reconnect)) }
            }
        }

        CodeSection(agent, enrolled = enrollment != null, codeConfigured = codeConfigured, staleKey = keyDevice != null && !codeConfigured) {
            localTick++
        }

        SectionCard(stringResource(R.string.cmd_section_wipe)) {
            var confirming by remember { mutableStateOf(false) }
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f).padding(end = 8.dp)) {
                    Text(stringResource(R.string.cmd_wipe_allow), style = MaterialTheme.typography.bodyLarge)
                    Text(stringResource(R.string.cmd_wipe_summary), style = MaterialTheme.typography.bodySmall)
                }
                Switch(
                    checked = wipeAllowed,
                    enabled = wipeAllowed || codeConfigured,
                    onCheckedChange = { on -> if (on) confirming = true else agent.settings.set(CommandSettings.ALLOW_WIPE, false) },
                )
            }
            if (!codeConfigured && !wipeAllowed) Text(stringResource(R.string.cmd_wipe_needs_code), style = MaterialTheme.typography.bodySmall, color = toneColor(Tone.WARN))
            if (confirming) {
                WipeConfirmDialog(onDismiss = { confirming = false }) {
                    agent.settings.set(CommandSettings.ALLOW_WIPE, true)
                    confirming = false
                }
            }
        }

        SectionCard(stringResource(R.string.cmd_section_lock_message)) {
            if (!deviceOwner) {
                Text(stringResource(R.string.cmd_lock_message_needs_owner), style = MaterialTheme.typography.bodySmall)
            } else if (lockMessage.isNullOrBlank()) {
                Text(stringResource(R.string.cmd_lock_message_none), style = MaterialTheme.typography.bodySmall)
            } else {
                Text("“$lockMessage”", style = MaterialTheme.typography.bodyMedium)
                OutlinedButton(onClick = {
                    scope.launch {
                        withContext(Dispatchers.IO) { PolicyModule.clearLockScreenMessage(agent) }
                        localTick++
                    }
                }) { Text(stringResource(R.string.cmd_lock_message_clear)) }
            }
        }

        SectionCard(stringResource(R.string.cmd_section_history)) {
            if (history.isEmpty()) Text(stringResource(R.string.cmd_history_empty), style = MaterialTheme.typography.bodySmall)
            history.forEachIndexed { i, e ->
                if (i > 0) HorizontalDivider()
                val tone = when (e.status) {
                    "executed" -> Tone.OK
                    "failed" -> Tone.WARN
                    else -> Tone.ERROR
                }
                StatusLine(
                    stringResource(CommandLabels.type(e.type)),
                    stringResource(CommandLabels.status(e.status)) + if (e.signed) " · " + stringResource(R.string.cmd_history_signed) else "",
                    tone,
                )
                Text(
                    Format.dateTime(e.atMs) + (CommandLabels.detail(context, e.status, e.detail)?.let { " — $it" } ?: ""),
                    style = MaterialTheme.typography.bodySmall,
                )
            }
        }
    }
}

@Composable
private fun CodeSection(agent: Agent, enrolled: Boolean, codeConfigured: Boolean, staleKey: Boolean, onChanged: () -> Unit) {
    val scope = rememberCoroutineScope()
    var code by remember { mutableStateOf("") }
    var confirm by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var message by remember { mutableStateOf<Int?>(null) }
    var editing by remember { mutableStateOf(false) }
    SectionCard(stringResource(R.string.cmd_section_code)) {
        Text(stringResource(R.string.cmd_code_explain), style = MaterialTheme.typography.bodySmall)
        when {
            !enrolled -> StatusLine(stringResource(R.string.cmd_state), stringResource(R.string.cmd_code_not_enrolled), Tone.WARN)
            codeConfigured -> StatusLine(stringResource(R.string.cmd_state), stringResource(R.string.cmd_code_set, Format.dateTime(agent.commands.keys.setAtMs())), Tone.OK)
            staleKey -> StatusLine(stringResource(R.string.cmd_state), stringResource(R.string.cmd_code_stale), Tone.WARN)
            else -> StatusLine(stringResource(R.string.cmd_state), stringResource(R.string.cmd_code_unset), Tone.WARN)
        }
        if (enrolled && (editing || !codeConfigured)) {
            OutlinedTextField(
                value = code,
                onValueChange = { code = it.take(256) },
                label = { Text(stringResource(R.string.cmd_code_field)) },
                singleLine = true,
                visualTransformation = PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password, autoCorrectEnabled = false),
                modifier = Modifier.fillMaxWidth(),
            )
            OutlinedTextField(
                value = confirm,
                onValueChange = { confirm = it.take(256) },
                label = { Text(stringResource(R.string.cmd_code_confirm)) },
                singleLine = true,
                visualTransformation = PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password, autoCorrectEnabled = false),
                modifier = Modifier.fillMaxWidth(),
            )
            Button(enabled = !busy && code.isNotEmpty(), onClick = {
                busy = true
                message = R.string.cmd_code_saving
                scope.launch {
                    val result = withContext(Dispatchers.Default) { agent.commands.setCode(code, confirm) }
                    busy = false
                    message = when (result) {
                        RemoteCommands.CodeResult.Saved -> R.string.cmd_code_saved
                        RemoteCommands.CodeResult.TooShort -> R.string.cmd_code_too_short
                        RemoteCommands.CodeResult.TooWeak -> R.string.cmd_code_too_weak
                        RemoteCommands.CodeResult.Mismatch -> R.string.cmd_code_mismatch
                        RemoteCommands.CodeResult.NotEnrolled -> R.string.cmd_code_not_enrolled
                    }
                    if (result == RemoteCommands.CodeResult.Saved) {
                        // The code is not kept anywhere, not even in this screen.
                        code = ""
                        confirm = ""
                        editing = false
                        onChanged()
                    }
                }
            }) { Text(stringResource(R.string.cmd_code_save)) }
        }
        message?.let { Text(stringResource(it), style = MaterialTheme.typography.bodySmall) }
        if (codeConfigured && !editing) {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(onClick = { editing = true }) { Text(stringResource(R.string.cmd_code_change)) }
                OutlinedButton(onClick = {
                    scope.launch {
                        withContext(Dispatchers.IO) { agent.commands.clearCode() }
                        message = R.string.cmd_code_deleted
                        onChanged()
                    }
                }) { Text(stringResource(R.string.cmd_code_delete)) }
            }
        }
    }
}

@Composable
private fun WipeConfirmDialog(onDismiss: () -> Unit, onConfirm: () -> Unit) {
    var typed by remember { mutableStateOf("") }
    val word = stringResource(R.string.cmd_wipe_confirm_word)
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.cmd_wipe_confirm_title)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(stringResource(R.string.cmd_wipe_confirm_text))
                OutlinedTextField(value = typed, onValueChange = { typed = it.take(20) }, singleLine = true)
            }
        },
        confirmButton = {
            TextButton(enabled = typed.trim() == word, onClick = onConfirm) { Text(stringResource(R.string.cmd_wipe_confirm_action)) }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.action_cancel)) } },
    )
}
