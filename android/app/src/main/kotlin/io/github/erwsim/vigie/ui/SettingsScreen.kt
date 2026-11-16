package io.github.erwsim.vigie.ui

import android.content.pm.ApplicationInfo
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.selectableGroup
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import io.github.erwsim.vigie.BuildConfig
import io.github.erwsim.vigie.R
import io.github.erwsim.vigie.core.Agent
import io.github.erwsim.vigie.core.settings.AgentSettings
import io.github.erwsim.vigie.core.settings.CoreSettings
import io.github.erwsim.vigie.core.settings.SettingSpec
import io.github.erwsim.vigie.policy.PolicyModule

private val coreSpecs = listOf(
    SettingSpec.IntSpec(CoreSettings.BUFFER_MAX_MB, R.string.setting_buffer_max, R.string.setting_buffer_max_summary, "Mio"),
    SettingSpec.IntSpec(CoreSettings.BUFFER_MAX_AGE_DAYS, R.string.setting_buffer_age, R.string.setting_buffer_age_summary, "j"),
    SettingSpec.IntSpec(CoreSettings.UPLOAD_INTERVAL_MIN, R.string.setting_upload_interval, R.string.setting_upload_interval_summary, "min"),
    SettingSpec.BoolSpec(CoreSettings.WIFI_ONLY_LARGE, R.string.setting_wifi_only, R.string.setting_wifi_only_summary),
    SettingSpec.IntSpec(CoreSettings.LARGE_THRESHOLD_MB, R.string.setting_large_threshold, R.string.setting_large_threshold_summary, "Mio"),
)

/** Local settings only: nothing here can be changed by the server. Each change emits `agent.config_changed`. */
@Composable
fun SettingsScreen(agent: Agent, resumeTick: Int, modifier: Modifier, navigate: (Screen) -> Unit) {
    val context = LocalContext.current
    var changeTick by remember { mutableIntStateOf(0) }
    LaunchedEffect(Unit) { agent.settings.changes.collect { changeTick++ } }
    val tick = resumeTick + changeTick
    val testOnly = remember { context.applicationInfo.flags and ApplicationInfo.FLAG_TEST_ONLY != 0 }

    Column(
        modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        SectionCard(stringResource(R.string.settings_buffer_title)) {
            coreSpecs.forEach { SettingRow(agent.settings, it, tick) }
        }
        SectionCard(stringResource(R.string.nav_collectors)) {
            Text(stringResource(R.string.settings_collectors_hint), style = MaterialTheme.typography.bodySmall)
            OutlinedButton(onClick = { navigate(Screen.Collectors) }) { Text(stringResource(R.string.action_open)) }
        }
        SectionCard(stringResource(R.string.settings_owner_title)) {
            PolicyModule.settings.forEach { SettingRow(agent.settings, it, tick) }
            OutlinedButton(onClick = { navigate(Screen.Policy) }) { Text(stringResource(R.string.screen_policy)) }
        }
        SectionCard(stringResource(R.string.screen_commands)) {
            Text(stringResource(R.string.cmd_intro), style = MaterialTheme.typography.bodySmall)
            OutlinedButton(onClick = { navigate(Screen.Commands) }) { Text(stringResource(R.string.action_open)) }
        }
        SectionCard(stringResource(R.string.screen_enrollment)) {
            Text(stringResource(R.string.settings_enrollment_summary), style = MaterialTheme.typography.bodySmall)
            OutlinedButton(onClick = { navigate(Screen.Enrollment) }) { Text(stringResource(R.string.action_open)) }
        }
        SectionCard(stringResource(R.string.settings_about_title)) {
            StatusLine(stringResource(R.string.settings_version), "${BuildConfig.VERSION_NAME} (${BuildConfig.VERSION_CODE})")
            StatusLine(stringResource(R.string.settings_build_type), BuildConfig.BUILD_TYPE)
            StatusLine(
                stringResource(R.string.settings_test_only),
                stringResource(if (testOnly) R.string.yes else R.string.no),
                if (testOnly) Tone.NEUTRAL else Tone.WARN,
            )
            Text(stringResource(R.string.settings_test_only_summary), style = MaterialTheme.typography.bodySmall)
        }
    }
}

/** Generic rendering of a [SettingSpec] (used for core, collector and policy settings). */
@Composable
fun SettingRow(settings: AgentSettings, spec: SettingSpec, tick: Int) {
    when (spec) {
        is SettingSpec.BoolSpec -> {
            var value by remember(tick) { mutableStateOf(settings[spec.key]) }
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                SettingTexts(spec, Modifier.weight(1f))
                Switch(checked = value, onCheckedChange = {
                    value = it
                    settings.set(spec.key, it)
                })
            }
        }
        is SettingSpec.IntSpec -> {
            val value = remember(tick) { settings[spec.key] }
            var editing by remember { mutableStateOf(false) }
            Row(
                Modifier.fillMaxWidth().clickable { editing = true }.padding(vertical = 4.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                SettingTexts(spec, Modifier.weight(1f))
                Text("$value ${spec.unit}".trim(), style = MaterialTheme.typography.titleSmall)
            }
            if (editing) {
                IntSettingDialog(spec, value, onDismiss = { editing = false }) {
                    settings.set(spec.key, it)
                    editing = false
                }
            }
        }
        is SettingSpec.ChoiceSpec -> {
            var value by remember(tick) { mutableStateOf(settings[spec.key]) }
            Column(Modifier.fillMaxWidth().selectableGroup()) {
                SettingTexts(spec, Modifier.fillMaxWidth())
                spec.options.forEach { option ->
                    Row(
                        Modifier
                            .fillMaxWidth()
                            .selectable(selected = value == option.value, role = Role.RadioButton) {
                                value = option.value
                                settings.set(spec.key, option.value)
                            }
                            .padding(vertical = 4.dp),
                        verticalAlignment = Alignment.Top,
                    ) {
                        RadioButton(selected = value == option.value, onClick = null)
                        Column(Modifier.padding(start = 8.dp)) {
                            Text(stringResource(option.labelRes), style = MaterialTheme.typography.bodyMedium)
                            option.descriptionRes?.let { Text(stringResource(it), style = MaterialTheme.typography.bodySmall) }
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun SettingTexts(spec: SettingSpec, modifier: Modifier) {
    Column(modifier.padding(end = 8.dp)) {
        Text(stringResource(spec.titleRes), style = MaterialTheme.typography.bodyLarge)
        if (spec.experimental) {
            Text(stringResource(R.string.setting_experimental), color = toneColor(Tone.WARN), style = MaterialTheme.typography.labelMedium)
        }
        spec.summaryRes?.let { Text(stringResource(it), style = MaterialTheme.typography.bodySmall) }
    }
}

@Composable
private fun IntSettingDialog(spec: SettingSpec.IntSpec, current: Int, onDismiss: () -> Unit, onConfirm: (Int) -> Unit) {
    var text by remember { mutableStateOf(current.toString()) }
    val parsed = text.toIntOrNull()
    val valid = parsed != null && parsed in spec.key.min..spec.key.max
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(spec.titleRes)) },
        text = {
            OutlinedTextField(
                value = text,
                onValueChange = { text = it.filter(Char::isDigit).take(6) },
                singleLine = true,
                isError = !valid,
                suffix = { Text(spec.unit) },
                supportingText = { Text(stringResource(R.string.setting_range, spec.key.min, spec.key.max)) },
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
            )
        },
        confirmButton = {
            TextButton(enabled = valid, onClick = { parsed?.let(onConfirm) }) { Text(stringResource(R.string.action_save)) }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.action_cancel)) } },
    )
}
