package io.github.erwsim.watchpost.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import io.github.erwsim.watchpost.R
import io.github.erwsim.watchpost.collectors.risk.PackageManagerFactsSource
import io.github.erwsim.watchpost.collectors.risk.RiskAssessment
import io.github.erwsim.watchpost.collectors.risk.RiskLevel
import io.github.erwsim.watchpost.collectors.risk.RiskScorer
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import io.github.erwsim.watchpost.core.Agent
import io.github.erwsim.watchpost.policy.PolicyModule
import io.github.erwsim.watchpost.policy.engine.CapabilityGuards
import io.github.erwsim.watchpost.policy.engine.GuardKey
import io.github.erwsim.watchpost.policy.engine.GuardPreview
import io.github.erwsim.watchpost.policy.ui.PolicyController
import io.github.erwsim.watchpost.policy.ui.PolicyUiState

/** Texts of one guard (contract §11.1): what it blocks, what it can break, what it cannot prevent. */
private data class GuardTexts(val title: Int, val blocks: Int, val breaks: Int, val limits: Int, val extended: Int? = null, val extendedDesc: Int? = null)

private fun texts(key: GuardKey): GuardTexts = when (key) {
    GuardKey.SMS -> GuardTexts(R.string.guard_sms_title, R.string.guard_sms_blocks, R.string.guard_sms_breaks, R.string.guard_sms_limits, R.string.guard_sms_extended, R.string.guard_sms_extended_desc)
    GuardKey.CALLS -> GuardTexts(R.string.guard_calls_title, R.string.guard_calls_blocks, R.string.guard_calls_breaks, R.string.guard_calls_limits, R.string.guard_calls_extended, R.string.guard_calls_extended_desc)
    GuardKey.ACCESSIBILITY -> GuardTexts(R.string.guard_accessibility_title, R.string.guard_accessibility_blocks, R.string.guard_accessibility_breaks, R.string.guard_accessibility_limits)
    GuardKey.INPUT_METHODS -> GuardTexts(R.string.guard_input_methods_title, R.string.guard_input_methods_blocks, R.string.guard_input_methods_breaks, R.string.guard_input_methods_limits)
    GuardKey.QUARANTINE -> GuardTexts(R.string.guard_quarantine_title, R.string.guard_quarantine_blocks, R.string.guard_quarantine_breaks, R.string.guard_quarantine_limits)
}

/** Order of the cards: from the least to the most risky to try. */
val GUARD_ORDER = listOf(GuardKey.QUARANTINE, GuardKey.INPUT_METHODS, GuardKey.ACCESSIBILITY, GuardKey.CALLS, GuardKey.SMS)

@Composable
fun GuardsIntroCard() {
    SectionCard(stringResource(R.string.guards_title)) {
        Text(stringResource(R.string.guards_intro), style = MaterialTheme.typography.bodySmall)
        Text(stringResource(R.string.guards_order), style = MaterialTheme.typography.bodySmall, color = toneColor(Tone.WARN))
    }
}

/** One guard: what it does, its option and list, its state, preview buttons. */
@Composable
fun GuardCard(agent: Agent, key: GuardKey, state: PolicyUiState, controller: PolicyController, navigate: (Screen) -> Unit, tick: Int) {
    val t = texts(key)
    val status = state.guards[key]
    val active = status?.active == true
    var edits by remember { mutableIntStateOf(0) }
    SectionCard(stringResource(t.title)) {
        Text(stringResource(R.string.guard_blocks, stringResource(t.blocks)), style = MaterialTheme.typography.bodySmall)
        Text(stringResource(R.string.guard_breaks, stringResource(t.breaks)), style = MaterialTheme.typography.bodySmall, color = toneColor(Tone.WARN))
        Text(stringResource(t.limits), style = MaterialTheme.typography.bodySmall)
        HorizontalDivider()
        when {
            status?.pending == true -> Text(stringResource(R.string.guard_state_pending), color = toneColor(Tone.WARN), style = MaterialTheme.typography.bodyMedium)
            active -> Text(stringResource(R.string.guard_state_on, Format.dateTime(status.activatedAtMs)), color = toneColor(Tone.OK), style = MaterialTheme.typography.bodyMedium)
            else -> Text(stringResource(R.string.guard_state_off), style = MaterialTheme.typography.bodyMedium)
        }
        status?.lastError?.let { Text(stringResource(R.string.policy_item_error, it), color = toneColor(Tone.ERROR), style = MaterialTheme.typography.bodySmall) }
        if (active && key.perPackage && key != GuardKey.QUARANTINE) {
            Text(stringResource(R.string.guard_apps_count, status.packages.count { r -> r.permissions.any { it.applied } }), style = MaterialTheme.typography.bodySmall)
        }
        if (active && status.permitted != null) {
            Text(stringResource(R.string.guard_permitted, status.permitted.orEmpty().joinToString().ifEmpty { stringResource(R.string.guard_preview_system_only) }), style = MaterialTheme.typography.bodySmall)
        }
        val failures = status?.packages.orEmpty().flatMap { r -> r.permissions.filter { !it.applied }.map { "${r.target} (${CapabilityGuards.short(it.permission)})" } }
        if (failures.isNotEmpty()) Text(stringResource(R.string.guard_failures, failures.joinToString()), color = toneColor(Tone.ERROR), style = MaterialTheme.typography.bodySmall)
        if (!active && status != null && status.packages.isNotEmpty()) {
            Text(stringResource(R.string.guard_leftovers, status.packages.size), color = toneColor(Tone.WARN), style = MaterialTheme.typography.bodySmall)
            status.packages.forEach { r ->
                AppRow(r.target, note = r.permissions.joinToString { CapabilityGuards.short(it.permission) }) {
                    OutlinedButton(enabled = !state.busy, onClick = { controller.revert(r.id) }) { Text(stringResource(R.string.policy_item_restore)) }
                }
            }
        }
        // Option and list: pending choices, applied with "Aperçu et (ré)application".
        if (key.hasExtended && t.extended != null) {
            var extended by remember(tick, edits) { mutableStateOf(controller.guardExtended(key)) }
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f).padding(end = 8.dp)) {
                    Text(stringResource(t.extended), style = MaterialTheme.typography.bodyLarge)
                    t.extendedDesc?.let { Text(stringResource(it), style = MaterialTheme.typography.bodySmall) }
                }
                Switch(checked = extended, enabled = !state.busy, onCheckedChange = {
                    extended = it
                    controller.setGuardExtended(key, it)
                    edits++
                })
            }
        }
        PolicyModule.GUARD_LIST_SPECS[key]?.let { spec ->
            val roles = state.roles
            val locked = when (key) {
                GuardKey.SMS -> setOfNotNull(roles.sms)
                GuardKey.CALLS -> setOfNotNull(roles.dialer, roles.systemDialer)
                else -> emptySet()
            }
            PackageListRow(agent.settings, spec.copy(locked = { locked }), tick) { edits++ }
        }
        val changed = remember(tick, edits, status) {
            active && key.hasList && (controller.guardList(key) != status!!.allowed.toSet() || (key.hasExtended && controller.guardExtended(key) != status.extended))
        }
        if (changed) Text(stringResource(R.string.guard_changed), color = toneColor(Tone.WARN), style = MaterialTheme.typography.bodySmall)
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            if (!active || key != GuardKey.QUARANTINE) {
                Button(enabled = !state.busy && state.deviceOwner, onClick = { controller.previewGuard(key, true) }) {
                    Text(stringResource(if (active) R.string.guard_reapply else R.string.guard_enable))
                }
            }
            if (active || status?.pending == true) {
                OutlinedButton(enabled = !state.busy, onClick = { controller.previewGuard(key, false) }) { Text(stringResource(R.string.guard_disable)) }
            }
        }
        if (key == GuardKey.QUARANTINE && (active || state.quarantined.isNotEmpty())) {
            TextButton(onClick = { navigate(Screen.Quarantine) }) { Text(stringResource(R.string.guard_open_quarantine, state.quarantined.size)) }
        }
    }
}

/** "Ce qui va changer" for a guard: exactly which apps lose or regain what. */
@Composable
fun GuardPreviewDialog(preview: GuardPreview, onDismiss: () -> Unit, onApply: () -> Unit) {
    val title = stringResource(texts(preview.key).title)
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(if (preview.enable) R.string.guard_preview_title_on else R.string.guard_preview_title_off, title)) },
        text = {
            Column(Modifier.heightIn(max = 480.dp).verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                val changes = preview.lines.filter { it.deny.isNotEmpty() || it.restore.isNotEmpty() }
                if (preview.key.perPackage && changes.isEmpty()) Text(stringResource(R.string.guard_preview_nobody))
                preview.lines.forEach { line ->
                    val parts = listOfNotNull(
                        stringResource(R.string.guard_preview_loses, line.deny.joinToString { CapabilityGuards.short(it) }).takeIf { line.deny.isNotEmpty() },
                        stringResource(R.string.guard_preview_regains, line.restore.joinToString { CapabilityGuards.short(it) }).takeIf { line.restore.isNotEmpty() },
                        line.note,
                    )
                    AppRow(line.pkg, note = parts.joinToString(" · "))
                }
                if (preview.exempt.isNotEmpty()) {
                    HorizontalDivider()
                    Text(stringResource(R.string.guard_preview_exempt, ""), style = MaterialTheme.typography.labelLarge)
                    preview.exempt.forEach { (pkg, reason) -> AppRow(pkg, note = reason) }
                }
                if (preview.kept.isNotEmpty()) Text(stringResource(R.string.guard_preview_kept, preview.kept.joinToString()), color = toneColor(Tone.WARN), style = MaterialTheme.typography.bodySmall)
                if (preview.blocked.isNotEmpty()) Text(stringResource(R.string.guard_preview_blocked, preview.blocked.joinToString()), style = MaterialTheme.typography.bodySmall)
                if (!preview.key.perPackage) {
                    val list = preview.permitted
                    val shown = when {
                        list == null -> stringResource(R.string.guard_preview_no_list)
                        list.isEmpty() -> stringResource(R.string.guard_preview_system_only)
                        else -> list.joinToString()
                    }
                    Text(stringResource(R.string.guard_preview_permitted, shown), style = MaterialTheme.typography.bodySmall)
                }
                preview.notes.forEach { Text(it, style = MaterialTheme.typography.bodySmall) }
            }
        },
        confirmButton = { TextButton(onClick = onApply) { Text(stringResource(R.string.guard_confirm)) } },
        dismissButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.action_cancel)) } },
    )
}

/**
 * Risk profile of an app (same scoring as `app.risk`, contract §11.2), computed on the phone: helps the owner
 * decide whether to release it. Nothing is shown if the facts cannot be read.
 */
@Composable
private fun RiskSummary(pkg: String) {
    val context = LocalContext.current
    val assessment by produceState<RiskAssessment?>(null, pkg) {
        value = withContext(Dispatchers.IO) {
            try {
                PackageManagerFactsSource.read(context, pkg)?.let(RiskScorer::score)
            } catch (_: Exception) {
                null
            }
        }
    }
    val a = assessment ?: return
    val (level, tone) = when (a.level) {
        RiskLevel.LOW -> R.string.quarantine_risk_low to Tone.NEUTRAL
        RiskLevel.MEDIUM -> R.string.quarantine_risk_medium to Tone.WARN
        RiskLevel.HIGH -> R.string.quarantine_risk_high to Tone.ERROR
    }
    Text(stringResource(R.string.quarantine_risk, stringResource(level), a.score), color = toneColor(tone), style = MaterialTheme.typography.bodyMedium)
    a.reasons.forEach { reason ->
        Text("• ${stringResource(reason.labelRes)} : ${stringResource(reason.descRes)}", style = MaterialTheme.typography.bodySmall)
    }
}

/** "Applications en quarantaine": what is denied to each, its risk profile, and "Libérer". */
@Composable
fun QuarantineScreen(agent: Agent, resumeTick: Int, modifier: Modifier) {
    val controller = remember { PolicyModule.controller(agent) }
    val state by controller.state.collectAsStateWithLifecycle()
    LaunchedEffect(resumeTick) { controller.refresh() }
    val context = LocalContext.current
    var confirm by rememberSaveable { mutableStateOf<String?>(null) }
    LazyColumn(modifier.fillMaxSize(), contentPadding = PaddingValues(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        item {
            SectionCard(stringResource(R.string.screen_quarantine)) {
                Text(stringResource(R.string.quarantine_intro), style = MaterialTheme.typography.bodySmall)
                if (state.guards[GuardKey.QUARANTINE]?.active != true) Text(stringResource(R.string.quarantine_off), color = toneColor(Tone.WARN), style = MaterialTheme.typography.bodySmall)
                if (state.loaded && state.quarantined.isEmpty()) Text(stringResource(R.string.quarantine_empty), style = MaterialTheme.typography.bodyMedium)
            }
        }
        if (state.busy) item { LinearProgressIndicator(Modifier.fillMaxWidth()) }
        state.message?.let { msg -> item { Text(msg, style = MaterialTheme.typography.bodySmall) } }
        items(state.quarantined, key = { it.id }) { r ->
            val denied = r.permissions.filter { it.applied }.map { CapabilityGuards.short(it.permission) }
            SectionCard(Apps.label(context, r.target)) {
                AppRow(
                    r.target,
                    note = listOfNotNull(
                        stringResource(R.string.quarantine_since, Format.dateTime(r.appliedAtMs)),
                        if (denied.isEmpty()) stringResource(R.string.quarantine_nothing) else stringResource(R.string.quarantine_denied, denied.joinToString()),
                        stringResource(R.string.quarantine_absent).takeIf { !Apps.isInstalled(context, r.target) },
                    ).joinToString("\n"),
                )
                r.lastError?.let { Text(stringResource(R.string.policy_item_error, it), color = toneColor(Tone.ERROR), style = MaterialTheme.typography.bodySmall) }
                RiskSummary(r.target)
                Button(enabled = !state.busy, onClick = { confirm = r.target }) { Text(stringResource(R.string.quarantine_release)) }
            }
        }
    }
    confirm?.let { pkg ->
        val record = state.quarantined.firstOrNull { it.target == pkg }
        val denied = record?.permissions?.filter { it.applied }?.joinToString { CapabilityGuards.short(it.permission) }.orEmpty().ifEmpty { "—" }
        AlertDialog(
            onDismissRequest = { confirm = null },
            title = { Text(stringResource(R.string.quarantine_release)) },
            text = { Text(stringResource(R.string.quarantine_release_confirm, "${Apps.label(context, pkg)} ($pkg)", denied)) },
            confirmButton = {
                TextButton(onClick = {
                    confirm = null
                    controller.release(pkg)
                }) { Text(stringResource(R.string.quarantine_release)) }
            },
            dismissButton = { TextButton(onClick = { confirm = null }) { Text(stringResource(R.string.action_cancel)) } },
        )
    }
}
