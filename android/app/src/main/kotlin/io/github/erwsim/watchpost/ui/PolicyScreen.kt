package io.github.erwsim.watchpost.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import io.github.erwsim.watchpost.R
import io.github.erwsim.watchpost.core.Agent
import io.github.erwsim.watchpost.policy.PolicyModule
import io.github.erwsim.watchpost.policy.engine.CatalogItem
import io.github.erwsim.watchpost.policy.engine.ChangeOp
import io.github.erwsim.watchpost.policy.engine.PackageDenyList
import io.github.erwsim.watchpost.policy.engine.PackageEntry
import io.github.erwsim.watchpost.policy.engine.PackageMethod
import io.github.erwsim.watchpost.policy.engine.PermissionEntry
import io.github.erwsim.watchpost.policy.engine.PlannedChange
import io.github.erwsim.watchpost.policy.engine.PolicySelection
import io.github.erwsim.watchpost.policy.engine.Profile
import io.github.erwsim.watchpost.policy.engine.RestrictionEntry
import io.github.erwsim.watchpost.policy.engine.Risk
import io.github.erwsim.watchpost.policy.engine.SettingEntry
import io.github.erwsim.watchpost.policy.ui.PolicyController
import io.github.erwsim.watchpost.policy.ui.PolicyUiState

/**
 * "Policy" screen of the `:policy` module: Device Owner state, profile with preview, per-item
 * switches and undo, private DNS, VPN, action log, "Restore everything" and "Remove Device
 * Owner". Nothing is applied before the user confirms the preview.
 */
@Composable
fun PolicyScreen(agent: Agent, resumeTick: Int, modifier: Modifier, navigate: (Screen) -> Unit = {}) {
    val controller = remember { PolicyModule.controller(agent) }
    val state by controller.state.collectAsStateWithLifecycle()
    LaunchedEffect(resumeTick) { controller.refresh() }
    var confirmRevertAll by rememberSaveable { mutableStateOf(false) }
    var confirmRemove by rememberSaveable { mutableStateOf(false) }
    var offerForce by rememberSaveable { mutableStateOf(false) }

    val catalog = controller.catalog
    val selection = state.selection
    fun visible(item: CatalogItem) = selection.profile.includes(item.profile) || state.applied.containsKey(item.id)

    LazyColumn(
        modifier.fillMaxSize(),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        item { StatusCard(state) }
        if (state.busy) item { LinearProgressIndicator(Modifier.fillMaxWidth()) }
        state.message?.let { msg ->
            item {
                SectionCard(stringResource(R.string.policy_status_title)) {
                    Text(msg, style = MaterialTheme.typography.bodySmall)
                    TextButton(onClick = controller::clearMessage) { Text(stringResource(R.string.policy_close)) }
                }
            }
        }
        if (!state.loaded) return@LazyColumn
        if (!state.deviceOwner) {
            item {
                SectionCard(stringResource(R.string.screen_policy)) {
                    Text(stringResource(R.string.policy_not_owner), style = MaterialTheme.typography.bodyMedium)
                }
            }
            if (state.applied.isNotEmpty()) item { ActionLogCard(state) }
            item { RescueCard() }
            return@LazyColumn
        }
        item { ProfileCard(state, controller) }
        item { DnsCard(state, controller) }
        // Capability guards (contract §11.1): switched on one by one, each after its own preview.
        item { GuardsIntroCard() }
        GUARD_ORDER.forEach { key -> item(key = "guard_${key.wire}") { GuardCard(agent, key, state, controller, navigate, resumeTick) } }
        item {
            val items = catalog.packages.filter(::visible)
            ItemsCard(stringResource(R.string.policy_packages_title), stringResource(R.string.policy_packages_desc), state, controller, items) {
                items.forEach { CatalogRow(it, state, controller) }
            }
        }
        item {
            val items = catalog.permissions.filter(::visible)
            ItemsCard(stringResource(R.string.policy_permissions_title), stringResource(R.string.policy_permissions_desc), state, controller, items) {
                items.forEach { CatalogRow(it, state, controller) }
            }
        }
        item {
            val items = catalog.restrictions.filter(::visible)
            ItemsCard(stringResource(R.string.policy_restrictions_title), stringResource(R.string.policy_restrictions_never), state, controller, items) {
                items.forEach { CatalogRow(it, state, controller) }
            }
        }
        item { SettingsCard(state, controller) }
        item { VpnCard(state, controller) }
        item { ActionLogCard(state) }
        item {
            SectionCard(stringResource(R.string.policy_undo_title)) {
                Text(stringResource(R.string.policy_revert_all_desc), style = MaterialTheme.typography.bodySmall)
                OutlinedButton(enabled = !state.busy, onClick = { confirmRevertAll = true }) { Text(stringResource(R.string.policy_revert_all)) }
                HorizontalDivider()
                Text(stringResource(R.string.policy_remove_owner_desc), style = MaterialTheme.typography.bodySmall)
                Button(
                    enabled = !state.busy,
                    onClick = { confirmRemove = true },
                    colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.error),
                ) { Text(stringResource(R.string.policy_remove_owner)) }
                if (offerForce && state.deviceOwner) {
                    Text(stringResource(R.string.policy_force_remove_desc), style = MaterialTheme.typography.bodySmall, color = toneColor(Tone.WARN))
                    OutlinedButton(enabled = !state.busy, onClick = {
                        offerForce = false
                        controller.removeDeviceOwner(force = true)
                    }) { Text(stringResource(R.string.policy_force_remove)) }
                }
            }
        }
        item { RescueCard() }
    }

    state.guardPreview?.let { preview ->
        GuardPreviewDialog(preview, onDismiss = controller::dismissGuardPreview, onApply = controller::applyGuard)
    }
    state.preview?.let { preview ->
        PreviewDialog(preview, onDismiss = controller::dismissPreview, onApply = controller::applySelection)
    }
    if (confirmRevertAll) {
        ConfirmDialog(stringResource(R.string.policy_confirm_revert_all), requireCheck = false, onDismiss = { confirmRevertAll = false }) {
            confirmRevertAll = false
            controller.revertAll()
        }
    }
    if (confirmRemove) {
        ConfirmDialog(stringResource(R.string.policy_confirm_remove), requireCheck = true, onDismiss = { confirmRemove = false }) {
            confirmRemove = false
            offerForce = true
            controller.removeDeviceOwner(force = false)
        }
    }
}

@Composable
private fun StatusCard(state: PolicyUiState) {
    SectionCard(stringResource(R.string.policy_status_title)) {
        StatusLine(
            stringResource(R.string.home_device_owner),
            stringResource(if (state.deviceOwner) R.string.yes else R.string.no),
            if (state.deviceOwner) Tone.OK else Tone.WARN,
        )
        StatusLine(stringResource(R.string.policy_test_only), stringResource(if (state.testOnly) R.string.yes else R.string.no))
        if (state.deviceOwner) {
            StatusLine(stringResource(R.string.policy_applied_count), state.applied.size.toString())
            StatusLine(stringResource(R.string.policy_network_logging), onOff(state.networkLogging))
            StatusLine(stringResource(R.string.policy_security_logging), onOff(state.securityLogging))
            Text(stringResource(R.string.policy_logs_hint), style = MaterialTheme.typography.bodySmall)
            Text(stringResource(R.string.policy_intro), style = MaterialTheme.typography.bodySmall)
        }
    }
}

@Composable
private fun onOff(value: Boolean?): String = when (value) {
    true -> stringResource(R.string.state_active)
    false -> stringResource(R.string.state_inactive)
    null -> "—"
}

@Composable
private fun ProfileCard(state: PolicyUiState, controller: PolicyController) {
    SectionCard(stringResource(R.string.policy_profile_title)) {
        listOf(
            Triple(Profile.BALANCED, R.string.policy_profile_balanced, R.string.policy_profile_balanced_desc),
            Triple(Profile.STRICT, R.string.policy_profile_strict, R.string.policy_profile_strict_desc),
        ).forEach { (profile, title, desc) ->
            Row(
                Modifier.fillMaxWidth().clickable { controller.setProfile(profile) },
                verticalAlignment = Alignment.Top,
            ) {
                RadioButton(selected = state.selection.profile == profile, onClick = { controller.setProfile(profile) })
                Column(Modifier.padding(top = 12.dp)) {
                    Text(stringResource(title), style = MaterialTheme.typography.titleSmall)
                    Text(stringResource(desc), style = MaterialTheme.typography.bodySmall)
                }
            }
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(enabled = !state.busy, onClick = controller::requestPreview) { Text(stringResource(R.string.policy_preview)) }
            TextButton(enabled = !state.busy, onClick = controller::resetSelection) { Text(stringResource(R.string.policy_reset_selection)) }
        }
        // To apply one thing only (e.g. just the private DNS): switch everything off, then pick.
        TextButton(enabled = !state.busy, onClick = controller::selectNothing) { Text(stringResource(R.string.policy_select_nothing)) }
        Text(stringResource(R.string.policy_select_nothing_desc), style = MaterialTheme.typography.bodySmall)
    }
}

@Composable
private fun DnsCard(state: PolicyUiState, controller: PolicyController) {
    val record = state.applied[PolicySelection.ID_DNS]
    SectionCard(stringResource(R.string.policy_dns_title)) {
        Text(stringResource(R.string.policy_dns_desc), style = MaterialTheme.typography.bodySmall)
        val host = state.dnsHost
        if (host == null) {
            Text(stringResource(R.string.policy_dns_none), style = MaterialTheme.typography.bodyMedium, color = toneColor(Tone.WARN))
        } else {
            StatusLine(stringResource(R.string.policy_dns_host), host)
        }
        StatusLine(stringResource(R.string.policy_dns_current), listOfNotNull(state.dnsMode, state.dnsCurrentHost).joinToString(" · ").ifEmpty { "—" })
        if (record?.dnsFallback == true) {
            Text(stringResource(R.string.policy_dns_fallback_active), color = toneColor(Tone.WARN), style = MaterialTheme.typography.bodySmall)
        }
        SwitchRow(stringResource(R.string.policy_dns_enable), null, state.selection.privateDns, enabled = state.dnsHost != null && !state.busy) {
            controller.setSelected(PolicySelection.ID_DNS, it)
        }
        SwitchRow(stringResource(R.string.policy_dns_lock), stringResource(R.string.policy_dns_lock_desc), state.selection.privateDnsLock, enabled = !state.busy) {
            controller.setSelected(PolicySelection.ID_DNS_LOCK, it)
        }
        if (record != null) RestoreButton(state, controller, PolicySelection.ID_DNS, record.lastError)
    }
}

@Composable
private fun ItemsCard(
    title: String,
    description: String,
    state: PolicyUiState,
    controller: PolicyController,
    items: List<CatalogItem>,
    content: @Composable () -> Unit,
) {
    SectionCard(title) {
        Text(description, style = MaterialTheme.typography.bodySmall)
        // Only the items of the current profile can be switched (the others are shown because applied).
        val switchable = items.filter { state.selection.profile.includes(it.profile) }
        if (switchable.isNotEmpty()) {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                TextButton(enabled = !state.busy, onClick = { controller.setSection(switchable, false) }) {
                    Text(stringResource(R.string.policy_section_none))
                }
                TextButton(enabled = !state.busy, onClick = { controller.setSection(switchable.filter { it.default }, true) }) {
                    Text(stringResource(R.string.policy_section_defaults))
                }
            }
        }
        content()
    }
}

@Composable
private fun CatalogRow(item: CatalogItem, state: PolicyUiState, controller: PolicyController) {
    val record = state.applied[item.id]
    val (title, subtitle, body, breaks) = when (item) {
        is PackageEntry -> listOf(
            item.label,
            "${item.pkg} · ${item.publisher} · ${stringResource(if (item.method == PackageMethod.HIDE) R.string.policy_method_hide else R.string.policy_method_suspend)}",
            item.role,
            item.effect,
        )
        is PermissionEntry -> listOf(item.label, item.pkg, item.permissions.joinToString { it.substringAfterLast('.') }, item.effect)
        is RestrictionEntry -> listOf(item.title, item.key, item.description, item.breaks)
        is SettingEntry -> listOf(item.title, "${item.namespace}:${item.key} = ${item.value}", item.description, item.breaks)
    }
    val pkg = (item as? PackageEntry)?.pkg ?: (item as? PermissionEntry)?.pkg
    val absent = pkg != null && pkg !in state.installed
    val denied = pkg != null && PackageDenyList.isDenied(pkg)
    HorizontalDivider()
    Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f).padding(end = 8.dp)) {
                Text(title, style = MaterialTheme.typography.bodyLarge)
                Text(subtitle, style = MaterialTheme.typography.labelSmall, fontFamily = FontFamily.Monospace)
            }
            Switch(
                checked = state.selection.isSelected(item),
                enabled = !state.busy && !denied && state.selection.profile.includes(item.profile),
                onCheckedChange = { controller.setSelected(item.id, it) },
            )
        }
        Text(body, style = MaterialTheme.typography.bodySmall)
        Text(stringResource(R.string.policy_breaks, breaks), style = MaterialTheme.typography.bodySmall, color = toneColor(riskTone(item.risk)))
        val tags = listOfNotNull(
            stringResource(riskLabel(item.risk)),
            stringResource(R.string.policy_item_applied).takeIf { record != null },
            stringResource(R.string.policy_item_absent).takeIf { absent && record == null },
        )
        Text(tags.joinToString(" · "), style = MaterialTheme.typography.labelMedium, color = toneColor(if (record != null) Tone.OK else Tone.NEUTRAL))
        if (record != null) RestoreButton(state, controller, item.id, record.lastError)
    }
}

@Composable
private fun RestoreButton(state: PolicyUiState, controller: PolicyController, id: String, lastError: String?) {
    lastError?.let { Text(stringResource(R.string.policy_item_error, it), style = MaterialTheme.typography.bodySmall, color = toneColor(Tone.ERROR)) }
    OutlinedButton(enabled = !state.busy, onClick = { controller.revert(id) }) { Text(stringResource(R.string.policy_item_restore)) }
}

@Composable
private fun SettingsCard(state: PolicyUiState, controller: PolicyController) {
    SectionCard(stringResource(R.string.policy_settings_title)) {
        if (!state.writeSecureSettings) {
            Text(stringResource(R.string.policy_settings_missing_permission), style = MaterialTheme.typography.bodySmall, color = toneColor(Tone.WARN))
        }
        controller.catalog.settings.filter { state.selection.profile.includes(it.profile) || state.applied.containsKey(it.id) }
            .forEach { CatalogRow(it, state, controller) }
        Text(stringResource(R.string.policy_settings_wifi_note), style = MaterialTheme.typography.bodySmall)
        HorizontalDivider()
        StatusLine(stringResource(R.string.policy_backup_state), onOff(state.backupEnabled))
        SwitchRow(
            stringResource(R.string.policy_backup_title),
            stringResource(R.string.policy_backup_desc),
            state.selection.restoreBackup,
            enabled = !state.busy && state.selection.profile == Profile.BALANCED,
        ) { controller.setSelected(PolicySelection.ID_BACKUP, it) }
        state.applied[PolicySelection.ID_BACKUP]?.let { RestoreButton(state, controller, it.id, it.lastError) }
    }
}

@Composable
private fun VpnCard(state: PolicyUiState, controller: PolicyController) {
    var chosen by rememberSaveable(state.vpnPackage) { mutableStateOf(state.vpnPackage ?: state.vpnApps.firstOrNull()) }
    var lockdown by rememberSaveable(state.vpnLockdown) { mutableStateOf(state.vpnLockdown) }
    SectionCard(stringResource(R.string.policy_vpn_title)) {
        Text(stringResource(R.string.policy_vpn_desc), style = MaterialTheme.typography.bodySmall)
        StatusLine(stringResource(R.string.policy_vpn_current), state.vpnPackage ?: "—")
        if (state.vpnApps.isEmpty()) {
            Text(stringResource(R.string.policy_vpn_none), style = MaterialTheme.typography.bodySmall)
            return@SectionCard
        }
        state.vpnApps.forEach { pkg ->
            Row(Modifier.fillMaxWidth().clickable { chosen = pkg }, verticalAlignment = Alignment.CenterVertically) {
                RadioButton(selected = chosen == pkg, onClick = { chosen = pkg })
                Text(pkg, style = MaterialTheme.typography.bodyMedium, fontFamily = FontFamily.Monospace)
            }
        }
        SwitchRow(stringResource(R.string.policy_vpn_lockdown), null, lockdown, enabled = !state.busy) { lockdown = it }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton(enabled = !state.busy && chosen != null, onClick = { controller.setVpn(chosen, lockdown) }) {
                Text(stringResource(R.string.policy_vpn_set))
            }
            if (state.applied.containsKey(PolicySelection.ID_VPN)) {
                TextButton(enabled = !state.busy, onClick = { controller.setVpn(null, false) }) { Text(stringResource(R.string.policy_vpn_clear)) }
            }
        }
    }
}

@Composable
private fun ActionLogCard(state: PolicyUiState) {
    SectionCard(stringResource(R.string.policy_action_log_title)) {
        if (state.actionLog.isEmpty()) {
            Text(stringResource(R.string.policy_action_log_empty), style = MaterialTheme.typography.bodySmall)
        }
        state.actionLog.take(ACTION_LOG_LINES).forEach { e ->
            Column {
                Text(
                    "${Format.dateTime(e.tsMs)} · ${e.action} · ${stringResource(if (e.ok) R.string.policy_action_log_ok else R.string.policy_action_log_failed)}",
                    style = MaterialTheme.typography.labelMedium,
                    color = toneColor(if (e.ok) Tone.NEUTRAL else Tone.ERROR),
                )
                Text(e.target, style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace)
                e.error?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = toneColor(if (e.ok) Tone.WARN else Tone.ERROR)) }
            }
        }
    }
}

@Composable
private fun RescueCard() {
    SectionCard(stringResource(R.string.policy_rescue_title)) {
        Text(stringResource(R.string.policy_rescue_desc), style = MaterialTheme.typography.bodySmall)
    }
}

@Composable
private fun SwitchRow(title: String, summary: String?, checked: Boolean, enabled: Boolean, onChange: (Boolean) -> Unit) {
    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
        Column(Modifier.weight(1f).padding(end = 8.dp)) {
            Text(title, style = MaterialTheme.typography.bodyLarge)
            summary?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
        }
        Switch(checked = checked, enabled = enabled, onCheckedChange = onChange)
    }
}

@Composable
private fun PreviewDialog(preview: List<PlannedChange>, onDismiss: () -> Unit, onApply: () -> Unit) {
    val actionable = preview.filter { it.op == ChangeOp.APPLY || it.op == ChangeOp.REVERT }
    val risky = actionable.any { it.op == ChangeOp.APPLY && (it.risk == Risk.HIGH || it.risk == Risk.CRITICAL) }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.policy_preview_title)) },
        text = {
            Column(Modifier.heightIn(max = 480.dp).verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                if (actionable.isEmpty()) Text(stringResource(R.string.policy_preview_nothing))
                if (risky) Text(stringResource(R.string.policy_preview_risky), color = toneColor(Tone.ERROR))
                // Changes first, then what is skipped and why.
                preview.sortedBy { it.op.ordinal }.forEach { c ->
                    val tone = when (c.op) {
                        ChangeOp.APPLY -> riskTone(c.risk)
                        ChangeOp.REVERT -> Tone.OK
                        else -> Tone.NEUTRAL
                    }
                    Column {
                        Text("${opLabel(c.op)} · ${c.label}", style = MaterialTheme.typography.bodyMedium, color = toneColor(tone))
                        Text(
                            listOfNotNull(c.target, c.detail).joinToString(" · "),
                            style = MaterialTheme.typography.bodySmall,
                            fontFamily = FontFamily.Monospace,
                        )
                    }
                }
            }
        },
        confirmButton = {
            TextButton(enabled = actionable.isNotEmpty(), onClick = onApply) { Text(stringResource(R.string.policy_confirm_apply)) }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.action_cancel)) } },
    )
}

@Composable
private fun ConfirmDialog(text: String, requireCheck: Boolean, onDismiss: () -> Unit, onConfirm: () -> Unit) {
    var checked by remember { mutableStateOf(!requireCheck) }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.policy_confirm_title)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(text)
                if (requireCheck) {
                    Row(Modifier.clickable { checked = !checked }, verticalAlignment = Alignment.CenterVertically) {
                        Checkbox(checked = checked, onCheckedChange = { checked = it })
                        Text(stringResource(R.string.policy_confirm_remove_check))
                    }
                }
            }
        },
        confirmButton = { TextButton(enabled = checked, onClick = onConfirm) { Text(stringResource(R.string.policy_confirm_title)) } },
        dismissButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.action_cancel)) } },
    )
}

@Composable
private fun opLabel(op: ChangeOp): String = stringResource(
    when (op) {
        ChangeOp.APPLY -> R.string.policy_op_apply
        ChangeOp.REVERT -> R.string.policy_op_revert
        ChangeOp.UNCHANGED -> R.string.policy_op_unchanged
        ChangeOp.SKIP_ABSENT -> R.string.policy_op_absent
        ChangeOp.SKIP_DENIED -> R.string.policy_op_denied
        ChangeOp.SKIP_ALREADY -> R.string.policy_op_already
        ChangeOp.SKIP_UNSUPPORTED -> R.string.policy_op_unsupported
    },
)

private fun riskLabel(risk: Risk): Int = when (risk) {
    Risk.LOW -> R.string.policy_risk_low
    Risk.MEDIUM -> R.string.policy_risk_medium
    Risk.HIGH -> R.string.policy_risk_high
    Risk.CRITICAL -> R.string.policy_risk_critical
}

private fun riskTone(risk: Risk): Tone = when (risk) {
    Risk.LOW -> Tone.NEUTRAL
    Risk.MEDIUM -> Tone.WARN
    Risk.HIGH, Risk.CRITICAL -> Tone.ERROR
}

private const val ACTION_LOG_LINES = 40
