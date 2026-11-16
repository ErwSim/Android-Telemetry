package io.github.erwsim.vigie.policy.ui

import android.content.Context
import android.content.pm.ApplicationInfo
import androidx.annotation.StringRes
import io.github.erwsim.vigie.policy.R
import io.github.erwsim.vigie.policy.engine.AndroidDevicePolicyGateway
import io.github.erwsim.vigie.policy.engine.AppliedRecord
import io.github.erwsim.vigie.policy.engine.CatalogItem
import io.github.erwsim.vigie.policy.engine.Dpm
import io.github.erwsim.vigie.policy.engine.EngineReport
import io.github.erwsim.vigie.policy.engine.JournalEntry
import io.github.erwsim.vigie.policy.engine.PlannedChange
import io.github.erwsim.vigie.policy.engine.PolicyCatalog
import io.github.erwsim.vigie.policy.engine.PolicyEngine
import io.github.erwsim.vigie.policy.engine.PolicySelection
import io.github.erwsim.vigie.policy.engine.Profile
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

/** Everything the "Politique" screen shows. */
data class PolicyUiState(
    val loaded: Boolean = false,
    val deviceOwner: Boolean = false,
    val testOnly: Boolean = false,
    val selection: PolicySelection = PolicySelection(),
    val applied: Map<String, AppliedRecord> = emptyMap(),
    /** Catalog packages installed on this device. */
    val installed: Set<String> = emptySet(),
    val preview: List<PlannedChange>? = null,
    val busy: Boolean = false,
    val message: String? = null,
    val journal: List<JournalEntry> = emptyList(),
    val dnsHost: String? = null,
    val dnsMode: String? = null,
    val dnsCurrentHost: String? = null,
    val writeSecureSettings: Boolean = false,
    val networkLogging: Boolean? = null,
    val securityLogging: Boolean? = null,
    val backupEnabled: Boolean? = null,
    val vpnApps: List<String> = emptyList(),
    val vpnPackage: String? = null,
    val vpnLockdown: Boolean = false,
)

/**
 * State holder of the "Politique" screen (no Compose here). Every engine operation runs on
 * `Dispatchers.IO` in a scope that outlives the screen: leaving the screen never cuts an
 * application or an undo in the middle.
 */
class PolicyController(
    private val context: Context,
    private val engine: PolicyEngine,
    private val gateway: AndroidDevicePolicyGateway,
    private val scope: CoroutineScope,
    private val dnsHost: () -> String? = { null },
    private val onApplied: () -> Unit = {},
) {
    val catalog: PolicyCatalog get() = engine.catalog

    private val _state = MutableStateFlow(PolicyUiState(selection = engine.selection()))
    val state: StateFlow<PolicyUiState> = _state.asStateFlow()

    fun refresh() {
        scope.launch(Dispatchers.IO) { reload() }
    }

    private fun reload(message: String? = _state.value.message) {
        val owner = engine.isDeviceOwner()
        fun <T> read(block: () -> T): T? = if (!owner) null else try {
            block()
        } catch (_: Exception) {
            null
        }
        val dnsMode = read { gateway.privateDnsMode() }
        _state.update {
            it.copy(
                loaded = true,
                deviceOwner = owner,
                testOnly = context.applicationInfo.flags and ApplicationInfo.FLAG_TEST_ONLY != 0,
                selection = engine.selection(),
                applied = engine.state().records.associateBy { r -> r.id },
                installed = catalog.packages.map { p -> p.pkg }.plus(catalog.permissions.map { p -> p.pkg })
                    .filter { pkg -> runCatching { gateway.isInstalled(pkg) }.getOrDefault(false) }.toSet(),
                journal = engine.journal().asReversed(),
                dnsHost = currentDnsHost(),
                dnsMode = dnsMode?.let(Dpm::dnsModeName),
                dnsCurrentHost = if (dnsMode == Dpm.DNS_MODE_HOSTNAME) read { gateway.privateDnsHost() } else null,
                writeSecureSettings = runCatching { gateway.canWriteSecureSettings() }.getOrDefault(false),
                networkLogging = read { gateway.isNetworkLoggingEnabled() },
                securityLogging = read { gateway.isSecurityLoggingEnabled() },
                backupEnabled = read { gateway.isBackupServiceEnabled() },
                vpnApps = gateway.vpnApps(),
                vpnPackage = read { gateway.alwaysOnVpnPackage() },
                vpnLockdown = read { gateway.isAlwaysOnVpnLockdown() } ?: false,
                message = message,
            )
        }
    }

    private fun currentDnsHost(): String? = dnsHost() ?: io.github.erwsim.vigie.core.Agent.getOrNull()?.enrollment?.state?.value?.privateDnsHost

    fun setProfile(profile: Profile) = updateSelection { it.copy(profile = profile) }

    fun setSelected(id: String, selected: Boolean) = updateSelection { it.copy(overrides = it.overrides + (id to selected)) }

    /** Switches a whole section (packages, permissions, restrictions…) on or off. */
    fun setSection(items: List<CatalogItem>, selected: Boolean) = updateSelection { it.withItems(items, selected) }

    /** Nothing selected: every item, the private DNS, its lock and the backup switched off. */
    fun selectNothing() = updateSelection { it.withNothingSelected(catalog) }

    /** Back to the catalog defaults of the current profile. */
    fun resetSelection() = updateSelection { it.copy(overrides = emptyMap()) }

    private fun updateSelection(change: (PolicySelection) -> PolicySelection) {
        val next = change(_state.value.selection)
        _state.update { it.copy(selection = next, preview = null) }
        scope.launch(Dispatchers.IO) { engine.saveSelection(next) }
    }

    fun requestPreview() = run(null) {
        val preview = engine.preview(_state.value.selection)
        _state.update { it.copy(preview = preview) }
        null
    }

    fun dismissPreview() = _state.update { it.copy(preview = null) }

    fun applySelection() = run(R.string.policy_msg_applied) {
        _state.update { it.copy(preview = null) }
        engine.apply(_state.value.selection).also { onApplied() }
    }

    fun revert(id: String) = run(R.string.policy_msg_reverted) { engine.revert(id) }

    fun revertAll() = run(R.string.policy_msg_reverted) { engine.revertAll() }

    fun removeDeviceOwner(force: Boolean) = run(R.string.policy_msg_removed) { engine.removeDeviceOwner(force) }

    fun setVpn(pkg: String?, lockdown: Boolean) = run(R.string.policy_msg_applied) { engine.setAlwaysOnVpn(pkg, lockdown) }

    fun clearMessage() = _state.update { it.copy(message = null) }

    private fun run(@StringRes successMessage: Int?, op: () -> EngineReport?) {
        if (_state.value.busy) return
        _state.update { it.copy(busy = true, message = null) }
        scope.launch(Dispatchers.IO) {
            val message = try {
                val report = op()
                when {
                    report == null -> null
                    report.allOk -> successMessage?.let { context.getString(it, report.succeeded.size) }
                    else -> context.getString(R.string.policy_msg_failures, report.failed.size, report.failed.joinToString("\n"))
                }
            } catch (e: Exception) {
                context.getString(R.string.policy_msg_error, "${e.javaClass.simpleName} ${e.message.orEmpty()}")
            }
            try {
                reload(message)
            } finally {
                _state.update { it.copy(busy = false) }
            }
        }
    }
}
