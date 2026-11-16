package io.github.erwsim.vigie.policy.engine

import io.github.erwsim.vigie.core.event.AgentClock
import io.github.erwsim.vigie.core.event.Severity
import io.github.erwsim.vigie.core.sink.EventSink
import io.github.erwsim.vigie.core.sink.emit
import io.github.erwsim.vigie.policy.dns.DnsProbe

/** What a preview line would do. */
enum class ChangeOp {
    /** Will be applied. */
    APPLY,

    /** Applied earlier, no longer selected: will be undone. */
    REVERT,

    /** Selected and already applied by Vigie: nothing to do. */
    UNCHANGED,

    /** Package not installed on this device. */
    SKIP_ABSENT,

    /** Refused by the hard-coded deny list or restriction guard. */
    SKIP_DENIED,

    /** Already in the wanted state without Vigie (left alone, and therefore never undone). */
    SKIP_ALREADY,

    /** Not possible here (missing WRITE_SECURE_SETTINGS, unreadable key, no DNS host…). */
    SKIP_UNSUPPORTED,
}

data class PlannedChange(
    val id: String,
    val kind: ItemKind,
    val target: String,
    val label: String,
    val op: ChangeOp,
    val risk: Risk,
    val detail: String? = null,
)

/** Outcome of an engine operation. */
data class EngineReport(val succeeded: List<String> = emptyList(), val failed: List<String> = emptyList()) {
    val allOk: Boolean get() = failed.isEmpty()

    operator fun plus(other: EngineReport) = EngineReport(succeeded + other.succeeded, failed + other.failed)
}

/**
 * The Device Owner policy engine. Contract:
 * - nothing is applied without an explicit call (the owner presses "Appliquer" after a preview);
 * - the deny list ([PackageDenyList]) and the restriction guard ([RestrictionGuard]) are checked
 *   before every change, at preview AND at application time;
 * - every change is recorded (write-ahead, then confirmed after reading the effect back) with the
 *   previous state, so that [revert]/[revertAll] restore the device exactly, after an app update or
 *   a reboot as well;
 * - every action emits `security.policy` (`action`, `target`, `profile`, `ok`, `error`) and a line in
 *   the local journal; a failure never stops the other items (partial application is reported).
 *
 * Blocking (binder calls, DNS check): call from a background thread. All public methods are
 * serialized (screen, ADB rescue receiver and DNS guard may run concurrently).
 */
class PolicyEngine(
    internal val gateway: DevicePolicyGateway,
    internal val store: PolicyStore,
    val catalog: PolicyCatalog,
    private val probe: DnsProbe,
    internal val clock: AgentClock,
    private val sink: () -> EventSink?,
    /** Private DNS host from the enrollment (`private_dns_host`), null if none. */
    private val dnsHost: () -> String?,
    /** Called right before `clearDeviceOwnerApp`: announce the voluntary removal, flush pending events. */
    private val beforeClearOwner: () -> Unit = {},
    /** Called right after `clearDeviceOwnerApp` with its outcome (true: no longer Device Owner). */
    private val afterClearOwner: (cleared: Boolean) -> Unit = {},
    /** A guard acted on its own (quarantine, role change): shown to the owner as a notification. */
    onGuardNotice: (GuardNotice) -> Unit = {},
    /** "La liste suit": a package became a default role holder and joins the guard's exception list. */
    onGuardListFollow: (GuardKey, String) -> Unit = { _, _ -> },
) {
    internal val lock = Any()

    /** Capability guards (contract §11.1): same lock, same state, same undo as the rest of the policy. */
    val guards = CapabilityGuards(this, onGuardNotice, onGuardListFollow)

    fun state(): AppliedState = synchronized(lock) { store.state() }

    fun journal(): List<JournalEntry> = store.journal()

    /** The persisted state could not be read entirely: "Tout rétablir" then also sweeps the catalog. */
    fun stateWasUnreadable(): Boolean = store.stateWasUnreadable()

    fun selection(): PolicySelection = store.selection()

    fun saveSelection(selection: PolicySelection) = store.saveSelection(selection)

    fun isDeviceOwner(): Boolean = safe { gateway.isDeviceOwner() } ?: false

    // ---------------------------------------------------------------- preview

    /** "Ce qui va changer": pure reads, no side effect. */
    fun preview(selection: PolicySelection): List<PlannedChange> = synchronized(lock) {
        val applied = store.state().records.associateBy { it.id }
        val protected = safe { gateway.protectedPackages() } ?: emptySet()
        val out = ArrayList<PlannedChange>()
        for (item in catalog.items) {
            val wanted = selection.isSelected(item)
            val record = applied[item.id]
            when {
                // Applied by an earlier version (or before the app became launcher, keyboard…) and now
                // refused by the guards: undone, never kept.
                record != null && isRefused(item, protected) -> out += change(item, ChangeOp.REVERT, "désormais refusé par les garde-fous")
                record != null && wanted -> out += change(item, ChangeOp.UNCHANGED)
                record != null -> out += change(item, ChangeOp.REVERT)
                wanted -> out += planItem(item, protected)
            }
        }
        // Applied by an older version whose catalog no longer lists the item: undone, never left behind.
        val known = catalog.items.map { it.id }.toSet() + setOf(PolicySelection.ID_DNS, PolicySelection.ID_BACKUP, PolicySelection.ID_VPN)
        // Guard records are managed by CapabilityGuards, never by the catalog selection.
        for (orphan in applied.values.filter { it.id !in known && !CapabilityGuards.isGuardId(it.id) }) {
            out += PlannedChange(orphan.id, orphan.kind, orphan.target, orphan.target, ChangeOp.REVERT, Risk.LOW, "retiré du catalogue")
        }
        val dnsRecord = applied[PolicySelection.ID_DNS]
        val host = dnsHost()
        if (selection.privateDns) {
            out += when {
                host == null -> dnsChange(ChangeOp.SKIP_UNSUPPORTED, "-", "aucun hôte DNS privé dans l'enrôlement")
                dnsRecord != null && dnsRecord.target == host && dnsRecord.dnsLockedByUs == selection.privateDnsLock ->
                    dnsChange(ChangeOp.UNCHANGED, host, if (dnsRecord.dnsFallback) "en repli (serveur injoignable)" else null)
                dnsRecord != null -> dnsChange(ChangeOp.APPLY, host, "réappliqué avec les nouveaux paramètres")
                else -> dnsChange(ChangeOp.APPLY, host, if (selection.privateDnsLock) "verrouillé" else "non verrouillé")
            }
        } else if (dnsRecord != null) {
            out += dnsChange(ChangeOp.REVERT, dnsRecord.target, "retour à « ${Dpm.dnsModeName(dnsRecord.prevDnsMode ?: 0)} »")
        }
        val backupRecord = applied[PolicySelection.ID_BACKUP]
        if (selection.restoreBackup && backupRecord == null) {
            val enabled = safe { gateway.isBackupServiceEnabled() }
            out += PlannedChange(
                PolicySelection.ID_BACKUP, ItemKind.BACKUP, "backup", LABEL_BACKUP,
                if (enabled == true) ChangeOp.SKIP_ALREADY else ChangeOp.APPLY, Risk.LOW,
            )
        } else if (!selection.restoreBackup && backupRecord != null) {
            out += PlannedChange(PolicySelection.ID_BACKUP, ItemKind.BACKUP, "backup", LABEL_BACKUP, ChangeOp.REVERT, Risk.LOW)
        } else if (backupRecord != null) {
            out += PlannedChange(PolicySelection.ID_BACKUP, ItemKind.BACKUP, "backup", LABEL_BACKUP, ChangeOp.UNCHANGED, Risk.LOW)
        }
        out
    }

    private fun dnsChange(op: ChangeOp, host: String, detail: String?) =
        PlannedChange(PolicySelection.ID_DNS, ItemKind.PRIVATE_DNS, host, LABEL_DNS, op, Risk.MEDIUM, detail)

    private fun change(item: CatalogItem, op: ChangeOp, detail: String? = null) =
        PlannedChange(item.id, kindOf(item), targetOf(item), labelOf(item), op, item.risk, detail)

    /** Hard-coded guards: [PackageDenyList], [RestrictionGuard], [SettingGuard]. */
    private fun isRefused(item: CatalogItem, protected: Set<String>): Boolean = when (item) {
        is PackageEntry -> PackageDenyList.isDenied(item.pkg, protected)
        is PermissionEntry -> PackageDenyList.isDenied(item.pkg, protected)
        is RestrictionEntry -> RestrictionGuard.isForbidden(item.key)
        is SettingEntry -> SettingGuard.isForbidden(item.namespace, item.key)
    }

    private fun planItem(item: CatalogItem, protected: Set<String>): PlannedChange = when (item) {
        is PackageEntry -> when {
            PackageDenyList.isDenied(item.pkg, protected) -> change(item, ChangeOp.SKIP_DENIED, DENY_REASON)
            safe { gateway.isInstalled(item.pkg) } != true -> change(item, ChangeOp.SKIP_ABSENT)
            safe { gateway.isHidden(item.pkg) || gateway.isSuspended(item.pkg) } == true ->
                change(item, ChangeOp.SKIP_ALREADY, "déjà masqué ou suspendu hors de Vigie")
            else -> change(item, ChangeOp.APPLY, if (item.method == PackageMethod.HIDE) "masqué" else "suspendu")
        }
        is PermissionEntry -> when {
            PackageDenyList.isDenied(item.pkg, protected) -> change(item, ChangeOp.SKIP_DENIED, DENY_REASON)
            safe { gateway.isInstalled(item.pkg) } != true -> change(item, ChangeOp.SKIP_ABSENT)
            else -> {
                val todo = item.permissions.filter { p ->
                    safe { gateway.requestsPermission(item.pkg, p) && gateway.permissionGrantState(item.pkg, p) != Dpm.GRANT_DENIED } == true
                }
                if (todo.isEmpty()) {
                    change(item, ChangeOp.SKIP_ALREADY, "permissions non demandées ou déjà refusées")
                } else {
                    change(item, ChangeOp.APPLY, todo.joinToString { it.substringAfterLast('.') })
                }
            }
        }
        is RestrictionEntry -> when {
            RestrictionGuard.isForbidden(item.key) -> change(item, ChangeOp.SKIP_DENIED, "restriction interdite (porte de secours, fonctions vitales, ou hors de la liste vérifiée)")
            safe { gateway.hasRestriction(item.key) } == true -> change(item, ChangeOp.SKIP_ALREADY, "déjà posée hors de Vigie")
            else -> change(item, ChangeOp.APPLY)
        }
        is SettingEntry -> when {
            SettingGuard.isForbidden(item.namespace, item.key) -> change(item, ChangeOp.SKIP_DENIED, "réglage hors de la liste vérifiée")
            safe { gateway.canWriteSecureSettings() } != true ->
                change(item, ChangeOp.SKIP_UNSUPPORTED, "WRITE_SECURE_SETTINGS non accordée (script grant-adb-permissions)")
            else -> when (val current = readSettingOrError(item)) {
                is Result.Failure -> change(item, ChangeOp.SKIP_UNSUPPORTED, "réglage illisible : ${current.error}")
                is Result.Value -> if (current.value == item.value) {
                    change(item, ChangeOp.SKIP_ALREADY, "déjà à ${item.value}")
                } else {
                    change(item, ChangeOp.APPLY, "${current.value ?: "absent"} → ${item.value}")
                }
            }
        }
    }

    // ---------------------------------------------------------------- apply

    /**
     * Makes the device match [selection]: applies what is selected and not yet applied, undoes
     * what was applied and is no longer selected. The preview is recomputed here (and the deny
     * list re-checked), never trusted from the screen.
     */
    fun apply(selection: PolicySelection): EngineReport = synchronized(lock) {
        if (!isDeviceOwner()) return EngineReport(failed = listOf("Vigie n'est pas Device Owner"))
        store.saveSelection(selection)
        val profile = selection.profile.wire
        var report = EngineReport()
        val plan = preview(selection)
        // Undo first (frees restrictions/packages), then apply.
        for (c in plan.filter { it.op == ChangeOp.REVERT }) report += isolated(c.id) { revertLocked(c.id) }
        for (c in plan.filter { it.op == ChangeOp.APPLY }) {
            report += isolated(c.id) {
                when (c.kind) {
                    ItemKind.PRIVATE_DNS -> dnsHost()?.let { applyDns(it, selection.privateDnsLock, profile) } ?: EngineReport()
                    ItemKind.BACKUP -> applyBackup(profile)
                    else -> catalog.item(c.id)?.let { applyCatalogItem(it, profile) } ?: EngineReport()
                }
            }
        }
        report
    }

    private fun applyCatalogItem(item: CatalogItem, profile: String): EngineReport = when (item) {
        is PackageEntry -> applyPackage(item, profile)
        is PermissionEntry -> applyPermissions(item, profile)
        is RestrictionEntry -> applyRestriction(item, profile)
        is SettingEntry -> applySetting(item, profile)
    }

    private fun applyPackage(e: PackageEntry, profile: String): EngineReport {
        val protected = safe { gateway.protectedPackages() } ?: emptySet()
        // Defense in depth: the preview already filtered it, but nothing reaches the device without this check.
        if (PackageDenyList.isDenied(e.pkg, protected)) return refused("package_disabled", e.pkg, profile)
        val record = AppliedRecord(
            id = e.id, kind = ItemKind.PACKAGE, target = e.pkg, profile = profile,
            appliedAtMs = clock.nowMillis(), method = e.method,
        )
        putRecord(record)
        val error = attempt {
            val ok = if (e.method == PackageMethod.HIDE) gateway.setHidden(e.pkg, true) else gateway.setSuspended(e.pkg, true)
            if (!ok) "refusé par le système (paquet protégé, actif ou requis ?)" else null
        }
        val effective = packageDisabled(e.pkg, e.method)
        return if (effective) {
            putRecord(record.copy(status = RecordStatus.APPLIED))
            outcome("package_disabled", e.pkg, profile, true, null)
        } else {
            removeRecord(record.id)
            outcome("package_disabled", e.pkg, profile, false, error ?: "aucun effet constaté")
        }
    }

    private fun packageDisabled(pkg: String, method: PackageMethod): Boolean =
        safe { if (method == PackageMethod.HIDE) gateway.isHidden(pkg) else gateway.isSuspended(pkg) } == true

    private fun applyPermissions(e: PermissionEntry, profile: String): EngineReport {
        val protected = safe { gateway.protectedPackages() } ?: emptySet()
        if (PackageDenyList.isDenied(e.pkg, protected)) return refused("permission_denied", e.pkg, profile)
        val todo = e.permissions.filter { p -> safe { gateway.requestsPermission(e.pkg, p) } == true }
        if (todo.isEmpty()) return EngineReport()
        val base = AppliedRecord(id = e.id, kind = ItemKind.PERMISSION, target = e.pkg, profile = profile, appliedAtMs = clock.nowMillis())
        return denyPermissions(base, todo)
    }

    /**
     * Denies [permissions] of `base.target` and records them in [base] (created or extended), write-ahead:
     * the record (with each permission's previous state) is on disk before the first change, each
     * permission is marked applied once its denial is read back. A permission already denied:
     * - by another record of Vigie (a catalog item, another guard): shared, with that record's original
     *   state, so that whichever is undone last restores it (see [revertPermissions]);
     * - outside Vigie: left alone and not recorded (never undone).
     * A permission that fails is reported and does not stop the others. With [keepEmpty] (quarantine),
     * the record is kept even when nothing was denied.
     */
    internal fun denyPermissions(base: AppliedRecord, permissions: Collection<String>, keepEmpty: Boolean = false): EngineReport {
        val pkg = base.target
        val existing = record(base.id)
        val start = existing ?: base
        val held = start.permissions.map { it.permission }.toSet()
        val added = ArrayList<PermissionPrev>()
        for (p in permissions.distinct().filter { it !in held }) {
            val state = safe { gateway.permissionGrantState(pkg, p) } ?: continue
            if (state == Dpm.GRANT_DENIED) {
                claimOf(pkg, p, base.id)?.let { added += it.copy(applied = true) }
            } else {
                added += PermissionPrev(p, state, safe { gateway.isPermissionGranted(pkg, p) } ?: false)
            }
        }
        if (added.isEmpty()) {
            if (existing == null && keepEmpty) putRecord(base.copy(status = RecordStatus.APPLIED))
            return EngineReport()
        }
        var record = start.copy(permissions = start.permissions + added, status = RecordStatus.PENDING)
        putRecord(record)
        var report = EngineReport()
        val guard = CapabilityGuards.isGuardId(base.id)
        for (prev in added.filter { !it.applied }) {
            val error = attempt {
                if (!gateway.setPermissionGrantState(pkg, prev.permission, Dpm.GRANT_DENIED)) "refusé par le système" else null
            }
            val denied = safe {
                gateway.permissionGrantState(pkg, prev.permission) == Dpm.GRANT_DENIED && !gateway.isPermissionGranted(pkg, prev.permission)
            } == true
            if (denied) {
                record = record.copy(permissions = record.permissions.map { if (it.permission == prev.permission) it.copy(applied = true) else it })
                putRecord(record)
            }
            report += if (guard) {
                outcome("permission_denied", pkg, base.profile, denied, if (denied) null else error ?: "aucun effet constaté", permission = prev.permission)
            } else {
                outcome("permission_denied", "$pkg/${prev.permission}", base.profile, denied, if (denied) null else error ?: "aucun effet constaté")
            }
        }
        // Permissions that could not be denied stay listed, not applied (nothing to undo for them): the screen
        // shows them, and a guard does not retry (and report) them at every reconciliation — switching the
        // guard on again retries them. A catalog record with nothing applied is dropped, as before.
        val keep = keepEmpty || record.permissions.any { it.applied } || (guard && record.permissions.isNotEmpty())
        if (keep) putRecord(record.copy(status = RecordStatus.APPLIED)) else removeRecord(record.id)
        return report
    }

    /** The original state of [permission] of [pkg] if another record of Vigie holds it denied, else null. */
    internal fun claimOf(pkg: String, permission: String, exceptId: String): PermissionPrev? =
        store.state().records.asSequence()
            .filter { it.id != exceptId && it.kind == ItemKind.PERMISSION && it.target == pkg }
            .flatMap { it.permissions.asSequence() }
            .firstOrNull { it.permission == permission && it.applied }

    private fun applyRestriction(e: RestrictionEntry, profile: String): EngineReport {
        if (RestrictionGuard.isForbidden(e.key)) return refused("restriction_set", e.key, profile)
        val record = AppliedRecord(id = e.id, kind = ItemKind.RESTRICTION, target = e.key, profile = profile, appliedAtMs = clock.nowMillis())
        putRecord(record)
        val error = attempt { gateway.addRestriction(e.key); null }
        val set = safe { gateway.hasRestriction(e.key) } == true
        return if (set) {
            putRecord(record.copy(status = RecordStatus.APPLIED))
            outcome("restriction_set", e.key, profile, true, null)
        } else {
            removeRecord(record.id)
            outcome("restriction_set", e.key, profile, false, error ?: "aucun effet constaté")
        }
    }

    private fun applySetting(e: SettingEntry, profile: String): EngineReport {
        val target = "${e.key}=${e.value}"
        if (SettingGuard.isForbidden(e.namespace, e.key)) return refused("setting_changed", target, profile, "réglage hors de la liste vérifiée")
        val prev = when (val r = readSettingOrError(e)) {
            is Result.Failure -> return outcome("setting_changed", target, profile, false, "lecture préalable impossible : ${r.error}")
            is Result.Value -> r.value
        }
        val record = AppliedRecord(
            id = e.id, kind = ItemKind.SETTING, target = e.key, profile = profile, appliedAtMs = clock.nowMillis(),
            namespace = e.namespace, prevValue = prev, newValue = e.value,
        )
        putRecord(record)
        val error = attempt { if (!gateway.writeSetting(e.namespace, e.key, e.value)) "écriture refusée" else null }
        val now = (readSettingOrError(e) as? Result.Value)?.value
        return if (now == e.value) {
            putRecord(record.copy(status = RecordStatus.APPLIED))
            outcome("setting_changed", target, profile, true, null)
        } else {
            removeRecord(record.id)
            outcome("setting_changed", target, profile, false, error ?: "aucun effet constaté")
        }
    }

    private fun applyBackup(profile: String): EngineReport {
        val prev = safe { gateway.isBackupServiceEnabled() }
            ?: return outcome("backup_service", "enabled", profile, false, "état de la sauvegarde illisible")
        if (prev) return EngineReport()
        val record = AppliedRecord(PolicySelection.ID_BACKUP, ItemKind.BACKUP, "backup", profile, appliedAtMs = clock.nowMillis(), prevBool = false)
        putRecord(record)
        val error = attempt { gateway.setBackupServiceEnabled(true); null }
        return if (safe { gateway.isBackupServiceEnabled() } == true) {
            putRecord(record.copy(status = RecordStatus.APPLIED))
            outcome("backup_service", "enabled", profile, true, null)
        } else {
            removeRecord(record.id)
            outcome("backup_service", "enabled", profile, false, error ?: "aucun effet constaté")
        }
    }

    /**
     * Imposes the private DNS. The host is first checked from here (TLS + one DNS query): a host
     * that does not answer would leave the phone without DNS, hence without Internet.
     */
    private fun applyDns(host: String, lockWanted: Boolean, profile: String?): EngineReport {
        val existing = store.state().records.firstOrNull { it.id == PolicySelection.ID_DNS }
        val check = probe.probe(host, existing?.dnsAddresses.orEmpty())
        if (!check.ok) return outcome("private_dns_set", host, profile, false, "vérification préalable : ${check.error}")
        val record = existing?.copy(target = host, profile = profile, dnsAddresses = check.addresses, dnsFallback = false)
            ?: AppliedRecord(
                id = PolicySelection.ID_DNS, kind = ItemKind.PRIVATE_DNS, target = host, profile = profile,
                appliedAtMs = clock.nowMillis(),
                prevDnsMode = safe { gateway.privateDnsMode() } ?: Dpm.DNS_MODE_UNKNOWN,
                prevDnsHost = safe { gateway.privateDnsHost() },
                dnsAddresses = check.addresses,
            )
        putRecord(record)
        var error: String? = null
        val code = try {
            gateway.setPrivateDnsSpecifiedHost(host)
        } catch (e: Exception) {
            error = describe(e)
            -1
        }
        if (code != Dpm.DNS_SET_OK && error == null) error = Dpm.dnsSetError(code)
        val active = safe { gateway.privateDnsMode() == Dpm.DNS_MODE_HOSTNAME && gateway.privateDnsHost() == host } == true
        if (!active) {
            if (existing == null) removeRecord(record.id) else putRecord(existing)
            return outcome("private_dns_set", host, profile, false, error ?: "aucun effet constaté")
        }
        var result = outcome("private_dns_set", host, profile, true, null)
        var locked = record.dnsLockedByUs
        if (lockWanted && !locked && safe { gateway.hasRestriction(RestrictionGuard.DNS_LOCK) } != true) {
            val lockError = attempt { gateway.addRestriction(RestrictionGuard.DNS_LOCK); null }
            locked = safe { gateway.hasRestriction(RestrictionGuard.DNS_LOCK) } == true
            result += outcome("restriction_set", RestrictionGuard.DNS_LOCK, profile, locked, if (locked) null else lockError ?: "aucun effet constaté")
        } else if (!lockWanted && locked) {
            val unlockError = attempt { gateway.clearRestriction(RestrictionGuard.DNS_LOCK); null }
            locked = safe { gateway.hasRestriction(RestrictionGuard.DNS_LOCK) } == true
            result += outcome("restriction_cleared", RestrictionGuard.DNS_LOCK, profile, !locked, if (!locked) null else unlockError ?: "aucun effet constaté")
        }
        putRecord(record.copy(status = RecordStatus.APPLIED, dnsLockedByUs = locked))
        return result
    }

    // ---------------------------------------------------------------- DNS fallback

    /** The imposed DNS host, its known addresses and whether the fallback is active; null if not imposed. */
    fun dnsRecord(): AppliedRecord? = state().records.firstOrNull { it.id == PolicySelection.ID_DNS && it.status == RecordStatus.APPLIED }

    /**
     * Fallback when the imposed DNS server is durably unreachable: switch to the opportunistic
     * mode (encrypted when the network's resolver supports it, network DNS otherwise) so that the
     * phone keeps Internet access. Logged with sev 2: an attacker blocking port 853 gains this
     * downgrade, but never silently.
     */
    fun dnsFallback(reason: String): EngineReport = synchronized(lock) {
        val record = dnsRecord() ?: return EngineReport()
        if (record.dnsFallback) return EngineReport()
        val error = attempt { val c = gateway.setPrivateDnsOpportunistic(); Dpm.dnsSetError(c) }
        val ok = safe { gateway.privateDnsMode() == Dpm.DNS_MODE_OPPORTUNISTIC } == true
        if (ok) putRecord(record.copy(dnsFallback = true, lastError = reason))
        outcome("private_dns_set", "opportunistic", record.profile, ok, if (ok) "repli : $reason" else error ?: "aucun effet constaté", Severity.WARNING)
    }

    /** Re-imposes the host after a fallback, once it answers again (re-checked first). */
    fun dnsReapply(): EngineReport = synchronized(lock) {
        val record = dnsRecord() ?: return EngineReport()
        if (!record.dnsFallback) return EngineReport()
        applyDns(record.target, record.dnsLockedByUs, record.profile)
    }

    // ---------------------------------------------------------------- VPN (manual)

    /** Always-on VPN for an installed VPN app ([pkg] null removes Vigie's setting). */
    fun setAlwaysOnVpn(pkg: String?, lockdown: Boolean): EngineReport = synchronized(lock) {
        if (!isDeviceOwner()) return EngineReport(failed = listOf("Vigie n'est pas Device Owner"))
        if (pkg == null) return revertLocked(PolicySelection.ID_VPN)
        val protected = safe { gateway.protectedPackages() } ?: emptySet()
        if (PackageDenyList.isDenied(pkg, protected)) return refused("always_on_vpn", pkg, null)
        val existing = store.state().records.firstOrNull { it.id == PolicySelection.ID_VPN }
        val record = existing?.copy(target = pkg, vpnLockdown = lockdown) ?: AppliedRecord(
            id = PolicySelection.ID_VPN, kind = ItemKind.VPN, target = pkg, appliedAtMs = clock.nowMillis(),
            prevVpnPackage = safe { gateway.alwaysOnVpnPackage() }, prevVpnLockdown = safe { gateway.isAlwaysOnVpnLockdown() } ?: false,
            vpnLockdown = lockdown,
        )
        putRecord(record)
        val error = attempt { gateway.setAlwaysOnVpn(pkg, lockdown); null }
        val ok = safe { gateway.alwaysOnVpnPackage() == pkg && gateway.isAlwaysOnVpnLockdown() == lockdown } == true
        val target = if (lockdown) "$pkg (lockdown)" else pkg
        when {
            ok -> putRecord(record.copy(status = RecordStatus.APPLIED))
            existing == null -> removeRecord(record.id)
            else -> putRecord(existing)
        }
        outcome("always_on_vpn", target, null, ok, if (ok) null else error ?: "aucun effet constaté")
    }

    // ---------------------------------------------------------------- undo

    fun revert(id: String): EngineReport = synchronized(lock) { revertLocked(id) }

    /** "Tout rétablir": undoes every recorded change, newest first. Failed items stay recorded (retry). */
    fun revertAll(): EngineReport = synchronized(lock) {
        val report = revertEverythingLocked()
        val ok = report.allOk
        logAction("policy_reverted", "all", null, ok, if (ok) null else report.failed.joinToString("; ").take(MAX_ERROR), if (ok) Severity.NOTABLE else Severity.WARNING)
        report
    }

    /**
     * Safety net when the applied state cannot be trusted (unreadable preferences, or on request from
     * the ADB rescue): restores everything the catalog can have changed, without knowing what Vigie
     * really applied. Catalog packages hidden or suspended are shown again, catalog restrictions set
     * by this admin (and the private DNS lock) are cleared, catalog permissions denied by policy go
     * back to the user's control, and the private DNS stops being imposed on the enrolled host
     * (automatic mode). Nothing outside the catalog is touched. What cannot be restored blindly (a
     * setting whose previous value is unknown) is reported as a failure, to be fixed by hand.
     */
    fun sweepCatalog(): EngineReport = synchronized(lock) { sweepLocked() }

    private fun sweepLocked(): EngineReport {
        if (!isDeviceOwner()) return EngineReport(failed = listOf("Vigie n'est pas Device Owner"))
        var report = EngineReport()
        for (e in catalog.packages) {
            if (safe { gateway.isInstalled(e.pkg) } != true) continue
            val hidden = safe { gateway.isHidden(e.pkg) } == true
            val suspended = safe { gateway.isSuspended(e.pkg) } == true
            if (!hidden && !suspended) continue
            val error = attempt {
                var failure: String? = null
                if (hidden && !gateway.setHidden(e.pkg, false)) failure = "refusé par le système"
                if (suspended && !gateway.setSuspended(e.pkg, false)) failure = "refusé par le système"
                failure
            }
            val restored = safe { !gateway.isHidden(e.pkg) && !gateway.isSuspended(e.pkg) } == true
            report += outcome("package_enabled", e.pkg, null, restored, if (restored) null else error ?: "état non restauré")
        }
        for (key in catalog.restrictions.map { it.key }.distinct() + RestrictionGuard.DNS_LOCK) {
            if (safe { gateway.hasRestriction(key) } != true) continue
            val error = attempt { gateway.clearRestriction(key); null }
            val cleared = safe { gateway.hasRestriction(key) } == false
            report += outcome("restriction_cleared", key, null, cleared, if (cleared) null else error ?: "aucun effet constaté")
        }
        for (e in catalog.permissions) {
            if (safe { gateway.isInstalled(e.pkg) } != true) continue
            for (p in e.permissions.distinct()) {
                if (safe { gateway.permissionGrantState(e.pkg, p) } != Dpm.GRANT_DENIED) continue
                val error = attempt { if (!gateway.setPermissionGrantState(e.pkg, p, Dpm.GRANT_DEFAULT)) "refusé par le système" else null }
                val freed = safe { gateway.permissionGrantState(e.pkg, p) } == Dpm.GRANT_DEFAULT
                report += outcome("permission_restored", "${e.pkg}/$p", null, freed, if (freed) null else error ?: "état non restauré")
            }
        }
        val host = dnsHost()
        if (host != null && safe { gateway.privateDnsMode() == Dpm.DNS_MODE_HOSTNAME && gateway.privateDnsHost() == host } == true) {
            val error = attempt { Dpm.dnsSetError(gateway.setPrivateDnsOpportunistic()) }
            val ok = safe { gateway.privateDnsMode() } == Dpm.DNS_MODE_OPPORTUNISTIC
            report += outcome("private_dns_set", "opportunistic", null, ok, if (ok) null else error ?: "aucun effet constaté")
        }
        for (e in catalog.settings) {
            val now = (readSettingOrError(e) as? Result.Value)?.value
            if (now == e.value) {
                report += outcome("setting_restored", "${e.key}=?", null, false, "valeur d'origine inconnue (état perdu) : à rétablir à la main si besoin")
            }
        }
        report += isolated("sweep guards") { guards.sweepLocked() }
        // The unreadable text has served: everything reachable was restored (failures stay in the journal).
        if (report.failed.none { !it.startsWith("setting_restored") }) store.clearUnreadableMarker()
        return report
    }

    private fun revertLocked(id: String): EngineReport {
        val record = store.state().records.firstOrNull { it.id == id } ?: return EngineReport()
        val p = record.profile
        return when (record.kind) {
            ItemKind.PACKAGE -> {
                val method = record.method ?: PackageMethod.HIDE
                val error = attempt {
                    val ok = if (method == PackageMethod.HIDE) gateway.setHidden(record.target, false) else gateway.setSuspended(record.target, false)
                    if (!ok) "refusé par le système" else null
                }
                // An uninstalled package has nothing left to restore.
                val restored = safe { !gateway.isInstalled(record.target) || !packageDisabled(record.target, method) } == true
                finish(record, restored, "package_enabled", record.target, p, error)
            }
            ItemKind.PERMISSION -> if (CapabilityGuards.isQuarantineId(record.id)) guards.undoQuarantined(record) else revertPermissions(record)
            ItemKind.RESTRICTION -> {
                val error = attempt { gateway.clearRestriction(record.target); null }
                finish(record, safe { gateway.hasRestriction(record.target) } == false, "restriction_cleared", record.target, p, error)
            }
            ItemKind.SETTING -> {
                val ns = record.namespace ?: "global"
                val error = attempt { if (!gateway.writeSetting(ns, record.target, record.prevValue)) "écriture refusée" else null }
                val now = safe { gateway.readSetting(ns, record.target) }
                finish(record, now == record.prevValue, "setting_restored", "${record.target}=${record.prevValue ?: "absent"}", p, error)
            }
            ItemKind.PRIVATE_DNS -> revertDns(record)
            ItemKind.BACKUP -> {
                val prev = record.prevBool ?: false
                val error = attempt { gateway.setBackupServiceEnabled(prev); null }
                finish(record, safe { gateway.isBackupServiceEnabled() } == prev, "backup_service", if (prev) "enabled" else "disabled", p, error)
            }
            ItemKind.GUARD -> guards.revertGuardRecord(record)
            ItemKind.VPN -> {
                val prevLockdown = record.prevVpnLockdown ?: false
                val error = attempt { gateway.setAlwaysOnVpn(record.prevVpnPackage, prevLockdown); null }
                val ok = safe { gateway.alwaysOnVpnPackage() == record.prevVpnPackage } == true
                finish(record, ok, "always_on_vpn", record.prevVpnPackage ?: "none", p, error)
            }
        }
    }

    /**
     * Restores the permissions of a PERMISSION record ([only]: a subset of them) to their exact previous
     * state. A permission still held denied by another record of Vigie is not touched (that record keeps
     * the same original state and restores it when it is undone). The record is removed once nothing in
     * it remains applied, unless [keepRecord] (quarantine: the package stays quarantined).
     */
    internal fun revertPermissions(record: AppliedRecord, only: Set<String>? = null, keepRecord: Boolean = false, grant: Set<String> = emptySet()): EngineReport {
        var report = EngineReport()
        var remaining = record.permissions
        val pkg = record.target
        val guard = CapabilityGuards.isGuardId(record.id)
        // A permission listed in the record without being confirmed (the process died while denying, or the
        // denial was read back as failed) may nevertheless be denied on the device. Whatever is denied by
        // policy now and was not before is restored too (otherwise it would stay denied and locked in the
        // Settings for ever): only this admin can have denied it, and a denial held by another record of
        // Vigie is left to that record below.
        fun deniedByTheCrash(p: PermissionPrev) = !p.applied && p.prevState != Dpm.GRANT_DENIED &&
            safe { gateway.permissionGrantState(pkg, p.permission) } == Dpm.GRANT_DENIED
        // Foreground location before background location when granting back.
        val order = record.permissions.filter { (only == null || it.permission in only) && (it.applied || deniedByTheCrash(it)) }
            .sortedBy { if (it.permission.endsWith("ACCESS_BACKGROUND_LOCATION")) 1 else 0 }
        for (prev in order) {
            if (claimOf(pkg, prev.permission, record.id) != null) {
                // Still denied on behalf of another item: released from this record only.
                remaining = remaining.map { if (it.permission == prev.permission) it.copy(applied = false) else it }
                continue
            }
            // [grant]: the package became the holder of a role that Android would have granted this permission
            // to, had our denial not been in the way (see GuardSafety.roleGrants): it is granted, best effort.
            val roleGrant = prev.permission in grant && !prev.prevGranted && prev.prevState == Dpm.GRANT_DEFAULT
            val error = attempt {
                when {
                    prev.prevState != Dpm.GRANT_DEFAULT -> gateway.setPermissionGrantState(pkg, prev.permission, prev.prevState)
                    prev.prevGranted || roleGrant -> {
                        // Grant then hand back to the user: granted, still user-controlled (as before).
                        gateway.setPermissionGrantState(pkg, prev.permission, Dpm.GRANT_GRANTED)
                        gateway.setPermissionGrantState(pkg, prev.permission, Dpm.GRANT_DEFAULT)
                    }
                    else -> gateway.setPermissionGrantState(pkg, prev.permission, Dpm.GRANT_DEFAULT)
                }
                null
            }
            val restored = safe {
                !gateway.isInstalled(pkg) || (
                    gateway.permissionGrantState(pkg, prev.permission) == prev.prevState &&
                        // A role grant that did not take is not a failure of the undo: the denial is lifted.
                        (roleGrant || gateway.isPermissionGranted(pkg, prev.permission) == prev.prevGranted)
                    )
            } == true
            val grantedNow = prev.prevGranted || (roleGrant && safe { gateway.isPermissionGranted(pkg, prev.permission) } == true)
            // Kept (marked applied) until it is really restored, so that a retry finds it.
            remaining = remaining.map { if (it.permission == prev.permission) it.copy(applied = !restored) else it }
            val action = if (grantedNow) "permission_granted" else "permission_restored"
            val failure = if (restored) null else error ?: "état non restauré"
            report += if (guard) outcome(action, pkg, record.profile, restored, failure, permission = prev.permission) else outcome(action, "$pkg/${prev.permission}", record.profile, restored, failure)
        }
        if (only != null) remaining = remaining.filter { it.applied || it.permission !in only }
        report += bookkeeping(record.id) {
            if (remaining.none { it.applied } && !keepRecord) {
                removeRecord(record.id)
            } else {
                putRecord(record.copy(status = RecordStatus.APPLIED, permissions = remaining, lastError = report.failed.lastOrNull()))
            }
        }
        return report
    }

    private fun revertDns(record: AppliedRecord): EngineReport {
        var report = EngineReport()
        if (record.dnsLockedByUs) {
            val error = attempt { gateway.clearRestriction(RestrictionGuard.DNS_LOCK); null }
            val cleared = safe { gateway.hasRestriction(RestrictionGuard.DNS_LOCK) } == false
            report += outcome("restriction_cleared", RestrictionGuard.DNS_LOCK, record.profile, cleared, if (cleared) null else error ?: "aucun effet constaté")
            if (cleared) report += bookkeeping(record.id) { putRecord(record.copy(dnsLockedByUs = false)) }
        }
        val prevMode = record.prevDnsMode ?: Dpm.DNS_MODE_UNKNOWN
        val prevHost = record.prevDnsHost
        var target = Dpm.dnsModeName(prevMode)
        val error = attempt {
            when (prevMode) {
                Dpm.DNS_MODE_OFF -> { gateway.setPrivateDnsOff(); null }
                Dpm.DNS_MODE_HOSTNAME -> if (prevHost != null) {
                    target = prevHost
                    Dpm.dnsSetError(gateway.setPrivateDnsSpecifiedHost(prevHost))
                } else {
                    Dpm.dnsSetError(gateway.setPrivateDnsOpportunistic())
                }
                // Unknown previous mode: opportunistic is the Android default.
                else -> Dpm.dnsSetError(gateway.setPrivateDnsOpportunistic())
            }
        }
        val mode = safe { gateway.privateDnsMode() }
        val restored = when (prevMode) {
            Dpm.DNS_MODE_OFF -> mode == Dpm.DNS_MODE_OFF
            Dpm.DNS_MODE_HOSTNAME -> mode == Dpm.DNS_MODE_HOSTNAME && safe { gateway.privateDnsHost() } == prevHost
            else -> mode == Dpm.DNS_MODE_OPPORTUNISTIC
        }
        var failure = if (restored) null else error ?: "aucun effet constaté"
        // Could not restore "off" or the previous host: at least stop imposing our host (automatic mode),
        // so that the phone never stays bound to a server Vigie no longer manages. Kept for a retry.
        if (!restored && mode == Dpm.DNS_MODE_HOSTNAME && safe { gateway.privateDnsHost() } == record.target) {
            attempt { Dpm.dnsSetError(gateway.setPrivateDnsOpportunistic()) }
            if (safe { gateway.privateDnsMode() } == Dpm.DNS_MODE_OPPORTUNISTIC) failure += " ; mode automatique appliqué à la place"
        }
        report += outcome("private_dns_set", target, record.profile, restored, failure)
        val lockStillSet = record.dnsLockedByUs && safe { gateway.hasRestriction(RestrictionGuard.DNS_LOCK) } != false
        report += bookkeeping(record.id) {
            val current = store.state().records.firstOrNull { it.id == record.id } ?: record
            if (restored && !lockStillSet) removeRecord(record.id) else putRecord(current.copy(dnsLockedByUs = lockStillSet, lastError = report.failed.lastOrNull()))
        }
        return report
    }

    private fun finish(record: AppliedRecord, restored: Boolean, action: String, target: String, profile: String?, error: String?): EngineReport {
        val written = bookkeeping(record.id) {
            if (restored) removeRecord(record.id) else putRecord(record.copy(lastError = error ?: "état non restauré"))
        }
        return outcome(action, target, profile, restored, if (restored) null else error ?: "état non restauré") + written
    }

    /**
     * State writes while undoing: the device is what matters. If the state cannot be written (storage
     * full), the undo of this item and of the following ones still goes on; the stale record is
     * reported and cleared by a later "Tout rétablir".
     */
    internal inline fun bookkeeping(id: String, block: () -> Unit): EngineReport = try {
        block()
        EngineReport()
    } catch (e: Exception) {
        EngineReport(failed = listOf("$id : état non enregistré (${describe(e)})"))
    }

    // ---------------------------------------------------------------- leaving Device Owner

    /**
     * "Retirer le Device Owner": undoes everything, stops the system logs, removes the force-stop
     * protection, then `clearDeviceOwnerApp`. Stops before the last step if something could not be
     * undone, unless [force] (the remaining items are listed in the report).
     */
    fun removeDeviceOwner(force: Boolean): EngineReport = synchronized(lock) {
        if (!isDeviceOwner()) return EngineReport(failed = listOf("Vigie n'est pas Device Owner"))
        val undo = revertAllLockedForRemoval()
        if (!undo.allOk && !force) return undo
        var report = undo
        attempt { gateway.setNetworkLoggingEnabled(false); null }.let { e ->
            val off = safe { !gateway.isNetworkLoggingEnabled() } == true
            report += outcome("network_logging", "disabled", null, off, if (off) null else e ?: "aucun effet constaté")
        }
        attempt { gateway.setSecurityLoggingEnabled(false); null }.let { e ->
            val off = safe { !gateway.isSecurityLoggingEnabled() } == true
            report += outcome("security_logging", "disabled", null, off, if (off) null else e ?: "aucun effet constaté")
        }
        attempt { gateway.clearUserControlDisabledPackages(); null }.let { e ->
            report += outcome("force_stop_protection", "disabled", null, e == null, e)
        }
        logAction("device_owner_cleared", OWNER_TARGET, null, true, if (undo.allOk) null else "forcé ; non rétabli : ${undo.failed.joinToString("; ")}".take(MAX_ERROR), Severity.WARNING)
        safe { beforeClearOwner() }
        val error = attempt { gateway.clearDeviceOwner(); null }
        val cleared = !isDeviceOwner()
        safe { afterClearOwner(cleared) }
        if (!cleared) report += outcome("device_owner_cleared", OWNER_TARGET, null, false, error ?: "toujours Device Owner")
        report
    }

    /**
     * Every recorded change, undone item by item. The guards go first: once their records are gone they
     * stop applying themselves to new packages, so that a crash in the middle of "Tout rétablir" never
     * leaves a guard that re-denies what was just restored. Then the rest, newest first.
     */
    private fun revertEverythingLocked(): EngineReport {
        var report = EngineReport()
        // 1. Every per-package guard is switched off before anything is restored (no device change).
        for (record in store.state().records.filter { it.kind == ItemKind.GUARD }) report += isolated(record.id) { guards.switchOff(record) }
        // 2. The rest (guard lists, package records of the guards, catalog items…), newest first.
        for (record in store.state().records.reversed()) report += isolated(record.id) { revertLocked(record.id) }
        if (store.stateWasUnreadable()) report += isolated("sweep") { sweepLocked() }
        return report
    }

    private fun revertAllLockedForRemoval(): EngineReport {
        val report = revertEverythingLocked()
        logAction("policy_reverted", "all", null, report.allOk, if (report.allOk) null else report.failed.joinToString("; ").take(MAX_ERROR), Severity.NOTABLE)
        return report
    }

    // ---------------------------------------------------------------- helpers

    /** Records a policy action that is not an item of the state (logging switches, self-grant…). */
    fun logAction(action: String, target: String, profile: String?, ok: Boolean, error: String?, sev: Int = if (ok) Severity.INFO else Severity.NOTABLE, permission: String? = null) {
        try {
            store.appendJournal(JournalEntry(clock.nowMillis(), action, target, profile, ok, error, permission))
        } catch (_: Exception) {
            // Storage full: the action itself matters more than its trace.
        }
        try {
            sink()?.emit(EVENT_TYPE, sev) {
                put("action", action)
                put("target", target)
                put("profile", profile)
                put("ok", ok)
                put("error", error)
                put("permission", permission)
            }
        } catch (_: Exception) {
            // The journal entry is kept; the event is best effort.
        }
    }

    /**
     * One item failing in an unexpected way (typically the state that cannot be written: storage
     * full) never stops the others: "Tout rétablir" must go through every item it can.
     */
    internal inline fun isolated(id: String, block: () -> EngineReport): EngineReport = try {
        block()
    } catch (e: Exception) {
        EngineReport(failed = listOf("$id : ${describe(e)}"))
    }

    internal fun outcome(action: String, target: String, profile: String?, ok: Boolean, error: String?, sev: Int? = null, permission: String? = null): EngineReport {
        logAction(action, target, profile, ok, error?.take(MAX_ERROR), sev ?: if (ok) Severity.INFO else Severity.NOTABLE, permission)
        return if (ok) EngineReport(succeeded = listOf("$action $target")) else EngineReport(failed = listOf("$action $target : ${error.orEmpty()}"))
    }

    private fun refused(action: String, target: String, profile: String?, reason: String = DENY_REASON) =
        outcome(action, target, profile, false, "refusé : $reason")

    internal fun record(id: String): AppliedRecord? = store.state().records.firstOrNull { it.id == id }

    internal fun putRecord(record: AppliedRecord) {
        val state = store.state()
        val list = state.records.filterNot { it.id == record.id }
        val index = state.records.indexOfFirst { it.id == record.id }
        val records = if (index >= 0) list.toMutableList().apply { add(index, record) } else list + record
        store.saveState(state.copy(records = records))
    }

    internal fun removeRecord(id: String) {
        val state = store.state()
        store.saveState(state.copy(records = state.records.filterNot { it.id == id }))
    }

    private sealed class Result {
        data class Value(val value: String?) : Result()
        data class Failure(val error: String) : Result()
    }

    private fun readSettingOrError(e: SettingEntry): Result = try {
        Result.Value(gateway.readSetting(e.namespace, e.key))
    } catch (ex: Exception) {
        Result.Failure(describe(ex))
    }

    /** Runs [block]; returns its error text, or the exception's. */
    internal inline fun attempt(block: () -> String?): String? = try {
        block()
    } catch (e: Exception) {
        describe(e)
    }

    internal inline fun <T> safe(block: () -> T): T? = try {
        block()
    } catch (_: Exception) {
        null
    }

    internal fun describe(e: Exception) = "${e.javaClass.simpleName}: ${e.message.orEmpty()}".trim().take(MAX_ERROR)

    companion object {
        const val EVENT_TYPE = "security.policy"
        const val LABEL_DNS = "DNS privé imposé"
        const val LABEL_BACKUP = "Réactiver la sauvegarde Android"
        const val DENY_REASON = "liste de refus (paquet vital, OTA, attestation, lanceur, téléphone, clavier, installeur ou Vigie)"
        const val OWNER_TARGET = "io.github.erwsim.vigie"
        internal const val MAX_ERROR = 300

        fun kindOf(item: CatalogItem): ItemKind = when (item) {
            is PackageEntry -> ItemKind.PACKAGE
            is PermissionEntry -> ItemKind.PERMISSION
            is RestrictionEntry -> ItemKind.RESTRICTION
            is SettingEntry -> ItemKind.SETTING
        }

        fun targetOf(item: CatalogItem): String = when (item) {
            is PackageEntry -> item.pkg
            is PermissionEntry -> item.pkg
            is RestrictionEntry -> item.key
            is SettingEntry -> item.key
        }

        fun labelOf(item: CatalogItem): String = when (item) {
            is PackageEntry -> item.label
            is PermissionEntry -> item.label
            is RestrictionEntry -> item.title
            is SettingEntry -> item.title
        }
    }
}
