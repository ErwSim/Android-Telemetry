package io.github.erwsim.watchpost.policy.engine

import io.github.erwsim.watchpost.core.event.Severity

/** The five capability guards of contract §11.1. [wire] is the `<clé>` of `profile = "guard:<clé>"`. */
enum class GuardKey(val wire: String) {
    SMS("sms"),
    CALLS("calls"),
    ACCESSIBILITY("accessibility"),
    INPUT_METHODS("input_methods"),
    QUARANTINE("quarantine"),
    ;

    /** Id of the record that says the guard is on. */
    val recordId: String get() = CapabilityGuards.PREFIX + wire

    /** `security.policy.profile` of everything the guard does. */
    val profile: String get() = "guard:$wire"

    /** Id of the record of the permissions this guard denied to [pkg]. */
    fun packageRecordId(pkg: String) = "$recordId:$pkg"

    /** Guards acting package by package (applied to packages installed or updated later too). */
    val perPackage: Boolean get() = this == SMS || this == CALLS || this == QUARANTINE

    /** Guards with an exception list chosen by the owner. */
    val hasList: Boolean get() = this != QUARANTINE

    /** Guards with the "also deny…" option. */
    val hasExtended: Boolean get() = this == SMS || this == CALLS

    companion object {
        fun of(wire: String): GuardKey? = entries.firstOrNull { it.wire == wire }
    }
}

/** Runtime permissions each guard denies (names checked against the android-37 SDK `Manifest.permission`). */
object GuardPermissions {
    val SMS_SEND = listOf("android.permission.SEND_SMS")

    /** Option "refuser aussi la lecture et la réception" (contract: READ_SMS/RECEIVE_SMS; MMS and WAP push are the same group). */
    val SMS_EXTENDED = listOf(
        "android.permission.READ_SMS",
        "android.permission.RECEIVE_SMS",
        "android.permission.RECEIVE_MMS",
        "android.permission.RECEIVE_WAP_PUSH",
    )
    val CALLS = listOf("android.permission.CALL_PHONE")

    /** Option: answering calls and the call log (contract: ANSWER_PHONE_CALLS, READ_CALL_LOG; WRITE_CALL_LOG added). */
    val CALLS_EXTENDED = listOf(
        "android.permission.ANSWER_PHONE_CALLS",
        "android.permission.READ_CALL_LOG",
        "android.permission.WRITE_CALL_LOG",
    )

    /** Quarantine: SMS, calls, call log, contacts, microphone, camera, background location, nearby devices. */
    val QUARANTINE = SMS_SEND + SMS_EXTENDED + CALLS + CALLS_EXTENDED + listOf(
        "android.permission.READ_CONTACTS",
        "android.permission.WRITE_CONTACTS",
        "android.permission.GET_ACCOUNTS",
        "android.permission.RECORD_AUDIO",
        "android.permission.CAMERA",
        "android.permission.ACCESS_BACKGROUND_LOCATION",
        "android.permission.BLUETOOTH_SCAN",
        "android.permission.BLUETOOTH_CONNECT",
        "android.permission.BLUETOOTH_ADVERTISE",
        "android.permission.NEARBY_WIFI_DEVICES",
        "android.permission.UWB_RANGING",
        "android.permission.RANGING",
    )

    /** Every permission a guard can deny (the blind sweep restores only these). */
    val ALL: Set<String> = QUARANTINE.toSet()

    fun of(key: GuardKey, extended: Boolean): List<String> = when (key) {
        GuardKey.SMS -> if (extended) SMS_SEND + SMS_EXTENDED else SMS_SEND
        GuardKey.CALLS -> if (extended) CALLS + CALLS_EXTENDED else CALLS
        GuardKey.QUARANTINE -> QUARANTINE
        GuardKey.ACCESSIBILITY, GuardKey.INPUT_METHODS -> emptyList()
    }
}

/**
 * Packages a guard never touches, whatever its list says (contract §11.1 "Garde-fous", §11.4): Watchpost and
 * its companion, every system app (`FLAG_SYSTEM`: SOS, carrier and Samsung services that send SMS or
 * call), the hard-coded [PackageDenyList], and the **current** holder of the role that matches the guard:
 * the default SMS app for `sms`, the default dialer for `calls`. A keyboard or a home screen chosen by the
 * user is **not** spared (§11.4): "choose a home app" is one tap a malicious app can ask for, and neither
 * role needs SMS or calls. Neither are the active device admins nor every app able to be a launcher.
 * Quarantine spares no role holder: a quarantined app that becomes the default SMS app or dialer only gets
 * the permissions of that role back ([CapabilityGuards] `applyQuarantine`).
 */
object GuardSafety {
    const val SELF = "io.github.erwsim.watchpost"
    const val COMPANION = "io.github.erwsim.watchpost.notifier"

    const val REASON_SELF = "Watchpost ou son compagnon"
    const val REASON_SYSTEM = "application du système"
    const val REASON_DENY_LIST = "liste de refus (composant vital)"
    const val REASON_SMS = "appli SMS par défaut"
    const val REASON_DIALER = "composeur par défaut"
    const val REASON_LIST = "liste choisie"

    /**
     * Why [app] is out of reach of guard [key] (null: it is not). [allowed] is the guard's exception list.
     * Role holders are spared only by the guard of their own role; quarantine spares none.
     */
    fun exemption(key: GuardKey, app: AppInfo, roles: DeviceRoles, allowed: Collection<String> = emptySet()): String? = when {
        app.pkg == SELF || app.pkg == COMPANION -> REASON_SELF
        app.system -> REASON_SYSTEM
        PackageDenyList.isDenied(app.pkg) -> REASON_DENY_LIST
        else -> ownRoleOf(key, app.pkg, roles) ?: REASON_LIST.takeIf { app.pkg in allowed }
    }

    /** The role of [pkg] that guard [key] spares: SMS app for `sms`, dialer for `calls`, nothing otherwise. */
    fun ownRoleOf(key: GuardKey, pkg: String, roles: DeviceRoles): String? = when (key) {
        GuardKey.SMS -> REASON_SMS.takeIf { pkg == roles.sms }
        GuardKey.CALLS -> REASON_DIALER.takeIf { pkg == roles.dialer || pkg == roles.systemDialer }
        else -> null
    }

    /** SMS app or dialer role of [pkg] (the two roles whose permissions a quarantine gives back). */
    fun smsOrDialerRole(pkg: String, roles: DeviceRoles): String? = when (pkg) {
        roles.sms -> REASON_SMS
        roles.dialer, roles.systemDialer -> REASON_DIALER
        else -> null
    }

    fun isRoleReason(reason: String?): Boolean = reason == REASON_SMS || reason == REASON_DIALER


    /**
     * Permissions Android grants to the holder of a role (`roles.xml` of the Permission module: the SMS and
     * dialer roles both get the `sms` and `phone` sets) and that a denial by policy made it skip: the role
     * grant stops at a permission "fixed to revoked" (`Permissions.grantSingleAsUser`). When a guard lifts
     * its denial because the app became the default SMS app or dialer, these are granted, as the role would
     * have done — otherwise the new SMS app could neither send nor (with the option) receive, and incoming
     * SMS would be lost until the user notices. Sensors and contacts are left to the usual prompt.
     */
    fun roleGrants(reason: String?): Set<String> = when (reason) {
        REASON_SMS -> (GuardPermissions.SMS_SEND + GuardPermissions.SMS_EXTENDED + GuardPermissions.CALLS).toSet()
        REASON_DIALER -> (GuardPermissions.SMS_SEND + GuardPermissions.SMS_EXTENDED + GuardPermissions.CALLS + GuardPermissions.CALLS_EXTENDED).toSet()
        else -> emptySet()
    }
}

/** Something a guard did on its own, to be shown to the owner (never silent). */
sealed class GuardNotice {
    /** A newly installed app was quarantined; [denied] may be empty (nothing risky requested yet). */
    data class Quarantined(val pkg: String, val denied: List<String>) : GuardNotice()

    /**
     * A package became a default role holder: its denials were lifted. [joined]: it also joined the guard's
     * exception list (default SMS app for the SMS guard, default dialer for the calls guard); otherwise it
     * is only spared while it holds the role (keyboard, home screen…).
     */
    data class RoleHolder(val key: GuardKey, val pkg: String, val role: String, val lifted: List<String>, val joined: Boolean = true) : GuardNotice()

    /** A quarantined app was released automatically (it became a role holder). */
    data class Released(val pkg: String, val reason: String) : GuardNotice()
}

/** One application in a guard preview: what it loses, what it gets back. */
data class GuardLine(val pkg: String, val deny: List<String> = emptyList(), val restore: List<String> = emptyList(), val note: String? = null)

/** "Ce qui va changer" for one guard. */
data class GuardPreview(
    val key: GuardKey,
    val enable: Boolean,
    /** Apps that lose or regain permissions. */
    val lines: List<GuardLine> = emptyList(),
    /** Apps that request the guarded permissions but are left alone, with the reason. */
    val exempt: List<Pair<String, String>> = emptyList(),
    /** Accessibility/keyboards: enabled non-system services that stay allowed (Android requires it). */
    val kept: List<String> = emptyList(),
    /** Accessibility/keyboards: installed non-system services that can no longer be switched on. */
    val blocked: List<String> = emptyList(),
    /** Accessibility/keyboards: the permitted list that will be set (null: no restriction). */
    val permitted: List<String>? = null,
    val notes: List<String> = emptyList(),
) {
    val changes: Boolean get() = lines.any { it.deny.isNotEmpty() || it.restore.isNotEmpty() } || permitted != null || !enable
}

/** What the screen shows of one guard. */
data class GuardStatus(
    val key: GuardKey,
    val active: Boolean,
    /** Written but not confirmed (the process died while applying): completed at the next reconciliation. */
    val pending: Boolean = false,
    val extended: Boolean = false,
    /** Exception list in force (snapshot taken when applied). */
    val allowed: List<String> = emptyList(),
    /** Package records of this guard (also those left over after a failed undo). */
    val packages: List<AppliedRecord> = emptyList(),
    val activatedAtMs: Long = 0,
    val permitted: List<String>? = null,
    val lastError: String? = null,
)

/**
 * The capability guards (contract §11.1), built on the policy engine: same lock, same persisted state
 * ([PolicyStore], write-ahead), same undo. Records:
 * - `guard:<clé>` ([ItemKind.GUARD]): the guard is on, with its option and the exception list in force;
 *   for `accessibility` / `input_methods` it also holds the permitted list before Watchpost;
 * - `guard:<clé>:<paquet>` ([ItemKind.PERMISSION]): the permissions this guard denied to a package, with
 *   their previous state (undone by [PolicyEngine.revertPermissions], crash-safe like a catalog item).
 *
 * "Tout rétablir", the ADB rescue and the removal of the Device Owner undo the guard records first
 * ([PolicyEngine.revertAll]); with an unreadable state the sweep ([sweepLocked]) gives every guarded
 * permission denied without a record back to the user and lifts the permitted lists.
 *
 * Permission denials only reach the packages that request the permission; system apps and the role
 * holders of [GuardSafety] are never touched. A failure on one package is reported and does not stop
 * the others.
 */
class CapabilityGuards internal constructor(
    private val e: PolicyEngine,
    private val notify: (GuardNotice) -> Unit,
    private val follow: (GuardKey, String) -> Unit,
) {
    private val gw get() = e.gateway

    // ---------------------------------------------------------------- reading

    fun status(): Map<GuardKey, GuardStatus> = synchronized(e.lock) {
        val records = e.store.state().records
        GuardKey.entries.associateWith { key ->
            val g = records.firstOrNull { it.id == key.recordId }
            GuardStatus(
                key = key,
                active = g != null,
                pending = g?.status == RecordStatus.PENDING,
                extended = g?.guardExtended ?: false,
                allowed = g?.guardAllowed.orEmpty(),
                packages = records.filter { it.id.startsWith(key.recordId + ":") },
                activatedAtMs = g?.appliedAtMs ?: 0,
                permitted = g?.appliedList,
                lastError = g?.lastError,
            )
        }
    }

    fun isActive(key: GuardKey): Boolean = e.record(key.recordId) != null

    /** Quarantined applications (records), oldest first. */
    fun quarantined(): List<AppliedRecord> = synchronized(e.lock) {
        e.store.state().records.filter { it.id.startsWith(GuardKey.QUARANTINE.recordId + ":") }
    }

    // ---------------------------------------------------------------- preview

    /**
     * Exactly which applications lose or regain what if [key] is switched to [enable] with [extended]
     * and the exception list [allowed]. Pure reads.
     */
    fun preview(key: GuardKey, enable: Boolean, extended: Boolean = false, allowed: Set<String> = emptySet()): GuardPreview = synchronized(e.lock) {
        val g = e.record(key.recordId)
        if (!enable) return@synchronized previewDisable(key, g)
        when (key) {
            GuardKey.SMS, GuardKey.CALLS -> previewPermissions(key, extended, allowed)
            GuardKey.QUARANTINE -> GuardPreview(
                key, true,
                notes = listOf(
                    if (g == null) "Aucune application déjà installée n'est touchée." else "Garde déjà active.",
                    "Chaque application non système installée ensuite se verra refuser : " +
                        GuardPermissions.QUARANTINE.joinToString { short(it) } + ", jusqu'à ce que vous la libériez. Une notification l'annonce à chaque fois.",
                ),
            )
            GuardKey.ACCESSIBILITY, GuardKey.INPUT_METHODS -> previewServices(key, allowed)
        }
    }

    private fun previewDisable(key: GuardKey, g: AppliedRecord?): GuardPreview {
        if (key.perPackage) {
            val lines = e.store.state().records.filter { it.id.startsWith(key.recordId + ":") }.map { r ->
                GuardLine(r.target, restore = r.permissions.filter { it.applied }.map { it.permission }, note = if (key == GuardKey.QUARANTINE) "libérée" else null)
            }
            return GuardPreview(key, false, lines = lines)
        }
        val prev = if (g?.prevListSet == true) g.prevList else null
        return GuardPreview(key, false, permitted = prev, notes = listOf(if (prev == null) "Plus aucune restriction : tout service peut de nouveau être activé." else "Liste d'avant Watchpost rétablie."))
    }

    private fun previewPermissions(key: GuardKey, extended: Boolean, allowed: Set<String>): GuardPreview {
        val wanted = GuardPermissions.of(key, extended)
        val roles = e.safe { gw.roles() } ?: DeviceRoles()
        val apps = e.safe { gw.installedApps() } ?: return GuardPreview(key, true, notes = listOf("Liste des applications illisible : rien ne serait appliqué."))
        val lines = ArrayList<GuardLine>()
        val exempt = ArrayList<Pair<String, String>>()
        for (app in apps.sortedBy { it.pkg }) {
            val requested = wanted.filter { it in app.requested }
            val record = e.record(key.packageRecordId(app.pkg))
            val held = record?.permissions?.filter { it.applied }?.map { it.permission }.orEmpty()
            if (requested.isEmpty() && held.isEmpty()) continue
            val reason = GuardSafety.exemption(key, app, roles, allowed)
            if (reason != null) {
                if (requested.isNotEmpty()) exempt += app.pkg to reason
                if (held.isNotEmpty()) lines += GuardLine(app.pkg, restore = held, note = reason)
                continue
            }
            val deny = requested.filter { it !in held && e.safe { gw.permissionGrantState(app.pkg, it) } != Dpm.GRANT_DENIED }
            val alreadyDenied = requested.filter { it !in held && it !in deny }
            val shared = alreadyDenied.filter { e.claimOf(app.pkg, it, key.packageRecordId(app.pkg)) != null }
            val outside = alreadyDenied - shared.toSet()
            val restore = held.filter { it !in wanted }
            val granted = deny.filter { e.safe { gw.isPermissionGranted(app.pkg, it) } == true }
            if (deny.isNotEmpty() || restore.isNotEmpty() || shared.isNotEmpty()) {
                lines += GuardLine(
                    app.pkg, deny, restore,
                    listOfNotNull(
                        "déjà accordée, sera retirée : ${granted.joinToString { short(it) }}".takeIf { granted.isNotEmpty() },
                        "déjà refusée par un autre élément de Watchpost : ${shared.joinToString { short(it) }}".takeIf { shared.isNotEmpty() },
                        "déjà refusée hors de Watchpost (laissée telle quelle) : ${outside.joinToString { short(it) }}".takeIf { outside.isNotEmpty() },
                    ).joinToString(" ; ").ifEmpty { null },
                )
            }
        }
        // Records of packages that are no longer installed: cleaned up.
        val installed = apps.map { it.pkg }.toSet()
        e.store.state().records.filter { it.id.startsWith(key.recordId + ":") && it.target !in installed }
            .forEach { lines += GuardLine(it.target, restore = it.permissions.filter { p -> p.applied }.map { p -> p.permission }, note = "désinstallée") }
        return GuardPreview(
            key, true, lines = lines, exempt = exempt,
            notes = listOf("Appliquée aussi aux applications installées ou mises à jour ensuite (sauf exceptions)."),
        )
    }

    private fun previewServices(key: GuardKey, allowed: Set<String>): GuardPreview {
        val services = e.safe { if (key == GuardKey.ACCESSIBILITY) gw.accessibilityServices() else gw.inputMethods() }
            ?: return GuardPreview(key, true, notes = listOf("Liste des services illisible : rien ne serait appliqué."))
        val (permitted, kept) = permittedList(services, allowed)
        val blocked = services.filter { !it.system && !it.enabled && it.pkg !in permitted }.map { it.pkg }
        val missing = allowed.filter { a -> services.none { it.pkg == a } }
        return GuardPreview(
            key, true, kept = kept, blocked = blocked, permitted = permitted,
            notes = listOfNotNull(
                "Les services du système restent toujours permis (Android ne permet pas de les restreindre).",
                ("Déjà activés, gardés car Android l'exige : ${kept.joinToString()}. Désactivez-les dans les Paramètres d'abord " +
                    "s'ils ne doivent pas l'être, puis réappliquez.").takeIf { kept.isNotEmpty() },
                "Dans la liste mais absents (aucun service de ce type installé) : ${missing.joinToString()}.".takeIf { missing.isNotEmpty() },
            ),
        )
    }

    /** List to set: the owner's choice plus every enabled non-system service (the platform refuses otherwise). */
    private fun permittedList(services: List<ServiceApp>, allowed: Set<String>): Pair<List<String>, List<String>> {
        val kept = services.filter { it.enabled && !it.system && it.pkg !in allowed }.map { it.pkg }.distinct()
        return (allowed + kept).sorted() to kept.sorted()
    }

    // ---------------------------------------------------------------- switching

    /**
     * Switches [key] on (or re-applies it with a new option or list) or off. The guard record is written
     * before anything changes on the device; each package is handled in isolation.
     */
    fun set(key: GuardKey, enable: Boolean, extended: Boolean = false, allowed: Set<String> = emptySet()): EngineReport = synchronized(e.lock) {
        if (!e.isDeviceOwner()) return@synchronized EngineReport(failed = listOf("Watchpost n'est pas Device Owner"))
        if (!enable) {
            val g = e.record(key.recordId) ?: return@synchronized EngineReport()
            return@synchronized e.isolated(key.recordId) { revertGuardRecord(g) }
        }
        e.isolated(key.recordId) {
            when (key) {
                GuardKey.SMS, GuardKey.CALLS -> enablePermissions(key, extended, allowed)
                GuardKey.QUARANTINE -> enableQuarantine()
                GuardKey.ACCESSIBILITY, GuardKey.INPUT_METHODS -> enableServices(key, allowed)
            }
        }
    }

    private fun guardRecord(key: GuardKey, existing: AppliedRecord?) = existing ?: AppliedRecord(
        id = key.recordId, kind = ItemKind.GUARD, target = key.wire, profile = key.profile, appliedAtMs = e.clock.nowMillis(),
    )

    private fun enablePermissions(key: GuardKey, extended: Boolean, allowed: Set<String>): EngineReport {
        val existing = e.record(key.recordId)
        val g = guardRecord(key, existing).copy(status = RecordStatus.PENDING, guardExtended = extended, guardAllowed = allowed.sorted(), lastError = null)
        e.putRecord(g)
        retryFailed(key)
        val apps = gw.installedApps()
        val report = applyPermissionGuard(key, apps, e.safe { gw.roles() } ?: DeviceRoles(), cleanup = true)
        e.putRecord((e.record(key.recordId) ?: g).copy(status = RecordStatus.APPLIED, lastError = report.failed.lastOrNull()))
        return report + enabledEvent(key, report, existing != null)
    }

    private fun enableQuarantine(): EngineReport {
        val key = GuardKey.QUARANTINE
        val existing = e.record(key.recordId)
        if (existing != null) return EngineReport()
        // Nothing changes on the device now: from this instant, new installs are quarantined.
        e.putRecord(guardRecord(key, null).copy(status = RecordStatus.APPLIED))
        return enabledEvent(key, EngineReport(), false)
    }

    private fun enableServices(key: GuardKey, allowed: Set<String>): EngineReport {
        val acc = key == GuardKey.ACCESSIBILITY
        val existing = e.record(key.recordId)
        val services = if (acc) gw.accessibilityServices() else gw.inputMethods()
        val (permitted, _) = permittedList(services, allowed)
        val before = if (acc) gw.permittedAccessibilityServices() else gw.permittedInputMethods()
        val g = guardRecord(key, existing).copy(
            status = RecordStatus.PENDING,
            guardAllowed = allowed.sorted(),
            appliedList = permitted,
            // The state before Watchpost is recorded once, on the first activation.
            prevList = existing?.prevList ?: before,
            prevListSet = existing?.prevListSet ?: (before != null),
            lastError = null,
        )
        e.putRecord(g)
        val error = e.attempt {
            val ok = if (acc) gw.setPermittedAccessibilityServices(permitted) else gw.setPermittedInputMethods(permitted)
            if (!ok) "refusé par le système (un service activé manque à la liste ?)" else null
        }
        val now = e.safe { if (acc) gw.permittedAccessibilityServices() else gw.permittedInputMethods() }
        val ok = now != null && now.toSet() == permitted.toSet()
        when {
            ok -> e.putRecord(g.copy(status = RecordStatus.APPLIED))
            existing != null -> e.putRecord(existing)
            sameList(now, before) -> e.removeRecord(g.id)
            // Something changed but not what was asked: kept (pending) so that "Rétablir" restores the list before.
            else -> e.putRecord(g.copy(lastError = error ?: "aucun effet constaté"))
        }
        return e.outcome("guard_enabled", key.wire, key.profile, ok, if (ok) null else error ?: "aucun effet constaté", if (ok) Severity.NOTABLE else null)
    }

    private fun enabledEvent(key: GuardKey, report: EngineReport, reapplied: Boolean): EngineReport {
        val failures = report.failed.size
        val detail = listOfNotNull("réappliquée".takeIf { reapplied }, "$failures échec(s) sur des paquets".takeIf { failures > 0 }).joinToString(" ; ").ifEmpty { null }
        // The guard is on even if a package failed (reported by its own permission_denied event).
        e.logAction("guard_enabled", key.wire, key.profile, true, detail, Severity.NOTABLE)
        return EngineReport(succeeded = listOf("guard_enabled ${key.wire}"))
    }

    // ---------------------------------------------------------------- application to packages

    /**
     * Brings every package to what the SMS or calls guard wants: denied what it requests unless exempt,
     * restored what is no longer wanted (option or list reduced, role holder, uninstalled).
     */
    private fun applyPermissionGuard(key: GuardKey, apps: List<AppInfo>, roles: DeviceRoles, cleanup: Boolean): EngineReport {
        var g = e.record(key.recordId) ?: return EngineReport()
        val wanted = GuardPermissions.of(key, g.guardExtended == true)
        var report = EngineReport()
        for (app in apps) {
            val id = key.packageRecordId(app.pkg)
            val record = e.record(id)
            val requested = wanted.filter { it in app.requested }
            if (requested.isEmpty() && record == null) continue
            val reason = GuardSafety.exemption(key, app, roles, g.guardAllowed.orEmpty())
            // (The role comes before the list in [GuardSafety.exemption]: a listed app that becomes the default SMS app is a role holder.)
            val role = reason.takeIf(GuardSafety::isRoleReason)
            val lifted = record?.permissions?.filter { it.applied }?.map { it.permission }.orEmpty()
            // "La liste suit": a new default SMS app (SMS guard) / dialer (calls guard) requesting the guarded
            // permissions joins the list (only the guard's own role is ever a reason here, §11.4).
            if (role != null && requested.isNotEmpty() && app.pkg !in g.guardAllowed.orEmpty()) {
                g = g.copy(guardAllowed = (g.guardAllowed.orEmpty() + app.pkg).sorted())
                report += e.bookkeeping(g.id) { e.putRecord(g) }
                e.safe { follow(key, app.pkg) }
                e.safe { notify(GuardNotice.RoleHolder(key, app.pkg, role, lifted, joined = true)) }
            } else if (role != null && lifted.isNotEmpty()) {
                e.safe { notify(GuardNotice.RoleHolder(key, app.pkg, role, lifted, joined = false)) }
            }
            val target = if (reason == null) requested else emptyList()
            // What Android grants to the new default SMS app / dialer and our denial made it skip is granted back.
            val grant = if (role != null && lifted.isNotEmpty()) GuardSafety.roleGrants(role) else emptySet()
            report += e.isolated(id) { sync(key, app.pkg, record, target, keepEmpty = false, grant = grant) }
        }
        if (cleanup) report += cleanupUninstalled(key, apps)
        return report
    }

    /** Makes the record of [pkg] hold exactly [wanted] denied (restores the extra ones, denies the missing ones). */
    private fun sync(key: GuardKey, pkg: String, stored: AppliedRecord?, wanted: List<String>, keepEmpty: Boolean, grant: Set<String> = emptySet()): EngineReport {
        var report = EngineReport()
        val record = stored?.let { settle(it, keepEmpty) }
        if (record != null) {
            val extra = record.permissions.map { it.permission }.filter { it !in wanted }.toSet()
            if (extra.isNotEmpty()) report += e.revertPermissions(record, only = extra, keepRecord = keepEmpty, grant = grant)
        }
        // Entries not applied are earlier failures: not retried here (see retryFailed).
        val held = e.record(key.packageRecordId(pkg))?.permissions?.map { it.permission }.orEmpty()
        val missing = wanted.filter { it !in held }
        if (missing.isNotEmpty()) {
            val base = AppliedRecord(id = key.packageRecordId(pkg), kind = ItemKind.PERMISSION, target = pkg, profile = key.profile, appliedAtMs = e.clock.nowMillis())
            report += e.denyPermissions(base, missing, keepEmpty)
        }
        return report
    }

    /**
     * Brings a package record back in line with the device before it is used. Returns the record to work
     * with (null: nothing of it is left and it was dropped).
     * - A record left **pending** by a crash: a permission denied on the device without having been
     *   confirmed is confirmed (it was denied by us: its previous state is in the record, so it can be
     *   undone); one that was not reached is forgotten, so that it is denied now. Without this, the
     *   interrupted guard would stay half applied for ever, and a later re-application would forget the
     *   unconfirmed denial — leaving the permission denied and locked with nothing to undo it.
     * - A permission recorded as denied that is **no longer denied by policy** on the device (the app was
     *   uninstalled and reinstalled between two passes, or Watchpost lost the Device Owner role for a while:
     *   both reset the policy state) is forgotten too, hence denied again with its fresh previous state.
     * A state that cannot be read changes nothing.
     */
    private fun settle(record: AppliedRecord, keepEmpty: Boolean): AppliedRecord? {
        val pending = record.status == RecordStatus.PENDING
        var unknown = false
        val permissions = record.permissions.mapNotNull { p ->
            val state = e.safe { gw.permissionGrantState(record.target, p.permission) }
            when {
                state == null -> p.also { unknown = true }
                p.applied -> p.takeIf { state == Dpm.GRANT_DENIED }
                !pending -> p // an earlier failure: retried only by a re-application (see retryFailed)
                state == Dpm.GRANT_DENIED && p.prevState != Dpm.GRANT_DENIED -> p.copy(applied = true)
                else -> null
            }
        }
        val status = if (pending && unknown) RecordStatus.PENDING else RecordStatus.APPLIED
        if (permissions == record.permissions && status == record.status) return record
        if (permissions.isEmpty() && !keepEmpty) {
            e.removeRecord(record.id)
            return null
        }
        return record.copy(permissions = permissions, status = status).also { e.putRecord(it) }
    }

    /** Permissions that failed earlier are forgotten, so that the next application tries them again. */
    private fun retryFailed(key: GuardKey) {
        for (stored in e.store.state().records.filter { it.id.startsWith(key.recordId + ":") }) {
            // First what a crash left unconfirmed (never forgotten while it is denied on the device).
            val r = settle(stored, keepEmpty = key == GuardKey.QUARANTINE) ?: continue
            if (r.status == RecordStatus.PENDING || r.permissions.all { it.applied }) continue
            val kept = r.permissions.filter { it.applied }
            if (kept.isEmpty() && key != GuardKey.QUARANTINE) e.removeRecord(r.id) else e.putRecord(r.copy(permissions = kept))
        }
    }

    /** Records of packages that are gone: the denial is lifted (best effort) and the record dropped. */
    private fun cleanupUninstalled(key: GuardKey, apps: List<AppInfo>): EngineReport {
        val installed = apps.map { it.pkg }.toSet()
        var report = EngineReport()
        for (r in e.store.state().records.filter { it.id.startsWith(key.recordId + ":") && it.target !in installed }) {
            // Still installed according to the package manager (the list was partial)? Then leave it.
            if (e.safe { gw.isInstalled(r.target) } != false) continue
            report += e.isolated(r.id) { e.revertPermissions(r) }
        }
        return report
    }

    // ---------------------------------------------------------------- quarantine

    private fun applyQuarantine(apps: List<AppInfo>, roles: DeviceRoles): EngineReport {
        val key = GuardKey.QUARANTINE
        var g = e.record(key.recordId) ?: return EngineReport()
        var report = EngineReport()
        for (app in apps) {
            val id = key.packageRecordId(app.pkg)
            val record = e.record(id)
            val reason = GuardSafety.exemption(key, app, roles)
            val requested = GuardPermissions.QUARANTINE.filter { it in app.requested }
            // Becoming the default SMS app or dialer is exactly the path of SMS trojans (one system dialog): the
            // app stays in quarantine. Only the permissions of its role are given back (granted, as Android
            // would have done: otherwise incoming SMS or calls would be lost silently), contacts, microphone,
            // camera, location and nearby devices stay denied, and the owner is told loudly. He releases it,
            // or changes the default app back (the role permissions are then denied again).
            val role = GuardSafety.smsOrDialerRole(app.pkg, roles)
            val roleGrants = if (role != null) GuardSafety.roleGrants(role) else emptySet()
            if (record != null) {
                if (reason != null) continue // system app or Watchpost: never quarantined (cannot happen in practice)
                val wanted = (record.permissions.map { it.permission } + requested).distinct().filter { it !in roleGrants }
                val lifted = record.permissions.filter { it.applied && it.permission in roleGrants }.map { it.permission }
                // Update of a quarantined app: newly requested risky permissions are denied too.
                report += e.isolated(id) { sync(key, app.pkg, record, wanted, keepEmpty = true, grant = roleGrants) }
                if (role != null && lifted.isNotEmpty()) e.safe { notify(GuardNotice.RoleHolder(key, app.pkg, role, lifted, joined = false)) }
                continue
            }
            if (reason != null) continue
            // Present at activation, or released (and not reinstalled since): never quarantined.
            if (app.firstInstallMs < g.appliedAtMs) continue
            if (g.released[app.pkg] == app.firstInstallMs) continue
            report += e.isolated(id) { quarantine(app, requested.filter { it !in roleGrants }) }
            if (role != null) e.safe { notify(GuardNotice.RoleHolder(key, app.pkg, role, emptyList(), joined = false)) }
        }
        report += cleanupUninstalled(key, apps)
        // Released packages that are gone: a later install is a new one (quarantined again).
        val installed = apps.associate { it.pkg to it.firstInstallMs }
        val pruned = g.released.filter { (pkg, t) -> installed[pkg] == t }
        if (pruned.size != g.released.size) report += e.bookkeeping(g.id) { e.putRecord(g.copy(released = pruned)) }
        return report
    }

    private fun quarantine(app: AppInfo, requested: List<String>): EngineReport {
        val key = GuardKey.QUARANTINE
        val base = AppliedRecord(
            id = key.packageRecordId(app.pkg), kind = ItemKind.PERMISSION, target = app.pkg, profile = key.profile,
            appliedAtMs = e.clock.nowMillis(), firstInstallMs = app.firstInstallMs,
        )
        var report = e.denyPermissions(base, requested, keepEmpty = true)
        val record = e.record(base.id)
        val denied = record?.permissions?.filter { it.applied }?.map { it.permission }.orEmpty()
        val failed = requested.filter { it !in denied && e.safe { gw.permissionGrantState(app.pkg, it) } != Dpm.GRANT_DENIED }
        val ok = record != null && failed.isEmpty()
        report += e.outcome(
            "quarantined", app.pkg, key.profile, ok,
            when {
                record == null -> "état non enregistré"
                failed.isNotEmpty() -> "non refusées : ${failed.joinToString { short(it) }}"
                else -> null
            },
            Severity.NOTABLE,
        )
        e.safe { notify(GuardNotice.Quarantined(app.pkg, denied)) }
        return report
    }

    /** "Libérer": the quarantined app's permissions go back to their state before the quarantine ("à demander" for a new install). */
    fun release(pkg: String): EngineReport = synchronized(e.lock) {
        val record = e.record(GuardKey.QUARANTINE.packageRecordId(pkg)) ?: return@synchronized EngineReport()
        if (!e.isDeviceOwner()) return@synchronized EngineReport(failed = listOf("Watchpost n'est pas Device Owner"))
        e.isolated(record.id) { releaseLocked(record, auto = null) }
    }

    private fun releaseLocked(record: AppliedRecord, auto: String?, grant: Set<String> = emptySet()): EngineReport {
        val key = GuardKey.QUARANTINE
        var report = e.revertPermissions(record, grant = grant)
        val done = e.record(record.id) == null
        if (done) {
            val firstInstall = e.safe { gw.appInfo(record.target) }?.firstInstallMs ?: record.firstInstallMs
            e.record(key.recordId)?.let { g ->
                if (firstInstall != null) report += e.bookkeeping(g.id) { e.putRecord(g.copy(released = g.released + (record.target to firstInstall))) }
            }
        }
        report += e.outcome("released", record.target, key.profile, done, if (done) auto?.let { "automatique : $it" } else report.failed.lastOrNull() ?: "état non restauré")
        if (done && auto != null) e.safe { notify(GuardNotice.Released(record.target, auto)) }
        return report
    }

    // ---------------------------------------------------------------- reconciliation

    /**
     * Re-applies every active guard to the current packages: new installs (quarantine, SMS, calls),
     * updates that request new permissions, role changes (lifted for the new holder, "la liste suit"),
     * uninstalled packages (cleaned up). Called on package broadcasts, at agent start, by the 15-min
     * maintenance and when the screen opens. A guard left pending by a crash is completed.
     */
    fun reconcile(): EngineReport = synchronized(e.lock) {
        val guards = e.store.state().records.filter { it.kind == ItemKind.GUARD }
        if (guards.none { GuardKey.of(it.target)?.perPackage == true }) return@synchronized EngineReport()
        if (!e.isDeviceOwner()) return@synchronized EngineReport()
        val apps = e.safe { gw.installedApps() } ?: return@synchronized EngineReport(failed = listOf("liste des applications illisible"))
        val roles = e.safe { gw.roles() } ?: DeviceRoles()
        var report = EngineReport()
        for (g in guards) {
            val key = GuardKey.of(g.target) ?: continue
            report += e.isolated(g.id) {
                val r = when (key) {
                    GuardKey.SMS, GuardKey.CALLS -> applyPermissionGuard(key, apps, roles, cleanup = true)
                    GuardKey.QUARANTINE -> applyQuarantine(apps, roles)
                    else -> EngineReport()
                }
                if (g.status == RecordStatus.PENDING && key.perPackage) {
                    e.record(g.id)?.let { e.putRecord(it.copy(status = RecordStatus.APPLIED)) }
                }
                r
            }
        }
        report
    }

    // ---------------------------------------------------------------- undo

    /** Undoes a guard: its package records first, then the guard itself (accessibility/keyboards: the list before). */
    internal fun revertGuardRecord(g: AppliedRecord): EngineReport {
        val key = GuardKey.of(g.target) ?: return e.bookkeeping(g.id) { e.removeRecord(g.id) }
        var report = EngineReport()
        if (key.perPackage) {
            // The guard is switched off first: if the process dies while its packages are being restored, it
            // must not deny again (at the next reconciliation) what was already given back. What is left is
            // undone by the next "Tout rétablir".
            report += e.bookkeeping(g.id) { e.removeRecord(g.id) }
            for (r in e.store.state().records.filter { it.id.startsWith(key.recordId + ":") }) {
                report += e.isolated(r.id) { if (key == GuardKey.QUARANTINE) undoQuarantined(r) else e.revertPermissions(r) }
            }
            val left = report.failed.size
            return report + e.outcome("guard_disabled", key.wire, key.profile, true, if (left > 0) "$left élément(s) non rétabli(s), à réessayer" else null, Severity.NOTABLE)
        }
        val acc = key == GuardKey.ACCESSIBILITY
        val prev = if (g.prevListSet) g.prevList.orEmpty() else null
        val error = e.attempt {
            val ok = if (acc) gw.setPermittedAccessibilityServices(prev) else gw.setPermittedInputMethods(prev)
            if (!ok) "refusé par le système" else null
        }
        val now = e.safe { if (acc) gw.permittedAccessibilityServices() else gw.permittedInputMethods() }
        val restored = e.safe { gw.isDeviceOwner() } == true && sameList(now, prev)
        report += e.bookkeeping(g.id) { if (restored) e.removeRecord(g.id) else e.putRecord(g.copy(lastError = error ?: "état non restauré")) }
        return report + e.outcome("guard_disabled", key.wire, key.profile, restored, if (restored) null else error ?: "état non restauré", Severity.NOTABLE)
    }

    /**
     * "Tout rétablir", first step: a per-package guard stops applying itself (its record goes, nothing changes on
     * the device; its package records are undone next, like any other record). Accessibility and keyboards
     * guards are undone by [revertGuardRecord] in the second step (they hold the list before Watchpost).
     */
    internal fun switchOff(g: AppliedRecord): EngineReport {
        val key = GuardKey.of(g.target)
        if (key != null && !key.perPackage) return EngineReport()
        val report = e.bookkeeping(g.id) { e.removeRecord(g.id) }
        return report + e.outcome("guard_disabled", g.target, g.profile, report.allOk, report.failed.lastOrNull(), Severity.NOTABLE)
    }

    /** Undo of a quarantined app outside "Libérer" (guard switched off, "Tout rétablir"): reported as released. */
    internal fun undoQuarantined(r: AppliedRecord): EngineReport {
        val sub = e.revertPermissions(r)
        val done = e.record(r.id) == null
        return sub + e.outcome("released", r.target, GuardKey.QUARANTINE.profile, done, if (done) "quarantaine levée" else sub.failed.lastOrNull() ?: "état non restauré")
    }

    /**
     * Blind undo when the state cannot be trusted: every guarded permission denied to a non-system
     * package without a record that still holds it goes back to the user's control (`DEFAULT`: not
     * granted again — the user grants it again if needed), and the permitted accessibility / keyboard
     * lists set by this admin are lifted when no guard record holds them. Only Watchpost can have set
     * these states (it is the only device admin with these powers on the phone).
     */
    internal fun sweepLocked(): EngineReport {
        var report = EngineReport()
        val records = e.store.state().records
        fun claimed(pkg: String, p: String) = records.any { r -> r.kind == ItemKind.PERMISSION && r.target == pkg && r.permissions.any { it.permission == p && it.applied } }
        val apps = e.safe { gw.installedApps() }.orEmpty()
        for (app in apps.filter { !it.system }) {
            for (p in GuardPermissions.ALL.filter { it in app.requested }) {
                if (e.safe { gw.permissionGrantState(app.pkg, p) } != Dpm.GRANT_DENIED || claimed(app.pkg, p)) continue
                val error = e.attempt { if (!gw.setPermissionGrantState(app.pkg, p, Dpm.GRANT_DEFAULT)) "refusé par le système" else null }
                val freed = e.safe { gw.permissionGrantState(app.pkg, p) } == Dpm.GRANT_DEFAULT
                report += e.outcome("permission_restored", app.pkg, null, freed, if (freed) null else error ?: "état non restauré", permission = p)
            }
        }
        for (key in listOf(GuardKey.ACCESSIBILITY, GuardKey.INPUT_METHODS)) {
            if (records.any { it.id == key.recordId }) continue
            val acc = key == GuardKey.ACCESSIBILITY
            if (e.safe { if (acc) gw.permittedAccessibilityServices() else gw.permittedInputMethods() } == null) continue
            val error = e.attempt { if (!(if (acc) gw.setPermittedAccessibilityServices(null) else gw.setPermittedInputMethods(null))) "refusé par le système" else null }
            val lifted = e.safe { if (acc) gw.permittedAccessibilityServices() else gw.permittedInputMethods() } == null
            report += e.outcome("guard_disabled", key.wire, key.profile, lifted, if (lifted) "balayage" else error ?: "aucun effet constaté")
        }
        return report
    }

    companion object {
        const val PREFIX = "guard:"

        fun isGuardId(id: String): Boolean = id.startsWith(PREFIX)

        fun isQuarantineId(id: String): Boolean = id.startsWith(GuardKey.QUARANTINE.recordId + ":")

        /** `android.permission.SEND_SMS` → `SEND_SMS`. */
        fun short(permission: String): String = permission.substringAfterLast('.')

        private fun sameList(a: List<String>?, b: List<String>?): Boolean = if (a == null || b == null) a == b else a.toSet() == b.toSet()
    }
}
