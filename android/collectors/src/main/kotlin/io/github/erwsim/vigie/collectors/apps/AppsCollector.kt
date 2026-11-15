package io.github.erwsim.vigie.collectors.apps

import android.annotation.SuppressLint
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.content.pm.PermissionInfo
import androidx.core.content.edit
import io.github.erwsim.vigie.collectors.R
import io.github.erwsim.vigie.collectors.common.sha256Hex
import io.github.erwsim.vigie.core.collector.CollectReason
import io.github.erwsim.vigie.core.collector.Collector
import io.github.erwsim.vigie.core.collector.CollectorContext
import io.github.erwsim.vigie.core.collector.PeriodicSpec
import io.github.erwsim.vigie.core.event.Severity
import io.github.erwsim.vigie.core.event.UlidGenerator
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.util.concurrent.ConcurrentHashMap

/**
 * Installed applications:
 * - `app.inventory`: full list once a day and after each boot, split into parts of < 16 KiB
 *   sharing an `inventory_id` (≈ 10 to 20 events for 400 apps);
 * - `app.installed` / `app.updated` / `app.removed` as soon as the system broadcasts them, and by
 *   difference with the previous inventory for changes made while the agent was not running;
 * - `app.permission_changed`: runtime permissions granted/revoked, found by comparing hourly
 *   scans with the persisted previous state (there is no public broadcast for this).
 *
 * Cost: one package scan per hour (no labels, one binder call), labels only for the daily
 * inventory. QUERY_ALL_PACKAGES (normal permission) makes every app visible.
 */
class AppsCollector : Collector {
    override val id = "apps"
    override val titleRes = R.string.collector_apps_title
    override val descriptionRes = R.string.collector_apps_desc
    override val eventTypes = listOf(TYPE_INVENTORY, TYPE_INSTALLED, TYPE_UPDATED, TYPE_REMOVED, TYPE_PERMISSION)
    override val periodic = PeriodicSpec(intervalMinutes = 60, runAtStart = true)

    private val mutex = Mutex()
    private val dangerous = ConcurrentHashMap<String, Boolean>()
    private val ulids = UlidGenerator()

    override suspend fun start(ctx: CollectorContext) {
        val filter = IntentFilter().apply {
            addAction(Intent.ACTION_PACKAGE_ADDED)
            addAction(Intent.ACTION_PACKAGE_REPLACED)
            addAction(Intent.ACTION_PACKAGE_REMOVED)
            addDataScheme("package")
        }
        ctx.registerReceiver(filter) { intent ->
            val pkg = intent.data?.schemeSpecificPart ?: return@registerReceiver
            val replacing = intent.getBooleanExtra(Intent.EXTRA_REPLACING, false)
            val action = intent.action
            ctx.scope.launch { onPackageBroadcast(ctx, action, pkg, replacing) }
        }
    }

    private suspend fun onPackageBroadcast(ctx: CollectorContext, action: String?, pkg: String, replacing: Boolean) = mutex.withLock {
        val pm = ctx.appContext.packageManager ?: return@withLock
        val state = AppInventoryLogic.decode(ctx.prefs.getString(K_STATE, null))?.toMutableMap() ?: return@withLock
        when {
            action == Intent.ACTION_PACKAGE_ADDED && !replacing -> {
                val rec = withContext(Dispatchers.IO) { recordOf(pm, pkg, withInstaller = true) } ?: return@withLock
                state[pkg] = rec
                emitChange(ctx, TYPE_INSTALLED, rec)
            }
            action == Intent.ACTION_PACKAGE_REPLACED -> {
                val rec = withContext(Dispatchers.IO) { recordOf(pm, pkg, withInstaller = true) } ?: return@withLock
                val old = state.put(pkg, rec)
                emitChange(ctx, TYPE_UPDATED, rec, signerChanged = old != null && old.signer != rec.signer)
                if (old != null) AppInventoryLogic.permissionChanges(old, rec).forEach { emitPermission(ctx, it) }
            }
            action == Intent.ACTION_PACKAGE_REMOVED && !replacing -> {
                val old = state.remove(pkg) ?: AppRecord(pkg, null, 0, null, emptySet())
                emitChange(ctx, TYPE_REMOVED, old)
            }
            else -> return@withLock
        }
        ctx.prefs.edit { putString(K_STATE, AppInventoryLogic.encode(state)) }
    }

    override suspend fun collectOnce(ctx: CollectorContext, reason: CollectReason) = mutex.withLock {
        val pm = ctx.appContext.packageManager ?: return@withLock
        val now = ctx.clock.nowMillis()
        val lastInventory = ctx.prefs.getLong(K_INVENTORY_MS, 0)
        val inventoryDue = now - lastInventory !in 0 until 20 * 3_600_000L ||
            (reason == CollectReason.START && (ctx.boot.isNewBoot || ctx.boot.isFirstRun))
        val scan = withContext(Dispatchers.IO) { scan(pm, details = inventoryDue) }
        val old = AppInventoryLogic.decode(ctx.prefs.getString(K_STATE, null))
        var current = AppInventoryLogic.carryInstallers(old.orEmpty(), scan.records)
        if (old != null) {
            val diff = AppInventoryLogic.diff(old, current)
            val withInstaller = (diff.installed + diff.updated).associate { r ->
                r.pkg to (r.installer?.let { r } ?: withContext(Dispatchers.IO) { r.copy(installer = installerOf(pm, r.pkg)) })
            }
            current = current + withInstaller
            diff.installed.forEach { emitChange(ctx, TYPE_INSTALLED, withInstaller.getValue(it.pkg)) }
            diff.updated.forEach { emitChange(ctx, TYPE_UPDATED, withInstaller.getValue(it.pkg), signerChanged = old[it.pkg]?.signer != it.signer) }
            diff.removed.forEach { emitChange(ctx, TYPE_REMOVED, it) }
            diff.permissionChanges.forEach { emitPermission(ctx, it) }
        }
        if (old == null || old != current) {
            ctx.prefs.edit { putString(K_STATE, AppInventoryLogic.encode(current)) }
        }
        if (inventoryDue) {
            emitInventory(ctx, scan, current)
            ctx.prefs.edit { putLong(K_INVENTORY_MS, now) }
        }
    }

    private fun emitChange(ctx: CollectorContext, type: String, r: AppRecord, signerChanged: Boolean = false) {
        ctx.sink.emit(type, AppInventoryLogic.changeSeverity(type, r, signerChanged), AppInventoryLogic.changeData(r))
    }

    private fun emitPermission(ctx: CollectorContext, c: PermissionChange) {
        ctx.sink.emit(TYPE_PERMISSION, if (c.granted) Severity.NOTABLE else Severity.INFO, AppInventoryLogic.permissionData(c))
    }

    private fun emitInventory(ctx: CollectorContext, scan: Scan, records: Map<String, AppRecord>) {
        val items = scan.details.sortedBy { it.pkg }.map { d -> AppInventoryLogic.inventoryItem(d, records[d.pkg]) }
        AppInventoryLogic.inventoryParts(items, ulids.next(ctx.clock.nowMillis()), PART_BYTES).forEach { part ->
            ctx.sink.emit(TYPE_INVENTORY, Severity.INFO, part)
        }
    }

    // ---- Package manager (blocking: call on Dispatchers.IO) ----

    private class Scan(val records: Map<String, AppRecord>, val details: List<AppDetails>)

    @SuppressLint("QueryPermissionsNeeded") // QUERY_ALL_PACKAGES is declared.
    private fun scan(pm: PackageManager, details: Boolean): Scan {
        val flags = (PackageManager.GET_PERMISSIONS or PackageManager.GET_SIGNING_CERTIFICATES or PackageManager.MATCH_UNINSTALLED_PACKAGES).toLong()
        val all = pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(flags)).orEmpty()
        // Hidden apps (DevicePolicyManager.setApplicationHidden) are only listed with MATCH_UNINSTALLED_PACKAGES.
        val visible = pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(0)).orEmpty().map { it.packageName }.toHashSet()
        val records = HashMap<String, AppRecord>()
        val detailList = ArrayList<AppDetails>()
        for (info in all) {
            val ai = info.applicationInfo ?: continue
            if (ai.flags and ApplicationInfo.FLAG_INSTALLED == 0) continue // Uninstalled, data kept.
            records[info.packageName] = record(pm, info, installer = null)
            if (details) {
                detailList += AppDetails(
                    pkg = info.packageName,
                    label = try {
                        ai.loadLabel(pm).toString().take(MAX_LABEL).takeIf { it.isNotBlank() && it != info.packageName }
                    } catch (_: Exception) {
                        null
                    },
                    enabled = ai.enabled,
                    suspended = ai.flags and ApplicationInfo.FLAG_SUSPENDED != 0,
                    hidden = info.packageName !in visible,
                    targetSdk = ai.targetSdkVersion,
                    firstInstall = info.firstInstallTime.takeIf { it > 0 },
                    lastUpdate = info.lastUpdateTime.takeIf { it > 0 },
                )
            }
        }
        return Scan(records, detailList)
    }

    private fun recordOf(pm: PackageManager, pkg: String, withInstaller: Boolean): AppRecord? = try {
        val flags = (PackageManager.GET_PERMISSIONS or PackageManager.GET_SIGNING_CERTIFICATES).toLong()
        record(pm, pm.getPackageInfo(pkg, PackageManager.PackageInfoFlags.of(flags)), if (withInstaller) installerOf(pm, pkg) else null)
    } catch (_: PackageManager.NameNotFoundException) {
        null
    }

    private fun record(pm: PackageManager, info: PackageInfo, installer: String?) = AppRecord(
        pkg = info.packageName,
        versionName = info.versionName?.take(MAX_LABEL),
        versionCode = info.longVersionCode,
        signer = signer(info),
        granted = granted(pm, info),
        installer = installer,
        system = (info.applicationInfo?.flags ?: 0) and ApplicationInfo.FLAG_SYSTEM != 0,
    )

    private fun installerOf(pm: PackageManager, pkg: String): String? = try {
        pm.getInstallSourceInfo(pkg).installingPackageName
    } catch (_: Exception) {
        null
    }

    private fun signer(info: PackageInfo): String? {
        val si = info.signingInfo ?: return null
        val certs = if (si.hasMultipleSigners()) si.apkContentsSigners else si.signingCertificateHistory?.takeLast(1)?.toTypedArray()
        return certs?.map { sha256Hex(it.toByteArray()) }?.sorted()?.joinToString(",")?.takeIf { it.isNotEmpty() }
    }

    private fun granted(pm: PackageManager, info: PackageInfo): Set<String> {
        val names = info.requestedPermissions ?: return emptySet()
        val flags = info.requestedPermissionsFlags ?: return emptySet()
        val out = HashSet<String>()
        for (i in names.indices) {
            if (i >= flags.size || flags[i] and PackageInfo.REQUESTED_PERMISSION_GRANTED == 0) continue
            val name = names[i]
            if (isDangerous(pm, name)) out += name
        }
        return out
    }

    private fun isDangerous(pm: PackageManager, name: String): Boolean = dangerous.getOrPut(name) {
        try {
            pm.getPermissionInfo(name, 0).protection == PermissionInfo.PROTECTION_DANGEROUS
        } catch (_: PackageManager.NameNotFoundException) {
            false
        }
    }

    companion object {
        const val TYPE_INVENTORY = "app.inventory"
        const val TYPE_INSTALLED = "app.installed"
        const val TYPE_UPDATED = "app.updated"
        const val TYPE_REMOVED = "app.removed"
        const val TYPE_PERMISSION = "app.permission_changed"

        /** Budget of the `apps` array of one part; the whole event stays far below 32 KiB. */
        const val PART_BYTES = 16 * 1024
        private const val MAX_LABEL = 100
        private const val K_STATE = "apps_state"
        private const val K_INVENTORY_MS = "inventory_ms"
    }
}
