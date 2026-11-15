package io.github.erwsim.vigie.collectors.apps

import android.Manifest
import android.accessibilityservice.AccessibilityServiceInfo
import android.annotation.SuppressLint
import android.app.AppOpsManager
import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.database.ContentObserver
import android.net.VpnService
import android.provider.Settings
import android.provider.Telephony
import android.telecom.TelecomManager
import android.view.accessibility.AccessibilityManager
import androidx.core.content.edit
import androidx.core.net.toUri
import io.github.erwsim.vigie.collectors.R
import io.github.erwsim.vigie.core.collector.CollectReason
import io.github.erwsim.vigie.core.collector.Collector
import io.github.erwsim.vigie.core.collector.CollectorContext
import io.github.erwsim.vigie.core.collector.PeriodicSpec
import io.github.erwsim.vigie.core.event.Severity
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

/**
 * `app.special_access`: who holds the powerful special accesses. Emitted when the set changes and
 * once a day. Read without privilege:
 * - accessibility services (AccessibilityManager), device admins (DevicePolicyManager);
 * - notification listeners (secure setting `enabled_notification_listeners`, read as AndroidX does;
 *   absent if the system refuses);
 * - overlay, unknown sources ("install unknown apps"), usage access: app-op of every app that
 *   requests the matching permission (`unsafeCheckOpNoThrow` on other apps, absent if refused);
 * - VPN apps: apps that declare a VpnService (the active VPN's owner is not visible to other apps);
 * - default apps: browser, home, dialer, SMS, keyboard, and assistant/autofill if readable.
 *
 * Checked after package changes, settings changes (content observers) and at most every 15 min at
 * screen off (app-ops have no public change broadcast). Each check is one package scan.
 */
class SpecialAccessCollector : Collector {
    override val id = "special_access"
    override val titleRes = R.string.collector_special_access_title
    override val descriptionRes = R.string.collector_special_access_desc
    override val eventTypes = listOf(TYPE)
    override val periodic = PeriodicSpec(intervalMinutes = 24 * 60, runAtStart = true)

    private val mutex = Mutex()
    private var pending: Job? = null
    private var lastScreenOffCheck = Long.MIN_VALUE / 2

    override suspend fun start(ctx: CollectorContext) {
        pending = null
        lastScreenOffCheck = Long.MIN_VALUE / 2
        val filter = IntentFilter().apply {
            addAction(Intent.ACTION_PACKAGE_ADDED)
            addAction(Intent.ACTION_PACKAGE_REMOVED)
            addAction(Intent.ACTION_PACKAGE_REPLACED)
            addAction(Intent.ACTION_PACKAGE_CHANGED)
            addDataScheme("package")
        }
        ctx.registerReceiver(filter) { schedule(ctx) }
        ctx.registerReceiver(IntentFilter(Intent.ACTION_SCREEN_OFF)) {
            val now = ctx.clock.elapsedRealtime()
            if (now - lastScreenOffCheck >= SCREEN_OFF_CHECK_MS) {
                lastScreenOffCheck = now
                schedule(ctx)
            }
        }
        val resolver = ctx.appContext.contentResolver ?: return
        val observer = object : ContentObserver(ctx.handler) {
            override fun onChange(selfChange: Boolean) = ctx.guard("settings") { schedule(ctx) }
        }
        for (key in OBSERVED_SECURE_KEYS) {
            resolver.registerContentObserver(Settings.Secure.getUriFor(key) ?: continue, false, observer)
        }
        ctx.onStop { resolver.unregisterContentObserver(observer) }
    }

    override suspend fun stop(ctx: CollectorContext) {
        pending = null
    }

    override suspend fun collectOnce(ctx: CollectorContext, reason: CollectReason) =
        check(ctx, force = reason == CollectReason.PERIODIC || reason == CollectReason.MANUAL)

    /** Coalesces bursts of triggers (an app update sends 3 broadcasts) into one check 5 s later. */
    private fun schedule(ctx: CollectorContext) {
        if (pending?.isActive == true) return
        pending = ctx.scope.launch {
            delay(5_000)
            check(ctx, force = false)
        }
    }

    private suspend fun check(ctx: CollectorContext, force: Boolean) = mutex.withLock {
        val snapshot = withContext(Dispatchers.IO) { read(ctx.appContext) } ?: return@withLock
        val previous = SpecialAccessSnapshot.decode(ctx.prefs.getString(K_LAST, null))
        val now = ctx.clock.nowMillis()
        val stale = now - ctx.prefs.getLong(K_LAST_MS, 0) !in 0 until 20 * 3_600_000L
        if (!force && !stale && previous == snapshot) return@withLock
        val sev = when {
            previous == null || previous == snapshot -> Severity.INFO
            snapshot.gainedCritical(previous) -> Severity.WARNING
            else -> Severity.NOTABLE
        }
        ctx.emit(TYPE, sev) { snapshot.writeTo(this) }
        ctx.prefs.edit { putString(K_LAST, snapshot.encode()); putLong(K_LAST_MS, now) }
    }

    // ---- Reading (blocking, Dispatchers.IO) ----

    @SuppressLint("QueryPermissionsNeeded")
    private fun read(context: Context): SpecialAccessSnapshot? {
        val pm = context.packageManager ?: return null
        val packages = try {
            pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(PackageManager.GET_PERMISSIONS.toLong())).orEmpty()
        } catch (_: Exception) {
            emptyList()
        }
        val ops = context.getSystemService(AppOpsManager::class.java)
        fun requesting(permission: String) = packages.filter { it.requestedPermissions?.contains(permission) == true }
        fun opHolders(op: String, permission: String, defaultMeansPermission: Boolean): List<String>? {
            if (ops == null) return null
            var refused = false
            val holders = requesting(permission).filter { p ->
                val uid = p.applicationInfo?.uid ?: return@filter false
                val mode = try {
                    ops.checkOpNoThrow(op, uid, p.packageName)
                } catch (_: Exception) {
                    refused = true
                    return@filter false
                }
                mode == AppOpsManager.MODE_ALLOWED ||
                    (mode == AppOpsManager.MODE_DEFAULT && defaultMeansPermission && granted(p, permission))
            }.map { it.packageName }
            return if (refused && holders.isEmpty()) null else holders.sorted()
        }

        return SpecialAccessSnapshot(
            accessibilityServices = try {
                context.getSystemService(AccessibilityManager::class.java)
                    ?.getEnabledAccessibilityServiceList(AccessibilityServiceInfo.FEEDBACK_ALL_MASK)
                    ?.mapNotNull { it.resolveInfo?.serviceInfo?.let { s -> ComponentName(s.packageName, s.name).flattenToShortString() } }
                    ?.sorted()
            } catch (_: Exception) {
                null
            },
            notificationListeners = secureComponents(context, "enabled_notification_listeners"),
            deviceAdmins = try {
                context.getSystemService(DevicePolicyManager::class.java)?.activeAdmins.orEmpty().map { it.flattenToShortString() }.sorted()
            } catch (_: Exception) {
                null
            },
            overlayApps = opHolders(AppOpsManager.OPSTR_SYSTEM_ALERT_WINDOW, Manifest.permission.SYSTEM_ALERT_WINDOW, defaultMeansPermission = false),
            unknownSourcesApps = opHolders(OPSTR_REQUEST_INSTALL_PACKAGES, Manifest.permission.REQUEST_INSTALL_PACKAGES, defaultMeansPermission = false),
            usageAccessApps = opHolders(AppOpsManager.OPSTR_GET_USAGE_STATS, Manifest.permission.PACKAGE_USAGE_STATS, defaultMeansPermission = true),
            vpnApps = try {
                pm.queryIntentServices(Intent(VpnService.SERVICE_INTERFACE), PackageManager.ResolveInfoFlags.of(0))
                    .mapNotNull { it.serviceInfo?.takeIf { s -> s.permission == Manifest.permission.BIND_VPN_SERVICE }?.packageName }
                    .distinct().sorted()
            } catch (_: Exception) {
                null
            },
            defaultApps = defaultApps(context, pm),
        )
    }

    private fun granted(p: PackageInfo, permission: String): Boolean {
        val i = p.requestedPermissions?.indexOf(permission) ?: return false
        val flags = p.requestedPermissionsFlags ?: return false
        return i in flags.indices && flags[i] and PackageInfo.REQUESTED_PERMISSION_GRANTED != 0
    }

    /** Colon-separated flattened components in a secure setting; null if unreadable. */
    private fun secureComponents(context: Context, key: String): List<String>? = try {
        val raw = Settings.Secure.getString(context.contentResolver, key)
        SpecialAccessSnapshot.splitComponents(raw)
    } catch (_: Exception) {
        null
    }

    private fun defaultApps(context: Context, pm: PackageManager): Map<String, String> {
        fun resolve(intent: Intent): String? = try {
            pm.resolveActivity(intent, PackageManager.ResolveInfoFlags.of(PackageManager.MATCH_DEFAULT_ONLY.toLong()))
                ?.activityInfo?.packageName?.takeIf { it != "android" } // "android" = chooser, no default.
        } catch (_: Exception) {
            null
        }
        fun secureComponentPackage(key: String): String? = try {
            Settings.Secure.getString(context.contentResolver, key)
                ?.let { ComponentName.unflattenFromString(it)?.packageName ?: it.substringBefore('/').takeIf { p -> p.isNotBlank() } }
        } catch (_: Exception) {
            null
        }
        return linkedMapOf(
            "browser" to resolve(Intent(Intent.ACTION_VIEW, "https://example.org".toUri()).addCategory(Intent.CATEGORY_BROWSABLE)),
            "home" to resolve(Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_HOME)),
            "dialer" to try {
                context.getSystemService(TelecomManager::class.java)?.defaultDialerPackage
            } catch (_: Exception) {
                null
            },
            "sms" to try {
                Telephony.Sms.getDefaultSmsPackage(context)
            } catch (_: Exception) {
                null
            },
            "keyboard" to secureComponentPackage(Settings.Secure.DEFAULT_INPUT_METHOD),
            "assistant" to secureComponentPackage("assistant"),
            "autofill" to secureComponentPackage("autofill_service"),
        ).mapNotNull { (role, pkg) -> pkg?.let { role to it } }.toMap()
    }

    companion object {
        const val TYPE = "app.special_access"
        private const val K_LAST = "last_snapshot"
        private const val K_LAST_MS = "last_ms"
        private const val SCREEN_OFF_CHECK_MS = 15 * 60_000L

        /** AppOpsManager.OPSTR_REQUEST_INSTALL_PACKAGES is not public; the string is stable. */
        const val OPSTR_REQUEST_INSTALL_PACKAGES = "android:request_install_packages"

        private val OBSERVED_SECURE_KEYS = listOf(
            Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES,
            "enabled_notification_listeners",
            Settings.Secure.DEFAULT_INPUT_METHOD,
            "assistant",
            "autofill_service",
        )
    }
}
