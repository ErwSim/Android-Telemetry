package io.github.erwsim.vigie.collectors.risk

import android.Manifest
import android.annotation.SuppressLint
import android.app.admin.DeviceAdminReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.net.VpnService
import io.github.erwsim.vigie.collectors.apps.DefaultApps
import io.github.erwsim.vigie.collectors.apps.PackageSupport

/** Where the `app_risk` collector gets its facts (replaced by a fake in tests). Blocking: call on `ctx.io`. */
interface FactsSource {
    /** Every installed app, null if the package list cannot be read. */
    fun readAll(context: Context): List<AppFacts>?

    /** One app (install or update), null if it is gone or unreadable. */
    fun read(context: Context, pkg: String): AppFacts?
}

/**
 * Reads [AppFacts] from `PackageManager`: one `getInstalledPackages` call (permissions), then one query per
 * kind of component (instead of loading every component of every app), then the installer of each app.
 *
 * A failed component query never makes an app look worse: the facts it would have set stay neutral
 * (`launcherActivity` stays true, the others false). A launcher query returning nothing at all is treated as
 * a failure (there is always at least the home screen).
 */
object PackageManagerFactsSource : FactsSource {
    private const val ACTION_ACCESSIBILITY = "android.accessibilityservice.AccessibilityService"
    private const val ACTION_NOTIFICATION_LISTENER = "android.service.notification.NotificationListenerService"

    /** Components of each kind, as sets of package names; null = that query failed. */
    private class Components(
        val launcher: Set<String>?,
        val accessibility: Set<String>?,
        val listener: Set<String>?,
        val admin: Set<String>?,
        val vpn: Set<String>?,
        val boot: Set<String>?,
    )

    @SuppressLint("QueryPermissionsNeeded") // QUERY_ALL_PACKAGES is declared by this module.
    override fun readAll(context: Context): List<AppFacts>? {
        val pm = context.packageManager ?: return null
        val flags = (PackageManager.GET_PERMISSIONS or PackageManager.MATCH_UNINSTALLED_PACKAGES).toLong()
        val all = try {
            pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(flags))
        } catch (_: Exception) {
            null
        } ?: return null
        val components = components(pm, pkg = null)
        val defaultSms = DefaultApps.read(context, pm)["sms"]
        return all.mapNotNull { info -> facts(context, pm, info, components, defaultSms) }
    }

    override fun read(context: Context, pkg: String): AppFacts? {
        val pm = context.packageManager ?: return null
        val info = try {
            pm.getPackageInfo(pkg, PackageManager.PackageInfoFlags.of(PackageManager.GET_PERMISSIONS.toLong()))
        } catch (_: Exception) {
            return null
        }
        return facts(context, pm, info, components(pm, pkg), DefaultApps.read(context, pm)["sms"])
    }

    private fun facts(context: Context, pm: PackageManager, info: PackageInfo, c: Components, defaultSms: String?): AppFacts? {
        val ai = info.applicationInfo ?: return null
        if (ai.flags and ApplicationInfo.FLAG_INSTALLED == 0) return null // Uninstalled, data kept.
        val pkg = info.packageName
        val requested = info.requestedPermissions?.toSet().orEmpty()
        return AppFacts(
            pkg = pkg,
            label = try {
                ai.loadLabel(pm).toString().take(MAX_LABEL).takeIf { it.isNotBlank() && it != pkg }
            } catch (_: Exception) {
                null
            },
            versionCode = info.longVersionCode,
            installer = PackageSupport.installerOf(pm, pkg),
            system = ai.flags and ApplicationInfo.FLAG_SYSTEM != 0,
            isSelf = pkg == context.packageName,
            requested = requested,
            granted = requested.filter { PackageSupport.isGranted(info, it) }.toSet(),
            accessibilityService = c.accessibility?.contains(pkg) ?: false,
            notificationListener = c.listener?.contains(pkg) ?: false,
            deviceAdminReceiver = c.admin?.contains(pkg) ?: false,
            vpnService = c.vpn?.contains(pkg) ?: false,
            bootReceiver = c.boot?.contains(pkg) ?: false,
            launcherActivity = c.launcher?.contains(pkg) ?: true,
            defaultSmsApp = pkg == defaultSms,
            targetSdk = ai.targetSdkVersion,
            debuggable = ai.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0,
        )
    }

    private fun components(pm: PackageManager, pkg: String?): Components {
        val disabledToo = PackageManager.MATCH_DISABLED_COMPONENTS.toLong() // A dormant component can be enabled later.
        val launcher = if (pkg == null) {
            // Only enabled launcher activities: an app that disabled its launcher alias is invisible.
            activityPackages(pm, Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER), 0L)?.takeIf { it.isNotEmpty() }
        } else {
            activityPackages(pm, Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER).setPackage(pkg), 0L)
        }
        return Components(
            launcher = launcher,
            accessibility = servicePackages(pm, ACTION_ACCESSIBILITY, Manifest.permission.BIND_ACCESSIBILITY_SERVICE, disabledToo, pkg),
            listener = servicePackages(pm, ACTION_NOTIFICATION_LISTENER, Manifest.permission.BIND_NOTIFICATION_LISTENER_SERVICE, disabledToo, pkg),
            admin = receiverPackages(pm, DeviceAdminReceiver.ACTION_DEVICE_ADMIN_ENABLED, Manifest.permission.BIND_DEVICE_ADMIN, disabledToo, pkg),
            vpn = servicePackages(pm, VpnService.SERVICE_INTERFACE, Manifest.permission.BIND_VPN_SERVICE, disabledToo, pkg),
            boot = receiverPackages(
                pm, Intent.ACTION_BOOT_COMPLETED, null,
                (PackageManager.MATCH_DIRECT_BOOT_AWARE or PackageManager.MATCH_DIRECT_BOOT_UNAWARE).toLong(), pkg,
            ),
        )
    }

    private fun activityPackages(pm: PackageManager, intent: Intent, flags: Long): Set<String>? = try {
        pm.queryIntentActivities(intent, PackageManager.ResolveInfoFlags.of(flags)).mapNotNull { it.activityInfo?.packageName }.toSet()
    } catch (_: Exception) {
        null
    }

    private fun servicePackages(pm: PackageManager, action: String, permission: String, flags: Long, pkg: String?): Set<String>? = try {
        val intent = Intent(action).also { if (pkg != null) it.setPackage(pkg) }
        pm.queryIntentServices(intent, PackageManager.ResolveInfoFlags.of(flags))
            .mapNotNull { it.serviceInfo?.takeIf { s -> s.permission == permission }?.packageName }.toSet()
    } catch (_: Exception) {
        null
    }

    private fun receiverPackages(pm: PackageManager, action: String, permission: String?, flags: Long, pkg: String?): Set<String>? = try {
        val intent = Intent(action).also { if (pkg != null) it.setPackage(pkg) }
        pm.queryBroadcastReceivers(intent, PackageManager.ResolveInfoFlags.of(flags))
            .mapNotNull { it.activityInfo?.takeIf { a -> permission == null || a.permission == permission }?.packageName }.toSet()
    } catch (_: Exception) {
        null
    }

    private const val MAX_LABEL = 100
}
