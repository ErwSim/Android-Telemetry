package io.github.erwsim.watchpost.policy.posture

import android.Manifest
import android.app.AppOpsManager
import android.app.KeyguardManager
import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import android.os.UserManager
import android.provider.Settings
import io.github.erwsim.watchpost.core.capability.SystemProps
import io.github.erwsim.watchpost.policy.WatchpostAdminReceiver
import java.security.KeyStore
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

/**
 * Reads the security posture by the most reliable means available (Device Owner API first, then
 * `Settings.Global`, then system properties). A field that cannot be read is left out, never
 * guessed. Blocking (getprop, package scan): call from `Dispatchers.IO`.
 */
class PostureReader(private val context: Context) {
    private val dpm: DevicePolicyManager? get() = context.getSystemService(DevicePolicyManager::class.java)
    private val admin get() = ComponentName(context, WatchpostAdminReceiver::class.java)

    /** Cached: these properties only change with a reboot. */
    private val verifiedBootState: String? by lazy { SystemProps.get("ro.boot.verifiedbootstate") }

    fun read(nowMs: Long, userCas: List<CaCert>): LinkedHashMap<String, Any?> {
        val p = LinkedHashMap<String, Any?>()
        val owner = tryOrNull { dpm?.isDeviceOwnerApp(context.packageName) } == true
        val patch = Build.VERSION.SECURITY_PATCH?.takeIf { it.isNotBlank() }
        p["security_patch"] = patch
        p["patch_age_days"] = PostureDiff.patchAgeDays(patch, nowMs)
        p["encrypted"] = tryOrNull {
            when (dpm?.storageEncryptionStatus) {
                DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE,
                DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE_DEFAULT_KEY,
                DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE_PER_USER,
                -> true
                DevicePolicyManager.ENCRYPTION_STATUS_INACTIVE, DevicePolicyManager.ENCRYPTION_STATUS_UNSUPPORTED -> false
                else -> null
            }
        }
        p["lock_secure"] = tryOrNull { context.getSystemService(KeyguardManager::class.java)?.isDeviceSecure }
        p["adb_enabled"] = globalFlag(Settings.Global.ADB_ENABLED)
        p["adb_wifi_enabled"] = globalFlag(KEY_ADB_WIFI)
        p["dev_options"] = globalFlag(Settings.Global.DEVELOPMENT_SETTINGS_ENABLED)
        p["unknown_sources"] = tryOrNull { unknownSources() }
        val (mode, host) = privateDns(owner)
        p["private_dns_mode"] = mode
        p["private_dns_host"] = if (mode == null) null else host.orEmpty()
        p["always_on_vpn"] = if (owner) tryOrNull { dpm?.getAlwaysOnVpnPackage(admin) != null } else null
        p["device_owner"] = owner
        p["verified_boot_state"] = verifiedBootState
        p["user_ca_certs"] = userCas.map { it.sha256 }.sorted()
        // play_protect: deliberately absent. No public API exposes the Play Protect switch and the
        // hidden key once used (package_verifier_user_consent) is gone from AOSP: a stale value would
        // raise false alerts. The contract allows absent fields.
        p["usb_data_signaling"] = if (owner) tryOrNull { dpm?.isUsbDataSignalingEnabled } else null
        return p
    }

    /**
     * User-installed CAs: `AndroidCAStore` aliases `user:*` (no permission needed), plus, as Device
     * Owner, `getInstalledCaCerts` (CAs installed by the user or a DPC).
     */
    fun userCaCerts(): List<CaCert> {
        val out = LinkedHashMap<String, CaCert>()
        try {
            val ks = KeyStore.getInstance("AndroidCAStore").apply { load(null) }
            for (alias in ks.aliases().toList().filter { it.startsWith("user:") }) {
                (ks.getCertificate(alias) as? X509Certificate)?.let { c -> ca(c).let { out[it.sha256] = it } }
            }
        } catch (_: Exception) {
            // Store unavailable: the DO list below may still answer.
        }
        try {
            if (dpm?.isDeviceOwnerApp(context.packageName) == true) {
                val factory = CertificateFactory.getInstance("X.509")
                dpm?.getInstalledCaCerts(admin)?.forEach { der ->
                    (factory.generateCertificate(der.inputStream()) as? X509Certificate)?.let { c -> ca(c).let { out[it.sha256] = it } }
                }
            }
        } catch (_: Exception) {
        }
        return out.values.sortedBy { it.sha256 }
    }

    private fun ca(c: X509Certificate) = CaCert(
        MessageDigest.getInstance("SHA-256").digest(c.encoded).joinToString("") { "%02x".format(it) },
        c.subjectX500Principal.name,
    )

    private fun privateDns(owner: Boolean): Pair<String?, String?> {
        if (owner) {
            tryOrNull {
                val d = dpm ?: return@tryOrNull null
                when (d.getGlobalPrivateDnsMode(admin)) {
                    DevicePolicyManager.PRIVATE_DNS_MODE_OFF -> "off" to null
                    DevicePolicyManager.PRIVATE_DNS_MODE_OPPORTUNISTIC -> "opportunistic" to null
                    DevicePolicyManager.PRIVATE_DNS_MODE_PROVIDER_HOSTNAME -> "hostname" to d.getGlobalPrivateDnsHost(admin)
                    else -> null
                }
            }?.let { return it }
        }
        // Hidden keys: readable or not depending on @Readable; a SecurityException leaves the fields out.
        val mode = tryOrNull { PostureDiff.dnsModeFromSetting(Settings.Global.getString(context.contentResolver, KEY_DNS_MODE)) }
        val host = if (mode == "hostname") tryOrNull { Settings.Global.getString(context.contentResolver, KEY_DNS_SPECIFIER) } else null
        return mode to host
    }

    /**
     * "Unknown sources": false when installs from unknown sources are forbidden by a user
     * restriction; otherwise true if at least one app is allowed to install APKs
     * (`REQUEST_INSTALL_PACKAGES` app-op allowed). Unreadable → left out.
     */
    private fun unknownSources(): Boolean? {
        val um = context.getSystemService(UserManager::class.java)
        if (um?.hasUserRestriction(UserManager.DISALLOW_INSTALL_UNKNOWN_SOURCES_GLOBALLY) == true ||
            um?.hasUserRestriction(UserManager.DISALLOW_INSTALL_UNKNOWN_SOURCES) == true
        ) {
            return false
        }
        val appOps = context.getSystemService(AppOpsManager::class.java) ?: return null
        val pm = context.packageManager
        val candidates = pm.getPackagesHoldingPermissions(arrayOf(Manifest.permission.REQUEST_INSTALL_PACKAGES), PackageManager.PackageInfoFlags.of(0))
        return candidates.any { info ->
            val app = info.applicationInfo ?: return@any false
            // Privileged installers (stores) do not use this app-op.
            if (app.flags and ApplicationInfo.FLAG_SYSTEM != 0 && pm.checkPermission(PERM_INSTALL_PACKAGES, info.packageName) == PackageManager.PERMISSION_GRANTED) {
                return@any false
            }
            appOps.unsafeCheckOpNoThrow(OP_REQUEST_INSTALL_PACKAGES, app.uid, info.packageName) == AppOpsManager.MODE_ALLOWED
        }
    }

    private fun globalFlag(key: String): Boolean? = tryOrNull {
        val raw = Settings.Global.getString(context.contentResolver, key)
        if (raw == null) false else raw.trim() == "1"
    }

    private inline fun <T> tryOrNull(block: () -> T?): T? = try {
        block()
    } catch (_: Exception) {
        null
    }

    companion object {
        const val KEY_ADB_WIFI = "adb_wifi_enabled"
        const val KEY_DNS_MODE = "private_dns_mode"
        const val KEY_DNS_SPECIFIER = "private_dns_specifier"
        private const val PERM_INSTALL_PACKAGES = "android.permission.INSTALL_PACKAGES"

        /** Hidden constant `AppOpsManager.OPSTR_REQUEST_INSTALL_PACKAGES` (string ops are resolved by name). */
        private const val OP_REQUEST_INSTALL_PACKAGES = "android:request_install_packages"
    }
}
