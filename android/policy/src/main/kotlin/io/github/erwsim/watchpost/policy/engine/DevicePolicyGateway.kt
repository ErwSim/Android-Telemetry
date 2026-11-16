package io.github.erwsim.watchpost.policy.engine

/**
 * Everything the policy engine does to the device, behind one interface so that the engine logic
 * (preview, deny list, persistence, undo, partial failures) is tested on the JVM against a fake.
 * The Android implementation is [AndroidDevicePolicyGateway].
 *
 * Every method may throw (SecurityException, IllegalArgumentException…): the engine catches,
 * reports `ok=false` and verifies the effect by reading the state back.
 */
interface DevicePolicyGateway {
    fun isDeviceOwner(): Boolean

    /** Packages that must never be touched right now (launcher, dialer, SMS, keyboards, installers, admins, self). */
    fun protectedPackages(): Set<String>

    fun isInstalled(pkg: String): Boolean

    fun isHidden(pkg: String): Boolean
    fun setHidden(pkg: String, hidden: Boolean): Boolean
    fun isSuspended(pkg: String): Boolean

    /** False when the platform refused (e.g. active launcher, required verifier). */
    fun setSuspended(pkg: String, suspended: Boolean): Boolean

    /** Whether [pkg] declares [permission] in its manifest. */
    fun requestsPermission(pkg: String, permission: String): Boolean
    fun isPermissionGranted(pkg: String, permission: String): Boolean

    /** `DevicePolicyManager.PERMISSION_GRANT_STATE_*`. */
    fun permissionGrantState(pkg: String, permission: String): Int
    fun setPermissionGrantState(pkg: String, permission: String, state: Int): Boolean

    /** Restrictions currently set by this admin. */
    fun hasRestriction(key: String): Boolean
    fun addRestriction(key: String)
    fun clearRestriction(key: String)

    /** `DevicePolicyManager.PRIVATE_DNS_MODE_*`. */
    fun privateDnsMode(): Int
    fun privateDnsHost(): String?

    /** Blocking (connectivity test): never on the main thread. Returns `PRIVATE_DNS_SET_*`. */
    fun setPrivateDnsSpecifiedHost(host: String): Int
    fun setPrivateDnsOpportunistic(): Int
    fun setPrivateDnsOff()

    fun canWriteSecureSettings(): Boolean

    /** @throws SecurityException when the key cannot be read (then it is never written). */
    fun readSetting(namespace: String, key: String): String?
    fun writeSetting(namespace: String, key: String, value: String?): Boolean

    fun isBackupServiceEnabled(): Boolean
    fun setBackupServiceEnabled(enabled: Boolean)

    fun alwaysOnVpnPackage(): String?
    fun isAlwaysOnVpnLockdown(): Boolean
    fun setAlwaysOnVpn(pkg: String?, lockdown: Boolean)

    fun isNetworkLoggingEnabled(): Boolean
    fun setNetworkLoggingEnabled(enabled: Boolean)
    fun isSecurityLoggingEnabled(): Boolean
    fun setSecurityLoggingEnabled(enabled: Boolean)

    /** Removes "force stop" protection from every package (called before leaving Device Owner). */
    fun clearUserControlDisabledPackages()

    /** `clearDeviceOwnerApp`: the end. */
    fun clearDeviceOwner()

    // ---- Capability guards (contract §11.1).

    /** Every installed package (one query): system flag, requested permissions, first install time. */
    fun installedApps(): List<AppInfo>

    /** One package, null if not installed. */
    fun appInfo(pkg: String): AppInfo?

    /** Current holders of the roles a guard must never cut (read at every application). */
    fun roles(): DeviceRoles

    /** Installed accessibility services, by package (system flag, enabled now). */
    fun accessibilityServices(): List<ServiceApp>

    /** Installed input methods, by package (system flag, enabled now). */
    fun inputMethods(): List<ServiceApp>

    /** `getPermittedAccessibilityServices`: null = no restriction. */
    fun permittedAccessibilityServices(): List<String>?

    /** False when the platform refused (an enabled non-system service is missing from the list). */
    fun setPermittedAccessibilityServices(packages: List<String>?): Boolean

    fun permittedInputMethods(): List<String>?

    fun setPermittedInputMethods(packages: List<String>?): Boolean
}

/** What the guards need to know about an installed package. */
data class AppInfo(
    val pkg: String,
    /** `ApplicationInfo.FLAG_SYSTEM` (also set for an updated system app). */
    val system: Boolean,
    val requested: Set<String>,
    /** `PackageInfo.firstInstallTime` (kept by updates, reset by a reinstall). */
    val firstInstallMs: Long,
)

/** Role holders (null when unknown or none). */
data class DeviceRoles(
    val sms: String? = null,
    val dialer: String? = null,
    val systemDialer: String? = null,
    /** Input method in use (`Settings.Secure.DEFAULT_INPUT_METHOD`). */
    val ime: String? = null,
    /** Default home screen (not every app able to be one: any app can declare a HOME activity). */
    val home: String? = null,
)

/** A package that provides an accessibility service or an input method. */
data class ServiceApp(val pkg: String, val system: Boolean, val enabled: Boolean)

/** Constants mirrored from `DevicePolicyManager` (same values; kept here so the engine is pure Kotlin). */
object Dpm {
    const val GRANT_DEFAULT = 0
    const val GRANT_GRANTED = 1
    const val GRANT_DENIED = 2

    const val DNS_MODE_UNKNOWN = 0
    const val DNS_MODE_OFF = 1
    const val DNS_MODE_OPPORTUNISTIC = 2
    const val DNS_MODE_HOSTNAME = 3

    const val DNS_SET_OK = 0
    const val DNS_SET_HOST_NOT_SERVING = 1
    const val DNS_SET_FAILURE = 2

    fun dnsModeName(mode: Int): String = when (mode) {
        DNS_MODE_OFF -> "off"
        DNS_MODE_OPPORTUNISTIC -> "opportunistic"
        DNS_MODE_HOSTNAME -> "hostname"
        else -> "unknown"
    }

    fun dnsSetError(code: Int): String? = when (code) {
        DNS_SET_OK -> null
        DNS_SET_HOST_NOT_SERVING -> "PRIVATE_DNS_SET_ERROR_HOST_NOT_SERVING: the host does not answer DNS over TLS"
        DNS_SET_FAILURE -> "PRIVATE_DNS_SET_ERROR_FAILURE_SETTING: writing the setting was refused"
        else -> "code $code"
    }
}
