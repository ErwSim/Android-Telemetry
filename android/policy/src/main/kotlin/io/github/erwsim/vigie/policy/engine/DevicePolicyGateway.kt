package io.github.erwsim.vigie.policy.engine

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
}

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
        DNS_SET_HOST_NOT_SERVING -> "PRIVATE_DNS_SET_ERROR_HOST_NOT_SERVING : l'hôte ne répond pas en DNS sur TLS"
        DNS_SET_FAILURE -> "PRIVATE_DNS_SET_ERROR_FAILURE_SETTING : écriture du réglage refusée"
        else -> "code $code"
    }
}
