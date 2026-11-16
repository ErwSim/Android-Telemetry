package io.github.erwsim.vigie.policy

import io.github.erwsim.vigie.policy.engine.AppInfo
import io.github.erwsim.vigie.policy.engine.DevicePolicyGateway
import io.github.erwsim.vigie.policy.engine.DeviceRoles
import io.github.erwsim.vigie.policy.engine.Dpm
import io.github.erwsim.vigie.policy.engine.ServiceApp

/**
 * In-memory device for the engine tests. [snapshot] captures everything the engine can change, to
 * compare "before" and "after undo" exactly. Failures are injected per package/permission/key.
 */
class FakeGateway : DevicePolicyGateway {
    var owner = true
    val installed = HashSet<String>()
    val hidden = HashSet<String>()
    val suspended = HashSet<String>()
    val dynamicProtected = HashSet<String>()

    /** pkg → requested permissions. */
    val requested = HashMap<String, MutableSet<String>>()
    val granted = HashSet<Pair<String, String>>()
    val grantState = HashMap<Pair<String, String>, Int>()
    val restrictions = HashSet<String>()
    var dnsMode = Dpm.DNS_MODE_OPPORTUNISTIC
    var dnsHost: String? = null
    var dnsSetResult = Dpm.DNS_SET_OK
    var writeSecure = true
    val settings = HashMap<String, String?>()
    val unreadableSettings = HashSet<String>()
    var backup = false
    var vpn: String? = null
    var vpnLockdown = false
    var networkLogging = true
    var securityLogging = true
    var userControlCleared = false

    /** Calls that touched the device (to prove the deny list is never crossed). */
    val calls = ArrayList<String>()

    // Failure injection.
    val failHide = HashSet<String>()
    val throwOnHide = HashSet<String>()
    val failPermission = HashSet<String>()
    val failRestriction = HashSet<String>()

    // Capability guards.
    val system = HashSet<String>()
    val firstInstall = HashMap<String, Long>()
    var roles = DeviceRoles()
    val accessibility = HashMap<String, ServiceApp>()
    val imes = HashMap<String, ServiceApp>()
    var permittedAccessibility: List<String>? = null
    var permittedImes: List<String>? = null

    /** Like Android: the list must contain every enabled non-system service, else false and nothing changes. */
    var enforceEnabledInList = true

    data class Snapshot(
        val hidden: Set<String>, val suspended: Set<String>, val granted: Set<Pair<String, String>>,
        val grantState: Map<Pair<String, String>, Int>, val restrictions: Set<String>, val dnsMode: Int,
        val dnsHost: String?, val settings: Map<String, String?>, val backup: Boolean, val vpn: String?, val vpnLockdown: Boolean,
        val permittedAccessibility: List<String>?, val permittedImes: List<String>?,
    )

    fun snapshot() = Snapshot(
        hidden.toSet(), suspended.toSet(), granted.toSet(), grantState.filterValues { it != Dpm.GRANT_DEFAULT }, restrictions.toSet(),
        dnsMode, dnsHost, settings.toMap(), backup, vpn, vpnLockdown, permittedAccessibility, permittedImes,
    )

    fun install(pkg: String, vararg permissions: String) {
        installed += pkg
        requested.getOrPut(pkg) { HashSet() } += permissions
        firstInstall.putIfAbsent(pkg, clockMs)
    }

    /** Time given to `firstInstallTime` of the next installs. */
    var clockMs = 1_000L

    fun uninstall(pkg: String) {
        installed -= pkg
        requested.remove(pkg)
        firstInstall.remove(pkg)
        granted.removeAll { it.first == pkg }
        grantState.keys.removeAll { it.first == pkg }
    }

    override fun isDeviceOwner() = owner
    override fun protectedPackages(): Set<String> = dynamicProtected + "io.github.erwsim.vigie"
    override fun isInstalled(pkg: String) = pkg in installed
    override fun isHidden(pkg: String) = pkg in hidden

    override fun setHidden(pkg: String, hidden: Boolean): Boolean {
        calls += "hide $pkg $hidden"
        if (pkg in throwOnHide) throw SecurityException("hide refused for $pkg")
        if (hidden && pkg in failHide) return false
        if (hidden) this.hidden += pkg else this.hidden -= pkg
        return true
    }

    override fun isSuspended(pkg: String) = pkg in suspended

    override fun setSuspended(pkg: String, suspended: Boolean): Boolean {
        calls += "suspend $pkg $suspended"
        if (suspended) this.suspended += pkg else this.suspended -= pkg
        return true
    }

    override fun requestsPermission(pkg: String, permission: String) = requested[pkg]?.contains(permission) == true
    override fun isPermissionGranted(pkg: String, permission: String) = (pkg to permission) in granted
    override fun permissionGrantState(pkg: String, permission: String) = grantState[pkg to permission] ?: Dpm.GRANT_DEFAULT

    override fun setPermissionGrantState(pkg: String, permission: String, state: Int): Boolean {
        calls += "perm $pkg $permission $state"
        if (permission in failPermission || "$pkg/$permission" in failPermission) return false
        if (pkg !in installed) return false
        grantState[pkg to permission] = state
        when (state) {
            Dpm.GRANT_DENIED -> granted -= pkg to permission
            Dpm.GRANT_GRANTED -> granted += pkg to permission
        }
        return true
    }

    override fun hasRestriction(key: String) = key in restrictions

    override fun addRestriction(key: String) {
        calls += "restrict $key"
        if (key in failRestriction) throw SecurityException("restriction $key refused")
        restrictions += key
    }

    override fun clearRestriction(key: String) {
        calls += "clear $key"
        restrictions -= key
    }

    override fun privateDnsMode() = dnsMode
    override fun privateDnsHost() = dnsHost

    override fun setPrivateDnsSpecifiedHost(host: String): Int {
        calls += "dns $host"
        if (dnsSetResult == Dpm.DNS_SET_OK) {
            dnsMode = Dpm.DNS_MODE_HOSTNAME
            dnsHost = host
        }
        return dnsSetResult
    }

    override fun setPrivateDnsOpportunistic(): Int {
        calls += "dns opportunistic"
        dnsMode = Dpm.DNS_MODE_OPPORTUNISTIC
        dnsHost = null
        return Dpm.DNS_SET_OK
    }

    var failDnsOff = false

    override fun setPrivateDnsOff() {
        calls += "dns off"
        if (failDnsOff) throw SecurityException("private_dns_mode not in allowlist")
        dnsMode = Dpm.DNS_MODE_OFF
        dnsHost = null
    }

    override fun canWriteSecureSettings() = writeSecure

    override fun readSetting(namespace: String, key: String): String? {
        if (key in unreadableSettings) throw SecurityException("$key not readable")
        return settings["$namespace:$key"]
    }

    override fun writeSetting(namespace: String, key: String, value: String?): Boolean {
        calls += "setting $key=$value"
        if (value == null) settings.remove("$namespace:$key") else settings["$namespace:$key"] = value
        return true
    }

    override fun isBackupServiceEnabled() = backup
    override fun setBackupServiceEnabled(enabled: Boolean) {
        backup = enabled
    }

    override fun alwaysOnVpnPackage() = vpn
    override fun isAlwaysOnVpnLockdown() = vpnLockdown
    override fun setAlwaysOnVpn(pkg: String?, lockdown: Boolean) {
        vpn = pkg
        vpnLockdown = pkg != null && lockdown
    }

    override fun isNetworkLoggingEnabled() = networkLogging
    override fun setNetworkLoggingEnabled(enabled: Boolean) {
        networkLogging = enabled
    }

    override fun isSecurityLoggingEnabled() = securityLogging
    override fun setSecurityLoggingEnabled(enabled: Boolean) {
        securityLogging = enabled
    }

    override fun clearUserControlDisabledPackages() {
        userControlCleared = true
    }

    override fun clearDeviceOwner() {
        calls += "clear owner"
        owner = false
    }

    override fun installedApps(): List<AppInfo> = installed.sorted().mapNotNull(::appInfo)

    override fun appInfo(pkg: String): AppInfo? =
        if (pkg in installed) AppInfo(pkg, pkg in system, requested[pkg].orEmpty().toSet(), firstInstall[pkg] ?: 0) else null

    override fun roles() = roles

    override fun accessibilityServices() = accessibility.values.sortedBy { it.pkg }

    override fun inputMethods() = imes.values.sortedBy { it.pkg }

    override fun permittedAccessibilityServices() = permittedAccessibility

    override fun setPermittedAccessibilityServices(packages: List<String>?): Boolean {
        calls += "permitted accessibility $packages"
        if (packages != null && enforceEnabledInList && accessibility.values.any { it.enabled && !it.system && it.pkg !in packages }) return false
        permittedAccessibility = packages?.toList()
        return true
    }

    override fun permittedInputMethods() = permittedImes

    override fun setPermittedInputMethods(packages: List<String>?): Boolean {
        calls += "permitted imes $packages"
        if (packages != null && enforceEnabledInList && imes.values.any { it.enabled && !it.system && it.pkg !in packages }) return false
        permittedImes = packages?.toList()
        return true
    }
}
