package io.github.erwsim.watchpost.policy.engine

/**
 * Packages Watchpost must never hide, suspend or restrict, whatever the catalog says
 * (docs/research/android-platform.md §3.6 and §7.3). `setApplicationHidden` has no platform
 * guard rail: hiding one of these can lock the phone (kgclient), stop OTA updates, break
 * attestation (Play Integrity), or leave no launcher, dialer, keyboard or ADB shell.
 *
 * Checked by [PolicyEngine] before every package or permission action; the dynamic part (default
 * launcher, dialer, SMS app, keyboards, installers, active admins) comes from
 * [DevicePolicyGateway.protectedPackages].
 */
object PackageDenyList {
    /** Exact package names. */
    val PACKAGES: Set<String> = setOf(
        // Watchpost itself and the platform.
        "io.github.erwsim.watchpost",
        "android",
        "com.android.shell", // ADB shell: the rescue path.
        "com.android.systemui",
        "com.android.settings",
        "com.samsung.android.settings",
        // Samsung lock / anti-theft / Knox guard: hiding kgclient locks the phone until factory reset.
        "com.samsung.android.kgclient",
        "com.samsung.android.sm.policy",
        "com.samsung.android.cidmanager",
        "com.samsung.android.gru",
        "com.samsung.android.wifi.softap.resources",
        "com.samsung.android.app.routines",
        "com.samsung.android.securitylogagent", // watches /system changes: useful to Watchpost.
        "com.sec.android.diagmonagent", // relaunch loop when disabled (heat, battery drain).
        // OTA updates.
        "com.sec.android.soagent",
        "com.wssyncmldm",
        "com.samsung.sdm",
        "com.samsung.sdm.sdmviewer",
        "com.samsung.android.fota",
        // Attestation, key provisioning, Play Integrity.
        "com.google.android.rkpdapp",
        "com.samsung.android.knox.attestation",
        "com.samsung.android.knox.containercore",
        "com.google.android.configupdater",
        // Core Google/Android modules.
        "com.google.android.ext.services",
        "com.android.ext.services",
        "com.google.android.networkstack",
        "com.android.networkstack",
        "com.google.android.networkstack.tethering",
        "com.google.android.permissioncontroller",
        "com.android.permissioncontroller",
        "com.google.android.modulemetadata",
        "com.google.android.webview",
        "com.android.webview",
        "com.google.android.trichromelibrary",
        "com.google.android.captiveportallogin",
        "com.android.captiveportallogin",
        "com.android.keychain",
        "com.android.certinstaller",
        "com.android.vpndialogs",
        "com.android.se",
        "com.android.bluetooth",
        "com.android.nfc",
        // Launcher, phone, SMS, emergency.
        "com.sec.android.app.launcher",
        "com.android.launcher3",
        "com.samsung.android.dialer",
        "com.samsung.android.incallui",
        "com.android.phone",
        "com.android.server.telecom",
        "com.samsung.android.messaging",
        "com.google.android.cellbroadcastreceiver",
        "com.android.cellbroadcastreceiver",
        "com.google.android.cellbroadcastservice",
        "com.android.emergency",
        "com.samsung.android.emergency",
        // Installers and setup.
        "com.google.android.packageinstaller",
        "com.android.packageinstaller",
        "com.samsung.android.packageinstaller",
        "com.google.android.setupwizard",
        "com.sec.android.app.SecSetupWizard",
        // Keyboard (only keyboard in Direct Boot) and biometrics.
        "com.samsung.android.honeyboard",
        "com.samsung.android.biometrics.app.setting",
    )

    /** Prefixes: content providers (contacts, media, telephony, settings…) are never touched. */
    val PREFIXES: List<String> = listOf("com.android.providers.", "com.google.android.providers.", "com.samsung.android.providers.")

    fun isDenied(pkg: String, dynamic: Set<String> = emptySet()): Boolean =
        pkg in PACKAGES || pkg in dynamic || PREFIXES.any { pkg.startsWith(it) }
}

/**
 * Restrictions Watchpost may set. Two lists, both hard-coded:
 * - [FORBIDDEN]: restrictions that would cut the ADB rescue path, the location the agent relies on,
 *   or a vital function of the phone. Listed explicitly so that the reason stays written down;
 * - [ALLOWED]: the only keys ever passed to `addUserRestriction`, each reviewed against the
 *   `UserManager` documentation (docs/research/android-platform.md §3.8). A catalog (or a future
 *   edit of it) naming any other key is refused: an unreviewed restriction such as
 *   `no_unmute_microphone` or `no_create_windows` can make the phone unusable just as well.
 * USB data signaling is never disabled either (no code path calls `setUsbDataSignalingEnabled(false)`).
 * Undoing (`clearUserRestriction`) is never filtered.
 */
object RestrictionGuard {
    const val DNS_LOCK = "disallow_config_private_dns"

    val FORBIDDEN: Set<String> = setOf(
        "no_debugging_features", // cuts ADB: the rescue path.
        "no_config_date_time",
        "no_share_location", // turns location off for the user, Watchpost included.
        "no_config_location",
        "no_usb_signaling", // defensive: not a public restriction, never set.
        "no_factory_reset", // the user's last resort stays available.
        "no_modify_accounts",
        "no_install_apps", // would also block "adb install" (updates of Watchpost itself).
        "no_uninstall_apps",
        "no_control_apps",
        "no_outgoing_calls",
        "no_sms",
        "no_config_mobile_networks",
        "no_config_wifi",
        "no_change_wifi_state",
        "no_config_vpn",
        "no_network_reset",
        "no_airplane_mode",
        // Set only by the private DNS lock, together with the DNS itself (never as a catalog entry).
        DNS_LOCK,
    )

    /** Reviewed keys: privacy/security restrictions that leave calls, network, ADB and settings usable. */
    val ALLOWED: Set<String> = setOf(
        "no_add_user",
        "no_cellular_2g",
        "no_install_unknown_sources_globally",
        "no_install_unknown_sources",
        "no_content_capture",
        "no_content_suggestions",
        "no_assist_content",
        "no_config_credentials",
        "no_safe_boot",
        "no_sim_globally",
        "no_ultra_wideband_radio",
        "no_thread_network",
        "no_near_field_communication_radio",
        "no_bluetooth_sharing",
        "no_usb_file_transfer", // MTP/PTP only: ADB is not a "file transfer" function.
        "no_autofill",
    )

    fun isForbidden(key: String): Boolean = key in FORBIDDEN || key !in ALLOWED
}

/**
 * `Settings.Global` / `Settings.Secure` keys Watchpost may write with WRITE_SECURE_SETTINGS. That
 * permission can write anything (`adb_enabled`, `user_setup_complete`, `private_dns_mode`,
 * `default_input_method`…): only the keys reviewed here ever reach `Settings.*.putString`, whatever
 * the catalog says. Undoing (writing back the recorded previous value) is never filtered.
 */
object SettingGuard {
    val ALLOWED: Set<String> = setOf(
        "global:ble_scan_always_enabled",
        "global:wifi_scan_always_enabled",
    )

    fun isForbidden(namespace: String, key: String): Boolean = "$namespace:$key" !in ALLOWED
}
