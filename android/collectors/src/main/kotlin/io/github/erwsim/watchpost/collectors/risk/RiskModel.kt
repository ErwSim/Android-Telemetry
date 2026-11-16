package io.github.erwsim.watchpost.collectors.risk

import androidx.annotation.StringRes
import io.github.erwsim.watchpost.collectors.R

/** `app.risk.level`. */
enum class RiskLevel(val wire: String) {
    LOW("low"),
    MEDIUM("medium"),
    HIGH("high"),
    ;

    companion object {
        /** Score ranges: 0..29 low, 30..69 medium, 70..100 high. */
        const val MEDIUM_FROM = 30
        const val HIGH_FROM = 70
        const val MAX_SCORE = 100

        /** Highest score of an app capped at "low" (system apps, Watchpost itself). */
        const val LOW_MAX = MEDIUM_FROM - 1

        fun of(score: Int): RiskLevel = when {
            score >= HIGH_FROM -> HIGH
            score >= MEDIUM_FROM -> MEDIUM
            else -> LOW
        }
    }
}

/**
 * Closed list of `app.risk.reasons` (contract §11.2) with the points each one adds. THE weighting table:
 * the README of the module reproduces it and a test checks that both agree. A combination (`combo_*`)
 * adds its own points on top of those of the reasons it combines: that is what makes a trojan stand out
 * from an app that merely holds one of the powers.
 *
 * Every code has a French label and explanation (`risk_reason_<code>` and `risk_reason_<code>_desc`).
 */
enum class RiskReason(
    val code: String,
    /** Points when the capability is DECLARED (permission requested, component declared). */
    val points: Int,
    /** Extra points when the permission behind it is also GRANTED right now (0 for reasons that are not grantable). */
    val grantedBonus: Int,
    @StringRes val labelRes: Int,
    @StringRes val descRes: Int,
) {
    SIDELOADED("sideloaded", 35, 0, R.string.risk_reason_sideloaded, R.string.risk_reason_sideloaded_desc),
    UNKNOWN_INSTALLER("unknown_installer", 25, 0, R.string.risk_reason_unknown_installer, R.string.risk_reason_unknown_installer_desc),
    NO_LAUNCHER_ICON("no_launcher_icon", 12, 0, R.string.risk_reason_no_launcher_icon, R.string.risk_reason_no_launcher_icon_desc),
    SMS_SEND("sms_send", 16, 4, R.string.risk_reason_sms_send, R.string.risk_reason_sms_send_desc),
    SMS_READ("sms_read", 6, 6, R.string.risk_reason_sms_read, R.string.risk_reason_sms_read_desc),
    CALLS("calls", 3, 7, R.string.risk_reason_calls, R.string.risk_reason_calls_desc),
    ACCESSIBILITY_SERVICE("accessibility_service", 25, 0, R.string.risk_reason_accessibility_service, R.string.risk_reason_accessibility_service_desc),
    NOTIFICATION_LISTENER("notification_listener", 15, 0, R.string.risk_reason_notification_listener, R.string.risk_reason_notification_listener_desc),
    DEVICE_ADMIN("device_admin", 15, 0, R.string.risk_reason_device_admin, R.string.risk_reason_device_admin_desc),
    OVERLAY("overlay", 12, 0, R.string.risk_reason_overlay, R.string.risk_reason_overlay_desc),
    INSTALL_PACKAGES("install_packages", 20, 0, R.string.risk_reason_install_packages, R.string.risk_reason_install_packages_desc),
    VPN_SERVICE("vpn_service", 10, 0, R.string.risk_reason_vpn_service, R.string.risk_reason_vpn_service_desc),
    BOOT_RECEIVER("boot_receiver", 5, 0, R.string.risk_reason_boot_receiver, R.string.risk_reason_boot_receiver_desc),
    BACKGROUND_LOCATION("background_location", 6, 4, R.string.risk_reason_background_location, R.string.risk_reason_background_location_desc),
    MIC_CAMERA_BACKGROUND("mic_camera_background", 3, 5, R.string.risk_reason_mic_camera_background, R.string.risk_reason_mic_camera_background_desc),
    OLD_TARGET_SDK("old_target_sdk", 8, 0, R.string.risk_reason_old_target_sdk, R.string.risk_reason_old_target_sdk_desc),
    DEBUGGABLE("debuggable", 10, 0, R.string.risk_reason_debuggable, R.string.risk_reason_debuggable_desc),
    COMBO_BANKING_TROJAN("combo_banking_trojan", 30, 0, R.string.risk_reason_combo_banking_trojan, R.string.risk_reason_combo_banking_trojan_desc),
    COMBO_SMS_FRAUD("combo_sms_fraud", 20, 6, R.string.risk_reason_combo_sms_fraud, R.string.risk_reason_combo_sms_fraud_desc),
    COMBO_STALKERWARE("combo_stalkerware", 30, 0, R.string.risk_reason_combo_stalkerware, R.string.risk_reason_combo_stalkerware_desc),
    ;

    /** True if the reason can be "granted" (it rests on a runtime permission), hence appears in `app.risk.granted`. */
    val grantable: Boolean get() = grantedBonus > 0

    companion object {
        private val BY_CODE = entries.associateBy { it.code }

        fun fromCode(code: String): RiskReason? = BY_CODE[code]
    }
}

/**
 * Everything the score is computed from, as exposed by `PackageManager` (no network, no APK content).
 * Pure data: the scoring function takes nothing else.
 */
data class AppFacts(
    val pkg: String,
    val label: String? = null,
    val versionCode: Long = 0,
    /** Installing package (`InstallSourceInfo.getInstallingPackageName`), null if unknown (ADB, file…). */
    val installer: String? = null,
    /** `FLAG_SYSTEM` (preinstalled, even if updated since). */
    val system: Boolean = false,
    /** The Watchpost agent itself. */
    val isSelf: Boolean = false,
    /** Every permission in the manifest (requested), granted or not. */
    val requested: Set<String> = emptySet(),
    /** Requested permissions currently granted. */
    val granted: Set<String> = emptySet(),
    /** Declares an `AccessibilityService` (protected by `BIND_ACCESSIBILITY_SERVICE`), enabled or not. */
    val accessibilityService: Boolean = false,
    val notificationListener: Boolean = false,
    /** Declares a device admin receiver (`BIND_DEVICE_ADMIN`). */
    val deviceAdminReceiver: Boolean = false,
    /** Declares a `VpnService` (`BIND_VPN_SERVICE`). */
    val vpnService: Boolean = false,
    /** Declares an enabled receiver for `BOOT_COMPLETED`. */
    val bootReceiver: Boolean = false,
    /** Has an enabled `MAIN`/`LAUNCHER` activity. True when unknown (never penalise a failed reading). */
    val launcherActivity: Boolean = true,
    /** Is the default SMS app right now. */
    val defaultSmsApp: Boolean = false,
    val targetSdk: Int = 36,
    val debuggable: Boolean = false,
)

/**
 * [reasons]: what the app DECLARES (the profile serves before any grant: install, quarantine screen).
 * [granted]: the subset of [reasons] whose permissions are also granted now (intent versus state).
 */
data class RiskAssessment(val score: Int, val level: RiskLevel, val reasons: List<RiskReason>, val granted: List<RiskReason> = emptyList()) {
    val reasonCodes: List<String> get() = reasons.map { it.code }
    val grantedCodes: List<String> get() = granted.map { it.code }
}

/** Pure scoring function of `app.risk`: facts in, score / level / reasons out. */
object RiskScorer {
    /** Installers that merely carry a file (package installer, file managers, ADB shell): a sideload. */
    val FILE_INSTALLERS = setOf(
        "com.google.android.packageinstaller",
        "com.android.packageinstaller",
        "com.samsung.android.packageinstaller",
        "com.google.android.documentsui",
        "com.android.documentsui",
        "com.sec.android.app.myfiles",
        "com.android.shell",
    )

    /** App stores (the same list as the inventory: Play, Galaxy Store, F-Droid…). */
    val STORES = io.github.erwsim.watchpost.collectors.apps.AppInventoryLogic.STORES

    private val SMS_SEND = setOf("android.permission.SEND_SMS")
    private val SMS_READ = setOf(
        "android.permission.READ_SMS", "android.permission.RECEIVE_SMS", "android.permission.RECEIVE_MMS",
        "android.permission.RECEIVE_WAP_PUSH",
    )
    private val CALLS = setOf(
        "android.permission.CALL_PHONE", "android.permission.READ_CALL_LOG", "android.permission.WRITE_CALL_LOG",
        "android.permission.ANSWER_PHONE_CALLS", "android.permission.PROCESS_OUTGOING_CALLS",
    )
    private val INSTALL = setOf("android.permission.REQUEST_INSTALL_PACKAGES", "android.permission.INSTALL_PACKAGES")
    private val FGS_MIC_CAMERA = setOf("android.permission.FOREGROUND_SERVICE_MICROPHONE", "android.permission.FOREGROUND_SERVICE_CAMERA")
    private val MIC_CAMERA = setOf("android.permission.RECORD_AUDIO", "android.permission.CAMERA")
    private val LOCATION = setOf(
        "android.permission.ACCESS_FINE_LOCATION", "android.permission.ACCESS_COARSE_LOCATION",
        "android.permission.ACCESS_BACKGROUND_LOCATION",
    )

    /** Target SDK below which an app escapes the protections added since Android 10. */
    const val OLD_TARGET_SDK_BELOW = 30

    /**
     * Score on DECLARED capabilities (permissions requested, components declared), plus a bonus for the
     * grantable ones that are also granted. An app that declares SMS permissions without holding them is
     * rated on its declaration; granting them raises the score a little and adds the reason to `granted`.
     */
    fun score(f: AppFacts): RiskAssessment {
        val fromStore = f.installer != null && f.installer in STORES
        val userApp = !f.system && !f.isSelf
        val r = LinkedHashSet<RiskReason>()

        // Origin (user apps only: a preinstalled app has no "installer" to judge).
        if (userApp && !fromStore) {
            if (f.installer == null || f.installer in FILE_INSTALLERS) r += RiskReason.SIDELOADED else r += RiskReason.UNKNOWN_INSTALLER
        }
        val noLauncher = userApp && !f.launcherActivity
        if (noLauncher) r += RiskReason.NO_LAUNCHER_ICON

        // Components and special requests: declared only (nothing to grant).
        if (f.accessibilityService) r += RiskReason.ACCESSIBILITY_SERVICE
        if (f.notificationListener) r += RiskReason.NOTIFICATION_LISTENER
        if (f.deviceAdminReceiver) r += RiskReason.DEVICE_ADMIN
        // Special accesses are not reliably "granted" in the package flags: the request is what counts.
        val overlay = "android.permission.SYSTEM_ALERT_WINDOW" in f.requested
        if (overlay) r += RiskReason.OVERLAY
        if (INSTALL.any { it in f.requested }) r += RiskReason.INSTALL_PACKAGES
        if (f.vpnService) r += RiskReason.VPN_SERVICE
        val boot = f.bootReceiver && "android.permission.RECEIVE_BOOT_COMPLETED" in f.requested
        if (boot) r += RiskReason.BOOT_RECEIVER
        if (userApp && f.targetSdk < OLD_TARGET_SDK_BELOW) r += RiskReason.OLD_TARGET_SDK
        if (userApp && f.debuggable) r += RiskReason.DEBUGGABLE

        // Permission-based reasons, evaluated twice: on what is requested, and on what is granted.
        val declared = permissionReasons(f, f.requested, boot, noLauncher, overlay)
        val held = permissionReasons(f, f.granted, boot, noLauncher, overlay)
        r += declared
        val granted = RiskReason.entries.filter { it.grantable && it in held && it in declared }

        val reasons = RiskReason.entries.filter { it in r } // Stable order: the table's.
        var score = minOf(RiskLevel.MAX_SCORE, reasons.sumOf { it.points } + granted.sumOf { it.grantedBonus })
        if (f.system || f.isSelf) score = minOf(score, RiskLevel.LOW_MAX)
        return RiskAssessment(score, RiskLevel.of(score), reasons, granted)
    }

    /** The reasons that rest on permissions, judged on [perms] (the requested or the granted ones). */
    private fun permissionReasons(f: AppFacts, perms: Set<String>, boot: Boolean, noLauncher: Boolean, overlay: Boolean): Set<RiskReason> {
        val r = LinkedHashSet<RiskReason>()
        val smsSend = SMS_SEND.any { it in perms }
        val smsRead = SMS_READ.any { it in perms }
        if (smsSend) r += RiskReason.SMS_SEND
        if (smsRead) r += RiskReason.SMS_READ
        if (CALLS.any { it in perms }) r += RiskReason.CALLS
        if ("android.permission.ACCESS_BACKGROUND_LOCATION" in perms) r += RiskReason.BACKGROUND_LOCATION
        if (MIC_CAMERA.any { it in perms } && (FGS_MIC_CAMERA.any { it in f.requested } || (f.targetSdk < 34 && "android.permission.FOREGROUND_SERVICE" in f.requested))) {
            r += RiskReason.MIC_CAMERA_BACKGROUND
        }
        // The three combinations of the contract.
        if (f.accessibilityService && overlay && (smsRead || f.notificationListener)) r += RiskReason.COMBO_BANKING_TROJAN
        if (smsSend && boot && !f.defaultSmsApp) r += RiskReason.COMBO_SMS_FRAUD
        val locationOrMic = LOCATION.any { it in perms } || "android.permission.RECORD_AUDIO" in perms
        if (noLauncher && locationOrMic && boot) r += RiskReason.COMBO_STALKERWARE
        return r
    }
}
