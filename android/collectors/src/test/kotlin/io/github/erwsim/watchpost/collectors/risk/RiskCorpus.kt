package io.github.erwsim.watchpost.collectors.risk

/**
 * Realistic profiles used to measure the false positives and the false negatives of [RiskScorer].
 *
 * They are NOT extracted from real APKs: each one is built from the features and the permissions such an app
 * usually has (manifest as commonly documented), with brand-free names. They show how the weighting behaves on
 * the families that matter, not how it behaves on one given application.
 */
object RiskCorpus {
    enum class Kind { LEGIT, MALICIOUS }

    /**
     * [ideal]: the level a human reviewer would want. [expected]: the level the scorer gives today (the test
     * fails when they drift, which forces the README table to be updated knowingly).
     */
    data class Profile(val id: String, val kind: Kind, val ideal: RiskLevel, val expected: RiskLevel, val note: String, val facts: AppFacts)

    private const val P = "android.permission."
    const val PLAY = "com.android.vending"
    const val FDROID = "org.fdroid.fdroid"
    const val INSTALLER = "com.google.android.packageinstaller"

    private fun perms(vararg names: String) = names.map { if ('.' in it) it else P + it }.toSet()

    private fun app(
        id: String,
        installer: String? = PLAY,
        requestedOnly: Set<String> = emptySet(),
        granted: Set<String> = emptySet(),
        system: Boolean = false,
        self: Boolean = false,
        accessibility: Boolean = false,
        listener: Boolean = false,
        admin: Boolean = false,
        vpn: Boolean = false,
        boot: Boolean = false,
        launcher: Boolean = true,
        defaultSms: Boolean = false,
        target: Int = 36,
        debuggable: Boolean = false,
    ) = AppFacts(
        pkg = "test.$id", label = id, versionCode = 1, installer = installer, system = system, isSelf = self,
        requested = granted + requestedOnly, granted = granted,
        accessibilityService = accessibility, notificationListener = listener, deviceAdminReceiver = admin, vpnService = vpn,
        bootReceiver = boot, launcherActivity = launcher, defaultSmsApp = defaultSms, targetSdk = target, debuggable = debuggable,
    )

    private val BOOT = perms("RECEIVE_BOOT_COMPLETED")
    private val SMS_ALL = perms("SEND_SMS", "READ_SMS", "RECEIVE_SMS", "RECEIVE_MMS", "RECEIVE_WAP_PUSH")

    val ALL: List<Profile> = listOf(
        // ---- Legitimate apps (installed by the user from a store, unless stated) ----
        legit(
            "encrypted_messenger", RiskLevel.LOW, RiskLevel.LOW, "Calls, microphone/camera during calls, start at boot.",
            app(
                "encrypted_messenger", granted = perms("CAMERA", "RECORD_AUDIO", "READ_CONTACTS", "READ_CALL_LOG", "ANSWER_PHONE_CALLS", "READ_PHONE_STATE", "ACCESS_FINE_LOCATION"),
                requestedOnly = BOOT + perms("FOREGROUND_SERVICE", "FOREGROUND_SERVICE_MICROPHONE", "FOREGROUND_SERVICE_CAMERA"), boot = true,
            ),
        ),
        legit(
            "messenger_declares_sms", RiskLevel.LOW, RiskLevel.MEDIUM, "Commercial messenger that DECLARES the SMS rights (send, read) without holding them, with calls, microphone and start at boot.",
            app(
                "messenger_declares_sms", granted = perms("CAMERA", "RECORD_AUDIO", "READ_CONTACTS", "READ_CALL_LOG", "CALL_PHONE"),
                requestedOnly = SMS_ALL + BOOT + perms("FOREGROUND_SERVICE_MICROPHONE", "FOREGROUND_SERVICE_CAMERA"), boot = true,
            ),
        ),
        legit("bank_declares_sms", RiskLevel.LOW, RiskLevel.LOW, "Bank that declares SMS reading (automatic code entry), without start at boot.", app("bank_declares_sms", granted = perms("CAMERA"), requestedOnly = perms("READ_SMS", "RECEIVE_SMS"))),
        legit("bank", RiskLevel.LOW, RiskLevel.LOW, "Camera (cheque, identity), location, phone state.", app("bank", granted = perms("CAMERA", "ACCESS_FINE_LOCATION", "READ_PHONE_STATE"))),
        legit("third_party_keyboard", RiskLevel.LOW, RiskLevel.LOW, "A keyboard is not scored for its input method service.", app("third_party_keyboard", granted = perms("READ_CONTACTS", "RECORD_AUDIO"), requestedOnly = BOOT, boot = true)),
        legit("browser", RiskLevel.LOW, RiskLevel.LOW, "Camera, microphone, location.", app("browser", granted = perms("CAMERA", "RECORD_AUDIO", "ACCESS_FINE_LOCATION"))),
        legit(
            "launcher", RiskLevel.LOW, RiskLevel.LOW, "Notification listener for the badges.",
            app("launcher", granted = perms("READ_CONTACTS"), requestedOnly = BOOT, listener = true, boot = true),
        ),
        legit(
            "launcher_lock_gesture", RiskLevel.LOW, RiskLevel.MEDIUM, "Launcher whose \"double tap to lock\" feature goes through accessibility.",
            app("launcher_lock_gesture", granted = perms("READ_CONTACTS"), requestedOnly = BOOT, listener = true, accessibility = true, boot = true),
        ),
        legit(
            "password_manager", RiskLevel.LOW, RiskLevel.MEDIUM, "Filling through accessibility and drawing over apps: indistinguishable from a trojan on these two criteria.",
            app("password_manager", granted = perms("CAMERA"), requestedOnly = perms("SYSTEM_ALERT_WINDOW"), accessibility = true),
        ),
        legit(
            "parental_control", RiskLevel.MEDIUM, RiskLevel.HIGH, "Same powers as spyware, by design: cannot be told apart without knowing who installed it.",
            app(
                "parental_control", granted = perms("ACCESS_FINE_LOCATION", "ACCESS_BACKGROUND_LOCATION", "READ_SMS", "READ_CALL_LOG", "READ_CONTACTS"),
                requestedOnly = BOOT + perms("SYSTEM_ALERT_WINDOW", "PACKAGE_USAGE_STATS"), accessibility = true, admin = true, vpn = true, listener = true, boot = true,
            ),
        ),
        legit("vpn", RiskLevel.LOW, RiskLevel.LOW, "VPN service and start at boot.", app("vpn", requestedOnly = BOOT, vpn = true, boot = true)),
        legit(
            "third_party_default_sms", RiskLevel.LOW, RiskLevel.MEDIUM, "Third-party SMS app chosen as default: it must have all the SMS rights.",
            app("third_party_default_sms", granted = SMS_ALL + perms("READ_CONTACTS"), requestedOnly = BOOT, boot = true, defaultSms = true),
        ),
        legit(
            "antivirus", RiskLevel.MEDIUM, RiskLevel.HIGH, "A security suite asks for accessibility, overlay, notifications, SMS, VPN and administration.",
            app(
                "antivirus", granted = perms("READ_SMS", "RECEIVE_SMS", "READ_CONTACTS"), requestedOnly = BOOT + perms("SYSTEM_ALERT_WINDOW"),
                accessibility = true, listener = true, admin = true, vpn = true, boot = true,
            ),
        ),
        legit(
            "automation", RiskLevel.MEDIUM, RiskLevel.HIGH, "An automation app (Tasker type) has all the powers: accessibility, SMS, calls, overlay.",
            app(
                "automation", granted = SMS_ALL + perms("CALL_PHONE", "READ_CONTACTS"), requestedOnly = BOOT + perms("SYSTEM_ALERT_WINDOW"),
                accessibility = true, listener = true, boot = true,
            ),
        ),
        legit("file_manager", RiskLevel.LOW, RiskLevel.LOW, "Asks to install packages (APK); F-Droid store.", app("file_manager", installer = FDROID, requestedOnly = perms("REQUEST_INSTALL_PACKAGES"))),
        legit("offline_navigation", RiskLevel.LOW, RiskLevel.LOW, "Background location for route tracking.", app("offline_navigation", installer = FDROID, granted = perms("ACCESS_FINE_LOCATION", "ACCESS_BACKGROUND_LOCATION"), requestedOnly = BOOT, boot = true)),
        legit(
            "caller_id", RiskLevel.LOW, RiskLevel.HIGH, "Caller identification with SMS rights (payment): sending SMS + start at boot without being the SMS app.",
            app(
                "caller_id", granted = SMS_ALL + perms("READ_CALL_LOG", "CALL_PHONE", "READ_CONTACTS"), requestedOnly = BOOT + perms("SYSTEM_ALERT_WINDOW"), boot = true,
            ),
        ),
        legit("third_party_dialer", RiskLevel.LOW, RiskLevel.LOW, "Third-party default dialer.", app("third_party_dialer", granted = perms("CALL_PHONE", "READ_CALL_LOG", "READ_CONTACTS", "ANSWER_PHONE_CALLS"), requestedOnly = BOOT, boot = true)),
        legit("authenticator", RiskLevel.LOW, RiskLevel.LOW, "Camera for QR codes.", app("authenticator", installer = FDROID, granted = perms("CAMERA"))),
        legit(
            "button_remapper", RiskLevel.LOW, RiskLevel.MEDIUM, "Button remapping: accessibility + overlay.",
            app("button_remapper", requestedOnly = perms("SYSTEM_ALERT_WINDOW"), accessibility = true, boot = false),
        ),
        legit("old_bank", RiskLevel.LOW, RiskLevel.LOW, "Abandoned banking app, targets Android 9.", app("old_bank", granted = perms("CAMERA", "READ_PHONE_STATE"), target = 28)),
        legit(
            "system_dialer", RiskLevel.LOW, RiskLevel.LOW, "System app (calls, SMS, notifications): capped at \"low\".",
            app(
                "system_dialer", installer = null, system = true, granted = SMS_ALL + perms("CALL_PHONE", "READ_CALL_LOG", "READ_CONTACTS"),
                requestedOnly = BOOT + perms("SYSTEM_ALERT_WINDOW"), listener = true, accessibility = true, boot = true, launcher = false,
            ),
        ),
        legit(
            "watchpost", RiskLevel.LOW, RiskLevel.LOW, "The agent itself: background location, start at boot, usage access.",
            app("watchpost", installer = null, self = true, granted = perms("ACCESS_FINE_LOCATION", "ACCESS_BACKGROUND_LOCATION", "READ_PHONE_STATE"), requestedOnly = BOOT, boot = true),
        ),

        // ---- Malicious profiles ----
        bad(
            "banking_trojan", RiskLevel.HIGH, RiskLevel.HIGH, "Fake PDF reader: accessibility + overlay + SMS + notifications + installation, outside a store.",
            app(
                "banking_trojan", installer = INSTALLER, granted = perms("READ_SMS", "RECEIVE_SMS"), requestedOnly = BOOT + perms("SYSTEM_ALERT_WINDOW", "REQUEST_INSTALL_PACKAGES"),
                accessibility = true, listener = true, boot = true, target = 31,
            ),
        ),
        bad(
            "sms_fraud", RiskLevel.HIGH, RiskLevel.HIGH, "SMS fraud: mass SMS sending in the background, fake wallpapers.",
            app("sms_fraud", installer = null, granted = perms("SEND_SMS", "READ_CONTACTS"), requestedOnly = BOOT, boot = true),
        ),
        bad(
            "sms_fraud_before_grant", RiskLevel.HIGH, RiskLevel.HIGH, "The same profile at install time: SMS rights declared, NOTHING granted (SMS guard active or quarantine screen).",
            app("sms_fraud_before_grant", installer = INSTALLER, requestedOnly = perms("SEND_SMS", "READ_CONTACTS") + BOOT, boot = true),
        ),
        bad(
            "spyware_before_grant", RiskLevel.HIGH, RiskLevel.HIGH, "Spyware without an icon at install time: location and microphone declared, nothing granted.",
            app("spyware_before_grant", installer = null, requestedOnly = perms("ACCESS_FINE_LOCATION", "RECORD_AUDIO") + BOOT, boot = true, launcher = false),
        ),
        bad(
            "sms_fraud_no_boot", RiskLevel.HIGH, RiskLevel.MEDIUM, "Same sending, triggered by a push notification: no start at boot, so no combination.",
            app("sms_fraud_no_boot", installer = INSTALLER, granted = perms("SEND_SMS")),
        ),
        bad(
            "sms_fraud_store", RiskLevel.HIGH, RiskLevel.MEDIUM, "Same profile distributed by the store: the store does not erase the risk, but does not add points either.",
            app("sms_fraud_store", granted = perms("SEND_SMS"), requestedOnly = BOOT, boot = true),
        ),
        bad(
            "spyware_no_icon", RiskLevel.HIGH, RiskLevel.HIGH, "Full spyware, installed through ADB, without an icon.",
            app(
                "spyware_no_icon", installer = null, granted = perms("ACCESS_FINE_LOCATION", "ACCESS_BACKGROUND_LOCATION", "RECORD_AUDIO", "READ_SMS", "READ_CALL_LOG", "READ_CONTACTS"),
                requestedOnly = BOOT + perms("FOREGROUND_SERVICE_MICROPHONE"), accessibility = true, listener = true, admin = true, boot = true, launcher = false,
            ),
        ),
        bad(
            "minimal_spyware", RiskLevel.HIGH, RiskLevel.HIGH, "Location tracking only: no icon, location, start at boot.",
            app("minimal_spyware", installer = null, granted = perms("ACCESS_FINE_LOCATION"), requestedOnly = BOOT, boot = true, launcher = false),
        ),
        bad(
            "discreet_spyware_with_icon", RiskLevel.HIGH, RiskLevel.MEDIUM, "Spyware that keeps a harmless icon (\"Notes\"): none of the three combinations sees it, only \"outside a store\" and the start at boot remain.",
            app("discreet_spyware_with_icon", installer = INSTALLER, granted = perms("ACCESS_FINE_LOCATION", "RECORD_AUDIO", "READ_CONTACTS"), requestedOnly = BOOT, boot = true),
        ),
        bad(
            "payload_installer", RiskLevel.HIGH, RiskLevel.MEDIUM, "Dropper outside a store: asks to install packages, nothing else. Medium, not high.",
            app("payload_installer", installer = INSTALLER, requestedOnly = perms("REQUEST_INSTALL_PACKAGES", "QUERY_ALL_PACKAGES", "FOREGROUND_SERVICE")),
        ),
        bad(
            "payload_installer_store", RiskLevel.HIGH, RiskLevel.LOW, "Dropper published on the store: only the install request gives it away, which is not enough.",
            app("payload_installer_store", requestedOnly = perms("REQUEST_INSTALL_PACKAGES", "QUERY_ALL_PACKAGES", "FOREGROUND_SERVICE")),
        ),
        bad(
            "rat_dropped_by_messenger", RiskLevel.HIGH, RiskLevel.HIGH, "Remote access tool dropped by a messenger app: accessibility, notifications, overlay, SMS.",
            app(
                "rat_dropped_by_messenger", installer = "org.telegram.messenger", granted = perms("READ_SMS", "RECEIVE_SMS"),
                requestedOnly = perms("SYSTEM_ALERT_WINDOW"), accessibility = true, listener = true, target = 30,
            ),
        ),
        bad(
            "accessibility_adware", RiskLevel.HIGH, RiskLevel.HIGH, "Advertising forced through accessibility and overlay, outside a store.",
            app("accessibility_adware", installer = INSTALLER, requestedOnly = perms("SYSTEM_ALERT_WINDOW"), accessibility = true),
        ),
        bad(
            "locker", RiskLevel.HIGH, RiskLevel.MEDIUM, "Ransom screen: administrator + overlay + start at boot, outside a store.",
            app("locker", installer = INSTALLER, requestedOnly = BOOT + perms("SYSTEM_ALERT_WINDOW"), admin = true, boot = true),
        ),
    )

    private fun legit(id: String, ideal: RiskLevel, expected: RiskLevel, note: String, facts: AppFacts) = Profile(id, Kind.LEGIT, ideal, expected, note, facts)

    private fun bad(id: String, ideal: RiskLevel, expected: RiskLevel, note: String, facts: AppFacts) = Profile(id, Kind.MALICIOUS, ideal, expected, note, facts)
}
