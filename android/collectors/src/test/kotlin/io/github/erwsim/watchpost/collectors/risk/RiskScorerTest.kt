package io.github.erwsim.watchpost.collectors.risk

import io.github.erwsim.watchpost.core.testing.Contract
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class RiskScorerTest {
    private val p = "android.permission."
    private fun facts(
        installer: String? = "com.android.vending",
        granted: Set<String> = emptySet(),
        requested: Set<String> = emptySet(),
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
        "test.app", installer = installer, system = system, isSelf = self, requested = requested + granted, granted = granted,
        accessibilityService = accessibility, notificationListener = listener, deviceAdminReceiver = admin, vpnService = vpn,
        bootReceiver = boot, launcherActivity = launcher, defaultSmsApp = defaultSms, targetSdk = target, debuggable = debuggable,
    )

    private fun codes(f: AppFacts) = RiskScorer.score(f).reasonCodes.toSet()

    @Test
    fun aCleanStoreAppHasNoReasonAndScoresZero() {
        val a = RiskScorer.score(facts())
        assertEquals(0, a.score)
        assertEquals(RiskLevel.LOW, a.level)
        assertTrue(a.reasons.isEmpty())
    }

    /** One minimal case per code: every code of the contract can be produced, alone, with its table points. */
    @Test
    fun everyCodeIsProducedAloneWithItsPoints() {
        val cases: Map<RiskReason, AppFacts> = mapOf(
            RiskReason.SIDELOADED to facts(installer = null),
            RiskReason.UNKNOWN_INSTALLER to facts(installer = "org.example.messenger"),
            RiskReason.NO_LAUNCHER_ICON to facts(launcher = false),
            RiskReason.SMS_SEND to facts(granted = setOf(p + "SEND_SMS")),
            RiskReason.SMS_READ to facts(granted = setOf(p + "RECEIVE_SMS")),
            RiskReason.CALLS to facts(granted = setOf(p + "READ_CALL_LOG")),
            RiskReason.ACCESSIBILITY_SERVICE to facts(accessibility = true),
            RiskReason.NOTIFICATION_LISTENER to facts(listener = true),
            RiskReason.DEVICE_ADMIN to facts(admin = true),
            RiskReason.OVERLAY to facts(requested = setOf(p + "SYSTEM_ALERT_WINDOW")),
            RiskReason.INSTALL_PACKAGES to facts(requested = setOf(p + "REQUEST_INSTALL_PACKAGES")),
            RiskReason.VPN_SERVICE to facts(vpn = true),
            RiskReason.BOOT_RECEIVER to facts(boot = true, requested = setOf(p + "RECEIVE_BOOT_COMPLETED")),
            RiskReason.BACKGROUND_LOCATION to facts(granted = setOf(p + "ACCESS_BACKGROUND_LOCATION")),
            RiskReason.MIC_CAMERA_BACKGROUND to facts(granted = setOf(p + "RECORD_AUDIO"), requested = setOf(p + "FOREGROUND_SERVICE_MICROPHONE")),
            RiskReason.OLD_TARGET_SDK to facts(target = 29),
            RiskReason.DEBUGGABLE to facts(debuggable = true),
        )
        cases.forEach { (reason, f) ->
            val a = RiskScorer.score(f)
            assertEquals("${reason.code} alone", listOf(reason), a.reasons)
            // `facts()` both requests and grants what it is given: a grantable reason also earns its bonus.
            assertEquals(reason.code, reason.points + if (reason.grantable) reason.grantedBonus else 0, a.score)
            assertEquals(reason.code, if (reason.grantable) listOf(reason) else emptyList<RiskReason>(), a.granted)
        }
        // The three combinations (and only they) are missing above: they need several facts at once.
        assertEquals(RiskReason.entries.size - 3, cases.size)
        assertEquals(RiskReason.entries.map { it.code }.toSet(), Contract.RISK_REASONS)
    }

    @Test
    fun theThreeCombinationsOfTheContract() {
        // Banking trojan: accessibility + overlay + (SMS reading or notification listening).
        val overlay = setOf(p + "SYSTEM_ALERT_WINDOW")
        assertTrue(RiskReason.COMBO_BANKING_TROJAN.code in codes(facts(accessibility = true, requested = overlay, granted = setOf(p + "READ_SMS"))))
        assertTrue(RiskReason.COMBO_BANKING_TROJAN.code in codes(facts(accessibility = true, requested = overlay, listener = true)))
        assertFalse(RiskReason.COMBO_BANKING_TROJAN.code in codes(facts(accessibility = true, requested = overlay)))
        assertFalse(RiskReason.COMBO_BANKING_TROJAN.code in codes(facts(requested = overlay, listener = true, granted = setOf(p + "READ_SMS"))))
        assertFalse(RiskReason.COMBO_BANKING_TROJAN.code in codes(facts(accessibility = true, listener = true, granted = setOf(p + "READ_SMS"))))

        // SMS fraud: SMS sending + boot start, without being the default SMS app.
        val boot = setOf(p + "RECEIVE_BOOT_COMPLETED")
        val send = setOf(p + "SEND_SMS")
        assertTrue(RiskReason.COMBO_SMS_FRAUD.code in codes(facts(granted = send, requested = boot, boot = true)))
        assertFalse(RiskReason.COMBO_SMS_FRAUD.code in codes(facts(granted = send, requested = boot, boot = true, defaultSms = true)))
        assertFalse(RiskReason.COMBO_SMS_FRAUD.code in codes(facts(granted = send)))
        assertFalse(RiskReason.COMBO_SMS_FRAUD.code in codes(facts(requested = boot, boot = true)))
        // A boot receiver without the permission to receive BOOT_COMPLETED never fires: not a boot start.
        assertFalse(RiskReason.BOOT_RECEIVER.code in codes(facts(boot = true)))

        // Stalkerware: no launcher icon + (location or microphone) + boot start.
        assertTrue(RiskReason.COMBO_STALKERWARE.code in codes(facts(launcher = false, granted = setOf(p + "ACCESS_COARSE_LOCATION"), requested = boot, boot = true)))
        assertTrue(RiskReason.COMBO_STALKERWARE.code in codes(facts(launcher = false, granted = setOf(p + "RECORD_AUDIO"), requested = boot, boot = true)))
        assertFalse(RiskReason.COMBO_STALKERWARE.code in codes(facts(launcher = true, granted = setOf(p + "ACCESS_FINE_LOCATION"), requested = boot, boot = true)))
        assertFalse(RiskReason.COMBO_STALKERWARE.code in codes(facts(launcher = false, granted = setOf(p + "ACCESS_FINE_LOCATION"))))
        assertFalse(RiskReason.COMBO_STALKERWARE.code in codes(facts(launcher = false, requested = boot, boot = true)))
    }

    @Test
    fun aCombinationAddsItsOwnPointsToTheReasonsItCombines() {
        val f = facts(
            installer = null, granted = setOf(p + "SEND_SMS"), requested = setOf(p + "RECEIVE_BOOT_COMPLETED"), boot = true,
        )
        val expected = RiskReason.SIDELOADED.points + RiskReason.SMS_SEND.points + RiskReason.SMS_SEND.grantedBonus + RiskReason.BOOT_RECEIVER.points +
            RiskReason.COMBO_SMS_FRAUD.points + RiskReason.COMBO_SMS_FRAUD.grantedBonus
        assertEquals(expected, RiskScorer.score(f).score)
    }

    @Test
    fun systemAppsAndWatchpostAreScoredButCappedAtLow() {
        val loaded = facts(
            installer = null, granted = setOf(p + "SEND_SMS", p + "READ_SMS", p + "CALL_PHONE"), requested = setOf(p + "SYSTEM_ALERT_WINDOW", p + "RECEIVE_BOOT_COMPLETED"),
            accessibility = true, listener = true, admin = true, boot = true,
        )
        val user = RiskScorer.score(loaded)
        assertEquals(RiskLevel.HIGH, user.level)
        for (capped in listOf(loaded.copy(system = true), loaded.copy(isSelf = true))) {
            val a = RiskScorer.score(capped)
            assertEquals(RiskLevel.LOW, a.level)
            assertEquals(RiskLevel.LOW_MAX, a.score)
            // The reasons are still reported (the user sees what a system app can do).
            assertTrue(RiskReason.ACCESSIBILITY_SERVICE in a.reasons && RiskReason.COMBO_BANKING_TROJAN in a.reasons)
            // But nothing about installers, launcher icon, target SDK, debug for a preinstalled app.
            assertTrue(a.reasons.none { it in setOf(RiskReason.SIDELOADED, RiskReason.UNKNOWN_INSTALLER, RiskReason.NO_LAUNCHER_ICON) })
        }
        val system = facts(system = true, installer = null, launcher = false, target = 20, debuggable = true)
        assertEquals(emptyList<RiskReason>(), RiskScorer.score(system).reasons)
    }

    @Test
    fun scoreIsBoundedAndLevelsFollowTheThresholds() {
        val everything = facts(
            installer = null, launcher = false, granted = setOf(p + "SEND_SMS", p + "READ_SMS", p + "CALL_PHONE", p + "ACCESS_BACKGROUND_LOCATION", p + "RECORD_AUDIO"),
            requested = setOf(p + "SYSTEM_ALERT_WINDOW", p + "REQUEST_INSTALL_PACKAGES", p + "RECEIVE_BOOT_COMPLETED", p + "FOREGROUND_SERVICE_MICROPHONE"),
            accessibility = true, listener = true, admin = true, vpn = true, boot = true, target = 26, debuggable = true,
        )
        val a = RiskScorer.score(everything)
        assertEquals(100, a.score)
        // Every code, in the table's order, except the installer reason that excludes `sideloaded`.
        assertEquals(RiskReason.entries.filter { it != RiskReason.UNKNOWN_INSTALLER }, a.reasons)
        assertEquals(RiskLevel.LOW, RiskLevel.of(0))
        assertEquals(RiskLevel.LOW, RiskLevel.of(29))
        assertEquals(RiskLevel.MEDIUM, RiskLevel.of(30))
        assertEquals(RiskLevel.MEDIUM, RiskLevel.of(69))
        assertEquals(RiskLevel.HIGH, RiskLevel.of(70))
    }

    // ---- Declared capabilities versus granted ones (contract §11.4) ----

    private val smsDeclared = setOf(p + "SEND_SMS", p + "READ_SMS", p + "RECEIVE_SMS", p + "RECEIVE_BOOT_COMPLETED")

    @Test
    fun theProfileRestsOnDeclaredCapabilitiesAndGrantedOnesAreListedApart() {
        // Declared, nothing granted: the reasons and the combination are there from the installation.
        val declaredOnly = AppFacts("test.app", installer = null, requested = smsDeclared, bootReceiver = true)
        val a = RiskScorer.score(declaredOnly)
        assertEquals(listOf(RiskReason.SIDELOADED, RiskReason.SMS_SEND, RiskReason.SMS_READ, RiskReason.BOOT_RECEIVER, RiskReason.COMBO_SMS_FRAUD), a.reasons)
        assertTrue(a.granted.isEmpty())
        assertEquals(RiskLevel.HIGH, a.level) // An SMS-fraud profile is high BEFORE any grant (and stays so if a guard prevents it).
        // Same app once SEND_SMS is granted: same reasons, a little more, and the grant is told.
        val granted = RiskScorer.score(declaredOnly.copy(granted = setOf(p + "SEND_SMS")))
        assertEquals(a.reasons, granted.reasons)
        assertEquals(listOf(RiskReason.SMS_SEND, RiskReason.COMBO_SMS_FRAUD), granted.granted)
        assertEquals(a.score + RiskReason.SMS_SEND.grantedBonus + RiskReason.COMBO_SMS_FRAUD.grantedBonus, granted.score)
        // Granting READ_SMS only: sms_read is granted, the sending combination is not.
        assertEquals(listOf(RiskReason.SMS_READ), RiskScorer.score(declaredOnly.copy(granted = setOf(p + "READ_SMS"))).granted)
        // `granted` is always a subset of `reasons`; special accesses and components never appear in it.
        val all = RiskScorer.score(declaredOnly.copy(granted = smsDeclared, accessibilityService = true, requested = smsDeclared + (p + "SYSTEM_ALERT_WINDOW")))
        assertTrue(all.reasons.containsAll(all.granted))
        assertTrue(all.granted.all { it.grantable })
    }

    @Test
    fun aStoreMessengerOrBankDeclaringSmsPermissionsIsNotHigh() {
        // Declares SMS send/read, calls and microphone, holds calls and microphone but NOT the SMS permissions.
        val messenger = AppFacts(
            "test.messenger", installer = "com.android.vending",
            requested = smsDeclared + setOf(p + "CALL_PHONE", p + "READ_CALL_LOG", p + "RECORD_AUDIO", p + "CAMERA", p + "FOREGROUND_SERVICE_MICROPHONE"),
            granted = setOf(p + "CALL_PHONE", p + "READ_CALL_LOG", p + "RECORD_AUDIO", p + "CAMERA"), bootReceiver = true,
        )
        assertEquals(RiskLevel.MEDIUM, RiskScorer.score(messenger).level)
        // A bank that declares SMS reading (OTP autofill), no boot receiver.
        val bank = AppFacts("test.bank", installer = "com.android.vending", requested = setOf(p + "READ_SMS", p + "RECEIVE_SMS", p + "CAMERA"), granted = setOf(p + "CAMERA"))
        assertEquals(RiskLevel.LOW, RiskScorer.score(bank).level)
    }

    @Test
    fun installerClassification() {
        assertTrue(RiskReason.SIDELOADED in RiskScorer.score(facts(installer = null)).reasons)
        assertTrue(RiskReason.SIDELOADED in RiskScorer.score(facts(installer = "com.google.android.packageinstaller")).reasons)
        assertTrue(RiskReason.SIDELOADED in RiskScorer.score(facts(installer = "com.android.shell")).reasons)
        assertTrue(RiskReason.UNKNOWN_INSTALLER in RiskScorer.score(facts(installer = "com.example.browser")).reasons)
        for (store in listOf("com.android.vending", "com.sec.android.app.samsungapps", "org.fdroid.fdroid")) {
            assertTrue(store, RiskScorer.score(facts(installer = store)).reasons.isEmpty())
        }
    }

    @Test
    fun targetSdkBoundary() {
        assertFalse(RiskReason.OLD_TARGET_SDK in RiskScorer.score(facts(target = 30)).reasons)
        assertTrue(RiskReason.OLD_TARGET_SDK in RiskScorer.score(facts(target = 29)).reasons)
    }

    @Test
    fun micCameraNeedsBothTheAccessAndTheForegroundServiceType() {
        val fgs = setOf(p + "FOREGROUND_SERVICE_CAMERA")
        assertFalse(RiskReason.MIC_CAMERA_BACKGROUND in RiskScorer.score(facts(granted = setOf(p + "CAMERA"))).reasons)
        assertFalse(RiskReason.MIC_CAMERA_BACKGROUND in RiskScorer.score(facts(requested = fgs)).reasons) // Not granted.
        assertTrue(RiskReason.MIC_CAMERA_BACKGROUND in RiskScorer.score(facts(granted = setOf(p + "CAMERA"), requested = fgs)).reasons)
        // Before Android 14 apps had no per-type permission: a plain foreground service stands in for it.
        assertTrue(RiskReason.MIC_CAMERA_BACKGROUND in RiskScorer.score(facts(granted = setOf(p + "CAMERA"), requested = setOf(p + "FOREGROUND_SERVICE"), target = 33)).reasons)
        assertFalse(RiskReason.MIC_CAMERA_BACKGROUND in RiskScorer.score(facts(granted = setOf(p + "CAMERA"), requested = setOf(p + "FOREGROUND_SERVICE"), target = 36)).reasons)
    }

    // ---- Corpus: false positives and false negatives ----

    @Test
    fun corpusIsScoredAsRecorded() {
        val wrong = RiskCorpus.ALL.filter { RiskScorer.score(it.facts).level != it.expected }
        assertTrue(
            "the scorer no longer gives the recorded level (update the corpus, the README and the report): " +
                wrong.joinToString { "${it.id}: ${RiskScorer.score(it.facts).level}/${RiskScorer.score(it.facts).score} (recorded ${it.expected})" },
            wrong.isEmpty(),
        )
        assertEquals(RiskCorpus.ALL.size, RiskCorpus.ALL.map { it.id }.toSet().size)
    }

    @Test
    fun corpusMeasures() {
        val legit = RiskCorpus.ALL.filter { it.kind == RiskCorpus.Kind.LEGIT }
        val bad = RiskCorpus.ALL.filter { it.kind == RiskCorpus.Kind.MALICIOUS }
        fun level(p: RiskCorpus.Profile) = RiskScorer.score(p.facts).level
        val legitHigh = legit.filter { level(it) == RiskLevel.HIGH }.map { it.id }
        val legitMedium = legit.filter { level(it) == RiskLevel.MEDIUM }.map { it.id }
        val badLow = bad.filter { level(it) == RiskLevel.LOW }.map { it.id }
        val badMedium = bad.filter { level(it) == RiskLevel.MEDIUM }.map { it.id }
        println("RISK CORPUS: ${legit.size} legit, ${bad.size} malicious")
        println("  legit high (false alarms): $legitHigh")
        println("  legit medium (noise): $legitMedium")
        println("  malicious low (missed): $badLow")
        println("  malicious medium (under-rated): $badMedium")
        RiskCorpus.ALL.forEach { println("  %-34s %-9s %3d %-6s %s".format(it.id, it.kind, RiskScorer.score(it.facts).score, level(it), RiskScorer.score(it.facts).reasonCodes)) }
        // What the user relies on: the four families the contract targets are all at least "medium", and the
        // three canonical ones (banking trojan, SMS fraud, full spyware) are "high".
        assertEquals(listOf("payload_installer_store"), badLow)
        assertTrue(listOf("banking_trojan", "sms_fraud", "sms_fraud_before_grant", "spyware_no_icon", "minimal_spyware", "spyware_before_grant").all { id -> level(bad.first { it.id == id }) == RiskLevel.HIGH })
        assertEquals(setOf("caller_id", "parental_control", "antivirus", "automation"), legitHigh.toSet())
        // A store messenger that declares SMS rights without holding them is noisy (medium) but never a false alarm.
        assertEquals(RiskLevel.MEDIUM, level(legit.first { it.id == "messenger_declares_sms" }))
        // No ordinary app (messaging, bank, keyboard, browser, launcher, VPN, dialer, authenticator, files) is above "low".
        val ordinary = setOf("encrypted_messenger", "bank", "third_party_keyboard", "browser", "launcher", "vpn", "third_party_dialer", "authenticator", "file_manager", "offline_navigation", "old_bank", "bank_declares_sms")
        assertTrue(legit.filter { it.id in ordinary }.all { level(it) == RiskLevel.LOW })
    }

    // ---- Documentation kept in step with the code ----

    /** Gradle runs the unit tests of a module with the module directory as working directory. */
    private fun moduleFile(path: String): File = File(path).also { check(it.exists()) { "${it.absolutePath} not found" } }

    @Test
    fun everyCodeHasAFrenchLabelAndExplanationInTheResources() {
        val xml = moduleFile("src/main/res/values/strings_risk.xml").readText()
        for (r in RiskReason.entries) {
            val label = Regex("<string name=\"risk_reason_${r.code}\">([^<]+)</string>").find(xml)?.groupValues?.get(1)
            val desc = Regex("<string name=\"risk_reason_${r.code}_desc\">([^<]+)</string>").find(xml)?.groupValues?.get(1)
            assertTrue("label of ${r.code}", !label.isNullOrBlank())
            assertTrue("explanation of ${r.code}", !desc.isNullOrBlank() && desc!!.length > 40)
        }
        // The resource ids of the enum exist (compile-time) and are distinct.
        assertEquals(RiskReason.entries.size * 2, RiskReason.entries.flatMap { listOf(it.labelRes, it.descRes) }.toSet().size)
    }

    @Test
    fun readmeTableAgreesWithTheCode() {
        val text = moduleFile("../README.md").readText()
        for (r in RiskReason.entries) {
            val row = Regex("\\|\\s*`${r.code}`\\s*\\|\\s*(\\d+)\\s*\\|\\s*\\+?(\\d+)\\s*\\|").find(text)
            assertTrue("README row of ${r.code} (| `${r.code}` | ${r.points} | +${r.grantedBonus} | …)", row != null)
            assertEquals("declared points of ${r.code} in the README", r.points, row!!.groupValues[1].toInt())
            assertEquals("granted bonus of ${r.code} in the README", r.grantedBonus, row.groupValues[2].toInt())
        }
    }
}
