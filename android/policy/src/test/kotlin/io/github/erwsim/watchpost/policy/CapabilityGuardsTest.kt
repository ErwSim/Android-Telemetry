package io.github.erwsim.watchpost.policy

import io.github.erwsim.watchpost.core.sink.EventSink
import io.github.erwsim.watchpost.core.testing.Contract
import io.github.erwsim.watchpost.core.testing.FakeClock
import io.github.erwsim.watchpost.core.testing.MemoryPrefs
import io.github.erwsim.watchpost.policy.dns.ProbeResult
import io.github.erwsim.watchpost.policy.engine.DevicePolicyGateway
import io.github.erwsim.watchpost.policy.engine.DeviceRoles
import io.github.erwsim.watchpost.policy.engine.Dpm
import io.github.erwsim.watchpost.policy.engine.GuardKey
import io.github.erwsim.watchpost.policy.engine.GuardNotice
import io.github.erwsim.watchpost.policy.engine.GuardPermissions
import io.github.erwsim.watchpost.policy.engine.PolicyCatalog
import io.github.erwsim.watchpost.policy.engine.PolicyEngine
import io.github.erwsim.watchpost.policy.engine.PolicySelection
import io.github.erwsim.watchpost.policy.engine.PolicyStore
import io.github.erwsim.watchpost.policy.engine.Profile
import io.github.erwsim.watchpost.policy.engine.ServiceApp
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * Contract §11.1: the five guards against the fake `DevicePolicyManager`, their hard limits, new
 * installs and updates, role changes, partial failures, and "Restore everything" / crash / unreadable state.
 */
class CapabilityGuardsTest {
    private val sendSms = "android.permission.SEND_SMS"
    private val readSms = "android.permission.READ_SMS"
    private val receiveSms = "android.permission.RECEIVE_SMS"
    private val callPhone = "android.permission.CALL_PHONE"
    private val readCallLog = "android.permission.READ_CALL_LOG"
    private val contacts = "android.permission.READ_CONTACTS"
    private val camera = "android.permission.CAMERA"
    private val mic = "android.permission.RECORD_AUDIO"
    private val fine = "android.permission.ACCESS_FINE_LOCATION"

    // Third-party apps.
    private val malware = "com.evil.sms"
    private val signal = "org.thoughtcrime.securesms"
    private val game = "com.example.game"
    private val bank = "fr.example.bank"
    private val otherDialer = "com.example.dialer"
    private val companion = "io.github.erwsim.watchpost.notifier"
    private val watchpost = "io.github.erwsim.watchpost"

    // System apps.
    private val samsungMessages = "com.samsung.android.messaging"
    private val sos = "com.samsung.android.emergency.sos"
    private val samsungDialer = "com.samsung.android.dialer"
    private val honeyboard = "com.samsung.android.honeyboard"
    private val talkback = "com.samsung.android.accessibility.talkback"

    private val catalogJson = """
    {
      "version": 1, "updated": "2026-11-16", "source": "test",
      "permissions": [
        { "package": "$bank", "label": "Bank", "permissions": ["$camera"], "risk": "low", "effect": "e", "profile": "balanced" }
      ]
    }
    """.trimIndent()

    private lateinit var gw: FakeGateway
    private lateinit var prefs: MemoryPrefs
    private val clock = FakeClock(now = 10_000L)
    private val events = ArrayList<JsonObject>()
    private val notices = ArrayList<GuardNotice>()
    private val followed = ArrayList<Pair<GuardKey, String>>()
    private val sink = object : EventSink {
        override fun emit(type: String, sev: Int, data: JsonObject, originTsMs: Long?) {
            assertEquals("security.policy", type)
            Contract.check(type, data)
            events += data
        }
    }

    private fun engine(gateway: DevicePolicyGateway = gw) = PolicyEngine(
        gateway = gateway,
        store = PolicyStore(prefs),
        catalog = PolicyCatalog.parse(catalogJson),
        probe = { _, _ -> ProbeResult(true, listOf("203.0.113.5")) },
        clock = clock,
        sink = { sink },
        dnsHost = { null },
        onGuardNotice = { notices += it },
        onGuardListFollow = { k, p -> followed += k to p },
    )

    private fun JsonObject.str(k: String) = (this[k] as? JsonPrimitive)?.content
    private fun eventsOf(action: String) = events.filter { it.str("action") == action }
    private fun state(pkg: String, p: String) = gw.permissionGrantState(pkg, p)

    @Before
    fun setUp() {
        gw = FakeGateway()
        prefs = MemoryPrefs()
        gw.clockMs = 5_000L // everything below was installed before any guard was switched on (clock = 10 000)
        gw.install(malware, sendSms, readSms, receiveSms, contacts)
        gw.install(signal, sendSms, readSms, receiveSms)
        gw.install(game, camera)
        gw.install(bank, camera, callPhone)
        gw.install(otherDialer, callPhone, readCallLog)
        gw.install(companion, sendSms) // hypothetical: the companion is never touched
        gw.install(watchpost, sendSms, fine)
        listOf(samsungMessages, sos, samsungDialer, honeyboard, talkback).forEach { gw.install(it, sendSms, callPhone); gw.system += it }
        gw.roles = DeviceRoles(sms = samsungMessages, dialer = samsungDialer, systemDialer = samsungDialer, ime = honeyboard, home = "com.sec.android.app.launcher")
        // The malware was granted SEND_SMS by the user; Signal reads SMS.
        gw.granted += malware to sendSms
        gw.granted += signal to readSms
        gw.accessibility[talkback] = ServiceApp(talkback, system = true, enabled = true)
        gw.accessibility["com.agilebits.onepassword"] = ServiceApp("com.agilebits.onepassword", system = false, enabled = true)
        gw.accessibility[malware] = ServiceApp(malware, system = false, enabled = false)
        gw.imes[honeyboard] = ServiceApp(honeyboard, system = true, enabled = true)
        gw.imes["com.google.android.inputmethod.latin"] = ServiceApp("com.google.android.inputmethod.latin", system = false, enabled = false)
        gw.imes["org.futo.inputmethod.latin"] = ServiceApp("org.futo.inputmethod.latin", system = false, enabled = true)
        gw.clockMs = 20_000L // later installs happen after the activations below
    }

    // ---------------------------------------------------------------- sms / calls

    @Test
    fun `sms guard denies SEND_SMS to every third-party app that requests it, also when already granted`() {
        val e = engine()
        val preview = e.guards.preview(GuardKey.SMS, enable = true, allowed = setOf(signal))
        assertEquals(listOf(malware), preview.lines.map { it.pkg })
        assertEquals(listOf(sendSms), preview.lines.single().deny)
        assertTrue("the preview says it was granted", preview.lines.single().note!!.contains("SEND_SMS"))
        val exempt = preview.exempt.toMap()
        assertEquals("chosen list", exempt[signal])
        assertEquals("system app", exempt[samsungMessages])
        assertEquals("system app", exempt[sos])
        assertEquals("Watchpost or its companion", exempt[companion])
        assertEquals("Watchpost or its companion", exempt[watchpost])

        assertTrue(e.guards.set(GuardKey.SMS, true, allowed = setOf(signal)).allOk)
        assertEquals(Dpm.GRANT_DENIED, state(malware, sendSms))
        assertFalse(gw.isPermissionGranted(malware, sendSms))
        // Never touched: the list, system apps (SOS sends SMS), the default SMS app, Watchpost and its companion.
        for (pkg in listOf(signal, samsungMessages, sos, companion, watchpost)) {
            assertFalse(pkg, gw.calls.any { it.startsWith("perm $pkg ") })
        }
        // Reading SMS is the option only.
        assertEquals(Dpm.GRANT_DEFAULT, state(malware, readSms))
        val denied = eventsOf("permission_denied").single()
        assertEquals(malware, denied.str("target"))
        assertEquals(sendSms, denied.str("permission"))
        assertEquals("guard:sms", denied.str("profile"))
        assertEquals("sms", eventsOf("guard_enabled").single().str("target"))
    }

    @Test
    fun `the extended option denies reading and receiving too, and is undone when switched off again`() {
        val e = engine()
        e.guards.set(GuardKey.SMS, true, extended = true)
        assertEquals(Dpm.GRANT_DENIED, state(malware, readSms))
        assertEquals(Dpm.GRANT_DENIED, state(signal, readSms))
        assertFalse(gw.isPermissionGranted(signal, readSms))
        // Re-applied without the option and with Signal in the list: Signal gets everything back as it was.
        val preview = e.guards.preview(GuardKey.SMS, true, extended = false, allowed = setOf(signal))
        assertEquals(listOf(readSms, receiveSms), preview.lines.single { it.pkg == malware }.restore)
        e.guards.set(GuardKey.SMS, true, extended = false, allowed = setOf(signal))
        assertEquals(Dpm.GRANT_DENIED, state(malware, sendSms))
        assertEquals(Dpm.GRANT_DEFAULT, state(malware, readSms))
        assertEquals(Dpm.GRANT_DEFAULT, state(signal, readSms))
        assertTrue("granted again, under the user's control", gw.isPermissionGranted(signal, readSms))
        assertNull(e.record(GuardKey.SMS.packageRecordId(signal)))
    }

    @Test
    fun `an app installed later, or updated to request SEND_SMS, is denied at the next reconciliation`() {
        val e = engine()
        e.guards.set(GuardKey.SMS, true)
        gw.install("com.new.dropper", sendSms)
        gw.install(game, sendSms) // update of an existing app that adds the permission
        e.guards.reconcile()
        assertEquals(Dpm.GRANT_DENIED, state("com.new.dropper", sendSms))
        assertEquals(Dpm.GRANT_DENIED, state(game, sendSms))
        // Steady state: nothing more is done.
        gw.calls.clear()
        e.guards.reconcile()
        assertTrue(gw.calls.none { it.startsWith("perm ") })
    }

    @Test
    fun `a new default SMS app gets its permission back, the list follows and the user is told`() {
        val e = engine()
        e.guards.set(GuardKey.SMS, true, allowed = setOf(samsungMessages))
        assertEquals(Dpm.GRANT_DENIED, state(signal, sendSms))
        gw.roles = gw.roles.copy(sms = signal)
        e.guards.reconcile()
        assertEquals(Dpm.GRANT_DEFAULT, state(signal, sendSms))
        // Android's role grant stopped at the permission fixed by policy: the guard grants it when it lifts the denial.
        assertTrue(gw.isPermissionGranted(signal, sendSms))
        assertEquals("permission_granted", events.last { it.str("target") == signal }.str("action"))
        assertTrue(signal in e.guards.status().getValue(GuardKey.SMS).allowed)
        assertEquals(listOf(GuardKey.SMS to signal), followed)
        val notice = notices.single() as GuardNotice.RoleHolder
        assertEquals(listOf(sendSms), notice.lifted)
        assertTrue(notice.joined)
        // The role moves back: Signal stays in the list (the user removes it if they want).
        gw.roles = gw.roles.copy(sms = samsungMessages)
        e.guards.reconcile()
        assertEquals(Dpm.GRANT_DEFAULT, state(signal, sendSms))
    }

    @Test
    fun `calls guard spares the default dialer and the system, option covers the call log`() {
        val e = engine()
        e.guards.set(GuardKey.CALLS, true, extended = true)
        assertEquals(Dpm.GRANT_DENIED, state(bank, callPhone))
        assertEquals(Dpm.GRANT_DENIED, state(otherDialer, readCallLog))
        assertFalse(gw.calls.any { it.startsWith("perm $samsungDialer") || it.startsWith("perm $sos") })
        // The user makes the third-party dialer the default one.
        gw.roles = gw.roles.copy(dialer = otherDialer)
        e.guards.reconcile()
        assertEquals(Dpm.GRANT_DEFAULT, state(otherDialer, callPhone))
        assertEquals(Dpm.GRANT_DEFAULT, state(otherDialer, readCallLog))
    }

    @Test
    fun `a package that fails is reported, the others go on, and it is not retried at every reconciliation`() {
        gw.failPermission += "$malware/$sendSms"
        gw.install("com.second.app", sendSms)
        val e = engine()
        val report = e.guards.set(GuardKey.SMS, true)
        assertFalse(report.allOk)
        assertEquals(Dpm.GRANT_DENIED, state("com.second.app", sendSms))
        assertTrue(e.guards.isActive(GuardKey.SMS))
        val failures = eventsOf("permission_denied").filter { it.str("ok") == "false" }
        assertEquals(malware, failures.single().str("target"))
        events.clear()
        e.guards.reconcile()
        assertTrue("no event storm", events.isEmpty())
        // Switching the guard on again retries.
        gw.failPermission.clear()
        assertTrue(e.guards.set(GuardKey.SMS, true).allOk)
        assertEquals(Dpm.GRANT_DENIED, state(malware, sendSms))
    }

    // ---------------------------------------------------------------- hard limits

    @Test
    fun `no list can make a guard touch the SMS app, the dialer, the system, Watchpost or its companion, but keyboard and home are not spared`() {
        val e = engine()
        // A hostile or careless list: empty, so nothing is exempt by choice.
        e.guards.set(GuardKey.SMS, true, extended = true, allowed = emptySet())
        e.guards.set(GuardKey.CALLS, true, extended = true, allowed = emptySet())
        gw.clockMs = 30_000
        e.guards.set(GuardKey.QUARANTINE, true)
        // The keyboard in use and the default launcher are third-party, installed after the quarantine.
        gw.install("com.third.keyboard", mic, sendSms)
        gw.install("com.third.launcher", contacts, callPhone)
        gw.roles = gw.roles.copy(ime = "com.third.keyboard", home = "com.third.launcher")
        e.guards.reconcile()
        for (pkg in listOf(samsungMessages, samsungDialer, sos, honeyboard, watchpost, companion)) {
            assertFalse(pkg, gw.calls.any { it.startsWith("perm $pkg ") })
            assertNull(pkg, e.record(GuardKey.QUARANTINE.packageRecordId(pkg)))
        }
        // Contract §11.4: a keyboard or a home screen is not spared by sms, calls or quarantine.
        assertEquals(Dpm.GRANT_DENIED, state("com.third.keyboard", sendSms))
        assertEquals(Dpm.GRANT_DENIED, state("com.third.keyboard", mic))
        assertEquals(Dpm.GRANT_DENIED, state("com.third.launcher", callPhone))
        assertEquals(Dpm.GRANT_DENIED, state("com.third.launcher", contacts))
        assertNotNull(e.record(GuardKey.QUARANTINE.packageRecordId("com.third.keyboard")))
        assertNotNull(e.record(GuardKey.QUARANTINE.packageRecordId("com.third.launcher")))
        // An app that merely declares a HOME activity, or becomes a device admin, is not protected for that.
        gw.dynamicProtected += malware
        e.guards.reconcile()
        assertEquals(Dpm.GRANT_DENIED, state(malware, sendSms))
    }

    @Test
    fun `accessibility guard keeps the enabled services Android requires, system services stay allowed, undo lifts it`() {
        val e = engine()
        val preview = e.guards.preview(GuardKey.ACCESSIBILITY, true, allowed = emptySet())
        assertEquals(listOf("com.agilebits.onepassword"), preview.kept)
        assertEquals(listOf(malware), preview.blocked)
        assertEquals(listOf("com.agilebits.onepassword"), preview.permitted)
        assertTrue(e.guards.set(GuardKey.ACCESSIBILITY, true, allowed = emptySet()).allOk)
        assertEquals(listOf("com.agilebits.onepassword"), gw.permittedAccessibility)
        assertFalse(talkback in gw.permittedAccessibility!!) // system: allowed by Android anyway, never listed
        assertTrue(e.guards.set(GuardKey.ACCESSIBILITY, false).allOk)
        assertNull(gw.permittedAccessibility)
        assertEquals(listOf("accessibility", "accessibility"), (eventsOf("guard_enabled") + eventsOf("guard_disabled")).map { it.str("target") })
    }

    @Test
    fun `keyboards guard keeps the keyboard in use, refused by Android is reported and leaves nothing behind`() {
        val e = engine()
        assertTrue(e.guards.set(GuardKey.INPUT_METHODS, true, allowed = setOf("com.google.android.inputmethod.latin")).allOk)
        assertEquals(listOf("com.google.android.inputmethod.latin", "org.futo.inputmethod.latin"), gw.permittedImes)
        e.guards.set(GuardKey.INPUT_METHODS, false)
        assertNull(gw.permittedImes)
        // Android refuses (here: forced): nothing recorded, nothing changed.
        gw.enforceEnabledInList = false
        val refusing = object : DevicePolicyGateway by gw {
            override fun setPermittedInputMethods(packages: List<String>?) = false
        }
        val r = engine(refusing).guards.set(GuardKey.INPUT_METHODS, true)
        assertFalse(r.allOk)
        assertNull(engine().record(GuardKey.INPUT_METHODS.recordId))
    }

    // ---------------------------------------------------------------- quarantine

    @Test
    fun `quarantine leaves present apps alone, quarantines new ones with a notice, release gives them back`() {
        val e = engine()
        assertTrue(e.guards.preview(GuardKey.QUARANTINE, true).lines.isEmpty())
        e.guards.set(GuardKey.QUARANTINE, true)
        assertTrue(gw.calls.none { it.startsWith("perm ") })
        gw.install("com.new.app", sendSms, contacts, camera, fine)
        gw.install("com.new.quiet") // asks for nothing risky
        e.guards.reconcile()
        for (p in listOf(sendSms, contacts, camera)) assertEquals(p, Dpm.GRANT_DENIED, state("com.new.app", p))
        assertEquals("not in the risky set", Dpm.GRANT_DEFAULT, state("com.new.app", fine))
        assertEquals(setOf("com.new.app", "com.new.quiet"), e.guards.quarantined().map { it.target }.toSet())
        assertEquals(2, notices.count { it is GuardNotice.Quarantined })
        assertEquals(setOf("com.new.app", "com.new.quiet"), eventsOf("quarantined").map { it.str("target") }.toSet())
        // An update of a quarantined app that asks for the microphone: denied too.
        gw.install("com.new.quiet", mic)
        e.guards.reconcile()
        assertEquals(Dpm.GRANT_DENIED, state("com.new.quiet", mic))
        // Release: back to "ask the user".
        assertTrue(e.guards.release("com.new.app").allOk)
        for (p in listOf(sendSms, contacts, camera)) assertEquals(Dpm.GRANT_DEFAULT, state("com.new.app", p))
        assertEquals("released", eventsOf("released").single().str("action"))
        // An update of a released app does not put it back in quarantine.
        gw.install("com.new.app", mic)
        e.guards.reconcile()
        assertNull(e.record(GuardKey.QUARANTINE.packageRecordId("com.new.app")))
        // Uninstalled then installed again: a new install, quarantined again.
        gw.uninstall("com.new.app")
        e.guards.reconcile()
        gw.clockMs = 40_000
        gw.install("com.new.app", sendSms)
        e.guards.reconcile()
        assertNotNull(e.record(GuardKey.QUARANTINE.packageRecordId("com.new.app")))
    }

    @Test
    fun `a quarantined app chosen as default SMS app gets only the SMS role back, stays in quarantine, and the user is told`() {
        val e = engine()
        e.guards.set(GuardKey.QUARANTINE, true)
        gw.install("com.sms.client", sendSms, readSms, receiveSms, contacts, mic)
        e.guards.reconcile()
        notices.clear()
        // One system dialog: exactly the path of SMS trojans.
        gw.roles = gw.roles.copy(sms = "com.sms.client")
        e.guards.reconcile()
        val record = e.record(GuardKey.QUARANTINE.packageRecordId("com.sms.client"))
        assertNotNull("still in quarantine", record)
        for (p in listOf(sendSms, readSms, receiveSms)) {
            assertEquals(p, Dpm.GRANT_DEFAULT, state("com.sms.client", p))
            assertTrue("granted as the role would have done: $p", gw.isPermissionGranted("com.sms.client", p))
        }
        assertEquals(Dpm.GRANT_DENIED, state("com.sms.client", contacts))
        assertEquals(Dpm.GRANT_DENIED, state("com.sms.client", mic))
        val notice = notices.single() as GuardNotice.RoleHolder
        assertEquals(GuardKey.QUARANTINE, notice.key)
        assertEquals("default SMS app", notice.role)
        assertEquals(setOf(sendSms, readSms, receiveSms), notice.lifted.toSet())
        // Steady state: no new notice.
        e.guards.reconcile()
        assertEquals(1, notices.size)
        // The user puts Samsung Messages back: the SMS permissions are denied again (still quarantined).
        gw.roles = gw.roles.copy(sms = samsungMessages)
        e.guards.reconcile()
        assertEquals(Dpm.GRANT_DENIED, state("com.sms.client", sendSms))
        // "Release", then "Restore everything": nothing left.
        assertTrue(e.guards.release("com.sms.client").allOk)
        assertEquals(Dpm.GRANT_DEFAULT, state("com.sms.client", contacts))
        assertTrue(engine().revertAll().allOk)
    }

    @Test
    fun `two guards denying the same permission, the last one undone restores it`() {
        val e = engine()
        e.guards.set(GuardKey.QUARANTINE, true)
        gw.install("com.new.sender", sendSms)
        gw.granted += "com.new.sender" to sendSms // e.g. installed with "adb install -g"
        e.guards.reconcile() // quarantine denies SEND_SMS
        e.guards.set(GuardKey.SMS, true) // shares it
        e.guards.set(GuardKey.QUARANTINE, false) // releases: SEND_SMS stays denied, the SMS guard holds it
        assertEquals(Dpm.GRANT_DENIED, state("com.new.sender", sendSms))
        e.guards.set(GuardKey.SMS, false)
        assertEquals(Dpm.GRANT_DEFAULT, state("com.new.sender", sendSms))
        assertTrue("exactly as before both guards", gw.isPermissionGranted("com.new.sender", sendSms))
    }

    // ---------------------------------------------------------------- undo everything

    @Test
    fun `Restore everything restores the exact initial state after every combination of guards`() {
        for (mask in 0 until (1 shl GuardKey.entries.size)) {
            setUp()
            events.clear()
            val initial = gw.snapshot()
            val e = engine()
            // A catalog item too, on an app that a guard also covers.
            e.apply(PolicySelection(Profile.BALANCED, mapOf("dns" to false, "backup" to false)))
            val keys = GuardKey.entries.filter { mask and (1 shl it.ordinal) != 0 }
            for (k in keys) assertTrue("$mask $k", e.guards.set(k, true, extended = true, allowed = emptySet()).allOk)
            // Activity afterwards: an install (quarantined), an update, a role change.
            gw.install("com.later.app", sendSms, callPhone, camera)
            gw.install(game, sendSms)
            gw.roles = gw.roles.copy(sms = signal)
            e.guards.reconcile()
            val initialWithInstalls = initial.copy()
            val report = engine().revertAll()
            assertTrue("$mask ${report.failed}", report.allOk)
            assertTrue("$mask", engine().state().records.isEmpty())
            val after = gw.snapshot()
            assertEquals("$mask", initialWithInstalls.grantState, after.grantState.filterKeys { it.first != "com.later.app" })
            assertTrue("$mask", after.grantState.keys.none { it.first == "com.later.app" })
            // Signal became the default SMS app while the SMS guard denied it: what Android's role grants and
            // the denial made it skip was granted by the guard when it lifted the denial (kept, like a role grant).
            val roleGrants = if (GuardKey.SMS in keys) setOf(signal to sendSms, signal to receiveSms) else emptySet()
            assertEquals("$mask", initial.granted + roleGrants, after.granted)
            assertEquals("$mask", initial.permittedAccessibility, after.permittedAccessibility)
            assertEquals("$mask", initial.permittedImes, after.permittedImes)
            for (k in keys) assertFalse(engine().guards.isActive(k))
        }
    }

    /** The process dies (not an exception the engine catches) right after the Nth change of the device. */
    private class ProcessDeath : Error("process killed")

    private inner class DyingGateway(var dieAfter: Int) : DevicePolicyGateway by gw {
        private fun tick() {
            if (--dieAfter == 0) throw ProcessDeath()
        }

        override fun setPermissionGrantState(pkg: String, permission: String, state: Int): Boolean = gw.setPermissionGrantState(pkg, permission, state).also { tick() }
        override fun setPermittedAccessibilityServices(packages: List<String>?) = gw.setPermittedAccessibilityServices(packages).also { tick() }
        override fun setPermittedInputMethods(packages: List<String>?) = gw.setPermittedInputMethods(packages).also { tick() }
    }

    @Test
    fun `a crash between persistence and application leaves nothing that Restore everything cannot undo`() {
        for (dieAfter in 1..8) {
            setUp()
            gw.install("com.second.sender", sendSms)
            gw.granted += "com.second.sender" to sendSms
            val initial = gw.snapshot()
            val dying = DyingGateway(dieAfter)
            val e = engine(dying)
            try {
                e.guards.set(GuardKey.ACCESSIBILITY, true)
                e.guards.set(GuardKey.SMS, true, extended = true)
                e.guards.set(GuardKey.INPUT_METHODS, true)
            } catch (_: ProcessDeath) {
                // The app restarts with what is on disk.
            }
            val report = engine().revertAll()
            assertTrue("$dieAfter ${report.failed}", report.allOk)
            assertEquals("$dieAfter", initial, gw.snapshot())
            assertTrue("$dieAfter", engine().state().records.isEmpty())
        }
    }

    @Test
    fun `a crash in the middle of Restore everything does not let a guard deny again what was restored`() {
        val e = engine()
        e.guards.set(GuardKey.SMS, true)
        e.guards.set(GuardKey.QUARANTINE, true)
        gw.install("com.new.app", sendSms)
        e.guards.reconcile()
        val dying = DyingGateway(1)
        try {
            engine(dying).revertAll()
        } catch (_: ProcessDeath) {
        }
        // Both guard records were removed before their package records were undone.
        val after = engine()
        assertFalse(after.guards.isActive(GuardKey.SMS))
        assertFalse(after.guards.isActive(GuardKey.QUARANTINE))
        gw.install("com.other.new", sendSms)
        after.guards.reconcile()
        assertEquals(Dpm.GRANT_DEFAULT, state("com.other.new", sendSms))
        val retry = after.revertAll()
        assertTrue(retry.failed.toString(), retry.allOk)
        assertEquals(Dpm.GRANT_DEFAULT, state(malware, sendSms))
        assertTrue(gw.isPermissionGranted(malware, sendSms))
    }

    @Test
    fun `with an unreadable state, Restore everything still lifts every guard`() {
        val e = engine()
        e.guards.set(GuardKey.SMS, true, extended = true)
        e.guards.set(GuardKey.ACCESSIBILITY, true)
        e.guards.set(GuardKey.INPUT_METHODS, true)
        prefs.edit().putString("applied_state", "{ broken").commit()
        val fresh = engine()
        assertTrue(fresh.state().records.isEmpty())
        assertTrue(fresh.stateWasUnreadable())
        val report = fresh.revertAll()
        assertTrue(report.failed.toString(), report.allOk)
        for (p in listOf(sendSms, readSms, receiveSms)) {
            assertEquals(Dpm.GRANT_DEFAULT, state(malware, p))
            assertEquals(Dpm.GRANT_DEFAULT, state(signal, p))
        }
        assertNull(gw.permittedAccessibility)
        assertNull(gw.permittedImes)
        // Granted state is not known any more: back under the user's control, not granted again.
        assertFalse(gw.isPermissionGranted(malware, sendSms))
    }

    @Test
    fun `removing the Device Owner undoes the guards first`() {
        val e = engine()
        e.guards.set(GuardKey.SMS, true)
        e.guards.set(GuardKey.ACCESSIBILITY, true)
        assertTrue(e.removeDeviceOwner(force = false).allOk)
        assertFalse(gw.owner)
        assertEquals(Dpm.GRANT_DEFAULT, state(malware, sendSms))
        assertNull(gw.permittedAccessibility)
    }

    @Test
    fun `guards are refused without Device Owner and the catalog selection never touches guard records`() {
        gw.owner = false
        assertFalse(engine().guards.set(GuardKey.SMS, true).allOk)
        gw.owner = true
        val e = engine()
        e.guards.set(GuardKey.SMS, true)
        val plan = e.preview(PolicySelection(Profile.BALANCED, mapOf("dns" to false, "backup" to false)))
        assertTrue(plan.none { it.id.startsWith("guard:") })
        e.apply(PolicySelection(Profile.BALANCED, mapOf("dns" to false, "backup" to false)))
        assertEquals(Dpm.GRANT_DENIED, state(malware, sendSms))
        assertTrue(GuardPermissions.ALL.containsAll(GuardPermissions.of(GuardKey.SMS, true) + GuardPermissions.of(GuardKey.CALLS, true)))
    }

    // ---------------------------------------------------------------- crash, then life goes on

    @Test
    fun `a crash while denying, then a re-application, leaves nothing that switching the guard off cannot undo`() {
        for (dieAfter in 1..8) {
            setUp()
            gw.install("com.second.sender", sendSms, readSms)
            gw.granted += "com.second.sender" to sendSms
            val initial = gw.snapshot()
            try {
                engine(DyingGateway(dieAfter)).guards.set(GuardKey.SMS, true, extended = true)
            } catch (_: ProcessDeath) {
                // The app restarts with what is on disk.
            }
            // Restart: reconciliation at agent start, then the user presses "Preview and re-apply", then switches off.
            val e = engine()
            e.guards.reconcile()
            assertTrue("$dieAfter", e.guards.set(GuardKey.SMS, true, extended = true).allOk)
            val off = e.guards.set(GuardKey.SMS, false)
            assertTrue("$dieAfter ${off.failed}", off.allOk)
            assertEquals("$dieAfter", initial, gw.snapshot())
            assertTrue("$dieAfter", engine().state().records.isEmpty())
        }
    }

    @Test
    fun `a guard interrupted by a crash is completed at the next reconciliation`() {
        for (dieAfter in 1..6) {
            setUp()
            gw.install("com.second.sender", sendSms, readSms)
            try {
                engine(DyingGateway(dieAfter)).guards.set(GuardKey.SMS, true, extended = true)
            } catch (_: ProcessDeath) {
            }
            val e = engine()
            e.guards.reconcile()
            for ((pkg, perms) in mapOf(malware to listOf(sendSms, readSms, receiveSms), signal to listOf(sendSms, readSms, receiveSms), "com.second.sender" to listOf(sendSms, readSms))) {
                for (p in perms) assertEquals("$dieAfter $pkg $p", Dpm.GRANT_DENIED, state(pkg, p))
            }
            assertFalse("$dieAfter", e.guards.status().getValue(GuardKey.SMS).pending)
        }
    }

    @Test
    fun `a quarantine interrupted by a crash denies the rest at the next reconciliation and release gives everything back`() {
        for (dieAfter in 1..3) {
            setUp()
            val e0 = engine()
            e0.guards.set(GuardKey.QUARANTINE, true)
            gw.install("com.new.app", sendSms, callPhone, contacts, mic)
            val initial = gw.snapshot()
            try {
                engine(DyingGateway(dieAfter)).guards.reconcile()
            } catch (_: ProcessDeath) {
            }
            val e = engine()
            e.guards.reconcile()
            for (p in listOf(sendSms, callPhone, contacts, mic)) assertEquals("$dieAfter $p", Dpm.GRANT_DENIED, state("com.new.app", p))
            assertTrue(e.guards.release("com.new.app").allOk)
            assertEquals("$dieAfter", initial, gw.snapshot())
        }
    }

    @Test
    fun `a home screen or a keyboard is not spared by the SMS guard and never joins its list`() {
        val launcher = "com.evil.launcher"
        gw.install(launcher, sendSms)
        val e = engine()
        e.guards.set(GuardKey.SMS, true, allowed = setOf(samsungMessages))
        assertEquals(Dpm.GRANT_DENIED, state(launcher, sendSms))
        // One tap on "always" in the home chooser, and the same app as keyboard: contract §11.4, not spared.
        gw.roles = gw.roles.copy(home = launcher, ime = launcher)
        e.guards.reconcile()
        assertEquals(Dpm.GRANT_DENIED, state(launcher, sendSms))
        assertFalse(launcher in e.guards.status().getValue(GuardKey.SMS).allowed)
        assertTrue(followed.isEmpty())
        assertTrue(notices.isEmpty())
        assertEquals(launcher to "chosen list", e.guards.preview(GuardKey.SMS, true, allowed = setOf(launcher)).exempt.first { it.first == launcher })
        assertTrue(e.guards.preview(GuardKey.SMS, true, allowed = setOf(samsungMessages)).exempt.none { it.first == launcher })
        assertTrue(e.guards.set(GuardKey.SMS, false).allOk)
        assertEquals(Dpm.GRANT_DEFAULT, state(launcher, sendSms))
    }

    @Test
    fun `an app uninstalled and reinstalled between two passes is denied again, and quarantined again`() {
        val e = engine()
        e.guards.set(GuardKey.SMS, true)
        e.guards.set(GuardKey.QUARANTINE, true)
        gw.install("com.new.app", sendSms, contacts)
        e.guards.reconcile()
        assertEquals(Dpm.GRANT_DENIED, state(malware, sendSms))
        assertEquals(Dpm.GRANT_DENIED, state("com.new.app", contacts))
        // Both are removed and installed again while the process is not running: the system forgets the policy state.
        for (pkg in listOf(malware, "com.new.app")) {
            val perms = gw.requested.getValue(pkg).toTypedArray()
            gw.uninstall(pkg)
            gw.clockMs = 30_000L
            gw.install(pkg, *perms)
        }
        assertEquals(Dpm.GRANT_DEFAULT, state(malware, sendSms))
        engine().guards.reconcile()
        assertEquals(Dpm.GRANT_DENIED, state(malware, sendSms))
        assertEquals(Dpm.GRANT_DENIED, state("com.new.app", sendSms))
        assertEquals(Dpm.GRANT_DENIED, state("com.new.app", contacts))
        // And the undo gives back the state of the reinstalled apps (nothing granted, nothing locked).
        assertTrue(engine().revertAll().allOk)
        assertEquals(Dpm.GRANT_DEFAULT, state(malware, sendSms))
        assertFalse(gw.isPermissionGranted(malware, sendSms))
        assertTrue(engine().state().records.isEmpty())
    }

    @Test
    fun `a quarantined app chosen as default dialer gets the permissions of the role, the rest stays in quarantine`() {
        val e = engine()
        e.guards.set(GuardKey.QUARANTINE, true)
        gw.install("com.new.dialer", callPhone, readCallLog, camera)
        e.guards.reconcile()
        assertEquals(Dpm.GRANT_DENIED, state("com.new.dialer", callPhone))
        gw.roles = gw.roles.copy(dialer = "com.new.dialer")
        e.guards.reconcile()
        assertEquals(listOf("com.new.dialer"), e.guards.quarantined().map { it.target })
        assertTrue(gw.isPermissionGranted("com.new.dialer", callPhone))
        assertTrue(gw.isPermissionGranted("com.new.dialer", readCallLog))
        assertEquals("the camera stays in quarantine", Dpm.GRANT_DENIED, state("com.new.dialer", camera))
        assertTrue(notices.any { it is GuardNotice.RoleHolder && it.key == GuardKey.QUARANTINE && it.pkg == "com.new.dialer" })
    }

    @Test
    fun `an app installed while already the default SMS app is quarantined except for its role, with a notice`() {
        val e = engine()
        e.guards.set(GuardKey.QUARANTINE, true)
        gw.install("com.fast.sms", sendSms, receiveSms, contacts)
        gw.roles = gw.roles.copy(sms = "com.fast.sms")
        e.guards.reconcile()
        assertNotNull(e.record(GuardKey.QUARANTINE.packageRecordId("com.fast.sms")))
        assertEquals(Dpm.GRANT_DEFAULT, state("com.fast.sms", sendSms))
        assertEquals(Dpm.GRANT_DENIED, state("com.fast.sms", contacts))
        assertTrue(notices.any { it is GuardNotice.Quarantined })
        assertTrue(notices.any { it is GuardNotice.RoleHolder && it.pkg == "com.fast.sms" })
    }

    @Test
    fun `a denial that took effect although it was reported as failed is still undone`() {
        // The system answers "false" and the read-back fails once, yet the permission ends up denied.
        var lie = true
        val flaky = object : DevicePolicyGateway by gw {
            override fun permissionGrantState(pkg: String, permission: String): Int =
                if (lie && pkg == malware && permission == sendSms && gw.permissionGrantState(pkg, permission) == Dpm.GRANT_DENIED) {
                    lie = false
                    Dpm.GRANT_DEFAULT
                } else {
                    gw.permissionGrantState(pkg, permission)
                }
        }
        val initial = gw.snapshot()
        val e = engine(flaky)
        e.guards.set(GuardKey.SMS, true)
        assertEquals(Dpm.GRANT_DENIED, state(malware, sendSms))
        assertTrue("recorded as a failure", e.guards.status().getValue(GuardKey.SMS).packages.any { r -> r.target == malware && r.permissions.any { !it.applied } })
        assertTrue(engine().guards.set(GuardKey.SMS, false).allOk)
        assertEquals(initial, gw.snapshot())
    }
}
