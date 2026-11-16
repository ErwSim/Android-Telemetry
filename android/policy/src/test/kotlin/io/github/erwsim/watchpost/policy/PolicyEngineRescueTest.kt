package io.github.erwsim.watchpost.policy

import io.github.erwsim.watchpost.core.sink.EventSink
import io.github.erwsim.watchpost.core.testing.Contract
import io.github.erwsim.watchpost.core.testing.FakeClock
import io.github.erwsim.watchpost.core.testing.MemoryPrefs
import io.github.erwsim.watchpost.policy.dns.ProbeResult
import io.github.erwsim.watchpost.policy.engine.AppliedRecord
import io.github.erwsim.watchpost.policy.engine.AppliedState
import io.github.erwsim.watchpost.policy.engine.ChangeOp
import io.github.erwsim.watchpost.policy.engine.Dpm
import io.github.erwsim.watchpost.policy.engine.ItemKind
import io.github.erwsim.watchpost.policy.engine.PackageMethod
import io.github.erwsim.watchpost.policy.engine.PermissionPrev
import io.github.erwsim.watchpost.policy.engine.PolicyCatalog
import io.github.erwsim.watchpost.policy.engine.PolicyEngine
import io.github.erwsim.watchpost.policy.engine.PolicySelection
import io.github.erwsim.watchpost.policy.engine.PolicyStore
import io.github.erwsim.watchpost.policy.engine.Profile
import io.github.erwsim.watchpost.policy.engine.RecordStatus
import io.github.erwsim.watchpost.policy.engine.RestrictionGuard
import io.github.erwsim.watchpost.policy.engine.SettingGuard
import kotlinx.serialization.json.JsonObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * "Can the phone be left in a state nobody can undo?" Regressions found by the pre-install review:
 * crash in the middle of a permission denial, unreadable persisted state, settings and restrictions
 * outside the reviewed list, items that a newer deny list forbids while they are applied.
 */
class PolicyEngineRescueTest {
    private val google = "com.google.android.googlequicksearchbox"
    private val fine = "android.permission.ACCESS_FINE_LOCATION"
    private val camera = "android.permission.CAMERA"

    private fun catalog(extraRestrictions: String = "", extraSettings: String = "") = """
    {
      "version": 1, "updated": "2026-11-16", "source": "test",
      "packages": [
        { "package": "com.samsung.android.rubin.app", "publisher": "samsung", "label": "Rubin", "role": "r", "risk": "low", "effect": "e", "profile": "balanced", "method": "hide" },
        { "package": "com.samsung.android.app.tips", "publisher": "samsung", "label": "Tips", "role": "r", "risk": "low", "effect": "e", "profile": "balanced", "method": "suspend" }
      ],
      "permissions": [
        { "package": "$google", "label": "Google", "permissions": ["$fine", "$camera"], "risk": "low", "effect": "e", "profile": "balanced" }
      ],
      "restrictions": [
        { "key": "no_cellular_2g", "title": "t", "description": "d", "breaks": "b", "risk": "low", "profile": "balanced" }$extraRestrictions
      ],
      "settings": [
        { "namespace": "global", "key": "ble_scan_always_enabled", "value": "0", "title": "t", "description": "d", "breaks": "b", "risk": "low", "profile": "balanced" }$extraSettings
      ]
    }
    """.trimIndent()

    private lateinit var gw: FakeGateway
    private lateinit var prefs: MemoryPrefs
    private val events = ArrayList<JsonObject>()
    private val sink = object : EventSink {
        override fun emit(type: String, sev: Int, data: JsonObject, originTsMs: Long?) {
            Contract.check(type, data)
            events += data
        }
    }

    private fun engine(catalogJson: String = catalog()) = PolicyEngine(
        gateway = gw,
        store = PolicyStore(prefs),
        catalog = PolicyCatalog.parse(catalogJson),
        probe = { _, _ -> ProbeResult(true, listOf("203.0.113.5")) },
        clock = FakeClock(),
        sink = { sink },
        dnsHost = { "dns.exemple.fr" },
    )

    @Before
    fun setUp() {
        gw = FakeGateway()
        prefs = MemoryPrefs()
        gw.install("com.samsung.android.rubin.app")
        gw.install("com.samsung.android.app.tips")
        gw.install(google, fine, camera)
        gw.granted += google to fine
        gw.settings["global:ble_scan_always_enabled"] = "1"
    }

    // ---------------------------------------------------------------- crash between record and device

    @Test
    fun `a permission denied right before a crash is restored although the record never confirmed it`() {
        // What is on disk and on the device when the process dies between setPermissionGrantState(DENIED)
        // and the confirmation of that permission: record pending, nothing marked applied, permission denied.
        PolicyStore(prefs).saveState(
            AppliedState(
                records = listOf(
                    AppliedRecord(
                        id = "perm:$google:0", kind = ItemKind.PERMISSION, target = google, status = RecordStatus.PENDING,
                        permissions = listOf(PermissionPrev(fine, Dpm.GRANT_DEFAULT, prevGranted = true), PermissionPrev(camera, Dpm.GRANT_DEFAULT, prevGranted = false)),
                    ),
                ),
            ),
        )
        gw.grantState[google to fine] = Dpm.GRANT_DENIED
        gw.granted -= google to fine

        assertTrue(engine().revertAll().allOk)
        assertEquals("the user gets the permission back, under his own control", Dpm.GRANT_DEFAULT, gw.permissionGrantState(google, fine))
        assertTrue(gw.isPermissionGranted(google, fine))
        // The permission the crash never reached is left alone.
        assertFalse(gw.calls.any { it.startsWith("perm $google $camera") })
        assertTrue(engine().state().records.isEmpty())
    }

    @Test
    fun `a pending permission that cannot be restored stays recorded for a retry`() {
        PolicyStore(prefs).saveState(
            AppliedState(
                records = listOf(
                    AppliedRecord(
                        id = "perm:$google:0", kind = ItemKind.PERMISSION, target = google, status = RecordStatus.PENDING,
                        permissions = listOf(PermissionPrev(fine, Dpm.GRANT_DEFAULT, prevGranted = true)),
                    ),
                ),
            ),
        )
        gw.grantState[google to fine] = Dpm.GRANT_DENIED
        gw.granted -= google to fine
        gw.failPermission += fine
        assertFalse(engine().revertAll().allOk)
        assertEquals(1, engine().state().records.size)
        gw.failPermission.clear()
        assertTrue(engine().revertAll().allOk)
        assertTrue(gw.isPermissionGranted(google, fine))
        assertTrue(engine().state().records.isEmpty())
    }

    // ---------------------------------------------------------------- unreadable persisted state

    @Test
    fun `one unreadable record does not lose the others`() {
        engine().apply(PolicySelection(Profile.BALANCED, mapOf("dns" to false, "backup" to false)))
        assertTrue("com.samsung.android.rubin.app" in gw.hidden)
        // A record written by a newer version with a kind this version does not know.
        val raw = prefs.getString("applied_state", null)!!
        prefs.edit().putString("applied_state", raw.replaceFirst("\"records\":[", "\"records\":[{\"id\":\"x:future\",\"kind\":\"quantum\",\"target\":\"t\"},")).commit()

        val e = engine()
        assertTrue("known records are still listed", e.state().records.any { it.id == "pkg:com.samsung.android.rubin.app" })
        assertTrue(e.revertAll().allOk)
        assertTrue(gw.hidden.isEmpty())
        assertTrue(gw.suspended.isEmpty())
        assertFalse("no_cellular_2g" in gw.restrictions)
    }

    @Test
    fun `with an unreadable state, undo everything still restores what the catalog can have changed`() {
        val initial = gw.snapshot()
        engine().apply(PolicySelection(Profile.BALANCED, mapOf("backup" to false, "dns_lock" to true)))
        assertTrue("com.samsung.android.rubin.app" in gw.hidden)
        assertEquals(Dpm.DNS_MODE_HOSTNAME, gw.dnsMode)
        assertTrue(RestrictionGuard.DNS_LOCK in gw.restrictions)
        prefs.edit().putString("applied_state", "{ this is not JSON").commit()

        val e = engine()
        assertTrue(e.state().records.isEmpty())
        assertTrue("the loss of the state is not silent", e.stateWasUnreadable())
        val report = e.revertAll()
        // Packages, restrictions, permissions and DNS are back; the setting's previous value is unknown.
        assertTrue(gw.hidden.isEmpty())
        assertTrue(gw.suspended.isEmpty())
        assertTrue(gw.restrictions.isEmpty())
        assertEquals(Dpm.GRANT_DEFAULT, gw.permissionGrantState(google, fine))
        assertEquals("our host is no longer imposed", Dpm.DNS_MODE_OPPORTUNISTIC, gw.dnsMode)
        assertEquals(initial.hidden, gw.snapshot().hidden)
        assertTrue(report.failed.toString(), report.failed.any { "ble_scan_always_enabled" in it })
        assertTrue(events.any { (it["action"].toString() == "\"package_enabled\"") })
    }

    @Test
    fun `a sweep never touches what the catalog does not list`() {
        gw.install("com.other.app")
        gw.hidden += "com.other.app"
        gw.restrictions += "no_add_user"
        engine().sweepCatalog()
        assertTrue("com.other.app" in gw.hidden)
        assertTrue("no_add_user" in gw.restrictions)
    }

    // ---------------------------------------------------------------- guards on a modified catalog

    @Test
    fun `a restriction that was never reviewed is refused even if a catalog lists it`() {
        val extra = """,
        { "key": "no_unmute_microphone", "title": "t", "description": "d", "breaks": "b", "risk": "low", "profile": "balanced" },
        { "key": "no_fun", "title": "t", "description": "d", "breaks": "b", "risk": "low", "profile": "balanced" }"""
        val e = engine(catalog(extraRestrictions = extra))
        val plan = e.preview(PolicySelection(Profile.BALANCED)).associateBy { it.id }
        assertEquals(ChangeOp.SKIP_DENIED, plan.getValue("restr:no_unmute_microphone").op)
        assertEquals(ChangeOp.SKIP_DENIED, plan.getValue("restr:no_fun").op)
        e.apply(PolicySelection(Profile.BALANCED, mapOf("restr:no_unmute_microphone" to true)))
        assertFalse(gw.calls.any { "no_unmute_microphone" in it || "no_fun" in it })
        assertTrue(RestrictionGuard.isForbidden("no_unmute_microphone"))
        assertFalse(RestrictionGuard.isForbidden("no_cellular_2g"))
    }

    @Test
    fun `a setting that could cut ADB or the DNS is never written`() {
        val extra = """,
        { "namespace": "global", "key": "adb_enabled", "value": "0", "title": "t", "description": "d", "breaks": "b", "risk": "low", "profile": "balanced" },
        { "namespace": "global", "key": "private_dns_mode", "value": "hostname", "title": "t", "description": "d", "breaks": "b", "risk": "low", "profile": "balanced" },
        { "namespace": "secure", "key": "user_setup_complete", "value": "0", "title": "t", "description": "d", "breaks": "b", "risk": "low", "profile": "balanced" }"""
        gw.settings["global:adb_enabled"] = "1"
        val e = engine(catalog(extraSettings = extra))
        val plan = e.preview(PolicySelection(Profile.BALANCED)).associateBy { it.id }
        assertEquals(ChangeOp.SKIP_DENIED, plan.getValue("set:global:adb_enabled").op)
        assertEquals(ChangeOp.SKIP_DENIED, plan.getValue("set:global:private_dns_mode").op)
        assertEquals(ChangeOp.SKIP_DENIED, plan.getValue("set:secure:user_setup_complete").op)
        assertEquals(ChangeOp.APPLY, plan.getValue("set:global:ble_scan_always_enabled").op)
        e.apply(PolicySelection(Profile.BALANCED))
        assertEquals("1", gw.settings["global:adb_enabled"])
        assertFalse(gw.calls.any { "adb_enabled" in it || "private_dns_mode" in it || "user_setup_complete" in it })
        assertTrue(SettingGuard.isForbidden("global", "adb_enabled"))
        assertFalse(SettingGuard.isForbidden("global", "ble_scan_always_enabled"))
    }

    // ---------------------------------------------------------------- update while a state is applied

    @Test
    fun `an applied item that the deny list now forbids is undone at the next application`() {
        // An older version hid a package that this version refuses to touch (it became the keyboard, the
        // launcher, or joined the hard-coded list).
        gw.dynamicProtected += "com.samsung.android.rubin.app"
        gw.hidden += "com.samsung.android.rubin.app"
        PolicyStore(prefs).saveState(
            AppliedState(
                records = listOf(
                    AppliedRecord(
                        id = "pkg:com.samsung.android.rubin.app", kind = ItemKind.PACKAGE, target = "com.samsung.android.rubin.app",
                        status = RecordStatus.APPLIED, method = PackageMethod.HIDE,
                    ),
                ),
            ),
        )
        val selection = PolicySelection(Profile.BALANCED, mapOf("dns" to false, "backup" to false))
        val plan = engine().preview(selection).associateBy { it.id }
        assertEquals(ChangeOp.REVERT, plan.getValue("pkg:com.samsung.android.rubin.app").op)
        engine().apply(selection)
        assertFalse("com.samsung.android.rubin.app" in gw.hidden)
        assertNull(engine().state().records.firstOrNull { it.id == "pkg:com.samsung.android.rubin.app" })
    }

    // ---------------------------------------------------------------- state that cannot be written

    /** SharedPreferences whose writes fail on demand (storage full). */
    private class FlakyPrefs(private val delegate: MemoryPrefs) : android.content.SharedPreferences by delegate {
        var failWrites = false

        override fun edit(): android.content.SharedPreferences.Editor {
            val real = delegate.edit()
            return java.lang.reflect.Proxy.newProxyInstance(javaClass.classLoader, arrayOf(android.content.SharedPreferences.Editor::class.java)) { proxy, method, args ->
                when {
                    method.name == "commit" -> if (failWrites) false else real.commit()
                    method.name == "apply" -> { if (!failWrites) real.apply(); null }
                    else -> { method.invoke(real, *(args ?: emptyArray())); proxy }
                }
            } as android.content.SharedPreferences.Editor
        }
    }

    @Test
    fun `undo everything restores every item even when the state can no longer be written`() {
        val flaky = FlakyPrefs(prefs)
        val e = PolicyEngine(
            gateway = gw, store = PolicyStore(flaky), catalog = PolicyCatalog.parse(catalog()),
            probe = { _, _ -> ProbeResult(true, listOf("203.0.113.5")) }, clock = FakeClock(), sink = { sink }, dnsHost = { "dns.exemple.fr" },
        )
        e.apply(PolicySelection(Profile.BALANCED, mapOf("backup" to false)))
        assertTrue("com.samsung.android.rubin.app" in gw.hidden)
        assertTrue("com.samsung.android.app.tips" in gw.suspended)
        flaky.failWrites = true
        val report = e.revertAll()
        // The device is restored item after item; only the bookkeeping failed (and is reported).
        assertFalse(report.allOk)
        assertTrue(gw.hidden.isEmpty())
        assertTrue(gw.suspended.isEmpty())
        assertFalse("no_cellular_2g" in gw.restrictions)
        assertEquals(Dpm.DNS_MODE_OPPORTUNISTIC, gw.dnsMode)
        assertEquals(Dpm.GRANT_DEFAULT, gw.permissionGrantState(google, fine))
        // Once the storage works again, a retry clears the leftover records.
        flaky.failWrites = false
        assertTrue(e.revertAll().allOk)
        assertTrue(e.state().records.isEmpty())
    }

    // ---------------------------------------------------------------- leaving Device Owner

    @Test
    fun `the role is kept when something could not be undone, unless forced`() {
        val e = engine()
        e.apply(PolicySelection(Profile.BALANCED, mapOf("dns" to false, "backup" to false)))
        gw.throwOnHide += "com.samsung.android.rubin.app"
        assertFalse(e.removeDeviceOwner(force = false).allOk)
        assertTrue("still Device Owner: Watchpost can retry later", gw.owner)
        assertTrue("com.samsung.android.rubin.app" in gw.hidden)
    }
}
