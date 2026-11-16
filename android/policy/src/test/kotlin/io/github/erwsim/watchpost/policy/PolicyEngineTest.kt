package io.github.erwsim.watchpost.policy

import io.github.erwsim.watchpost.core.testing.Contract
import io.github.erwsim.watchpost.core.testing.FakeClock
import io.github.erwsim.watchpost.core.testing.MemoryPrefs
import io.github.erwsim.watchpost.policy.dns.ProbeResult
import io.github.erwsim.watchpost.policy.engine.ChangeOp
import io.github.erwsim.watchpost.policy.engine.Dpm
import io.github.erwsim.watchpost.policy.engine.PolicyCatalog
import io.github.erwsim.watchpost.policy.engine.PolicyEngine
import io.github.erwsim.watchpost.policy.engine.PolicySelection
import io.github.erwsim.watchpost.policy.engine.PolicyStore
import io.github.erwsim.watchpost.policy.engine.Profile
import io.github.erwsim.watchpost.policy.engine.RecordStatus
import io.github.erwsim.watchpost.core.sink.EventSink
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class PolicyEngineTest {
    private val catalogJson = """
    {
      "version": 1, "updated": "2026-11-15", "source": "test",
      "packages": [
        { "package": "com.samsung.android.rubin.app", "publisher": "samsung", "label": "Rubin", "role": "r", "risk": "low", "effect": "e", "profile": "balanced", "method": "hide" },
        { "package": "com.samsung.android.app.tips", "publisher": "samsung", "label": "Tips", "role": "r", "risk": "low", "effect": "e", "profile": "balanced", "method": "suspend" },
        { "package": "com.absent.pkg", "publisher": "samsung", "label": "Absent", "role": "r", "risk": "low", "effect": "e", "profile": "balanced", "method": "hide" },
        { "package": "com.samsung.android.kgclient", "publisher": "samsung", "label": "KG", "role": "r", "risk": "critical", "effect": "e", "profile": "balanced", "method": "hide" },
        { "package": "com.example.launcher", "publisher": "x", "label": "Launcher", "role": "r", "risk": "low", "effect": "e", "profile": "balanced", "method": "hide" },
        { "package": "com.google.android.gms", "publisher": "google", "label": "GMS", "role": "r", "risk": "critical", "effect": "e", "profile": "strict", "method": "hide", "default": false },
        { "package": "com.osp.app.signin", "publisher": "samsung", "label": "Account", "role": "r", "risk": "high", "effect": "e", "profile": "strict", "method": "hide" }
      ],
      "permissions": [
        { "package": "com.google.android.googlequicksearchbox", "label": "Google loc", "permissions": ["android.permission.ACCESS_FINE_LOCATION", "android.permission.ACCESS_BACKGROUND_LOCATION", "android.permission.CAMERA"], "risk": "low", "effect": "e", "profile": "balanced" }
      ],
      "restrictions": [
        { "key": "no_add_user", "title": "t", "description": "d", "breaks": "b", "risk": "low", "profile": "balanced" },
        { "key": "no_cellular_2g", "title": "t", "description": "d", "breaks": "b", "risk": "low", "profile": "balanced" },
        { "key": "no_debugging_features", "title": "t", "description": "d", "breaks": "b", "risk": "low", "profile": "balanced" },
        { "key": "no_safe_boot", "title": "t", "description": "d", "breaks": "b", "risk": "low", "profile": "strict" }
      ],
      "settings": [
        { "namespace": "global", "key": "ble_scan_always_enabled", "value": "0", "title": "t", "description": "d", "breaks": "b", "risk": "low", "profile": "balanced" }
      ]
    }
    """.trimIndent()

    private val gms = "com.google.android.googlequicksearchbox"
    private val fine = "android.permission.ACCESS_FINE_LOCATION"
    private val bg = "android.permission.ACCESS_BACKGROUND_LOCATION"
    private val camera = "android.permission.CAMERA"

    private lateinit var gw: FakeGateway
    private lateinit var prefs: MemoryPrefs
    private val clock = FakeClock()
    private val events = ArrayList<Pair<Int, JsonObject>>()
    private var probeOk = true
    private val sink = object : EventSink {
        override fun emit(type: String, sev: Int, data: JsonObject, originTsMs: Long?) {
            assertEquals("security.policy", type)
            assertNull(originTsMs)
            Contract.check(type, data)
            events += sev to data
        }
    }

    private fun engine(host: String? = "dns.example.org") = PolicyEngine(
        gateway = gw,
        store = PolicyStore(prefs),
        catalog = PolicyCatalog.parse(catalogJson),
        probe = { h, _ -> if (probeOk) ProbeResult(true, listOf("203.0.113.5")) else ProbeResult(false, error = "$h: timeout") },
        clock = clock,
        sink = { sink },
        dnsHost = { host },
    )

    @Before
    fun setUp() {
        gw = FakeGateway()
        prefs = MemoryPrefs()
        listOf("com.samsung.android.rubin.app", "com.samsung.android.app.tips", "com.samsung.android.kgclient", "com.example.launcher", "com.google.android.gms", "com.osp.app.signin")
            .forEach { gw.install(it) }
        gw.install(gms, fine, bg, camera)
        gw.dynamicProtected += "com.example.launcher"
        // Initial state the user had: fine location granted (user-controlled), camera denied by an earlier policy,
        // a pre-existing restriction, BLE scan on, DNS "off".
        gw.granted += gms to fine
        gw.granted += gms to bg
        gw.grantState[gms to camera] = Dpm.GRANT_DENIED
        gw.restrictions += "no_add_user"
        gw.settings["global:ble_scan_always_enabled"] = "1"
        gw.dnsMode = Dpm.DNS_MODE_OFF
    }

    private fun data(i: Int) = events[i].second
    private fun JsonObject.str(k: String) = (this[k] as? JsonPrimitive)?.content

    @Test
    fun `preview lists what will change and applies nothing`() {
        val before = gw.snapshot()
        val plan = engine().preview(PolicySelection(Profile.BALANCED)).associateBy { it.id }
        assertEquals(ChangeOp.APPLY, plan.getValue("pkg:com.samsung.android.rubin.app").op)
        assertEquals(ChangeOp.APPLY, plan.getValue("pkg:com.samsung.android.app.tips").op)
        assertEquals(ChangeOp.SKIP_ABSENT, plan.getValue("pkg:com.absent.pkg").op)
        assertEquals(ChangeOp.SKIP_DENIED, plan.getValue("pkg:com.samsung.android.kgclient").op)
        assertEquals(ChangeOp.SKIP_DENIED, plan.getValue("pkg:com.example.launcher").op) // dynamic: default launcher
        assertEquals(ChangeOp.SKIP_DENIED, plan.getValue("restr:no_debugging_features").op)
        assertEquals(ChangeOp.SKIP_ALREADY, plan.getValue("restr:no_add_user").op) // not Watchpost's: never undone
        assertEquals(ChangeOp.APPLY, plan.getValue("restr:no_cellular_2g").op)
        assertEquals(ChangeOp.APPLY, plan.getValue("set:global:ble_scan_always_enabled").op)
        assertEquals(ChangeOp.APPLY, plan.getValue("perm:$gms:0").op)
        assertEquals(ChangeOp.APPLY, plan.getValue("dns").op)
        assertEquals(ChangeOp.APPLY, plan.getValue("backup").op)
        // Strict-only items are not part of the balanced preview.
        assertNull(plan["pkg:com.osp.app.signin"])
        assertEquals(before, gw.snapshot())
        assertTrue(gw.calls.isEmpty())
        assertTrue(events.isEmpty())
    }

    @Test
    fun `strict profile includes balanced items and respects per-item defaults`() {
        val plan = engine().preview(PolicySelection(Profile.STRICT)).associateBy { it.id }
        assertEquals(ChangeOp.APPLY, plan.getValue("pkg:com.osp.app.signin").op)
        assertEquals(ChangeOp.APPLY, plan.getValue("restr:no_safe_boot").op)
        assertEquals(ChangeOp.APPLY, plan.getValue("pkg:com.samsung.android.rubin.app").op)
        assertNull(plan["pkg:com.google.android.gms"]) // default false: opt-in only
        assertNull(plan["backup"]) // strict: backup is not re-enabled
        val optIn = engine().preview(PolicySelection(Profile.STRICT, mapOf("pkg:com.google.android.gms" to true))).associateBy { it.id }
        assertEquals(ChangeOp.APPLY, optIn.getValue("pkg:com.google.android.gms").op)
    }

    @Test
    fun `deny list cannot be crossed even when selected explicitly`() {
        val selection = PolicySelection(
            Profile.STRICT,
            mapOf("pkg:com.samsung.android.kgclient" to true, "pkg:com.example.launcher" to true, "restr:no_debugging_features" to true),
        )
        engine().apply(selection)
        assertFalse(gw.calls.any { "kgclient" in it || "com.example.launcher" in it || "no_debugging_features" in it })
        assertFalse("com.samsung.android.kgclient" in gw.hidden)
        assertFalse("no_debugging_features" in gw.restrictions)
        // Watchpost itself is always protected.
        assertTrue(io.github.erwsim.watchpost.policy.engine.PackageDenyList.isDenied("io.github.erwsim.watchpost"))
        assertTrue(io.github.erwsim.watchpost.policy.engine.PackageDenyList.isDenied("com.android.providers.contacts"))
    }

    @Test
    fun `apply then undo everything restores the exact initial state`() {
        val initial = gw.snapshot()
        val report = engine().apply(PolicySelection(Profile.STRICT, mapOf("dns_lock" to true)))
        assertTrue(report.failed.toString(), report.allOk)
        assertTrue("com.samsung.android.rubin.app" in gw.hidden)
        assertTrue("com.samsung.android.app.tips" in gw.suspended)
        assertTrue("com.osp.app.signin" in gw.hidden)
        assertEquals(Dpm.GRANT_DENIED, gw.permissionGrantState(gms, fine))
        assertFalse(gw.isPermissionGranted(gms, fine))
        assertTrue("no_cellular_2g" in gw.restrictions)
        assertTrue("no_safe_boot" in gw.restrictions)
        assertEquals("0", gw.settings["global:ble_scan_always_enabled"])
        assertEquals(Dpm.DNS_MODE_HOSTNAME, gw.dnsMode)
        assertEquals("dns.example.org", gw.dnsHost)
        assertTrue("disallow_config_private_dns" in gw.restrictions)
        // Camera was already denied: left alone (not recorded, not undone).
        assertFalse(gw.calls.any { it.startsWith("perm $gms $camera") })

        val undo = engine().revertAll()
        assertTrue(undo.failed.toString(), undo.allOk)
        assertEquals(initial, gw.snapshot())
        assertTrue(engine().state().records.isEmpty())
        val last = events.last().second
        assertEquals("policy_reverted", last.str("action"))
        assertEquals("true", last.str("ok"))
    }

    @Test
    fun `applied state is persisted and a new engine instance (app update, reboot) can undo it`() {
        engine().apply(PolicySelection(Profile.BALANCED))
        val records = engine().state().records
        assertTrue(records.isNotEmpty())
        assertTrue(records.all { it.status == RecordStatus.APPLIED })
        // Simulates a process restart: only the SharedPreferences survive.
        val fresh = engine()
        assertEquals(records, fresh.state().records)
        assertTrue(fresh.revert("pkg:com.samsung.android.rubin.app").allOk)
        assertFalse("com.samsung.android.rubin.app" in gw.hidden)
        assertNull(fresh.state().records.firstOrNull { it.id == "pkg:com.samsung.android.rubin.app" })
    }

    @Test
    fun `background location is granted back after foreground location`() {
        engine().apply(PolicySelection(Profile.BALANCED))
        gw.calls.clear()
        engine().revert("perm:$gms:0")
        val grants = gw.calls.filter { it.startsWith("perm") && it.endsWith(" ${Dpm.GRANT_GRANTED}") }
        assertEquals(listOf("perm $gms $fine ${Dpm.GRANT_GRANTED}", "perm $gms $bg ${Dpm.GRANT_GRANTED}"), grants)
        assertTrue(gw.isPermissionGranted(gms, fine))
        assertEquals(Dpm.GRANT_DEFAULT, gw.permissionGrantState(gms, fine)) // back under user control
    }

    @Test
    fun `partial application after failures keeps going and records only what changed`() {
        gw.failHide += "com.samsung.android.rubin.app"
        gw.failPermission += bg
        gw.failRestriction += "no_cellular_2g"
        val report = engine().apply(PolicySelection(Profile.BALANCED))
        assertFalse(report.allOk)
        assertEquals(3, report.failed.size)
        val ids = engine().state().records.map { it.id }.toSet()
        assertFalse("pkg:com.samsung.android.rubin.app" in ids)
        assertFalse("restr:no_cellular_2g" in ids)
        assertTrue("pkg:com.samsung.android.app.tips" in ids)
        val perm = engine().state().records.single { it.id == "perm:$gms:0" }
        assertEquals(mapOf(fine to true, bg to false), perm.permissions.associate { it.permission to it.applied })
        val failures = events.map { it.second }.filter { it.str("ok") == "false" }
        assertEquals(setOf("com.samsung.android.rubin.app", "$gms/$bg", "no_cellular_2g"), failures.map { it.str("target") }.toSet())
        assertTrue(failures.all { !it.str("error").isNullOrBlank() && it.str("profile") == "equilibre" })
        assertTrue(events.filter { it.second.str("ok") == "false" }.all { it.first == 1 })
        // Undo still restores what was applied.
        assertTrue(engine().revertAll().allOk)
        assertFalse("com.samsung.android.app.tips" in gw.suspended)
        assertTrue(gw.isPermissionGranted(gms, fine))
    }

    @Test
    fun `an exception from the platform is reported and does not stop the others`() {
        gw.throwOnHide += "com.samsung.android.rubin.app"
        val report = engine().apply(PolicySelection(Profile.BALANCED))
        assertEquals(1, report.failed.size)
        assertTrue(report.failed.single().contains("SecurityException"))
        assertTrue("com.samsung.android.app.tips" in gw.suspended)
    }

    @Test
    fun `private DNS is never imposed when the host does not answer`() {
        probeOk = false
        engine().apply(PolicySelection(Profile.BALANCED))
        assertEquals(Dpm.DNS_MODE_OFF, gw.dnsMode)
        assertFalse(gw.calls.any { it.startsWith("dns dns.example.org") })
        assertFalse("disallow_config_private_dns" in gw.restrictions)
        val dns = events.map { it.second }.single { it.str("action") == "private_dns_set" }
        assertEquals("false", dns.str("ok"))
        assertTrue(dns.str("error")!!.startsWith("prior check"))
    }

    @Test
    fun `private DNS error code from the platform is reported and nothing is recorded`() {
        gw.dnsSetResult = Dpm.DNS_SET_HOST_NOT_SERVING
        engine().apply(PolicySelection(Profile.BALANCED))
        assertNull(engine().dnsRecord())
        val dns = events.map { it.second }.single { it.str("action") == "private_dns_set" }
        assertTrue(dns.str("error")!!.contains("HOST_NOT_SERVING"))
    }

    @Test
    fun `the private DNS lock is off unless asked for`() {
        val e = engine()
        assertFalse(PolicySelection().privateDnsLock)
        e.apply(PolicySelection(Profile.BALANCED))
        assertEquals(Dpm.DNS_MODE_HOSTNAME, gw.dnsMode)
        assertFalse("first try without the lock", "disallow_config_private_dns" in gw.restrictions)
        // Asked for afterwards: the DNS is re-applied with the lock; asked off again: unlocked.
        e.apply(PolicySelection(Profile.BALANCED, mapOf("dns_lock" to true)))
        assertTrue("disallow_config_private_dns" in gw.restrictions)
        e.apply(PolicySelection(Profile.BALANCED))
        assertFalse("disallow_config_private_dns" in gw.restrictions)
        assertEquals(Dpm.DNS_MODE_HOSTNAME, gw.dnsMode)
    }

    @Test
    fun `nothing selected applies nothing, then one thing only`() {
        val e = engine()
        val catalog = e.catalog
        val none = PolicySelection(Profile.STRICT).withNothingSelected(catalog)
        assertTrue(e.preview(none).none { it.op == ChangeOp.APPLY })
        val before = gw.snapshot()
        assertTrue(e.apply(none).allOk)
        assertEquals(before, gw.snapshot())
        // Only the private DNS, without its lock.
        val dnsOnly = none.copy(overrides = none.overrides + ("dns" to true))
        assertEquals(listOf("dns"), e.preview(dnsOnly).filter { it.op == ChangeOp.APPLY }.map { it.id })
        e.apply(dnsOnly)
        assertEquals(Dpm.DNS_MODE_HOSTNAME, gw.dnsMode)
        assertEquals(before.hidden, gw.snapshot().hidden)
        assertEquals(before.restrictions, gw.snapshot().restrictions)
        // One section switched off, the others untouched.
        val noPackages = PolicySelection(Profile.BALANCED).withItems(catalog.packages, false)
        val plan = e.preview(noPackages)
        assertTrue(plan.none { it.id.startsWith("pkg:") && it.op == ChangeOp.APPLY })
        assertTrue(plan.any { it.id == "restr:no_cellular_2g" && it.op == ChangeOp.APPLY })
        // Applying "nothing" undoes what was applied.
        e.apply(none)
        assertEquals(before, gw.snapshot())
    }

    @Test
    fun `DNS fallback switches to opportunistic, reapply restores the host, undo restores the original mode`() {
        val e = engine()
        e.apply(PolicySelection(Profile.BALANCED))
        assertTrue(e.dnsFallback("unreachable").allOk)
        assertEquals(Dpm.DNS_MODE_OPPORTUNISTIC, gw.dnsMode)
        assertTrue(e.dnsRecord()!!.dnsFallback)
        val fallbackEvent = events.last()
        assertEquals(2, fallbackEvent.first)
        assertEquals("opportunistic", fallbackEvent.second.str("target"))
        // Second fallback call: nothing.
        assertTrue(e.dnsFallback("still").succeeded.isEmpty())
        assertTrue(e.dnsReapply().allOk)
        assertEquals("dns.example.org", gw.dnsHost)
        assertFalse(e.dnsRecord()!!.dnsFallback)
        e.revertAll()
        assertEquals(Dpm.DNS_MODE_OFF, gw.dnsMode)
        assertFalse("disallow_config_private_dns" in gw.restrictions)
    }

    @Test
    fun `failed reapply after fallback keeps the fallback recorded`() {
        val e = engine()
        e.apply(PolicySelection(Profile.BALANCED))
        e.dnsFallback("unreachable")
        probeOk = false
        assertFalse(e.dnsReapply().allOk)
        assertTrue(e.dnsRecord()!!.dnsFallback)
        assertEquals(Dpm.DNS_MODE_OPPORTUNISTIC, gw.dnsMode)
    }

    @Test
    fun `unreadable or missing permission settings are never written`() {
        gw.unreadableSettings += "ble_scan_always_enabled"
        val plan = engine().preview(PolicySelection(Profile.BALANCED)).associateBy { it.id }
        assertEquals(ChangeOp.SKIP_UNSUPPORTED, plan.getValue("set:global:ble_scan_always_enabled").op)
        gw.unreadableSettings.clear()
        gw.writeSecure = false
        engine().apply(PolicySelection(Profile.BALANCED))
        assertEquals("1", gw.settings["global:ble_scan_always_enabled"])
        assertFalse(gw.calls.any { it.startsWith("setting") })
    }

    @Test
    fun `deselecting an applied item undoes it on the next application`() {
        val e = engine()
        e.apply(PolicySelection(Profile.BALANCED))
        val selection = PolicySelection(Profile.BALANCED, mapOf("pkg:com.samsung.android.rubin.app" to false))
        val plan = e.preview(selection).associateBy { it.id }
        assertEquals(ChangeOp.REVERT, plan.getValue("pkg:com.samsung.android.rubin.app").op)
        assertEquals(ChangeOp.UNCHANGED, plan.getValue("pkg:com.samsung.android.app.tips").op)
        e.apply(selection)
        assertFalse("com.samsung.android.rubin.app" in gw.hidden)
        assertTrue("com.samsung.android.app.tips" in gw.suspended)
        assertEquals(selection, e.selection())
    }

    @Test
    fun `nothing is applied without Device Owner`() {
        gw.owner = false
        val report = engine().apply(PolicySelection(Profile.BALANCED))
        assertFalse(report.allOk)
        assertTrue(gw.calls.isEmpty())
    }

    @Test
    fun `remove device owner undoes everything, stops the logs, then clears the user`() {
        val initial = gw.snapshot()
        val e = engine()
        e.apply(PolicySelection(Profile.BALANCED))
        e.setAlwaysOnVpn("com.wireguard.android", lockdown = false)
        assertEquals("com.wireguard.android", gw.vpn)
        e.removeDeviceOwner(force = false)
        assertEquals(initial, gw.snapshot())
        assertFalse(gw.networkLogging)
        assertFalse(gw.securityLogging)
        assertTrue(gw.userControlCleared)
        assertFalse(gw.owner)
        assertEquals("clear owner", gw.calls.last())
        val actions = events.map { it.second.str("action") }
        assertTrue(actions.indexOf("device_owner_cleared") > actions.indexOf("policy_reverted"))
    }

    @Test
    fun `voluntary removal is announced before clearing and confirmed after`() {
        val hooks = ArrayList<String>()
        val e = PolicyEngine(
            gateway = gw,
            store = PolicyStore(prefs),
            catalog = PolicyCatalog.parse(catalogJson),
            probe = { _, _ -> ProbeResult(true, listOf("203.0.113.5")) },
            clock = clock,
            sink = { sink },
            dnsHost = { null },
            beforeClearOwner = { hooks += "before owner=${gw.owner} calls=${gw.calls.count { it == "clear owner" }}" },
            afterClearOwner = { cleared -> hooks += "after cleared=$cleared" },
        )
        e.removeDeviceOwner(force = false)
        assertEquals(listOf("before owner=true calls=0", "after cleared=true"), hooks)
        // device_owner_cleared (security.policy) is logged before the role disappears.
        assertTrue(events.any { it.second.str("action") == "device_owner_cleared" && it.second.str("ok") == "true" })
    }

    @Test
    fun `remove device owner stops before clearing when something could not be undone`() {
        val e = engine()
        e.apply(PolicySelection(Profile.BALANCED))
        // Undo will fail: the platform keeps the package hidden.
        gw.throwOnHide += "com.samsung.android.rubin.app"
        val report = e.removeDeviceOwner(force = false)
        assertFalse(report.allOk)
        assertTrue(gw.owner)
        assertTrue(e.state().records.any { it.id == "pkg:com.samsung.android.rubin.app" && it.lastError != null })
        e.removeDeviceOwner(force = true)
        assertFalse(gw.owner)
    }

    @Test
    fun `a pending write-ahead record (crash mid-apply) is still undone`() {
        val e = engine()
        e.apply(PolicySelection(Profile.BALANCED))
        // Simulate a crash right after the write-ahead record and the device change, before confirmation.
        val store = PolicyStore(prefs)
        val state = store.state()
        store.saveState(state.copy(records = state.records.map { if (it.id == "pkg:com.samsung.android.rubin.app") it.copy(status = RecordStatus.PENDING) else it }))
        assertTrue(engine().revertAll().allOk)
        assertFalse("com.samsung.android.rubin.app" in gw.hidden)
    }

    @Test
    fun `an item applied by an older version and gone from the catalog is undone, not forgotten`() {
        gw.install("com.old.tracker")
        gw.hidden += "com.old.tracker"
        val store = PolicyStore(prefs)
        store.saveState(
            io.github.erwsim.watchpost.policy.engine.AppliedState(
                records = listOf(
                    io.github.erwsim.watchpost.policy.engine.AppliedRecord(
                        id = "pkg:com.old.tracker", kind = io.github.erwsim.watchpost.policy.engine.ItemKind.PACKAGE,
                        target = "com.old.tracker", status = RecordStatus.APPLIED,
                        method = io.github.erwsim.watchpost.policy.engine.PackageMethod.HIDE,
                    ),
                ),
            ),
        )
        val plan = engine().preview(PolicySelection(Profile.BALANCED)).associateBy { it.id }
        assertEquals(ChangeOp.REVERT, plan.getValue("pkg:com.old.tracker").op)
        engine().apply(PolicySelection(Profile.BALANCED))
        assertFalse("com.old.tracker" in gw.hidden)
    }

    @Test
    fun `persisted JSON tolerates unknown fields written by a newer version`() {
        prefs.edit().putString(
            "applied_state",
            """{"version":2,"records":[{"id":"restr:no_cellular_2g","kind":"restriction","target":"no_cellular_2g","status":"applied","future_field":42}]}""",
        ).commit()
        gw.restrictions += "no_cellular_2g"
        assertTrue(engine().revertAll().allOk)
        assertFalse("no_cellular_2g" in gw.restrictions)
    }

    @Test
    fun `if the previous DNS mode cannot be restored, the host is no longer imposed and a retry finishes the job`() {
        val e = engine()
        e.apply(PolicySelection(Profile.BALANCED))
        gw.failDnsOff = true
        assertFalse(e.revertAll().allOk)
        assertEquals(Dpm.DNS_MODE_OPPORTUNISTIC, gw.dnsMode)
        assertTrue(e.state().records.any { it.id == "dns" && it.lastError != null })
        gw.failDnsOff = false
        assertTrue(e.revertAll().allOk)
        assertEquals(Dpm.DNS_MODE_OFF, gw.dnsMode)
    }

    @Test
    fun `action log keeps every action with its outcome`() {
        engine().apply(PolicySelection(Profile.BALANCED))
        val actionLog = engine().actionLog()
        assertEquals(events.size, actionLog.size)
        assertTrue(actionLog.any { it.action == "package_disabled" && it.target == "com.samsung.android.rubin.app" && it.ok })
        assertTrue(actionLog.any { it.action == "setting_changed" && it.target == "ble_scan_always_enabled=0" })
    }
}
