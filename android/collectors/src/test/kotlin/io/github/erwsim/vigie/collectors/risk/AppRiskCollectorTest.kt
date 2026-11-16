package io.github.erwsim.vigie.collectors.risk

import android.content.Context
import io.github.erwsim.vigie.core.collector.CollectorRunState
import io.github.erwsim.vigie.core.event.EventTypes
import io.github.erwsim.vigie.core.testing.CollectorHarness
import io.github.erwsim.vigie.core.testing.Contract
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

private class FakeFacts(var all: List<AppFacts>?) : FactsSource {
    override fun readAll(context: Context): List<AppFacts>? = all
    override fun read(context: Context, pkg: String): AppFacts? = all?.firstOrNull { it.pkg == pkg }
}

class AppRiskCollectorTest {
    private val p = "android.permission."
    private fun app(pkg: String, vc: Long = 1, installer: String? = "com.android.vending", system: Boolean = false, granted: Set<String> = emptySet()) =
        AppFacts(pkg, label = "App $pkg", versionCode = vc, installer = installer, system = system, requested = granted, granted = granted)

    @Test
    fun theFirstScanReportsEveryAppThenOnlyChanges() {
        val trojan = app("org.fake.pdf", installer = null).copy(accessibilityService = true, notificationListener = true, requested = setOf(p + "SYSTEM_ALERT_WINDOW"))
        val source = FakeFacts(listOf(app("org.good.bank"), app("org.good.mail", granted = setOf(p + "READ_CONTACTS")), trojan, app("com.android.settings", installer = null, system = true)))
        CollectorHarness(AppRiskCollector(source)).use { h ->
            h.collectOnce("app_risk")
            val first = h.eventsOf("app.risk")
            assertEquals(4, first.size)
            first.forEach { Contract.check(it.type, it.data) }
            val byPkg = first.associateBy { it.data["package"]!!.jsonPrimitive.content }
            val t = byPkg.getValue("org.fake.pdf")
            assertEquals("high", t.data["level"]!!.jsonPrimitive.content)
            assertEquals(100, t.data["score"]!!.jsonPrimitive.content.toInt()) // 35 + 25 + 15 + 12 + 30 = 117, bounded
            assertEquals("[]", t.data["granted"]!!.jsonArray.toString()) // Nothing granted: the profile is still high.
            assertEquals(false, t.data["from_store"]!!.jsonPrimitive.content.toBoolean())
            assertNull(t.data["installer"]) // Unknown installer: absent, not null.
            assertEquals(listOf("sideloaded", "accessibility_service", "notification_listener", "overlay", "combo_banking_trojan"), t.data["reasons"]!!.jsonArray.map { it.jsonPrimitive.content })
            assertEquals("low", byPkg.getValue("com.android.settings").data["level"]!!.jsonPrimitive.content)
            assertEquals("[]", byPkg.getValue("org.good.bank").data["reasons"]!!.jsonArray.toString())
            assertEquals(0, byPkg.getValue("org.good.bank").data["score"]!!.jsonPrimitive.content.toInt())
            assertEquals(true, byPkg.getValue("org.good.bank").data["from_store"]!!.jsonPrimitive.content.toBoolean())

            // Second scan, nothing changed: silence.
            h.clock.advance(24 * 3_600_000L)
            h.collectOnce("app_risk")
            assertEquals(4, h.eventsOf("app.risk").size)

            // One app gets a new capability: one event, for it only.
            source.all = source.all!!.map { if (it.pkg == "org.good.mail") it.copy(vpnService = true) else it }
            h.collectOnce("app_risk")
            val changed = h.eventsOf("app.risk").drop(4)
            assertEquals(listOf("org.good.mail"), changed.map { it.data["package"]!!.jsonPrimitive.content })
            assertEquals(listOf("vpn_service"), changed.single().data["reasons"]!!.jsonArray.map { it.jsonPrimitive.content })

            // An update missed while the agent was off (version changed, same score): reported.
            source.all = source.all!!.map { if (it.pkg == "org.good.bank") it.copy(versionCode = 2) else it }
            h.collectOnce("app_risk")
            assertEquals(6, h.eventsOf("app.risk").size)
            assertEquals("org.good.bank", h.eventsOf("app.risk").last().data["package"]!!.jsonPrimitive.content)

            // An app that disappears and comes back is reported again (its state was dropped).
            source.all = source.all!!.filterNot { it.pkg == "org.good.bank" }
            h.collectOnce("app_risk")
            source.all = source.all!! + app("org.good.bank", vc = 2)
            h.collectOnce("app_risk")
            assertEquals(7, h.eventsOf("app.risk").size)
            assertTrue(h.events.none { it.type == EventTypes.AGENT_COLLECTOR_ERROR })
        }
    }

    @Test
    fun severityFollowsTheLevel() {
        val source = FakeFacts(
            listOf(
                app("a.low"),
                app("b.medium", installer = null, granted = setOf(p + "SEND_SMS")), // 15 + 20 = 35
                app("c.high", installer = null).copy(accessibilityService = true, notificationListener = true, requested = setOf(p + "SYSTEM_ALERT_WINDOW")),
            ),
        )
        CollectorHarness(AppRiskCollector(source)).use { h ->
            h.collectOnce("app_risk")
            val sev = h.eventsOf("app.risk").associate { it.data["package"]!!.jsonPrimitive.content to it.sev }
            assertEquals(mapOf("a.low" to 0, "b.medium" to 1, "c.high" to 2), sev)
        }
    }

    @Test
    fun anUnreadablePackageListIsNotTreatedAsNoApps() {
        val source = FakeFacts(listOf(app("a.b")))
        CollectorHarness(AppRiskCollector(source)).use { h ->
            h.collectOnce("app_risk")
            assertEquals(1, h.eventsOf("app.risk").size)
            source.all = null
            h.collectOnce("app_risk")
            source.all = emptyList()
            h.collectOnce("app_risk")
            source.all = listOf(app("a.b"))
            h.collectOnce("app_risk")
            // State was kept through the failed readings: still one event.
            assertEquals(1, h.eventsOf("app.risk").size)
            assertTrue(h.events.none { it.type == EventTypes.AGENT_COLLECTOR_ERROR })
        }
    }

    @Test
    fun isScheduledDailyAndStartsOnTheJvmWithoutSystemServices() {
        CollectorHarness(AppRiskCollector()).use { h ->
            h.startAll()
            assertEquals(CollectorRunState.RUNNING, h.status("app_risk").state)
            assertTrue(h.scheduled.contains("+app_risk"))
            assertEquals(24 * 60L, AppRiskCollector().periodic!!.intervalMinutes)
            assertTrue(h.events.isEmpty())
        }
    }

    @Test
    fun emissionRuleAndPersistence() {
        val e = RiskEntry(5, 35, listOf("sideloaded", "sms_send"))
        assertFalse(RiskLogic.shouldEmit(e, e, RiskLogic.Trigger.DAILY))
        assertTrue(RiskLogic.shouldEmit(e, e, RiskLogic.Trigger.INSTALL_OR_UPDATE)) // An update is always reported.
        assertTrue(RiskLogic.shouldEmit(null, e, RiskLogic.Trigger.DAILY))
        assertTrue(RiskLogic.shouldEmit(e, e.copy(score = 36), RiskLogic.Trigger.DAILY))
        assertTrue(RiskLogic.shouldEmit(e, e.copy(reasons = listOf("sideloaded")), RiskLogic.Trigger.DAILY))
        // A grant that changes nothing else is still a change worth telling.
        assertTrue(RiskLogic.shouldEmit(e, e.copy(granted = listOf("sms_send")), RiskLogic.Trigger.DAILY))
        assertTrue(RiskLogic.shouldEmit(e, e.copy(versionCode = 6), RiskLogic.Trigger.DAILY))
        val state = mapOf("a.b" to e.copy(granted = listOf("sms_send")), "c.d" to RiskEntry(1, 0, emptyList()))
        assertEquals(state, RiskLogic.decode(RiskLogic.encode(state)))
        assertNull(RiskLogic.decode(null))
        assertNull(RiskLogic.decode("[]"))
        assertNull(RiskLogic.decode("""{"a":{"vc":1}}"""))
    }
}
