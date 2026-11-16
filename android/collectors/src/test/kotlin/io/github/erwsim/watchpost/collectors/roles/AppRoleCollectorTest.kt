package io.github.erwsim.watchpost.collectors.roles

import io.github.erwsim.watchpost.collectors.apps.DefaultApps
import io.github.erwsim.watchpost.core.collector.CollectorRunState
import io.github.erwsim.watchpost.core.event.EventTypes
import io.github.erwsim.watchpost.core.event.Severity
import io.github.erwsim.watchpost.core.testing.CollectorHarness
import io.github.erwsim.watchpost.core.testing.Contract
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class AppRoleCollectorTest {
    private val base = mapOf(
        "sms" to "com.samsung.android.messaging", "dialer" to "com.samsung.android.dialer", "browser" to "com.sec.android.app.sbrowser",
        "home" to "com.sec.android.app.launcher", "keyboard" to "com.samsung.android.honeyboard", "assistant" to "com.google.android.googlequicksearchbox",
    )

    @Test
    fun theFirstReadingIsABaselineThenEachChangeIsOneEvent() {
        var current: Map<String, String>? = base
        CollectorHarness(AppRoleCollector { current }).use { h ->
            h.collectOnce("app_role")
            assertTrue("baseline: no event", h.events.isEmpty())
            h.collectOnce("app_role")
            assertTrue(h.events.isEmpty())

            // A malicious app becomes the default SMS app; the keyboard changes too.
            current = base + ("sms" to "org.fake.fastsms") + ("keyboard" to "org.fake.keys")
            h.collectOnce("app_role")
            val e = h.eventsOf("app.role")
            assertEquals(2, e.size)
            e.forEach { Contract.check(it.type, it.data) }
            val sms = e.first { it.data["role"]!!.jsonPrimitive.content == "sms" }
            assertEquals("com.samsung.android.messaging", sms.data["old"]!!.jsonPrimitive.content)
            assertEquals("org.fake.fastsms", sms.data["new"]!!.jsonPrimitive.content)
            assertEquals(Severity.WARNING, sms.sev)

            // Same state again: silence.
            h.collectOnce("app_role")
            assertEquals(2, h.eventsOf("app.role").size)

            // Browser change: notable only.
            current = current!! + ("browser" to "org.mozilla.firefox")
            h.collectOnce("app_role")
            assertEquals(Severity.NOTABLE, h.eventsOf("app.role").last().sev)
            assertTrue(h.events.none { it.type == EventTypes.AGENT_COLLECTOR_ERROR })
        }
    }

    @Test
    fun aRoleThatBecomesUnreadableIsNotAChangeUnlessItsReadingIsReliable() {
        var current: Map<String, String>? = base
        CollectorHarness(AppRoleCollector { current }).use { h ->
            h.collectOnce("app_role")
            // The assistant is a hidden setting: absent = unknown, never "removed".
            current = base - "assistant"
            h.collectOnce("app_role")
            assertTrue(h.events.isEmpty())
            // Back: nothing either (the old value was kept).
            current = base
            h.collectOnce("app_role")
            assertTrue(h.events.isEmpty())
            // The keyboard comes from a public setting: its disappearance is real (old only, new absent).
            current = base - "keyboard"
            h.collectOnce("app_role")
            val e = h.eventsOf("app.role").single()
            Contract.check(e.type, e.data)
            assertEquals("keyboard", e.data["role"]!!.jsonPrimitive.content)
            assertNull(e.data["new"])
            assertEquals("com.samsung.android.honeyboard", e.data["old"]!!.jsonPrimitive.content)
        }
    }

    @Test
    fun aFailedReadingChangesNothing() {
        var current: Map<String, String>? = base
        CollectorHarness(AppRoleCollector { current }).use { h ->
            h.collectOnce("app_role")
            current = null
            h.collectOnce("app_role")
            current = emptyMap()
            h.collectOnce("app_role")
            current = base
            h.collectOnce("app_role")
            assertTrue(h.events.isEmpty())
        }
    }

    @Test
    fun startsAndIsScheduledHourlyOnTheJvm() {
        CollectorHarness(AppRoleCollector()).use { h ->
            h.startAll()
            assertEquals(CollectorRunState.RUNNING, h.status("app_role").state)
            assertTrue(h.scheduled.contains("+app_role"))
            assertTrue(h.events.isEmpty())
        }
    }

    @Test
    fun logicAndPersistence() {
        val (changes, next) = RoleLogic.diff(mapOf("sms" to "a", "assistant" to "x"), mapOf("sms" to "b", "home" to "h"))
        assertEquals(listOf(RoleChange("home", null, "h"), RoleChange("sms", "a", "b")), changes)
        assertEquals(mapOf("assistant" to "x", "home" to "h", "sms" to "b"), next)
        assertEquals(base, RoleLogic.decode(RoleLogic.encode(base)))
        assertNull(RoleLogic.decode(null))
        assertNull(RoleLogic.decode("{nope"))
        // Every role reported is a role the shared reader can produce, and the contract's own roles are among them.
        assertTrue(DefaultApps.ROLES.containsAll(listOf("sms", "dialer", "browser", "assistant", "home")))
        assertTrue(RoleLogic.RELIABLE.all { it in DefaultApps.ROLES })
    }

    @Test
    fun theSharedReaderParsesComponentSettings() {
        assertEquals("com.samsung.android.honeyboard", DefaultApps.packageOfComponent("com.samsung.android.honeyboard/.service.HoneyBoardService"))
        assertEquals("com.example.autofill", DefaultApps.packageOfComponent("com.example.autofill/com.example.autofill.Service"))
        assertEquals("com.bare", DefaultApps.packageOfComponent("com.bare"))
        assertNull(DefaultApps.packageOfComponent(""))
        assertNull(DefaultApps.packageOfComponent("/x"))
    }

}
