package io.github.erwsim.watchpost.collectors.notifications

import io.github.erwsim.watchpost.core.collector.CollectorRunState
import io.github.erwsim.watchpost.core.event.EventTypes
import io.github.erwsim.watchpost.core.settings.CoreSettings
import io.github.erwsim.watchpost.core.testing.CollectorHarness
import io.github.erwsim.watchpost.core.testing.Contract
import io.github.erwsim.watchpost.notifier.protocol.CodeRedactor.MASK
import io.github.erwsim.watchpost.notifier.protocol.Limits
import io.github.erwsim.watchpost.notifier.protocol.MapValues
import io.github.erwsim.watchpost.notifier.protocol.NotificationPayload
import io.github.erwsim.watchpost.notifier.protocol.NotifierConfig
import io.github.erwsim.watchpost.notifier.protocol.NotifierProtocol as P
import io.github.erwsim.watchpost.notifier.protocol.PackageLists
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Agent side of the channel: caller check, validation of hostile payloads, content rule applied
 * again, settings and lists, conformity of `app.notification` with the contract.
 */
class NotificationsAgentSideTest {
    private class Rig : AutoCloseable {
        val h = CollectorHarness(NotificationsCollector())
        val emitted = ArrayList<NotificationPayload>()
        var initialised = true
        var elapsed = 0L
        val statuses = ArrayList<Boolean>()
        var listsChanged = 0
        val endpoint = NotificationsEndpoint(
            settings = { if (initialised) h.settings else null },
            emit = { emitted += it; true },
            elapsedMs = { elapsed },
            onCompanionStatus = { statuses += it },
            onListsChanged = { listsChanged++ },
            maxCallsPerMinute = 50,
        )

        fun call(method: String, values: Map<String, Any?>, companion: Boolean = true) =
            endpoint.handle(method, MapValues(values + (P.KEY_PROTOCOL to P.VERSION)), companion)

        fun post(vararg values: Pair<String, Any?>) = call(P.METHOD_POST, mapOf(P.KEY_PACKAGE to "com.chat", P.KEY_EVENT to P.EVENT_POSTED) + values)

        override fun close() = h.close()
    }

    @Test
    fun onlyTheCompanionSignedByTheSameKeyIsServed() {
        assertTrue(CallerCheck.isCompanion(P.NOTIFIER_PACKAGE, arrayOf(P.NOTIFIER_PACKAGE), holdsPermission = true, sameSigningKey = true))
        assertFalse(CallerCheck.isCompanion(P.NOTIFIER_PACKAGE, arrayOf(P.NOTIFIER_PACKAGE), holdsPermission = true, sameSigningKey = false))
        assertFalse(CallerCheck.isCompanion(P.NOTIFIER_PACKAGE, arrayOf(P.NOTIFIER_PACKAGE), holdsPermission = false, sameSigningKey = true))
        assertFalse(CallerCheck.isCompanion("com.evil", arrayOf("com.evil"), holdsPermission = true, sameSigningKey = true))
        // Package name claimed by an app whose uid is another one.
        assertFalse(CallerCheck.isCompanion(P.NOTIFIER_PACKAGE, arrayOf("com.evil"), holdsPermission = true, sameSigningKey = true))
        assertFalse(CallerCheck.isCompanion(null, null, holdsPermission = true, sameSigningKey = true))

        Rig().use { r ->
            assertEquals(P.STATUS_DENIED, r.call(P.METHOD_CONFIG, emptyMap(), companion = false)[P.KEY_STATUS])
            assertEquals(P.STATUS_DENIED, r.call(P.METHOD_POST, mapOf(P.KEY_PACKAGE to "com.chat", P.KEY_EVENT to P.EVENT_POSTED), companion = false)[P.KEY_STATUS])
            assertTrue(r.emitted.isEmpty())
            assertEquals(P.STATUS_OK, r.post()[P.KEY_STATUS])
            assertEquals(1, r.emitted.size)
        }
    }

    @Test
    fun protocolStartupAndRateLimit() {
        Rig().use { r ->
            assertEquals(P.STATUS_PROTOCOL_MISMATCH, r.endpoint.handle(P.METHOD_CONFIG, MapValues(mapOf(P.KEY_PROTOCOL to 99)), true)[P.KEY_STATUS])
            assertEquals(P.STATUS_PROTOCOL_MISMATCH, r.endpoint.handle(P.METHOD_CONFIG, MapValues(emptyMap()), true)[P.KEY_STATUS])
            r.initialised = false
            assertEquals(P.STATUS_STARTING, r.post()[P.KEY_STATUS])
            r.initialised = true
            assertEquals(P.STATUS_INVALID, r.call("drop_table", emptyMap())[P.KEY_STATUS])
            repeat(49) { r.post() } // + the call above: 50 per minute
            assertEquals(P.STATUS_RATE_LIMITED, r.post()[P.KEY_STATUS])
            r.elapsed += 60_000
            assertEquals(P.STATUS_OK, r.post()[P.KEY_STATUS])
        }
    }

    @Test
    fun hostileOrHugePayloadsAreRefused() {
        Rig().use { r ->
            val refused = listOf(
                mapOf(P.KEY_EVENT to P.EVENT_POSTED), // no package
                mapOf(P.KEY_PACKAGE to "../../etc", P.KEY_EVENT to P.EVENT_POSTED),
                mapOf(P.KEY_PACKAGE to "com." + "a".repeat(400), P.KEY_EVENT to P.EVENT_POSTED),
                mapOf(P.KEY_PACKAGE to P.AGENT_PACKAGE, P.KEY_EVENT to P.EVENT_POSTED), // the agent's own
                mapOf(P.KEY_PACKAGE to "com.chat", P.KEY_EVENT to "deleted"),
                mapOf(P.KEY_PACKAGE to 42, P.KEY_EVENT to P.EVENT_POSTED), // wrong type
                mapOf(P.KEY_PACKAGE to "com.chat", P.KEY_EVENT to P.EVENT_POSTED, P.KEY_IMPORTANCE to "urgent"),
                mapOf(P.KEY_PACKAGE to "com.chat", P.KEY_EVENT to P.EVENT_POSTED, P.KEY_TITLE to "a".repeat(513)),
                mapOf(P.KEY_PACKAGE to "com.chat", P.KEY_EVENT to P.EVENT_POSTED, P.KEY_TEXT to "b".repeat(5_000_000)),
                mapOf(P.KEY_PACKAGE to "com.chat", P.KEY_EVENT to P.EVENT_POSTED, P.KEY_CATEGORY to "c".repeat(65)),
                mapOf(P.KEY_PACKAGE to "com.chat", P.KEY_EVENT to P.EVENT_POSTED, P.KEY_CHANNEL to "d".repeat(129)),
                mapOf(P.KEY_PACKAGE to "com.chat", P.KEY_EVENT to P.EVENT_POSTED) + (1..40).associate { "junk$it" to it },
            )
            refused.forEach { assertEquals(it.keys.toString(), P.STATUS_INVALID, r.call(P.METHOD_POST, it)[P.KEY_STATUS]) }
            assertTrue(r.emitted.isEmpty())
            // Within the bounds: 512 code points of emoji (1024 chars) are accepted.
            r.h.settings.set(NotificationsCollector.CONTENT, true)
            assertEquals(P.STATUS_OK, r.post(P.KEY_TITLE to "😀".repeat(512))[P.KEY_STATUS])
            assertEquals(512, r.emitted.single().title!!.codePointCount(0, 1024))
            // Wrong types read as absent; a removal never carries content.
            r.emitted.clear()
            r.post(P.KEY_ONGOING to "true", P.KEY_TITLE to 7)
            assertFalse(r.emitted.single().ongoing)
            assertNull(r.emitted.single().title)
            r.call(P.METHOD_POST, mapOf(P.KEY_PACKAGE to "com.chat", P.KEY_EVENT to P.EVENT_REMOVED, P.KEY_TITLE to "x", P.KEY_REDACTED to true))
            assertNull(r.emitted.last().title)
            assertNull(r.emitted.last().redacted)
        }
    }

    @Test
    fun theAgentAppliesTheContentRuleAgain() {
        Rig().use { r ->
            // Content off (default): the companion should not have sent any; if it did (stale settings), it is dropped here.
            r.post(P.KEY_TITLE to "Alice", P.KEY_TEXT to "Code 482913", P.KEY_REDACTED to false)
            with(r.emitted.last()) {
                assertNull(title)
                assertNull(text)
                assertNull(redacted)
            }
            r.h.settings.set(NotificationsCollector.CONTENT, true)
            // Masking is applied again (a companion that missed it).
            r.post(P.KEY_TITLE to "Alice", P.KEY_TEXT to "Code 482913")
            assertEquals("Code $MASK", r.emitted.last().text)
            assertEquals(true, r.emitted.last().redacted)
            // Excluded apps (default list: SMS) never get content.
            r.call(P.METHOD_POST, mapOf(P.KEY_PACKAGE to "com.samsung.android.messaging", P.KEY_EVENT to P.EVENT_POSTED, P.KEY_TEXT to "Hello"))
            assertNull(r.emitted.last().text)
            // Collector disabled, or agent stopped: nothing recorded.
            val before = r.emitted.size
            r.h.settings.set(r.h.settings.collectorEnabledKey(NotificationsCollector.ID, true), false)
            assertEquals(P.STATUS_NOT_ACCEPTING, r.post()[P.KEY_STATUS])
            r.h.settings.set(r.h.settings.collectorEnabledKey(NotificationsCollector.ID, true), true)
            r.h.settings.set(CoreSettings.AGENT_ENABLED, false)
            assertEquals(P.STATUS_NOT_ACCEPTING, r.post()[P.KEY_STATUS])
            assertEquals(before, r.emitted.size)
        }
    }

    @Test
    fun settingsAndListsThroughTheChannel() {
        Rig().use { r ->
            val defaults = NotifierConfig.fromValues(MapValues(r.call(P.METHOD_CONFIG, emptyMap())))!!
            assertTrue(defaults.accepting)
            assertFalse(defaults.contentEnabled) // contract §10: off by default
            assertTrue(defaults.redactCodes) // on by default
            assertEquals(PackageLists.DEFAULT_CONTENT_EXCLUDED.toSet(), defaults.contentExcluded)
            assertTrue(defaults.ignored.isEmpty())

            val reply = r.call(P.METHOD_SET_LISTS, mapOf(P.KEY_CONTENT_EXCLUDED to listOf("com.bank.a", "not valid"), P.KEY_IGNORED to arrayOf("com.noisy")))
            val c = NotifierConfig.fromValues(MapValues(reply))!!
            assertEquals(setOf("com.bank.a"), c.contentExcluded)
            assertEquals(setOf("com.noisy"), c.ignored)
            assertEquals(listOf("not valid"), reply[P.KEY_REJECTED])
            assertEquals(1, r.listsChanged)
            assertTrue(c.version != defaults.version)
            // Each changed list emits agent.config_changed.
            val changes = r.h.eventsOf(EventTypes.AGENT_CONFIG_CHANGED).map { (it.data["key"] as JsonPrimitive).content }
            assertEquals(listOf(NotificationsConfigStore.KEY_CONTENT_EXCLUDED, NotificationsConfigStore.KEY_IGNORED), changes)
            r.h.eventsOf(EventTypes.AGENT_CONFIG_CHANGED).forEach { Contract.check(it.type, it.data) }
            // Ignored apps are dropped by the agent too.
            val before = r.emitted.size
            assertEquals(P.STATUS_OK, r.call(P.METHOD_POST, mapOf(P.KEY_PACKAGE to "com.noisy", P.KEY_EVENT to P.EVENT_POSTED))[P.KEY_STATUS])
            assertEquals(before, r.emitted.size)
            // Reset to the defaults; an unchanged list emits nothing.
            r.call(P.METHOD_SET_LISTS, mapOf(P.KEY_RESET to true))
            assertEquals(defaults.version, NotifierConfig.fromValues(MapValues(r.call(P.METHOD_CONFIG, emptyMap())))!!.version)
            val count = r.h.eventsOf(EventTypes.AGENT_CONFIG_CHANGED).size
            r.call(P.METHOD_SET_LISTS, mapOf(P.KEY_IGNORED to emptyList<String>()))
            assertEquals(count, r.h.eventsOf(EventTypes.AGENT_CONFIG_CHANGED).size)
            // Status of the companion's listener.
            r.call(P.METHOD_STATUS, mapOf(P.KEY_LISTENER_CONNECTED to true))
            assertEquals(P.STATUS_INVALID, r.call(P.METHOD_STATUS, emptyMap())[P.KEY_STATUS])
            assertEquals(listOf(true), r.statuses)
        }
    }

    @Test
    fun appNotificationFollowsTheContract() {
        val full = NotificationPayload(
            packageName = "com.chat", event = P.EVENT_POSTED, category = "msg", channel = "messages", ongoing = false,
            importance = "high", title = "Alice", text = "Code $MASK", redacted = true,
        )
        val samples = listOf(
            full,
            full.copy(title = null, text = null, redacted = null), // content off
            full.copy(event = P.EVENT_REMOVED, title = null, text = null, redacted = null, importance = null, category = null, channel = null),
        )
        for (p in samples) {
            val data = NotificationEvents.data(p)
            checkContract(data)
            assertEquals(p.packageName, (data["package"] as JsonPrimitive).content)
        }
        // Absent rather than null.
        assertFalse("title" in NotificationEvents.data(samples[1]))
        assertFalse("redacted" in NotificationEvents.data(samples[1]))
        // Bounds of §10.
        assertEquals(512, Limits.MAX_CONTENT_CODE_POINTS)
    }

    /**
     * The shared [Contract] reference (testFixtures of :core) predates contract §10 and does not list
     * `importance` and `redacted` yet: they are checked here against §10 and stripped before
     * [Contract.check]; once Contract lists them, they are checked there (this function then strips nothing).
     */
    private fun checkContract(data: JsonObject) {
        val known = Contract.fields(NotificationEvents.TYPE)
        val pending = setOf("importance", "redacted") - known
        (data["importance"] as? JsonPrimitive)?.let { assertTrue(it.isString && it.content in setOf("none", "min", "low", "default", "high", "max")) }
        (data["redacted"] as? JsonPrimitive)?.let { assertTrue(!it.isString && it.content in setOf("true", "false")) }
        (data["title"] as? JsonPrimitive)?.let { assertTrue(it.content.codePointCount(0, it.content.length) <= 512) }
        (data["text"] as? JsonPrimitive)?.let { assertTrue(it.content.codePointCount(0, it.content.length) <= 512) }
        Contract.check(NotificationEvents.TYPE, JsonObject(data.filterKeys { it !in pending }))
    }

    @Test
    fun collectorIsUnavailableWithAReasonWithoutTheCompanion() {
        assertEquals(CompanionCheck.Problem.NOT_INSTALLED, CompanionCheck.evaluate(false, false, null, null))
        assertEquals(CompanionCheck.Problem.OTHER_KEY, CompanionCheck.evaluate(true, false, true, true))
        assertEquals(CompanionCheck.Problem.NO_ACCESS, CompanionCheck.evaluate(true, true, false, null))
        assertEquals(CompanionCheck.Problem.NO_ACCESS, CompanionCheck.evaluate(true, true, false, false))
        assertNull(CompanionCheck.evaluate(true, true, true, false)) // granted, listener momentarily disconnected
        assertNull(CompanionCheck.evaluate(true, true, null, null)) // setting unreadable: not blocked
        assertNull(CompanionCheck.evaluate(true, true, false, true)) // the companion says it is connected

        CollectorHarness(NotificationsCollector()).use { h ->
            h.startAll()
            val s = h.status(NotificationsCollector.ID)
            assertEquals(CollectorRunState.UNAVAILABLE, s.state)
            assertTrue(s.reason!!.isNotBlank())
            assertTrue(h.events.none { it.type == EventTypes.AGENT_COLLECTOR_ERROR })
            // Settings: content off, masking on by default; keys prefixed by the collector id.
            assertFalse(h.settings[NotificationsCollector.CONTENT])
            assertTrue(h.settings[NotificationsCollector.REDACT_CODES])
        }
    }
}
