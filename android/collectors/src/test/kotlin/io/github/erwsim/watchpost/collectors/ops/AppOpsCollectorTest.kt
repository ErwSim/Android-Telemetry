package io.github.erwsim.watchpost.collectors.ops

import android.Manifest
import io.github.erwsim.watchpost.core.collector.CollectorContext
import io.github.erwsim.watchpost.core.collector.CollectorRunState
import io.github.erwsim.watchpost.core.event.EventTypes
import io.github.erwsim.watchpost.core.event.Rfc3339
import io.github.erwsim.watchpost.core.event.Severity
import io.github.erwsim.watchpost.core.testing.CollectorHarness
import io.github.erwsim.watchpost.core.testing.Contract
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.CopyOnWriteArrayList

/** Scripted `dumpsys appops`: history and state text per op, or a failure. */
private class FakeDump : AppOpsDumpSource {
    val history = HashMap<String, DumpResult>()
    val state = HashMap<String, DumpResult>()
    val calls = CopyOnWriteArrayList<List<String>>()

    /** Same text for every op of the history. */
    var allHistory: DumpResult? = null

    override suspend fun dump(ctx: CollectorContext, args: List<String>, timeoutMs: Long, maxChars: Int): DumpResult {
        calls += args
        val op = args.last()
        return if ("--history" in args) allHistory ?: history[op] ?: DumpResult.Text(historyText(op, emptyMap())) else state[op] ?: DumpResult.Text("")
    }

    companion object {
        /** One snapshot, one `[state-s]` entry per (package, state): `counts[pkg] = fg to bg`. */
        fun historyText(op: String, counts: Map<String, Pair<Long, Long>>, rejected: Map<String, Long> = emptyMap()): String = buildString {
            appendLine("Current AppOps Service state:")
            appendLine()
            appendLine("  History:  mode=HISTORICAL_MODE_ENABLED_ACTIVE")
            appendLine()
            appendLine("    snapshot:")
            appendLine("      begin = 1970-01-01 01:00:00.000  (-20408d4h30m10s500ms)")
            appendLine("      end = 1970-01-01 01:07:41.220  (-20408d4h22m29s280ms)")
            appendLine()
            (counts.keys + rejected.keys).toList().forEachIndexed { i, pkg ->
                val c = counts[pkg] ?: (0L to 0L)
                appendLine("      Uid u0a${100 + i}:")
                appendLine("        Package $pkg:")
                appendLine("          Attribution null:")
                appendLine("            $op:")
                if (c.first > 0) appendLine("              [fg-s] = access=${c.first}")
                if (c.second > 0) appendLine("              [bg-s] = access=${c.second}")
                rejected[pkg]?.let { appendLine("              [bg-s] = reject=$it") }
            }
        }

        fun stateText(op: String, lastAccess: Map<String, String>): String = buildString {
            appendLine("Current AppOps Service state:")
            lastAccess.forEach { (pkg, rel) ->
                appendLine("  Uid u0a1:")
                appendLine("    Package $pkg:")
                appendLine("      $op (allow): ")
                appendLine("        null=[")
                appendLine("          Access: [bg-s] 2026-11-16 13:04:05.123 ($rel)")
                appendLine("        ]")
            }
        }
    }
}

class AppOpsCollectorTest {
    private fun harness(dump: FakeDump, enabled: Boolean = true, dumpGranted: Boolean = true, usageGranted: Boolean = true): CollectorHarness {
        val h = CollectorHarness(AppOpsCollector(dump))
        if (dumpGranted) h.granted += Manifest.permission.DUMP
        if (usageGranted) h.granted += Manifest.permission.PACKAGE_USAGE_STATS
        if (enabled) h.host.setEnabled("app_ops", true)
        h.settle()
        return h
    }

    /** The harness also records `agent.config_changed` (the collector was enabled): only look at what the collector emits. */
    private fun CollectorHarness.ops() = eventsOf("app.ops")

    private fun items(e: CollectorHarness.Recorded) = e.data["apps"]!!.jsonArray.map { it.jsonObject }

    @Test
    fun isExperimentalOffByDefaultAndTheEventTypeIsTheContractOne() {
        val c = AppOpsCollector(FakeDump())
        assertFalse(c.defaultEnabled)
        assertEquals(listOf("app.ops"), c.eventTypes)
        assertEquals(60L, c.periodic!!.intervalMinutes)
        assertEquals(setOf("send_sms", "read_sms", "receive_sms", "call_phone", "read_contacts", "read_call_log", "record_audio", "camera", "fine_location", "get_accounts"), AppOpsLogic.OPS.map { it.wire }.toSet())
        assertEquals(Contract.OPS, AppOpsLogic.OPS.map { it.wire }.toSet())
    }

    @Test
    fun unavailableWithAReasonUntilBothPermissionsAreGranted() {
        for ((dump, usage) in listOf(false to false, true to false, false to true)) {
            harness(FakeDump(), dumpGranted = dump, usageGranted = usage).use { h ->
                h.startAll()
                assertEquals(CollectorRunState.UNAVAILABLE, h.status("app_ops").state)
                assertFalse(h.status("app_ops").reason.isNullOrBlank())
                assertTrue(h.ops().isEmpty())
            }
        }
        harness(FakeDump()).use { h ->
            h.startAll()
            assertEquals(CollectorRunState.RUNNING, h.status("app_ops").state)
        }
        // Not enabled: not read at all.
        val dump = FakeDump()
        harness(dump, enabled = false).use { h ->
            h.startAll()
            assertEquals(CollectorRunState.DISABLED, h.status("app_ops").state)
            h.collectOnce("app_ops")
            assertTrue(dump.calls.isEmpty())
        }
    }

    @Test
    fun theFirstReadingIsOnlyABaselineThenCountsAreDifferences() {
        val dump = FakeDump()
        for (op in AppOpsLogic.OPS) dump.history[op.dumpName] = DumpResult.Text(FakeDump.historyText(op.dumpName, emptyMap()))
        dump.history["SEND_SMS"] = DumpResult.Text(FakeDump.historyText("SEND_SMS", mapOf("com.example.fastsms" to (10L to 100L), "com.example.sms" to (3L to 0L))))
        dump.history["RECORD_AUDIO"] = DumpResult.Text(FakeDump.historyText("RECORD_AUDIO", mapOf("com.example.recorder" to (0L to 4L))))
        harness(dump).use { h ->
            h.collectOnce("app_ops")
            assertTrue("baseline emits nothing: ${h.events}", h.ops().isEmpty())
            assertEquals(10, dump.calls.count { "--history" in it }) // One bounded history dump per op.

            // One hour later: the fast SMS app sent 2000 messages in the background, the other app 2.
            h.clock.advance(3_600_000)
            dump.history["SEND_SMS"] = DumpResult.Text(FakeDump.historyText("SEND_SMS", mapOf("com.example.fastsms" to (10L to 2100L), "com.example.sms" to (5L to 0L))))
            dump.state["SEND_SMS"] = DumpResult.Text(FakeDump.stateText("SEND_SMS", mapOf("com.example.fastsms" to "-2m3s100ms")))
            h.collectOnce("app_ops")
            val e = h.eventsOf("app.ops").single()
            Contract.check(e.type, e.data)
            assertEquals(Rfc3339.format(h.clock.now - 3_600_000), e.data["from"]!!.jsonPrimitive.content)
            assertEquals(Rfc3339.format(h.clock.now), e.data["to"]!!.jsonPrimitive.content)
            val apps = items(e)
            // Largest first; recorder did nothing new (4 = 4): absent.
            assertEquals(listOf("com.example.fastsms", "com.example.sms"), apps.map { it["package"]!!.jsonPrimitive.content })
            assertEquals("send_sms", apps[0]["op"]!!.jsonPrimitive.content)
            assertEquals(2000L, apps[0]["count"]!!.jsonPrimitive.content.toLong())
            assertEquals(2000L, apps[0]["background_count"]!!.jsonPrimitive.content.toLong())
            assertEquals(Rfc3339.format(h.clock.now - (2 * 60_000L + 3_100)), apps[0]["last_ts"]!!.jsonPrimitive.content)
            assertEquals(2L, apps[1]["count"]!!.jsonPrimitive.content.toLong())
            assertEquals(0L, apps[1]["background_count"]!!.jsonPrimitive.content.toLong())
            assertNull("no state dump for this package: last_ts absent", apps[1]["last_ts"])
            // Only the used op had a state dump.
            assertEquals(1, dump.calls.count { "--history" !in it })
            assertEquals(Severity.NOTABLE, e.sev) // SMS sending reported by the system is worth a glance.
        }
    }

    @Test
    fun anOpOnlyRefusedIsReportedWithItsRefusalCount() {
        val dump = FakeDump()
        harness(dump).use { h ->
            h.collectOnce("app_ops") // Baseline, nothing refused yet.
            h.clock.advance(3_600_000)
            // A guard turns the app down 2000 times; not one SMS goes out.
            dump.history["SEND_SMS"] = DumpResult.Text(FakeDump.historyText("SEND_SMS", emptyMap(), rejected = mapOf("com.example.fastsms" to 2000L)))
            h.collectOnce("app_ops")
            val e = h.eventsOf("app.ops").single()
            Contract.check(e.type, e.data)
            val item = items(e).single()
            assertEquals("com.example.fastsms", item["package"]!!.jsonPrimitive.content)
            assertEquals(0L, item["count"]!!.jsonPrimitive.content.toLong())
            assertEquals(2000L, item["rejected_count"]!!.jsonPrimitive.content.toLong())
            assertNull("no successful access: no last_ts", item["last_ts"])
            assertEquals(Severity.WARNING, e.sev)
            // Still refused, no new refusal: silence.
            h.clock.advance(3_600_000)
            h.collectOnce("app_ops")
            assertEquals(1, h.eventsOf("app.ops").size)
        }
    }

    @Test
    fun noUsageMeansNoEventAndTheSecondQuietHourStaysQuiet() {
        val dump = FakeDump()
        harness(dump).use { h ->
            h.collectOnce("app_ops")
            h.clock.advance(3_600_000)
            h.collectOnce("app_ops")
            assertTrue(h.ops().isEmpty())
        }
    }

    @Test
    fun aGapOfMoreThanADayIsAFreshBaselineAndADecreaseIsNeverNegative() {
        val dump = FakeDump()
        dump.history["SEND_SMS"] = DumpResult.Text(FakeDump.historyText("SEND_SMS", mapOf("a.b" to (50L to 0L))))
        harness(dump).use { h ->
            h.collectOnce("app_ops")
            h.clock.advance(25 * 3_600_000L)
            dump.history["SEND_SMS"] = DumpResult.Text(FakeDump.historyText("SEND_SMS", mapOf("a.b" to (500L to 0L))))
            h.collectOnce("app_ops")
            assertTrue("a 25 h gap is not an hourly window", h.ops().isEmpty())
            h.clock.advance(3_600_000)
            // Old snapshots expired from the system's history: the sum went down.
            dump.history["SEND_SMS"] = DumpResult.Text(FakeDump.historyText("SEND_SMS", mapOf("a.b" to (100L to 0L))))
            h.collectOnce("app_ops")
            assertTrue(h.ops().isEmpty())
            h.clock.advance(3_600_000)
            dump.history["SEND_SMS"] = DumpResult.Text(FakeDump.historyText("SEND_SMS", mapOf("a.b" to (103L to 0L))))
            h.collectOnce("app_ops")
            assertEquals(3L, items(h.eventsOf("app.ops").single()).single()["count"]!!.jsonPrimitive.content.toLong())
        }
    }

    @Test
    fun everyOpFailingMakesTheCollectorUnavailableWithOneErrorAndNoLoop() {
        val dump = FakeDump()
        dump.allHistory = DumpResult.Text(OpsSamples.HISTORY_ABSENT_ANDROID16_SQL)
        harness(dump).use { h ->
            h.startAll()
            assertEquals(CollectorRunState.RUNNING, h.status("app_ops").state)
            h.collectOnce("app_ops")
            h.awaitEvents(EventTypes.AGENT_COLLECTOR_ERROR, 1)
            val err = h.eventsOf(EventTypes.AGENT_COLLECTOR_ERROR).single()
            Contract.check(err.type, err.data)
            assertEquals("app_ops", err.data["collector"]!!.jsonPrimitive.content)
            assertTrue(err.data["error"]!!.jsonPrimitive.content.contains("no_history"))

            // The next reconciliation sees it unavailable: stopped, with the reason, not restarted.
            h.host.reconcile()
            h.settle()
            assertEquals(CollectorRunState.UNAVAILABLE, h.status("app_ops").state)
            assertFalse(h.status("app_ops").reason.isNullOrBlank())
            val callsBefore = dump.calls.size
            h.clock.advance(3_600_000)
            h.collectOnce("app_ops") // The host refuses: unavailable, nothing is read.
            h.collectOnce("app_ops")
            assertEquals(callsBefore, dump.calls.size)

            // After the retry delay, one more attempt; same failure: no second error event.
            h.clock.advance(AppOpsCollector.RETRY_AFTER_MS)
            h.host.reconcile()
            h.settle()
            h.collectOnce("app_ops")
            assertTrue(dump.calls.size > callsBefore)
            h.settle()
            assertEquals(1, h.eventsOf(EventTypes.AGENT_COLLECTOR_ERROR).size)

            // A different failure is a new error, once.
            h.clock.advance(AppOpsCollector.RETRY_AFTER_MS)
            dump.allHistory = DumpResult.Text(OpsSamples.PERMISSION_DENIED)
            h.collectOnce("app_ops")
            h.awaitEvents(EventTypes.AGENT_COLLECTOR_ERROR, 2)
            h.collectOnce("app_ops")
            h.settle()
            assertEquals(2, h.eventsOf(EventTypes.AGENT_COLLECTOR_ERROR).size)
            assertTrue(h.eventsOf("app.ops").isEmpty())
        }
    }

    @Test
    fun aRecoveredSystemClearsTheFailure() {
        val dump = FakeDump()
        dump.allHistory = DumpResult.Failed(OpsFailure.DUMP_FAILED)
        harness(dump).use { h ->
            h.collectOnce("app_ops")
            h.awaitEvents(EventTypes.AGENT_COLLECTOR_ERROR, 1)
            h.clock.advance(AppOpsCollector.RETRY_AFTER_MS + 1)
            dump.allHistory = null
            h.collectOnce("app_ops") // Baseline.
            h.startAll()
            assertEquals(CollectorRunState.RUNNING, h.status("app_ops").state)
        }
    }

    @Test
    fun oneUnreadableOpDoesNotStopTheOthers() {
        val dump = FakeDump()
        dump.history["SEND_SMS"] = DumpResult.Text(FakeDump.historyText("SEND_SMS", mapOf("a.b" to (1L to 0L))))
        dump.history["CAMERA"] = DumpResult.Failed(OpsFailure.TRUNCATED)
        dump.history["RECORD_AUDIO"] = DumpResult.Failed(OpsFailure.TIMEOUT)
        harness(dump).use { h ->
            h.startAll()
            h.collectOnce("app_ops")
            h.clock.advance(3_600_000)
            dump.history["SEND_SMS"] = DumpResult.Text(FakeDump.historyText("SEND_SMS", mapOf("a.b" to (4L to 0L))))
            h.collectOnce("app_ops")
            assertEquals(3L, items(h.eventsOf("app.ops").single()).single()["count"]!!.jsonPrimitive.content.toLong())
            assertEquals(CollectorRunState.RUNNING, h.status("app_ops").state)
            assertTrue(h.eventsOf(EventTypes.AGENT_COLLECTOR_ERROR).isEmpty())
        }
    }

    @Test
    fun eventsAreCutBySizeAndBoundedInNumber() {
        val items = (1..400).map { OpUsage("com.example.application.number$it", "send_sms", 1000L - it, 5, 1_763_242_983_974L) }
        val events = AppOpsLogic.events(1_763_239_383_974L, 1_763_242_983_974L, items)
        assertTrue(events.size > 1)
        assertEquals(AppOpsLogic.MAX_ITEMS, events.sumOf { (it["apps"] as JsonArray).size })
        events.forEach { e ->
            Contract.check("app.ops", e)
            assertTrue(e.toString().toByteArray().size < 16 * 1024)
            assertEquals(events[0]["from"], e["from"])
        }
        // The kept ones are the largest.
        assertEquals("com.example.application.number1", (events[0]["apps"] as JsonArray)[0].jsonObject["package"]!!.jsonPrimitive.content)
        assertTrue(AppOpsLogic.events(0, 1, emptyList()).isEmpty())
    }

    @Test
    fun deltasAreLowerBoundsAndBackgroundIsBoundedByTheTotal() {
        val op = AppOpsLogic.OPS.first()
        val before = mapOf("a" to OpCounts(10, 4), "gone" to OpCounts(5, 0), "r" to OpCounts(0, 0, 4))
        val now = mapOf("a" to OpCounts(15, 3), "new" to OpCounts(7, 7), "same" to OpCounts(2, 0), "r" to OpCounts(0, 0, 10), "quiet" to OpCounts(0, 0))
        val d = AppOpsLogic.deltas(op, before, now, mapOf("new" to 42L)).associateBy { it.pkg }
        assertEquals(setOf("a", "new", "same", "r"), d.keys) // "same" has no previous: counts in full; "r" only refused.
        assertEquals(OpUsage("r", "send_sms", 0, 0, null, rejectedCount = 6), d["r"])
        assertEquals(OpUsage("a", "send_sms", 5, 0, null), d["a"]) // Background went down: 0, not negative.
        assertEquals(OpUsage("new", "send_sms", 7, 7, 42L), d["new"])
    }

    @Test
    fun stateRoundTripsAndAnUnreadableStateIsABaseline() {
        val s = OpsState(mapOf("send_sms" to mapOf("a.b" to OpCounts(3, 1))), mapOf("send_sms" to 123L))
        assertEquals(s, AppOpsLogic.decode(AppOpsLogic.encode(s)))
        assertNull(AppOpsLogic.decode(null))
        assertNull(AppOpsLogic.decode("{not json"))
        assertNull(AppOpsLogic.decode("""{"c":{"x":{"a":[1]}},"t":{}}"""))
    }

    @Test
    fun everyFailureHasAFrenchReasonInTheResources() {
        val xml = java.io.File("src/main/res/values/strings_risk.xml").readText()
        for (f in OpsFailure.entries) {
            assertTrue(f.code, Regex("name=\"collector_app_ops_reason_${f.code}\"").containsMatchIn(xml))
            assertTrue(AppOpsCollector.reasonRes(f) != 0)
        }
        listOf("collector_app_ops_reason_dump", "collector_app_ops_reason_usage_stats", "collector_app_ops_title", "collector_app_ops_desc").forEach {
            assertTrue(it, xml.contains("name=\"$it\""))
        }
    }
}

