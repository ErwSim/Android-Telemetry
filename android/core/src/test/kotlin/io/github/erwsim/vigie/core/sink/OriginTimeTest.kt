package io.github.erwsim.vigie.core.sink

import io.github.erwsim.vigie.core.event.Event
import io.github.erwsim.vigie.core.event.Rfc3339
import io.github.erwsim.vigie.core.event.VigieJson
import io.github.erwsim.vigie.core.outbox.Outbox
import io.github.erwsim.vigie.core.outbox.OutboxDatabase
import io.github.erwsim.vigie.core.testing.FakeClock
import io.github.erwsim.vigie.core.testing.openTestDatabase
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/** Events read after the fact: `ts` = time of origin, `elapsed_ms` estimated, `seq` = emission order. */
class OriginTimeTest {
    @get:Rule
    val tmp = TemporaryFolder()

    private lateinit var db: OutboxDatabase
    private lateinit var outbox: Outbox
    private lateinit var scope: CoroutineScope
    private val clock = FakeClock(now = 1_763_242_983_974L, elapsed = 3_600_000L) // booted one hour ago

    @Before
    fun setUp() {
        db = openTestDatabase(tmp.root)
        outbox = Outbox(db)
        scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    }

    @After
    fun tearDown() {
        scope.cancel()
        db.close()
    }

    private suspend fun stored(): List<Event> = outbox.batch(100).map { VigieJson.decodeFromString(Event.serializer(), it.json) }

    @Test
    fun originTimeBecomesTsAndElapsedIsEstimatedOnTheSameBoot() = runBlocking {
        val sink = OutboxEventSink(outbox, clock, "boot", scope, flushDelayMs = 60_000)
        val now = clock.now
        sink.emit("device.screen") { put("state", "on") }
        // Read after the fact: 20 min ago (this boot), then 2 h ago (before this boot), then "now".
        sink.emit("net.dns", originTsMs = now - 20 * 60_000L) { put("hostname", "a.example") }
        sink.emit("security.log", originTsMs = now - 2 * 3_600_000L) { put("tag", "os_shutdown") }
        sink.emit("app.foreground", originTsMs = now + 5_000) { put("event", "resumed") }
        sink.flushNow()
        val events = stored()
        assertEquals(listOf(1L, 2L, 3L, 4L), events.map { it.seq }) // emission order, whatever ts
        assertEquals(Rfc3339.format(now), events[0].ts)
        assertEquals(3_600_000L, events[0].elapsedMs)
        assertEquals(Rfc3339.format(now - 20 * 60_000L), events[1].ts)
        assertEquals(3_600_000L - 20 * 60_000L, events[1].elapsedMs) // ts - elapsed_ms = boot time, as for every event
        assertEquals(Rfc3339.format(now - 2 * 3_600_000L), events[2].ts)
        assertEquals(0L, events[2].elapsedMs) // before the current boot: no elapsedRealtime, marked 0
        assertEquals(3_600_000L, events[3].elapsedMs) // origin after "now" (clock moved): emission elapsed
        // The ULID stays the emission order.
        assertEquals(events.map { it.id }.sorted(), events.map { it.id })
    }

    @Test
    fun invalidOriginTimeIsRefused() {
        val sink = OutboxEventSink(outbox, clock, "boot", scope)
        assertThrows(IllegalArgumentException::class.java) { sink.emit("net.dns", originTsMs = 0L) { put("hostname", "x") } }
    }

    @Test
    fun agePurgeAndUploadOrderDoNotAssumeTsFollowsSeq() = runBlocking {
        val sink = OutboxEventSink(outbox, clock, "boot", scope, flushDelayMs = 60_000)
        val now = clock.now
        val day = 86_400_000L
        sink.emit("device.screen") { put("state", "on") } // seq 1, now
        sink.emit("security.log", originTsMs = now - 40 * day) { put("tag", "os_startup") } // seq 2, very old origin
        sink.emit("net.dns", originTsMs = now - 3_600_000L) { put("hostname", "b.example") } // seq 3
        sink.flushNow()
        // Uploads take the oldest by seq.
        assertEquals(listOf(1L, 2L, 3L), outbox.batch(10).map { it.seq })
        // The age cap (30 days) removes exactly the event whose ts is too old, not "everything before it".
        val report = outbox.enforceLimits(maxBytes = Long.MAX_VALUE, maxAgeMs = 30 * day, nowMs = now)!!
        assertEquals(1L, report.dropped)
        assertEquals(now - 40 * day, report.oldestTsMs)
        assertEquals(now - 40 * day, report.newestTsMs)
        assertEquals(listOf(1L, 3L), outbox.batch(10).map { it.seq })
        assertEquals(now - 3_600_000L, outbox.oldestTsMs())
    }

    @Test
    fun elapsedEstimateIsClamped() {
        assertEquals(500L, OriginTime.elapsedAt(originTsMs = 1_500, nowMs = 2_000, elapsedNowMs = 1_000))
        assertEquals(0L, OriginTime.elapsedAt(originTsMs = 500, nowMs = 2_000, elapsedNowMs = 1_000))
        assertEquals(1_000L, OriginTime.elapsedAt(originTsMs = 9_000, nowMs = 2_000, elapsedNowMs = 1_000))
    }
}
