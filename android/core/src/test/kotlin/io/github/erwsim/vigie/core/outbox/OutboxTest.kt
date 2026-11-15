package io.github.erwsim.vigie.core.outbox

import io.github.erwsim.vigie.core.event.Severity
import io.github.erwsim.vigie.core.event.UlidGenerator
import io.github.erwsim.vigie.core.event.eventData
import io.github.erwsim.vigie.core.openTestDatabase
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class OutboxTest {
    @get:Rule
    val tmp = TemporaryFolder()

    private lateinit var db: OutboxDatabase
    private lateinit var outbox: Outbox
    private val ulid = UlidGenerator()
    private var t = 1_763_000_000_000L

    @Before
    fun setUp() {
        db = openTestDatabase(tmp.root)
        outbox = Outbox(db)
    }

    @After
    fun tearDown() {
        db.close()
    }

    private fun pending(sev: Int = Severity.INFO, type: String = "device.screen", tsMs: Long = t++, payload: String = "on") =
        PendingEvent(ulid.next(tsMs), tsMs, 1000, "boot", type, sev, eventData { put("state", payload) })

    @Test
    fun seqIsStrictlyIncreasingAndContiguous() = runBlocking {
        val first = outbox.append(List(3) { pending() })
        val second = outbox.append(List(2) { pending() })
        assertEquals(listOf(1L, 2L, 3L, 4L, 5L), (first + second).map { it.seq })
        assertEquals(5L, outbox.totals.value.count)
        assertEquals(outbox.batch(100).sumOf { it.sizeBytes.toLong() }, outbox.totals.value.bytes)
    }

    @Test
    fun seqContinuesAfterRestartAndAfterDeletion() = runBlocking {
        outbox.append(List(3) { pending() })
        outbox.remove(outbox.batch(3))
        db.close()
        // New process: same database file, fresh objects.
        db = openTestDatabase(tmp.root)
        outbox = Outbox(db)
        val events = outbox.append(List(2) { pending() })
        assertEquals(listOf(4L, 5L), events.map { it.seq })
        assertEquals(2L, outbox.refreshTotals().count)
    }

    @Test
    fun interruptedWriteLeavesNeitherRowsNorSequenceGap() = runBlocking {
        // Simulate a write that fails half-way (here: seq 2 already taken by a stray row).
        db.outboxDao().insertAll(listOf(OutboxEntity(2, "x", "device.screen", 0, t, "{}", 2)))
        val failed = runCatching { outbox.append(List(3) { pending() }) }
        assertTrue(failed.isFailure)
        // Rolled back: the stray row is the only one and the counter did not move.
        assertEquals(listOf(2L), outbox.batch(10).map { it.seq })
        assertEquals(0L, outbox.lastSeq())
        db.outboxDao().deleteSeqs(listOf(2L))
        assertEquals(listOf(1L, 2L, 3L), outbox.append(List(3) { pending() }).map { it.seq })
    }

    @Test
    fun clearKeepsTheSequence() = runBlocking {
        outbox.append(List(4) { pending() })
        outbox.clear()
        assertEquals(0L, outbox.totals.value.count)
        assertEquals(5L, outbox.append(listOf(pending())).single().seq)
    }

    @Test
    fun storedJsonIsTheContractEvent() = runBlocking {
        val e = outbox.append(listOf(pending(sev = Severity.WARNING, type = "agent.tamper"))).single()
        val row = outbox.batch(1).single()
        assertEquals(e.seq, row.seq)
        assertEquals(Severity.WARNING, row.sev)
        assertTrue(row.json.startsWith("{\"id\":\"${e.id}\",\"ts\":\"${e.ts}\",\"seq\":1,\"boot_id\":\"boot\""))
        assertEquals(row.json.toByteArray().size, row.sizeBytes)
    }

    @Test
    fun removeDeletesOnlyAcknowledgedRows() = runBlocking {
        outbox.append(List(10) { pending() })
        val firstFour = outbox.batch(4)
        outbox.remove(firstFour)
        val left = outbox.batch(100).map { it.seq }
        assertEquals((5L..10L).toList(), left)
        assertEquals(6L, outbox.totals.value.count)
        assertEquals(outbox.refreshTotals(), outbox.totals.value)
    }

    @Test
    fun sizeCapDropsLowestSeverityOldestFirst() = runBlocking {
        // Interleave severities: info, warning, critical, info, notable...
        val sevs = listOf(0, 2, 3, 0, 1, 0, 2, 0, 1, 3)
        outbox.append(sevs.map { pending(sev = it) })
        val rowSize = outbox.batch(1).single().sizeBytes.toLong()
        val total = outbox.totals.value.bytes
        // Cap so that a bit more than 4 rows must go: target is 90 % of the cap.
        val cap = (total - 4 * rowSize) * 10 / 9 + 1
        val report = outbox.enforceLimits(maxBytes = cap, maxAgeMs = Long.MAX_VALUE / 4, nowMs = t)
        assertNotNull(report)
        val remaining = outbox.batch(100)
        val droppedSeqs = (1L..10L).toSet() - remaining.map { it.seq }.toSet()
        // The four info events (seq 1, 4, 6, 8) go first, then the oldest notable (seq 5).
        assertTrue("dropped=$droppedSeqs", droppedSeqs.containsAll(listOf(1L, 4L, 6L, 8L)))
        assertTrue(remaining.none { it.sev == Severity.INFO })
        assertTrue(remaining.count { it.sev == Severity.CRITICAL } == 2)
        assertEquals(droppedSeqs.size.toLong(), report!!.dropped)
        assertTrue(outbox.totals.value.bytes <= cap * 9 / 10)
        assertEquals(report.dropped, outbox.droppedTotal())
    }

    @Test
    fun ageCapDropsOldEventsWhateverTheirSeverity() = runBlocking {
        val old = t
        outbox.append(listOf(pending(sev = Severity.CRITICAL, tsMs = old), pending(tsMs = old + 1)))
        val recent = old + 40L * 86_400_000
        outbox.append(listOf(pending(tsMs = recent)))
        val report = outbox.enforceLimits(maxBytes = Long.MAX_VALUE, maxAgeMs = 30L * 86_400_000, nowMs = recent)!!
        assertEquals(2L, report.dropped)
        assertEquals(old, report.oldestTsMs)
        assertEquals(old + 1, report.newestTsMs)
        assertEquals(listOf(3L), outbox.batch(10).map { it.seq })
    }

    @Test
    fun noPurgeUnderTheCaps() = runBlocking {
        outbox.append(List(5) { pending() })
        assertNull(outbox.enforceLimits(maxBytes = 10_000_000, maxAgeMs = 86_400_000, nowMs = t))
        assertEquals(0L, outbox.droppedTotal())
    }

    @Test
    fun batchCanBeRestrictedToHighSeverity() = runBlocking {
        outbox.append(listOf(pending(), pending(sev = Severity.WARNING), pending(), pending(sev = Severity.CRITICAL)))
        assertEquals(listOf(2L, 4L), outbox.batch(10, minSev = Severity.WARNING).map { it.seq })
        assertEquals(2L, outbox.countMinSev(Severity.WARNING))
    }
}
