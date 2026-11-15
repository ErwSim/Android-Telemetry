package io.github.erwsim.vigie.core.sink

import io.github.erwsim.vigie.core.testing.FakeClock
import io.github.erwsim.vigie.core.event.Event
import io.github.erwsim.vigie.core.event.Severity
import io.github.erwsim.vigie.core.event.VigieJson
import io.github.erwsim.vigie.core.testing.openTestDatabase
import io.github.erwsim.vigie.core.outbox.Outbox
import io.github.erwsim.vigie.core.outbox.OutboxDatabase
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class OutboxEventSinkTest {
    @get:Rule
    val tmp = TemporaryFolder()

    private lateinit var db: OutboxDatabase
    private lateinit var outbox: Outbox
    private lateinit var scope: CoroutineScope
    private val clock = FakeClock()

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

    @Test
    fun emitAssignsIdentityFieldsAndFlushAssignsSeq() = runBlocking {
        val sink = OutboxEventSink(outbox, clock, "boot-1", scope, flushDelayMs = 60_000)
        sink.emit("device.screen") { put("state", "on") }
        clock.advance(10)
        sink.emit("device.screen") { put("state", "off") }
        assertEquals(0L, outbox.totals.value.count) // grouped: nothing written yet
        assertTrue(sink.flushNow())
        val rows = outbox.batch(10)
        assertEquals(listOf(1L, 2L), rows.map { it.seq })
        val first = VigieJson.decodeFromString(Event.serializer(), rows[0].json)
        assertEquals("boot-1", first.bootId)
        assertEquals("2025-11-15T21:43:03.974Z", first.ts)
        assertEquals(86_400_123L, first.elapsedMs)
        assertEquals(26, first.id.length)
        assertTrue(rows[0].id < rows[1].id)
        assertEquals(listOf("off", "on"), sink.recent.events.value.map { it.data["state"].toString().trim('"') })
    }

    @Test
    fun groupedWriteHappensAfterTheDelay() = runBlocking {
        val sink = OutboxEventSink(outbox, clock, "b", scope, flushDelayMs = 200)
        sink.start()
        repeat(50) { sink.emit("device.screen") { put("state", "on") } }
        waitFor { outbox.totals.value.count == 50L }
        assertEquals((1L..50L).toList(), outbox.batch(100).map { it.seq })
    }

    @Test
    fun highSeverityIsWrittenImmediately() = runBlocking {
        val sink = OutboxEventSink(outbox, clock, "b", scope, flushDelayMs = 600_000)
        sink.start()
        sink.emit("device.screen") { put("state", "on") }
        sink.emit("agent.tamper", Severity.CRITICAL) { put("kind", "test"); put("detail", "x") }
        waitFor { outbox.totals.value.count == 2L }
    }

    @Test
    fun invalidTypeOrSeverityIsRejectedAtEmit() {
        val sink = OutboxEventSink(outbox, clock, "b", scope)
        assertThrows(IllegalArgumentException::class.java) { sink.emit("Bad.Type") }
        assertThrows(IllegalArgumentException::class.java) { sink.emit("agent.heartbeat", 4) }
    }

    @Test
    fun flushListenerSeesWrittenEvents() = runBlocking {
        val sink = OutboxEventSink(outbox, clock, "b", scope, flushDelayMs = 600_000)
        val seen = ArrayList<Long>()
        sink.listener = FlushListener { events -> seen += events.map { it.seq } }
        repeat(3) { sink.emit("device.screen") { put("state", "on") } }
        sink.flushNow()
        assertEquals(listOf(1L, 2L, 3L), seen)
    }

    private suspend fun waitFor(condition: () -> Boolean) {
        withTimeout(10_000) { while (!condition()) delay(20) }
    }
}
