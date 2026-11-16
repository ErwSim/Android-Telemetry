package io.github.erwsim.watchpost.core.outbox

import io.github.erwsim.watchpost.core.event.UlidGenerator
import io.github.erwsim.watchpost.core.event.eventData
import io.github.erwsim.watchpost.core.testing.FakeClock
import io.github.erwsim.watchpost.core.testing.MemoryPrefs
import io.github.erwsim.watchpost.core.testing.openTestDatabase
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/** The age purge must survive a wall clock that jumps (forward or back) without being defeated. */
class AgeHorizonTest {
    @get:Rule
    val tmp = TemporaryFolder()

    private val day = 86_400_000L
    private val maxAge = 30 * day
    private val clock = FakeClock()
    private val prefs = MemoryPrefs()
    private val ulid = UlidGenerator()
    private lateinit var db: OutboxDatabase
    private lateinit var outbox: Outbox

    @Before
    fun setUp() {
        db = openTestDatabase(tmp.root)
        outbox = Outbox(db, ageHorizon = AgeHorizon(prefs, clock, "boot-1"))
    }

    @After
    fun tearDown() {
        db.close()
    }

    private fun emit(n: Int) = runBlocking {
        outbox.append(List(n) { PendingEvent(ulid.next(clock.now), clock.now, clock.elapsed, "boot-1", "device.screen", 0, eventData { put("state", "on") }) })
    }

    private fun purge() = runBlocking { outbox.enforceLimits(maxBytes = Long.MAX_VALUE, maxAgeMs = maxAge, nowMs = clock.now) }

    private fun count() = runBlocking { outbox.refreshTotals().count }

    /** Time really passes: both clocks advance. */
    private fun elapse(ms: Long) = clock.advance(ms)

    /** The wall clock is set to another time; real (monotonic) time only advances by [realMs]. */
    private fun jumpWall(deltaMs: Long, realMs: Long = 15 * 60_000L) {
        clock.now += deltaMs + realMs
        clock.elapsed += realMs
    }

    @Test
    fun aWallClockJumpedForwardBeyondTheRetentionDoesNotPurgeTheBuffer() {
        emit(10)
        assertNull(purge())
        jumpWall(40 * day)
        assertNull(purge())
        assertEquals(10L, count())
        // Same buffer, same jump, without the horizon: everything is deleted (the defect this fixes).
        val legacy = Outbox(db)
        assertEquals(10L, runBlocking { legacy.enforceLimits(Long.MAX_VALUE, maxAge, clock.now) }!!.dropped)
    }

    @Test
    fun realAgeStillPurgesOnTime() {
        emit(10)
        assertNull(purge())
        repeat(30) { elapse(day); assertNull("day ${it + 1}", purge()) }
        elapse(day)
        assertEquals(10L, purge()!!.dropped) // 31 real days later
        assertEquals(0L, count())
    }

    @Test
    fun aClockThatStaysWrongAgesEventsAtMostTwiceAsFast() {
        emit(10)
        assertNull(purge())
        jumpWall(40 * day)
        // 14 real days later the horizon moved ~28 days: nothing is purged; 16 days later it is.
        repeat(14) { elapse(day); assertNull("day ${it + 1}", purge()) }
        assertEquals(10L, count())
        repeat(2) { elapse(day) }
        assertNotNull(purge())
        assertEquals(0L, count())
    }

    @Test
    fun aWallClockJumpedBackDoesNotPurgeEventsWrittenAfterTheJump() {
        emit(10)
        assertNull(purge())
        jumpWall(-60 * day)
        emit(5) // stamped with the (wrong) older time
        assertNull(purge())
        assertEquals(15L, count())
        // Clock fixed again: nothing is lost by the correction itself.
        jumpWall(60 * day)
        assertNull(purge())
        assertEquals(15L, count())
    }

    @Test
    fun eventsWrittenAfterABackwardJumpAreStillPurgedWhenTheyReallyAge() {
        emit(10)
        assertNull(purge())
        jumpWall(-60 * day)
        emit(5)
        repeat(30) { elapse(day); assertNull("day ${it + 1}", purge()) }
        elapse(day)
        assertEquals(5L, purge()!!.dropped) // the 5 events written after the jump, 31 days old by their own clock
        assertEquals(10L, count())
    }

    @Test
    fun aRebootCannotBeUsedToAdvanceTheHorizonMoreThanTheAllowance() {
        emit(10)
        assertNull(purge())
        // Wall clock +40 days and a reboot: no monotonic reference between the two boots.
        clock.now += 40 * day
        clock.elapsed = 5_000
        val afterReboot = Outbox(db, ageHorizon = AgeHorizon(prefs, clock, "boot-2"))
        assertNull(runBlocking { afterReboot.enforceLimits(Long.MAX_VALUE, maxAge, clock.now) })
        assertEquals(10L, count())
    }

    @Test
    fun aRebootAfterALegitimateShortStopKeepsFollowingTheWallClock() {
        emit(10)
        assertNull(purge())
        clock.now += 20 * 3_600_000L // phone off for 20 hours
        clock.elapsed = 5_000
        val horizon = AgeHorizon(prefs, clock, "boot-2")
        assertEquals(clock.now, horizon.reference(clock.now))
    }

    @Test
    fun horizonNeverGoesAheadOfTheWallClock() {
        val horizon = AgeHorizon(prefs, clock, "boot-1")
        assertEquals(clock.now, horizon.reference(clock.now))
        elapse(1_000)
        assertEquals(clock.now - 5_000, horizon.reference(clock.now - 5_000))
    }
}
