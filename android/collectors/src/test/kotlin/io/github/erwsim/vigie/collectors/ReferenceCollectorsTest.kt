package io.github.erwsim.vigie.collectors

import android.os.BatteryManager
import android.os.PowerManager
import io.github.erwsim.vigie.collectors.device.DeviceCollector
import io.github.erwsim.vigie.collectors.location.LocationCollector
import io.github.erwsim.vigie.collectors.location.MotionTracker
import io.github.erwsim.vigie.core.capability.SystemProps
import io.github.erwsim.vigie.core.event.EventTypes
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ReferenceCollectorsTest {
    @Test
    fun motionTrackerSwitchesToStationaryAfterFiveMinutesInPlace() {
        val t = MotionTracker()
        var now = 0L
        assertEquals(MotionTracker.Mode.MOVING, t.onFix(48.0, 2.0, 10f, 0f, now))
        // Jitter of a few metres around the anchor for 5 minutes.
        repeat(5) {
            now += 60_000
            t.onFix(48.0 + 0.00005, 2.0, 10f, 0.2f, now)
        }
        assertEquals(MotionTracker.Mode.STATIONARY, t.mode)
    }

    @Test
    fun motionTrackerDetectsMovementBySpeedOrDistance() {
        val t = MotionTracker(stationaryAfterMs = 1_000)
        t.onFix(48.0, 2.0, 5f, 0f, 0)
        t.onFix(48.0, 2.0, 5f, 0f, 2_000)
        assertEquals(MotionTracker.Mode.STATIONARY, t.mode)
        assertEquals(MotionTracker.Mode.MOVING, t.onFix(48.0, 2.0, 5f, 1.5f, 3_000))
        t.onFix(48.0, 2.0, 5f, 0f, 5_000)
        assertEquals(MotionTracker.Mode.STATIONARY, t.mode)
        // ~111 m north, no speed reported.
        assertEquals(MotionTracker.Mode.MOVING, t.onFix(48.001, 2.0, 5f, null, 6_000))
    }

    @Test
    fun poorAccuracyWidensTheStationaryCircle() {
        val t = MotionTracker(stationaryAfterMs = 1_000)
        t.onFix(48.0, 2.0, 100f, null, 0)
        // 111 m away but with 100 m accuracy: still considered in place.
        t.onFix(48.001, 2.0, 100f, null, 2_000)
        assertEquals(MotionTracker.Mode.STATIONARY, t.mode)
    }

    @Test
    fun significantMotionBringsBackTheFastCadence() {
        val t = MotionTracker(stationaryAfterMs = 1_000)
        t.onFix(48.0, 2.0, 5f, 0f, 0)
        t.onFix(48.0, 2.0, 5f, 0f, 2_000)
        assertEquals(MotionTracker.Mode.MOVING, t.onSignificantMotion(3_000))
    }

    @Test
    fun haversineDistance() {
        val d = MotionTracker.distanceM(48.8566, 2.3522, 45.7640, 4.8357) // Paris → Lyon
        assertTrue("$d", d in 390_000.0..393_000.0)
    }

    @Test
    fun batteryAndThermalValuesUseContractWords() {
        assertEquals("none", DeviceCollector.pluggedName(0))
        assertEquals("ac", DeviceCollector.pluggedName(BatteryManager.BATTERY_PLUGGED_AC))
        assertEquals("usb", DeviceCollector.pluggedName(BatteryManager.BATTERY_PLUGGED_USB))
        assertEquals("wireless", DeviceCollector.pluggedName(BatteryManager.BATTERY_PLUGGED_WIRELESS))
        assertEquals("ac", DeviceCollector.pluggedName(BatteryManager.BATTERY_PLUGGED_DOCK))
        assertEquals("charging", DeviceCollector.statusName(BatteryManager.BATTERY_STATUS_CHARGING))
        assertEquals("unknown", DeviceCollector.statusName(-1))
        assertEquals("overheat", DeviceCollector.healthName(BatteryManager.BATTERY_HEALTH_OVERHEAT))
        assertEquals("severe", DeviceCollector.thermalName(PowerManager.THERMAL_STATUS_SEVERE))
    }

    @Test
    fun oneUiVersionIsDecoded() {
        assertEquals("9.0", SystemProps.oneUiVersion("90000"))
        assertEquals("8.5", SystemProps.oneUiVersion("80500"))
        assertNull(SystemProps.oneUiVersion(null))
    }

    @Test
    fun declaredEventTypesAndIdsFollowTheContract() {
        val collectors = listOf(DeviceCollector(), LocationCollector(), io.github.erwsim.vigie.collectors.heartbeat.HeartbeatCollector())
        collectors.forEach { c ->
            assertTrue(c.id, Regex("^[a-z0-9_]+$").matches(c.id))
            c.eventTypes.forEach { assertTrue(it, EventTypes.isValid(it)) }
        }
        assertEquals(3, collectors.map { it.id }.toSet().size)
    }
}

class HeartbeatHarnessTest {
    @Test
    fun heartbeatCarriesTheContractFields() {
        io.github.erwsim.vigie.core.testing.CollectorHarness(
            io.github.erwsim.vigie.collectors.heartbeat.HeartbeatCollector(),
        ).use { h ->
            h.startAll()
            assertTrue(h.scheduled.contains("+heartbeat"))
            val beat = h.eventsOf("agent.heartbeat").single().data
            listOf("uptime_ms", "queue_depth", "queue_bytes", "dropped_total", "device_owner", "collectors").forEach {
                assertTrue("missing $it in $beat", beat.containsKey(it))
            }
            // No battery service on the JVM and no upload yet: absent, never null.
            assertTrue(!beat.containsKey("battery_pct") && !beat.containsKey("last_upload_ts"))
            assertEquals("\"running\"", beat["collectors"]!!.let { (it as kotlinx.serialization.json.JsonObject)["heartbeat"].toString() })
        }
    }

    @Test
    fun locationIsUnavailableWithoutPermission() {
        io.github.erwsim.vigie.core.testing.CollectorHarness(LocationCollector()).use { h ->
            h.startAll()
            assertEquals(io.github.erwsim.vigie.core.collector.CollectorRunState.UNAVAILABLE, h.status("location").state)
            assertTrue(h.status("location").reason!!.contains("ACCESS_FINE_LOCATION"))
        }
    }
}
