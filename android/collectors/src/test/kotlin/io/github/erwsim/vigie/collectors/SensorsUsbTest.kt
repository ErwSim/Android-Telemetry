package io.github.erwsim.vigie.collectors

import io.github.erwsim.vigie.core.testing.Contract
import android.media.MediaRecorder
import io.github.erwsim.vigie.collectors.common.RateLimiter
import io.github.erwsim.vigie.collectors.common.ScreenState
import io.github.erwsim.vigie.collectors.device.UsbLogic
import io.github.erwsim.vigie.collectors.sensors.AppOpsDump
import io.github.erwsim.vigie.collectors.sensors.CameraCollector
import io.github.erwsim.vigie.collectors.sensors.CameraStateTracker
import io.github.erwsim.vigie.collectors.sensors.MicState
import io.github.erwsim.vigie.collectors.sensors.MicrophoneCollector
import io.github.erwsim.vigie.collectors.sensors.Recording
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class SensorsUsbTest {
    @Test
    fun cameraReportsTransitionsNotTheInitialAvailableBurst() {
        val t = CameraStateTracker()
        // Registration: every camera is reported available → nothing to emit.
        assertNull(t.onAvailability("0", false))
        assertNull(t.onAvailability("1", false))
        assertEquals(true, t.onAvailability("1", true))
        assertNull(t.onAvailability("1", true))
        assertEquals(false, t.onAvailability("1", false))
        // A camera already in use when we start is reported.
        assertEquals(true, CameraStateTracker().onAvailability("0", true))
    }

    @Test
    fun cameraEventFields() {
        val data = CameraCollector.data("1", true, ScreenState(screenOn = false, locked = true), null)
        Contract.check("sensor.camera", data)
        assertEquals(setOf("camera_id", "in_use", "screen_on", "locked"), data.keys) // No package: unknown.
        Contract.check("sensor.camera", CameraCollector.data("0", false, ScreenState(null, null), "org.cam"))
    }

    @Test
    fun microphoneStateReduction() {
        assertEquals(MicState.IDLE, MicState.from(emptyList()))
        val s = MicState.from(listOf(Recording(MediaRecorder.AudioSource.MIC, silenced = true), Recording(MediaRecorder.AudioSource.VOICE_COMMUNICATION, silenced = false)))
        assertEquals(MicState(true, "voice_communication", false), s)
        assertEquals(MicState(true, "mic", true), MicState.from(listOf(Recording(MediaRecorder.AudioSource.MIC, true))))
        assertEquals("hotword", MicState.sourceName(1999))
        assertEquals("source_4242", MicState.sourceName(4242))

        val rec = MicrophoneCollector.data(s, ScreenState(true, false), null)
        Contract.check("sensor.microphone", rec)
        assertEquals(setOf("recording", "source", "silenced", "screen_on", "locked"), rec.keys)
        val idle = MicrophoneCollector.data(MicState.IDLE, ScreenState(true, false), null)
        assertEquals(setOf("recording", "screen_on", "locked"), idle.keys)
    }

    @Test
    fun appOpsDumpParserFindsRunningPackagesOnly() {
        val dump = """
            Current AppOps Service state:
              Settings:
                top_state_settle_time=+5s0ms
              Uid u0a201:
                state=top
                Package org.recorder:
                  RECORD_AUDIO (allow):
                    null=[
                      Access: [top-s] 2026-11-15 10:00:00.123 (-5s123ms) duration=+1s2ms
                    ]
                Package org.camera:
                  CAMERA (allow):
                    null=[
                      Access: [top-s] 2026-11-15 10:00:01.000 (-2s0ms)
                      Running start at: +2s0ms
                    ]
              Uid u0a202:
                Package org.other:
                  CAMERA (allow):
                    null=[
                      Access: [fg-s] 2026-11-14 09:00:00.000 (-1d1h0m0s0ms) duration=+30s
                    ]
                  RECORD_AUDIO (allow):
                    null=[
                      Running start at: +10s0ms
                    ]
        """.trimIndent()
        assertEquals(listOf("org.camera"), AppOpsDump.parseRunning(dump, "CAMERA"))
        assertEquals(listOf("org.other"), AppOpsDump.parseRunning(dump, "RECORD_AUDIO"))
        assertTrue(AppOpsDump.parseRunning(dump, "CAMERA", exclude = "org.camera").isEmpty())
        assertTrue(AppOpsDump.parseRunning("", "CAMERA").isEmpty())
        assertTrue(AppOpsDump.parseRunning("garbage\n  Running start at: +1s", "CAMERA").isEmpty())
    }

    @Test
    fun usbStateParsingAndEvents() {
        val extras = mapOf("connected" to true, "configured" to true, "mtp" to true, "adb" to true, "rndis" to false)
        val cable = UsbLogic.cableState { extras[it] ?: false }
        assertEquals(listOf("mtp", "adb"), cable.functions)
        val unplugged = UsbLogic.cableState { false }
        assertFalse(unplugged.connected)
        assertTrue(unplugged.functions.isEmpty())

        val charging = UsbLogic.Snapshot(UsbLogic.CableState(true, false, emptyList()), null, null)
        val debug = UsbLogic.Snapshot(cable, null, null)
        assertTrue(UsbLogic.isNotable(charging, debug)) // ADB appears.
        assertFalse(UsbLogic.isNotable(debug, debug.copy(cable = cable.copy(configured = false))))
        val key = UsbLogic.Snapshot(unplugged, UsbLogic.DeviceInfo(0x1050, 0x0407, 0, "Yubico", "YubiKey OTP+FIDO+CCID"), null)
        assertTrue(UsbLogic.isNotable(null, key))

        val data = UsbLogic.data(key)
        Contract.check("device.usb", data)
        assertEquals(true, data["connected"].toString().toBoolean()) // A device plugged into the phone.
        assertEquals(5, (data["device"] as JsonObject).size)
        assertEquals(0, (data["functions"] as JsonArray).size)
        Contract.check("device.usb", UsbLogic.data(UsbLogic.Snapshot(cable, null, UsbLogic.AccessoryInfo("Acme", null, "1.0"))))
    }

    @Test
    fun rateLimiterSlidingWindow() {
        val l = RateLimiter(2, 1_000)
        assertTrue(l.tryAcquire(0))
        assertTrue(l.tryAcquire(10))
        assertFalse(l.tryAcquire(500))
        assertTrue(l.tryAcquire(1_000))
        assertFalse(l.tryAcquire(1_005))
        assertTrue(l.tryAcquire(2_100))
    }
}
