package io.github.erwsim.vigie.collectors

import io.github.erwsim.vigie.collectors.bluetooth.BleTrackerCollector
import io.github.erwsim.vigie.collectors.bluetooth.BluetoothCollector
import io.github.erwsim.vigie.collectors.bluetooth.TrackerDetector
import io.github.erwsim.vigie.collectors.bluetooth.TrackerDetector.Position
import io.github.erwsim.vigie.collectors.bluetooth.TrackerSignatures
import io.github.erwsim.vigie.core.event.Rfc3339
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class BluetoothTrackerTest {
    private fun bytes(vararg v: Int) = ByteArray(v.size) { v[it].toByte() }

    /** Flags AD + one more AD structure. */
    private fun adv(vararg ad: Int) = bytes(0x02, 0x01, 0x06, *ad)

    // Apple Find My, separated: len 0x1E, type 0xFF, company 0x004C (LE), 0x12 0x19, status, 22-byte key + 2 bytes.
    private fun findMy(status: Int) = adv(0x1E, 0xFF, 0x4C, 0x00, 0x12, 0x19, status, *IntArray(24) { 0xAB })

    @Test
    fun recognisesTrackerSignatures() {
        assertEquals("airtag", TrackerSignatures.classify(findMy(0x10)))
        assertEquals("unknown", TrackerSignatures.classify(findMy(0x20))) // Third-party Find My accessory.
        // Apple "nearby" (owner close by): type 0x12 length 0x02 → not reported.
        assertNull(TrackerSignatures.classify(adv(0x07, 0xFF, 0x4C, 0x00, 0x12, 0x02, 0x00, 0x01)))
        // Other Apple adverts (iBeacon 0x02 0x15).
        assertNull(TrackerSignatures.classify(adv(0x06, 0xFF, 0x4C, 0x00, 0x02, 0x15, 0x00)))
        // SmartTag: service data 0xFD5A.
        assertEquals("smarttag", TrackerSignatures.classify(adv(0x05, 0x16, 0x5A, 0xFD, 0x01, 0x02)))
        // Tile: 16-bit service UUID list with 0xFEED.
        assertEquals("tile", TrackerSignatures.classify(adv(0x03, 0x03, 0xED, 0xFE)))
        // Google Find My Device, unwanted-tracking frame 0x41 on 0xFEAA; an Eddystone UID (0x00) is not.
        assertEquals("unknown", TrackerSignatures.classify(adv(0x04, 0x16, 0xAA, 0xFE, 0x41)))
        assertNull(TrackerSignatures.classify(adv(0x04, 0x16, 0xAA, 0xFE, 0x00)))
    }

    @Test
    fun malformedAdvertisingDataIsHarmless() {
        assertNull(TrackerSignatures.classify(null as ByteArray?))
        assertNull(TrackerSignatures.classify(bytes()))
        assertNull(TrackerSignatures.classify(bytes(0x1E, 0xFF, 0x4C))) // Truncated.
        assertNull(TrackerSignatures.classify(bytes(0x00, 0x00, 0x00))) // Padding.
        assertEquals("0000fd5a-0000-1000-8000-00805f9b34fb", TrackerSignatures.uuid16(0xFD5A))
    }

    private val paris = Position(48.8566, 2.3522)
    private fun moved(metresNorth: Double) = Position(paris.lat + metresNorth / 111_195.0, paris.lon)

    @Test
    fun trackerFollowingTheDeviceIsReportedOnce() {
        val d = TrackerDetector(minSightings = 4, minDurationMs = 30 * 60_000L, minDistanceM = 500.0)
        val wall = 1_000_000_000_000L
        var alert: TrackerDetector.Alert? = null
        // Seen every 5 min for 40 min while walking 2 km.
        for (i in 0..8) {
            val t = i * 5 * 60_000L
            val a = d.onSighting("aa:bb:cc:dd:ee:ff", "airtag", -70, wall + t, t, moved(i * 250.0))
            if (a != null) {
                assertNull("reported twice", alert)
                alert = a
            }
        }
        assertNotNull(alert)
        assertEquals("airtag", alert!!.kind)
        assertEquals(wall, alert.firstSeenWallMs)
        assertTrue(alert.sightings >= 4)
        val data = BleTrackerCollector.alertData(alert)
        Contract.check("net.ble_tracker", data)
        assertEquals(Rfc3339.format(wall), data["first_seen"]!!.jsonPrimitive.content)
    }

    @Test
    fun aStaticNeighbourTrackerIsNotReported() {
        val d = TrackerDetector()
        for (i in 0..30) {
            val t = i * 5 * 60_000L
            assertNull(d.onSighting("11:22:33:44:55:66", "smarttag", -80, t, t, moved(10.0 * (i % 2))))
        }
    }

    @Test
    fun withoutPositionNothingIsReported() {
        val d = TrackerDetector()
        for (i in 0..30) assertNull(d.onSighting("11:22:33:44:55:66", "tile", -80, 0, i * 5 * 60_000L, null))
    }

    @Test
    fun briefEncountersAreNotReported() {
        // Seen a lot but within 10 minutes (bus ride neighbour), even while moving.
        val d = TrackerDetector()
        for (i in 0..20) {
            val t = i * 30_000L
            assertNull(d.onSighting("11:22:33:44:55:66", "airtag", -60, t, t, moved(i * 100.0)))
        }
    }

    @Test
    fun advertisementsAreCountedOncePerMinuteAndForgotten() {
        val d = TrackerDetector(minSightings = 4, minDurationMs = 0, minDistanceM = 0.0, sightingGapMs = 60_000, forgetAfterMs = 10 * 60_000L)
        // 100 adverts in 30 s count as one sighting.
        for (i in 0 until 100) assertNull(d.onSighting("aa:aa:aa:aa:aa:aa", "tile", -50, 0, i * 300L, paris))
        assertEquals(1, d.trackedCount)
        // Unseen for 11 min: forgotten, the count restarts.
        d.prune(11 * 60_000L)
        assertEquals(0, d.trackedCount)
    }

    @Test
    fun trackedSetIsBounded() {
        val d = TrackerDetector(maxTracked = 10)
        for (i in 0 until 50) d.onSighting("aa:aa:aa:aa:aa:%02x".format(i), "tile", -50, 0, 0, paris)
        assertEquals(10, d.trackedCount)
    }

    @Test
    fun bluetoothEventsUseContractFields() {
        Contract.check("net.bluetooth", BluetoothCollector.stateData(true))
        val data = BluetoothCollector.deviceData("connected", "  Écouteurs  ", "aa:bb:cc:dd:ee:ff", "le")
        Contract.check("net.bluetooth", data)
        assertEquals("Écouteurs", data["name"]!!.jsonPrimitive.content)
        assertEquals(setOf("event", "address"), BluetoothCollector.deviceData("disconnected", " ", "aa:bb:cc:dd:ee:ff", null).keys)
    }
}
