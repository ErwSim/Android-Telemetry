package io.github.erwsim.vigie.collectors

import android.telephony.TelephonyManager
import io.github.erwsim.vigie.collectors.cell.CellLogic
import io.github.erwsim.vigie.collectors.cell.CellLogic.Registration
import io.github.erwsim.vigie.collectors.cell.CellLogic.ServingCell
import io.github.erwsim.vigie.core.event.eventData
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class CellLogicTest {
    private val lteReg = Registration(packetSwitched = true, circuitSwitched = true, tech = "lte", roaming = false)
    private val lteCell = ServingCell("lte", "208", "01", tac = 1234, ci = 56789L, pci = 101, band = 3, signalDbm = -95, operator = "Orange F")

    @Test
    fun technologyNames() {
        assertEquals("lte", CellLogic.techName(TelephonyManager.NETWORK_TYPE_LTE))
        assertEquals("nr", CellLogic.techName(TelephonyManager.NETWORK_TYPE_NR))
        assertEquals("edge", CellLogic.techName(TelephonyManager.NETWORK_TYPE_EDGE))
        assertNull(CellLogic.techName(TelephonyManager.NETWORK_TYPE_UNKNOWN))
        assertTrue(CellLogic.is2g("gsm") && CellLogic.is2g("gprs") && CellLogic.is2g("edge") && CellLogic.is2g("1xrtt"))
        assertFalse(CellLogic.is2g("umts") || CellLogic.is2g("lte") || CellLogic.is2g(null))
    }

    @Test
    fun snapshotFromServingCellUsesContractFields() {
        val s = CellLogic.snapshot(listOf(lteReg), lteCell, roaming = false, operatorName = "Orange", operatorNumeric = "20801")
        assertEquals("lte", s.tech)
        assertEquals(1234, s.tac)
        assertEquals("Orange F", s.operator)
        val data = eventData { s.writeTo(this, lteCell.signalDbm) }
        Contract.check("net.cell", data)
        assertEquals(10, data.size)
        assertEquals("208", data["mcc"]!!.jsonPrimitive.content)
    }

    @Test
    fun withoutLocationOnlyNetworkLevelFields() {
        // No serving cell (no ACCESS_FINE_LOCATION): MCC/MNC from the operator code, no identity.
        val s = CellLogic.snapshot(listOf(lteReg), null, roaming = true, operatorName = "Orange", operatorNumeric = "20801")
        val data = eventData { s.writeTo(this, null) }
        Contract.check("net.cell", data)
        assertEquals(setOf("tech", "mcc", "mnc", "roaming", "operator"), data.keys)
        assertEquals("01", data["mnc"]!!.jsonPrimitive.content)
    }

    @Test
    fun outOfServiceIsTechNone() {
        val s = CellLogic.snapshot(emptyList(), lteCell, roaming = null, operatorName = null, operatorNumeric = null)
        assertEquals("none", s.tech)
        assertEquals(setOf("tech"), eventData { s.writeTo(this, null) }.keys)
        // Unknown registration state (null): the serving cell is used.
        assertEquals("lte", CellLogic.snapshot(null, lteCell, null, null, null).tech)
    }

    @Test
    fun aCellOfAnotherGenerationIsNotMixedIn() {
        // Registered in NR for data, CellInfo still lists the old LTE cell: no LTE identity on an NR event.
        val nrReg = lteReg.copy(tech = "nr")
        val s = CellLogic.snapshot(listOf(nrReg), lteCell, false, "Orange", "20801")
        assertEquals("nr", s.tech)
        assertNull(s.ci)
    }

    @Test
    fun signalOnlyChangesAreNotEvents() {
        val f = CellLogic.ChangeFilter(minIntervalMs = 20_000)
        val s = CellLogic.snapshot(listOf(lteReg), lteCell, false, null, null)
        assertTrue(f.offer(s, 0))
        assertFalse(f.offer(CellLogic.snapshot(listOf(lteReg), lteCell.copy(signalDbm = -110), false, null, null), 1_000))
        // Cell change within 20 s: postponed, then reported by the next callback.
        val other = s.copy(ci = 99L)
        assertFalse(f.offer(other, 5_000))
        assertTrue(f.offer(other, 21_000))
        // Technology change: always immediate.
        assertTrue(f.offer(other.copy(tech = "nr"), 22_000))
        assertFalse(f.offer(other.copy(tech = "nr"), 23_000))
    }

    @Test
    fun downgradeTo2gIsDetectedOnce() {
        val d = CellLogic.DowngradeDetector(cooldownMs = 30 * 60_000L)
        assertNull(d.onState("lte", null, 0))
        val alert = d.onState("gsm", "gsm", 1_000)
        assertEquals("lte → gsm", alert)
        // Staying on 2G: no new alert.
        assertNull(d.onState("edge", "edge", 2_000))
        // Back to LTE then 2G again within the cooldown: suppressed.
        assertNull(d.onState("lte", null, 3_000))
        assertNull(d.onState("gsm", "gsm", 4_000))
        // After the cooldown: alert again.
        assertNull(d.onState("lte", null, 40 * 60_000L))
        assertNotNull(d.onState("gsm", "gsm", 41 * 60_000L))
    }

    @Test
    fun noServiceDoesNotHideADowngrade() {
        val d = CellLogic.DowngradeDetector()
        d.onState("nr", null, 0)
        assertNull(d.onState("none", null, 1_000))
        assertEquals("nr → gsm", d.onState("gsm", "gsm", 2_000))
    }

    @Test
    fun voiceOn2gWhileDataOnLteIsADowngrade() {
        val regs = listOf(lteReg.copy(circuitSwitched = false), Registration(false, true, "gsm", false))
        assertEquals("lte", CellLogic.currentTech(regs, null))
        assertEquals("gsm", CellLogic.tech2g(regs, null))
        val d = CellLogic.DowngradeDetector()
        d.onState("lte", null, 0)
        assertEquals("lte → gsm", d.onState("lte", CellLogic.tech2g(regs, null), 1_000))
        // A stale 2G cell in CellInfo is ignored once the registration state is known.
        assertNull(CellLogic.tech2g(listOf(lteReg), ServingCell("gsm")))
        assertEquals("gsm", CellLogic.tech2g(null, ServingCell("gsm")))
    }

    @Test
    fun firstObservationOn2gIsReported() {
        val d = CellLogic.DowngradeDetector()
        assertEquals("unknown → gsm", d.onState("gsm", "gsm", 0))
    }

    @Test
    fun securityEventFields() {
        val s = CellLogic.snapshot(listOf(Registration(true, true, "gsm", false)), ServingCell("gsm", "208", "10", tac = 42, ci = 7L), false, null, null)
        val data = CellLogic.downgradeData("lte → gsm", s)
        Contract.check("net.cell_security", data)
        assertEquals("downgrade_2g", data["kind"]!!.jsonPrimitive.content)
        assertEquals("lte → gsm, plmn 208-10, tac 42, ci 7", data["detail"]!!.jsonPrimitive.content)
    }

    @Test
    fun invalidIdentityValuesAreDropped() {
        assertNull(CellLogic.valid(Int.MAX_VALUE))
        assertNull(CellLogic.valid(-1))
        assertEquals(5, CellLogic.valid(5))
        assertNull(CellLogic.valid(Long.MAX_VALUE))
        assertNull(CellLogic.dbm(Int.MAX_VALUE))
        assertEquals(-100, CellLogic.dbm(-100))
    }
}
