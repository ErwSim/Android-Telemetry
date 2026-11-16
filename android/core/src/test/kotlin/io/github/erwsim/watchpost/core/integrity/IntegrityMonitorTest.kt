package io.github.erwsim.watchpost.core.integrity

import io.github.erwsim.watchpost.core.capability.Capabilities
import io.github.erwsim.watchpost.core.sink.EventSink
import io.github.erwsim.watchpost.core.testing.FakeClock
import io.github.erwsim.watchpost.core.testing.MemoryPrefs
import io.github.erwsim.watchpost.core.testing.TestContext
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/** `agent.tamper` for a lost Device Owner role, except after an announced voluntary removal. */
class IntegrityMonitorTest {
    @get:Rule
    val tmp = TemporaryFolder()

    private val tampers = ArrayList<String>()
    private var owner = true
    private val clock = FakeClock()
    private val prefs = MemoryPrefs()

    private fun monitor(): IntegrityMonitor {
        val context = TestContext(tmp.root)
        val capabilities = object : Capabilities(context) {
            override fun isDeviceOwner() = owner
            override fun hasPermission(permission: String) = true
            override fun declaredRuntimePermissions() = emptyList<String>()
        }
        val sink = object : EventSink {
            override fun emit(type: String, sev: Int, data: JsonObject, originTsMs: Long?) {
                assertEquals("agent.tamper", type)
                tampers += data["kind"]!!.jsonPrimitive.content
            }
        }
        return IntegrityMonitor(context, prefs, capabilities, sink, clock)
    }

    @Test
    fun unannouncedLossIsTampering() {
        val m = monitor()
        m.checkPermissionsAndOwnership()
        owner = false
        m.onAdminDisabled("io.github.erwsim.watchpost")
        m.checkPermissionsAndOwnership()
        assertEquals(listOf("admin_disabled", "device_owner_lost"), tampers)
    }

    @Test
    fun announcedRemovalIsNotTampering_andTheAnnouncementIsConsumed() {
        val m = monitor()
        m.checkPermissionsAndOwnership()
        m.expectOwnershipLoss()
        owner = false
        m.onAdminDisabled("io.github.erwsim.watchpost")
        // A later process (same prefs) sees the loss: still expected.
        monitor().checkPermissionsAndOwnership()
        assertTrue(tampers.isEmpty())
        assertFalse(m.isOwnershipLossExpected())
        // Device Owner again, then lost without announcement: tampering again.
        owner = true
        m.checkPermissionsAndOwnership()
        owner = false
        m.checkPermissionsAndOwnership()
        assertEquals(listOf("device_owner_lost"), tampers)
    }

    @Test
    fun announcementExpiresOrIsCancelled() {
        val m = monitor()
        m.checkPermissionsAndOwnership()
        m.expectOwnershipLoss(windowMs = 60_000)
        clock.advance(61_000)
        owner = false
        m.checkPermissionsAndOwnership()
        assertEquals(listOf("device_owner_lost"), tampers)

        tampers.clear()
        owner = true
        m.checkPermissionsAndOwnership()
        m.expectOwnershipLoss()
        m.cancelOwnershipLossExpectation() // clearDeviceOwnerApp failed
        owner = false
        m.checkPermissionsAndOwnership()
        assertEquals(listOf("device_owner_lost"), tampers)
    }
}
