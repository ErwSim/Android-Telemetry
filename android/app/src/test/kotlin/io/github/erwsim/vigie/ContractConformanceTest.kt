package io.github.erwsim.vigie

import io.github.erwsim.vigie.collectors.CollectorsModule
import io.github.erwsim.vigie.core.collector.CollectReason
import io.github.erwsim.vigie.core.collector.Collector
import io.github.erwsim.vigie.core.event.EventTypes
import io.github.erwsim.vigie.core.testing.CollectorHarness
import io.github.erwsim.vigie.core.testing.Contract
import io.github.erwsim.vigie.core.testing.TestContext
import io.github.erwsim.vigie.policy.PolicyModule
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.nio.file.Files

/**
 * End-to-end conformity of what the APK emits with `docs/contrat/contrat.md` §2 and its "Précisions"
 * (single reference: [Contract], testFixtures of `:core`).
 *
 * Every collector of the APK (the `:collectors` and `:policy` entry points, wired as in
 * [VigieApplication]) produces its typical events through the same code paths as on the device:
 * its public data builders, its log processors, or the harness on the JVM. Each event type a
 * collector declares is either produced here or listed in [notOnTheJvm] with the reason.
 */
class ContractConformanceTest {
    private val context = TestContext(Files.createTempDirectory("vigie-contract").toFile())
    private val all: List<Collector> = CollectorsModule.all(context) + PolicyModule.collectors(context)

    /** Types emitted only from an Android callback or a system service absent on the JVM (checked by reading). */
    private val notOnTheJvm = mapOf(
        "device.inventory" to "Build, Environment and StatFs (null in the JVM stubs)",
        "device.storage" to "Environment and StatFs (null in the JVM stubs)",
        "device.boot" to "getprop after a real reboot",
        "device.shutdown" to "ACTION_SHUTDOWN broadcast",
        "device.screen" to "screen broadcasts",
        "device.battery" to "sticky ACTION_BATTERY_CHANGED",
        "device.power_save" to "PowerManager",
        "device.thermal" to "thermal listener",
        "device.time_changed" to "ACTION_TIME_CHANGED broadcast",
        "device.timezone_changed" to "ACTION_TIMEZONE_CHANGED broadcast",
        "device.airplane_mode" to "ACTION_AIRPLANE_MODE_CHANGED broadcast",
        "location.provider" to "LocationManager",
        "net.hotspot" to "hotspot broadcast",
        "net.nfc" to "NFC adapter broadcast",
    )

    private val emitted = HashMap<String, MutableList<Pair<String, JsonObject>>>() // producer -> (type, data)

    private fun sample(collector: String, type: String, data: JsonObject) {
        emitted.getOrPut(collector) { ArrayList() } += type to data
    }

    @Test
    fun theApkHasTheExpectedCollectorsAndOnlyContractTypes() {
        val ids = all.map { it.id }
        assertEquals(
            listOf(
                "heartbeat", "device", "usb", "location", "connectivity", "wifi", "wifi_scan", "hotspot", "nfc", "cell", "bluetooth",
                "ble_tracker", "net_usage", "apps", "special_access", "foreground", "notifications", "camera", "microphone",
                "security_log", "network_log", "posture",
            ),
            ids,
        )
        assertEquals(ids.size, ids.toSet().size)
        for (c in all) {
            for (t in c.eventTypes) {
                assertTrue("${c.id}: $t", EventTypes.isValid(t))
                assertTrue("${c.id}: $t is not in the contract catalogue", t in Contract.TYPES)
            }
        }
    }

    @Test
    fun heartbeatListsEveryCollectorWithAContractState() {
        CollectorHarness(*all.toTypedArray()).use { h ->
            h.startAll()
            h.collectOnce("heartbeat")
            val beat = h.eventsOf(EventTypes.AGENT_HEARTBEAT).last().data
            Contract.check(EventTypes.AGENT_HEARTBEAT, beat)
            val states = (beat["collectors"] as JsonObject).mapValues { (it.value as JsonPrimitive).content }
            assertEquals(all.map { it.id }.toSet(), states.keys)
            assertTrue(states.toString(), states.values.all { it in Contract.COLLECTOR_STATES })
            // Not Device Owner on the JVM: the three :policy collectors wait for the role.
            listOf("security_log", "network_log").forEach { assertEquals(it, "unavailable", states[it]) }
            assertEquals("disabled", states["wifi_scan"]) // opt-in
            // Whatever ran on the JVM (heartbeat, inventory, storage, errors…) follows the contract.
            h.events.forEach { Contract.check(it.type, it.data) }
        }
    }

    @Test
    fun everyCollectorProducesContractEvents() {
        // Harness, public data builders, log processors and policy engine: see [ApkSamples].
        val samples = ApkSamples(all).produce()
        samples.forEach { sample(it.producer, it.type, it.data) }
        assertEquals(4, samples.count { it.producer == "policy_engine" })
        assertTrue("several inventory parts", samples.count { it.type == "app.inventory" } > 1)
        // Events read after the fact carry their time of origin.
        samples.filter { it.type in setOf("app.foreground", "net.dns", "net.connect", "security.log") }.forEach {
            assertTrue(it.type, it.originTsMs != null)
        }

        // ---- every sample follows the contract, and every declared type is covered
        for ((_, events) in emitted) events.forEach { (type, data) -> Contract.check(type, data) }
        val produced = emitted.values.flatten().map { it.first }.toSet()
        for (c in all) {
            val missing = c.eventTypes.filter { it !in produced && it !in notOnTheJvm }
            assertTrue("${c.id}: no sample for $missing", missing.isEmpty())
        }
    }

    @Test
    fun heartbeatCollectorReportsTheRealHostStates() {
        CollectorHarness(*all.toTypedArray()).use { h ->
            h.granted += "android.permission.ACCESS_FINE_LOCATION"
            h.startAll()
            h.collectOnce("heartbeat", CollectReason.MANUAL)
            val states = (h.eventsOf(EventTypes.AGENT_HEARTBEAT).last().data["collectors"] as JsonObject)
                .mapValues { (it.value as JsonPrimitive).content }
            all.forEach { c -> assertEquals(c.id, h.status(c.id).state.wire, states[c.id]) }
        }
    }
}
