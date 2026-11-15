package io.github.erwsim.vigie.core.collector

import io.github.erwsim.vigie.core.testing.FakeClock
import io.github.erwsim.vigie.core.testing.MemoryPrefs
import io.github.erwsim.vigie.core.testing.TestContext
import io.github.erwsim.vigie.core.capability.Capabilities
import io.github.erwsim.vigie.core.settings.AgentSettings
import io.github.erwsim.vigie.core.settings.SettingKey
import io.github.erwsim.vigie.core.settings.SettingSpec
import io.github.erwsim.vigie.core.sink.EventSink
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.Executors

/** Lifecycle and fault isolation of the collector framework (no Android thread: plain dispatcher). */
class CollectorHostTest {
    @get:Rule
    val tmp = TemporaryFolder()

    private val executor = Executors.newSingleThreadExecutor()
    private val dispatcher = executor.asCoroutineDispatcher()
    private val events = CopyOnWriteArrayList<Pair<String, JsonObject>>()
    private val sink = object : EventSink {
        override fun emit(type: String, sev: Int, data: JsonObject) {
            events += type to data
        }
    }
    private val granted = HashSet<String>()
    private val settings = AgentSettings(MemoryPrefs()).also { it.sink = sink }
    private val scheduled = CopyOnWriteArrayList<String>()

    @After
    fun tearDown() {
        executor.shutdownNow()
    }

    private open class Recording(override val id: String) : Collector {
        override val titleRes = 0
        override val descriptionRes = 0
        override val eventTypes = listOf("device.screen")
        val log = CopyOnWriteArrayList<String>()
        lateinit var ctx: CollectorContext
        override suspend fun start(ctx: CollectorContext) {
            this.ctx = ctx
            log += "start"
            ctx.emit("device.screen") { put("state", "on") }
        }
        override suspend fun stop(ctx: CollectorContext) {
            log += "stop"
        }
        override suspend fun collectOnce(ctx: CollectorContext, reason: CollectReason) {
            log += "collect:$reason"
        }
    }

    private fun host(vararg collectors: Collector): CollectorHost {
        val context = TestContext(tmp.root)
        val capabilities = object : Capabilities(context) {
            override fun hasPermission(permission: String) = permission in granted
            override fun isDeviceOwner() = false
        }
        val status = object : AgentStatusSource {
            override val agentVersion = "test"
            override fun queueDepth() = 0L
            override fun queueBytes() = 0L
            override suspend fun droppedTotal() = 0L
            override fun isDeviceOwner() = false
            override fun collectorStates() = emptyMap<String, CollectorRunState>()
            override fun lastUploadMs(): Long? = null
        }
        return CollectorHost(
            appContext = context,
            collectors = collectors.toList(),
            sink = sink,
            settings = settings,
            capabilities = capabilities,
            clock = FakeClock(),
            boot = BootInfo("boot", isNewBoot = false, isFirstRun = false),
            statusSource = { status },
            periodicScheduler = object : PeriodicScheduler {
                override fun schedule(collectorId: String, spec: PeriodicSpec) {
                    scheduled += "+$collectorId"
                }
                override fun cancel(collectorId: String) {
                    scheduled += "-$collectorId"
                }
            },
            threading = CollectorThreading(null, null, dispatcher),
            text = { id, args -> "reason:$id ${args.joinToString()}".trim() },
        )
    }

    /** Lets every coroutine queued on the collectors' dispatcher run (several rounds: errors relaunch). */
    private fun settle() = runBlocking { repeat(5) { withContext(dispatcher) { } } }

    private fun CollectorHost.state(id: String) = statuses.value.getValue(id).state

    @Test
    fun aFailingCollectorDoesNotStopTheOthers() {
        val good = Recording("good")
        val bad = object : Recording("bad") {
            override suspend fun start(ctx: CollectorContext) = throw IllegalStateException("boom")
        }
        val host = host(bad, good)
        host.startAll()
        settle()
        assertEquals(CollectorRunState.RUNNING, host.state("good"))
        assertEquals(CollectorRunState.UNAVAILABLE, host.state("bad"))
        assertTrue(host.statuses.value.getValue("bad").reason!!.contains("boom"))
        val error = events.single { it.first == "agent.collector_error" }.second
        assertEquals("bad", error["collector"]!!.jsonPrimitive.content)
        assertTrue(error["error"]!!.jsonPrimitive.content.contains("IllegalStateException: boom"))
        assertTrue(events.any { it.first == "device.screen" })
    }

    @Test
    fun errorsInCallbacksAreReportedAndRateLimited() {
        val noisy = Recording("noisy")
        val host = host(noisy)
        host.startAll()
        settle()
        repeat(7) { noisy.ctx.guard("callback") { throw RuntimeException("cb $it") } }
        noisy.ctx.scope.launch { throw IllegalArgumentException("in coroutine") }
        settle()
        assertEquals(CollectorRunState.RUNNING, host.state("noisy"))
        assertEquals(5, events.count { it.first == "agent.collector_error" })
        // After 20 errors within an hour the collector is stopped, not the agent.
        repeat(20) { noisy.ctx.reportError(RuntimeException("again")) }
        settle()
        assertEquals(CollectorRunState.UNAVAILABLE, host.state("noisy"))
        assertTrue(noisy.log.contains("stop"))
    }

    @Test
    fun missingPermissionMakesItUnavailableUntilGranted() {
        val located = object : Recording("located") {
            override val requirements = listOf(
                Requirement.Permission("android.permission.ACCESS_FINE_LOCATION"),
                Requirement.Permission("android.permission.ACCESS_BACKGROUND_LOCATION", optional = true),
            )
        }
        val host = host(located)
        host.startAll()
        settle()
        assertEquals(CollectorRunState.UNAVAILABLE, host.state("located"))
        assertTrue(host.statuses.value.getValue("located").reason!!.contains("ACCESS_FINE_LOCATION"))
        granted += "android.permission.ACCESS_FINE_LOCATION"
        host.reconcile()
        settle()
        assertEquals(CollectorRunState.RUNNING, host.state("located"))
        assertEquals(listOf("android.permission.ACCESS_BACKGROUND_LOCATION"), host.statuses.value.getValue("located").missingPermissions)
    }

    @Test
    fun disablingStopsAndEmitsConfigChanged() {
        val c = Recording("c")
        val host = host(c)
        host.startAll()
        settle()
        host.setEnabled("c", false)
        settle()
        assertEquals(CollectorRunState.DISABLED, host.state("c"))
        assertEquals(listOf("start", "stop"), c.log.toList())
        val change = events.single { it.first == "agent.config_changed" }.second
        assertEquals("collector.c.enabled", change["key"]!!.jsonPrimitive.content)
        assertEquals("true", change["old"]!!.jsonPrimitive.content)
        assertEquals("false", change["new"]!!.jsonPrimitive.content)
        host.setEnabled("c", true)
        settle()
        assertEquals(CollectorRunState.RUNNING, host.state("c"))
    }

    @Test
    fun disabledByDefaultCollectorsDoNotStart() {
        val optIn = object : Recording("opt_in") {
            override val defaultEnabled = false
        }
        val host = host(optIn)
        host.startAll()
        settle()
        assertEquals(CollectorRunState.DISABLED, host.state("opt_in"))
        assertTrue(optIn.log.isEmpty())
    }

    @Test
    fun changingOneOfItsSettingsRestartsTheCollector() {
        val key = SettingKey.IntKey("tunable.interval_s", 60, 10, 600)
        val tunable = object : Recording("tunable") {
            override val settings = listOf(SettingSpec.IntSpec(key, 0))
        }
        val host = host(tunable)
        host.startAll()
        settle()
        settings.set(key, 120)
        settle()
        assertEquals(listOf("start", "stop", "start"), tunable.log.toList())
        assertEquals(CollectorRunState.RUNNING, host.state("tunable"))
    }

    @Test
    fun periodicWorkIsScheduledAndRunsCollectOnce() = runBlocking {
        val periodic = object : Recording("periodic") {
            override val periodic = PeriodicSpec(intervalMinutes = 15, runAtStart = true)
        }
        val host = host(periodic)
        host.startAll()
        settle()
        assertTrue(scheduled.contains("+periodic"))
        assertTrue(periodic.log.contains("collect:START"))
        host.collectOnce("periodic", CollectReason.PERIODIC)
        assertTrue(periodic.log.contains("collect:PERIODIC"))
        host.setEnabled("periodic", false)
        settle()
        assertTrue(scheduled.contains("-periodic"))
    }

    @Test
    fun stopAllStopsEverything() {
        val a = Recording("a")
        val b = Recording("b")
        val host = host(a, b)
        host.startAll()
        settle()
        host.stopAll()
        assertEquals(listOf("start", "stop"), a.log.toList())
        assertEquals(listOf("start", "stop"), b.log.toList())
        assertEquals(CollectorRunState.DISABLED, host.state("a"))
    }
}
