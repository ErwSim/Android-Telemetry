package io.github.erwsim.vigie.core.testing

import io.github.erwsim.vigie.core.capability.Capabilities
import io.github.erwsim.vigie.core.collector.AgentStatusSource
import io.github.erwsim.vigie.core.collector.BootInfo
import io.github.erwsim.vigie.core.collector.CollectReason
import io.github.erwsim.vigie.core.collector.Collector
import io.github.erwsim.vigie.core.collector.CollectorHost
import io.github.erwsim.vigie.core.collector.CollectorRunState
import io.github.erwsim.vigie.core.collector.CollectorStatus
import io.github.erwsim.vigie.core.collector.CollectorThreading
import io.github.erwsim.vigie.core.collector.PeriodicScheduler
import io.github.erwsim.vigie.core.collector.PeriodicSpec
import io.github.erwsim.vigie.core.settings.AgentSettings
import io.github.erwsim.vigie.core.sink.EventSink
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.JsonObject
import java.io.File
import java.nio.file.Files
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.Executors

/**
 * Runs collectors on the JVM through the real [CollectorHost] (requirements, settings, fault
 * isolation, periodic scheduling) and records every emitted event.
 *
 * Limits (no Android runtime, no Robolectric): system services are null, broadcasts are never
 * delivered and `ctx.handler`/`ctx.looper` throw. Test the logic of a collector by extracting it
 * into pure functions (see MotionTracker) and its wiring with [collectOnce]/[startAll].
 */
class CollectorHarness(
    vararg collectors: Collector,
    dir: File = Files.createTempDirectory("vigie-harness").toFile(),
) : AutoCloseable {
    data class Recorded(val type: String, val sev: Int, val data: JsonObject)

    val events = CopyOnWriteArrayList<Recorded>()
    val granted: MutableSet<String> = java.util.concurrent.ConcurrentHashMap.newKeySet()
    @Volatile
    var deviceOwner = false
    val scheduled = CopyOnWriteArrayList<String>()
    val clock = FakeClock()
    val context = TestContext(dir)
    val sink = object : EventSink {
        override fun emit(type: String, sev: Int, data: JsonObject) {
            require(io.github.erwsim.vigie.core.event.EventTypes.isValid(type)) { "invalid type $type" }
            events += Recorded(type, sev, data)
        }
    }
    val settings = AgentSettings(MemoryPrefs()).also { it.sink = sink }

    private val executor = Executors.newSingleThreadExecutor()
    private val dispatcher = executor.asCoroutineDispatcher()

    val capabilities = object : Capabilities(context) {
        override fun hasPermission(permission: String) = permission in granted
        override fun isDeviceOwner() = deviceOwner
    }

    var status: AgentStatusSource = object : AgentStatusSource {
        override val agentVersion = "test"
        override fun queueDepth() = 0L
        override fun queueBytes() = 0L
        override suspend fun droppedTotal() = 0L
        override fun isDeviceOwner() = deviceOwner
        override fun collectorStates(): Map<String, CollectorRunState> = host.statuses.value.mapValues { it.value.state }
        override fun lastUploadMs(): Long? = null
    }

    val host = CollectorHost(
        appContext = context,
        collectors = collectors.toList(),
        sink = sink,
        settings = settings,
        capabilities = capabilities,
        clock = clock,
        boot = BootInfo("test-boot", isNewBoot = false, isFirstRun = false),
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

    fun startAll() {
        host.startAll()
        settle()
    }

    fun collectOnce(id: String, reason: CollectReason = CollectReason.MANUAL) {
        runBlocking { host.collectOnce(id, reason) }
        settle()
    }

    fun status(id: String): CollectorStatus = host.statuses.value.getValue(id)

    fun eventsOf(type: String): List<Recorded> = events.filter { it.type == type }

    /** Lets queued work on the collectors' dispatcher run (several rounds: errors relaunch work). */
    fun settle() = runBlocking { repeat(5) { withContext(dispatcher) { } } }

    override fun close() {
        host.stopAll()
        executor.shutdownNow()
    }
}
