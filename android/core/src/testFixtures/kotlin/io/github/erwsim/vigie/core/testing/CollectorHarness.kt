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
import io.github.erwsim.vigie.core.event.EventTypes
import io.github.erwsim.vigie.core.event.Severity
import io.github.erwsim.vigie.core.settings.AgentSettings
import io.github.erwsim.vigie.core.sink.EventSink
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonObject
import java.io.File
import java.nio.file.Files
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.Executor
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.atomic.AtomicInteger

/**
 * Runs collectors on the JVM through the real [CollectorHost] (requirements, settings, fault
 * isolation, periodic scheduling) and records every emitted event.
 *
 * Both the collectors' thread and the blocking-work dispatcher (`ctx.io`) are tracked executors:
 * [settle] returns once neither has queued or running work, so work that hops to `ctx.io` and back
 * is awaited (no race). A coroutine suspended in `delay` is idle for [settle]: use [awaitEvents].
 *
 * Limits (no Android runtime, no Robolectric): system services are null, broadcasts are never
 * delivered and `ctx.handler`/`ctx.looper` throw. System features are those in [features].
 * Test the logic of a collector by extracting it into pure functions (see MotionTracker) and its
 * wiring with [collectOnce]/[startAll].
 */
class CollectorHarness(
    vararg collectors: Collector,
    dir: File = Files.createTempDirectory("vigie-harness").toFile(),
) : AutoCloseable {
    /** [tsMs] is the event's `ts`: the origin time when one was given, else the harness clock. */
    data class Recorded(val type: String, val sev: Int, val data: JsonObject, val tsMs: Long, val originTsMs: Long? = null)

    val events = CopyOnWriteArrayList<Recorded>()
    val granted: MutableSet<String> = java.util.concurrent.ConcurrentHashMap.newKeySet()
    val features: MutableSet<String> = java.util.concurrent.ConcurrentHashMap.newKeySet()
    @Volatile
    var deviceOwner = false
    val scheduled = CopyOnWriteArrayList<String>()
    val clock = FakeClock()
    val context = TestContext(dir)
    val sink = object : EventSink {
        override fun emit(type: String, sev: Int, data: JsonObject, originTsMs: Long?) {
            require(EventTypes.isValid(type)) { "invalid type $type" }
            require(Severity.isValid(sev)) { "invalid severity $sev" }
            require(originTsMs == null || originTsMs > 0) { "invalid origin time $originTsMs" }
            events += Recorded(type, sev, data, originTsMs ?: clock.now, originTsMs)
        }
    }
    val settings = AgentSettings(MemoryPrefs()).also { it.sink = sink }

    private val main = TrackedExecutor(Executors.newSingleThreadExecutor())
    private val io = TrackedExecutor(Executors.newFixedThreadPool(4))

    val capabilities = object : Capabilities(context) {
        override fun hasPermission(permission: String) = permission in granted
        override fun isDeviceOwner() = deviceOwner
        override fun hasSystemFeature(feature: String) = feature in features
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
        threading = CollectorThreading(null, null, main.asCoroutineDispatcher(), io.asCoroutineDispatcher()),
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

    /**
     * Waits until the collectors' thread and `ctx.io` have no queued or running task, several
     * times in a row (a finishing task may enqueue the next step). Fails after [timeoutMs].
     */
    fun settle(timeoutMs: Long = 10_000) {
        val deadline = System.currentTimeMillis() + timeoutMs
        var quiet = 0
        while (quiet < QUIET_ROUNDS) {
            check(System.currentTimeMillis() < deadline) { "collectors still busy after $timeoutMs ms" }
            if (main.busy() || io.busy()) {
                quiet = 0
                Thread.sleep(1)
            } else {
                quiet++
                Thread.yield()
            }
        }
    }

    /** For work that suspends in `delay`: waits until [count] events of [type] were recorded. */
    fun awaitEvents(type: String, count: Int = 1, timeoutMs: Long = 10_000): List<Recorded> {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (eventsOf(type).size < count) {
            check(System.currentTimeMillis() < deadline) { "only ${eventsOf(type).size} $type event(s) after $timeoutMs ms" }
            Thread.sleep(5)
        }
        settle()
        return eventsOf(type)
    }

    override fun close() {
        host.stopAll()
        main.shutdown()
        io.shutdown()
    }

    /** Counts tasks submitted and not finished yet. */
    private class TrackedExecutor(private val delegate: ExecutorService) : Executor {
        private val inFlight = AtomicInteger()

        override fun execute(command: Runnable) {
            inFlight.incrementAndGet()
            try {
                delegate.execute {
                    try {
                        command.run()
                    } finally {
                        inFlight.decrementAndGet()
                    }
                }
            } catch (e: RejectedExecutionException) {
                inFlight.decrementAndGet()
                throw e
            }
        }

        fun busy(): Boolean = inFlight.get() > 0

        fun shutdown() {
            delegate.shutdownNow()
        }
    }

    private companion object {
        const val QUIET_ROUNDS = 20
    }
}
