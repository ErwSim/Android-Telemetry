package io.github.erwsim.vigie.core.collector

import android.content.Context
import android.os.Handler
import android.os.HandlerThread
import android.os.Looper
import kotlinx.coroutines.CoroutineDispatcher
import io.github.erwsim.vigie.core.R
import io.github.erwsim.vigie.core.capability.Capabilities
import io.github.erwsim.vigie.core.event.AgentClock
import io.github.erwsim.vigie.core.event.EventTypes
import io.github.erwsim.vigie.core.event.Severity
import io.github.erwsim.vigie.core.settings.AgentSettings
import io.github.erwsim.vigie.core.sink.EventSink
import io.github.erwsim.vigie.core.sink.emit
import kotlinx.coroutines.CoroutineExceptionHandler
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.android.asCoroutineDispatcher
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull

/**
 * The collectors' thread. In production a `HandlerThread` (so Android callbacks can be bound to its
 * Looper); JVM tests pass a plain single-thread dispatcher and no Looper.
 */
class CollectorThreading(
    val looper: Looper?,
    val handler: Handler?,
    val dispatcher: CoroutineDispatcher,
    /** Blocking work of the collectors ([CollectorContext.io]); tests pass a tracked dispatcher. */
    val io: CoroutineDispatcher = Dispatchers.IO,
) {
    companion object {
        fun android(): CollectorThreading {
            val thread = HandlerThread("vigie-collectors").apply { start() }
            val handler = Handler(thread.looper)
            return CollectorThreading(thread.looper, handler, handler.asCoroutineDispatcher("vigie-collectors"))
        }
    }
}

/** Schedules [Collector.periodic] work (WorkManager in production). */
interface PeriodicScheduler {
    fun schedule(collectorId: String, spec: PeriodicSpec)
    fun cancel(collectorId: String)
}

/**
 * Owns the collectors' thread and drives every collector's lifecycle with fault isolation:
 * an exception in one collector is reported as `agent.collector_error` and never stops the others.
 */
class CollectorHost(
    private val appContext: Context,
    val collectors: List<Collector>,
    private val sink: EventSink,
    private val settings: AgentSettings,
    private val capabilities: Capabilities,
    private val clock: AgentClock,
    private val boot: BootInfo,
    private val statusSource: () -> AgentStatusSource,
    private val periodicScheduler: PeriodicScheduler,
    private val threading: CollectorThreading = CollectorThreading.android(),
    /** French texts of the availability reasons (resources in production). */
    private val text: (Int, Array<out Any>) -> String = { id, args -> appContext.getString(id, *args) },
) {
    private val dispatcher = threading.dispatcher
    private val hostJob = SupervisorJob()
    private val hostScope = CoroutineScope(hostJob + dispatcher + CoroutineExceptionHandler { _, e ->
        android.util.Log.e(TAG, "host error", e)
    })

    private class Running(val ctx: CollectorContext, val job: Job)

    // Only touched on the collectors' thread.
    private val running = HashMap<String, Running>()
    private val errorLog = HashMap<String, ArrayDeque<Long>>()
    private val suppressed = HashMap<String, Int>()
    /** Collectors stopped after a start failure or repeated errors, with the reason; cleared on restart/re-enable. */
    private val failed = HashMap<String, String>()
    private var active = false

    private val _statuses = MutableStateFlow(collectors.associate { it.id to CollectorStatus(CollectorRunState.DISABLED) })
    val statuses: StateFlow<Map<String, CollectorStatus>> = _statuses.asStateFlow()

    init {
        val ids = collectors.map { it.id }
        require(ids.toSet().size == ids.size) { "duplicate collector id in $ids" }
        ids.forEach { require(ID_REGEX.matches(it)) { "bad collector id '$it'" } }
        hostScope.launch {
            settings.changes.collect { key -> onSettingChanged(key) }
        }
    }

    fun isEnabled(c: Collector): Boolean = settings[settings.collectorEnabledKey(c.id, c.defaultEnabled)]

    fun setEnabled(id: String, enabled: Boolean) {
        val c = collectors.firstOrNull { it.id == id } ?: return
        settings.set(settings.collectorEnabledKey(c.id, c.defaultEnabled), enabled)
    }

    /** Starts every enabled and available collector (agent service start). */
    fun startAll() {
        hostScope.launch {
            active = true
            failed.clear()
            reconcileEach()
        }
    }

    /** Re-evaluates enablement and requirements (permission granted, Device Owner gained…). */
    fun reconcile() {
        hostScope.launch { reconcileEach() }
    }

    /** One collector failing to reconcile (bug, unexpected platform exception) never stops the others. */
    private suspend fun reconcileEach() {
        for (c in collectors) {
            try {
                reconcileOne(c)
            } catch (e: Exception) {
                onError(c.id, e, "reconcile")
            }
        }
    }

    /** Stops every collector; blocks for at most [timeoutMs] (called from the service's onDestroy). */
    fun stopAll(timeoutMs: Long = 3_000) {
        runBlocking {
            withTimeoutOrNull(timeoutMs) {
                withContext(dispatcher) {
                    active = false
                    running.keys.toList().forEach { stopOne(it, CollectorRunState.DISABLED, null) }
                    collectors.forEach { refreshStatus(it) }
                }
            }
        }
    }

    /** Entry point of periodic work: runs [Collector.collectOnce] even if the service is not running. */
    suspend fun collectOnce(id: String, reason: CollectReason) {
        val c = collectors.firstOrNull { it.id == id } ?: return
        withContext(dispatcher) {
            if (!isEnabled(c) || availability(c) !is Availability.Available) return@withContext
            val existing = running[id]?.ctx
            val ctx = existing ?: newContext(c, SupervisorJob(hostJob))
            try {
                c.collectOnce(ctx, reason)
            } catch (e: Exception) {
                onError(c.id, e, "collectOnce")
            } finally {
                if (existing == null) {
                    ctx.runCleanups()
                    ctx.scope.cancel()
                }
            }
        }
    }

    /** Requirement check, in French, without starting anything. Never throws. */
    fun availability(c: Collector): Availability = try {
        checkRequirements(c)
    } catch (e: Exception) {
        Availability.Unavailable(text(R.string.vigie_reason_check_failed, arrayOf(e.toString())))
    }

    private fun checkRequirements(c: Collector): Availability {
        val missing = c.requirements.filterIsInstance<Requirement.Permission>()
            .filter { !it.optional && !capabilities.hasPermission(it.name) }
        if (missing.isNotEmpty()) {
            return Availability.Unavailable(
                text(R.string.vigie_reason_missing_permission, arrayOf(missing.joinToString { shortName(it.name) })),
            )
        }
        if (c.requirements.any { it is Requirement.DeviceOwner } && !capabilities.isDeviceOwner()) {
            return Availability.Unavailable(text(R.string.vigie_reason_device_owner, emptyArray()))
        }
        c.requirements.filterIsInstance<Requirement.SystemFeature>().firstOrNull { !capabilities.hasSystemFeature(it.name) }
            ?.let { return Availability.Unavailable(text(R.string.vigie_reason_feature, arrayOf(it.name))) }
        return try {
            c.checkAvailability(newContextForCheck(c))
        } catch (e: Exception) {
            Availability.Unavailable(text(R.string.vigie_reason_check_failed, arrayOf(e.toString())))
        }
    }

    private suspend fun reconcileOne(c: Collector) {
        val shouldRun = active && isEnabled(c) && c.id !in failed && availability(c) is Availability.Available
        val isRunning = running.containsKey(c.id)
        when {
            shouldRun && !isRunning -> startOne(c)
            !shouldRun && isRunning -> stopOne(c.id, CollectorRunState.DISABLED, null)
        }
        if (isEnabled(c) && availability(c) is Availability.Available) {
            c.periodic?.let { periodicScheduler.schedule(c.id, it) }
        } else if (c.periodic != null) {
            periodicScheduler.cancel(c.id)
        }
        refreshStatus(c)
    }

    private suspend fun startOne(c: Collector) {
        val job = SupervisorJob(hostJob)
        val ctx = newContext(c, job)
        running[c.id] = Running(ctx, job)
        try {
            c.start(ctx)
            if (c.periodic?.runAtStart == true) {
                ctx.scope.launch { c.collectOnce(ctx, CollectReason.START) }
            }
        } catch (e: Exception) {
            onError(c.id, e, "start")
            val reason = text(R.string.vigie_reason_start_failed, arrayOf(e.toString()))
            failed[c.id] = reason
            stopOne(c.id, CollectorRunState.UNAVAILABLE, reason)
        }
    }

    private suspend fun stopOne(id: String, newState: CollectorRunState, reason: String?) {
        val r = running.remove(id) ?: return
        val c = collectors.first { it.id == id }
        try {
            c.stop(r.ctx)
        } catch (e: Exception) {
            onError(id, e, "stop")
        }
        r.ctx.runCleanups()
        r.job.cancel()
        if (reason != null) {
            _statuses.value = _statuses.value + (id to CollectorStatus(newState, reason, _statuses.value[id]?.lastError))
        }
    }

    private suspend fun onSettingChanged(key: String) {
        for (c in collectors) {
            // An exception here would end the observation of every later setting change.
            try {
                val enabledKey = settings.collectorEnabledKey(c.id, c.defaultEnabled).name
                if (key == enabledKey) {
                    failed.remove(c.id)
                    reconcileOne(c)
                } else if (c.settings.any { it.key.name == key } && running.containsKey(c.id)) {
                    stopOne(c.id, CollectorRunState.DISABLED, null)
                    reconcileOne(c)
                }
            } catch (e: Exception) {
                onError(c.id, e, "setting $key")
            }
        }
    }

    private fun refreshStatus(c: Collector) {
        val previous = _statuses.value[c.id]
        val missingOptional = c.requirements.filterIsInstance<Requirement.Permission>()
            .filter { !capabilities.hasPermission(it.name) }.map { it.name }
        val status = when {
            running.containsKey(c.id) -> CollectorStatus(CollectorRunState.RUNNING, null, previous?.lastError, missingOptional)
            !isEnabled(c) -> CollectorStatus(CollectorRunState.DISABLED, null, previous?.lastError, missingOptional)
            c.id in failed -> CollectorStatus(CollectorRunState.UNAVAILABLE, failed[c.id], previous?.lastError, missingOptional)
            else -> when (val a = availability(c)) {
                is Availability.Unavailable -> CollectorStatus(CollectorRunState.UNAVAILABLE, a.reason, previous?.lastError, missingOptional)
                // Enabled and available but the agent is not running.
                Availability.Available -> CollectorStatus(CollectorRunState.DISABLED, null, previous?.lastError, missingOptional)
            }
        }
        _statuses.value = _statuses.value + (c.id to status)
    }

    /** Called from any thread. Rate limit: 5 events per collector per hour, then a summary. */
    private fun onError(id: String, error: Throwable, where: String) {
        android.util.Log.w(TAG, "collector $id failed in $where", error)
        val text = "$where: ${error.javaClass.simpleName}: ${error.message.orEmpty()}".take(MAX_ERROR_LEN)
        hostScope.launch {
            val now = clock.elapsedRealtime()
            val log = errorLog.getOrPut(id) { ArrayDeque() }
            while (log.isNotEmpty() && now - log.first() > HOUR_MS) log.removeFirst()
            log.addLast(now)
            val status = _statuses.value[id]
            if (status != null) _statuses.value = _statuses.value + (id to status.copy(lastError = text))
            if (log.size <= MAX_ERROR_EVENTS_PER_HOUR) {
                val skipped = suppressed.remove(id) ?: 0
                sink.emit(EventTypes.AGENT_COLLECTOR_ERROR, Severity.NOTABLE) {
                    put("collector", id)
                    put("error", if (skipped > 0) "$text (+$skipped)" else text)
                }
            } else {
                suppressed[id] = (suppressed[id] ?: 0) + 1
            }
            if (log.size >= MAX_ERRORS_BEFORE_STOP && running.containsKey(id)) {
                val reason = text(R.string.vigie_reason_too_many_errors, emptyArray())
                failed[id] = reason
                stopOne(id, CollectorRunState.UNAVAILABLE, reason)
            }
        }
    }

    private fun newContext(c: Collector, job: Job): CollectorContext {
        val scope = CoroutineScope(job + dispatcher + CoroutineExceptionHandler { _, e -> onError(c.id, e, "coroutine") })
        return CollectorContext(
            collectorId = c.id,
            appContext = appContext,
            rawSink = sink,
            settings = settings,
            capabilities = capabilities,
            clock = clock,
            boot = boot,
            status = statusSource(),
            threading = threading,
            scope = scope,
            errorReporter = { e, where -> onError(c.id, e, where) },
        )
    }

    private fun newContextForCheck(c: Collector): CollectorContext = newContext(c, Job().apply { cancel() })

    companion object {
        private const val TAG = "VigieCollectors"
        private val ID_REGEX = Regex("^[a-z0-9_]+$")
        private const val HOUR_MS = 3_600_000L
        private const val MAX_ERROR_EVENTS_PER_HOUR = 5
        private const val MAX_ERRORS_BEFORE_STOP = 20
        private const val MAX_ERROR_LEN = 500

        fun shortName(permission: String): String = permission.substringAfterLast('.')
    }
}
