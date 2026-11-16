package io.github.erwsim.watchpost.core.sink

import io.github.erwsim.watchpost.core.event.AgentClock
import io.github.erwsim.watchpost.core.event.Event
import io.github.erwsim.watchpost.core.event.EventTypes
import io.github.erwsim.watchpost.core.event.Severity
import io.github.erwsim.watchpost.core.event.UlidGenerator
import io.github.erwsim.watchpost.core.event.stripNulls
import io.github.erwsim.watchpost.core.outbox.Outbox
import io.github.erwsim.watchpost.core.outbox.PendingEvent
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.serialization.json.JsonObject
import java.util.concurrent.atomic.AtomicBoolean

/** Called after every successful write, on the sink's coroutine. */
fun interface FlushListener {
    suspend fun onFlushed(events: List<Event>)
}

/**
 * [EventSink] backed by the [Outbox], with grouped writes:
 * events wait in memory for at most [flushDelayMs] (default 3 s) and are written together in a
 * single transaction; `sev >= 2` or [maxPending] pending events trigger an immediate write.
 *
 * Trade-off (documented in ARCHITECTURE-CODE.md): on a hard kill, events emitted during the last
 * [flushDelayMs] that were not yet written are lost. They never received a `seq`, so the server
 * sees no gap and no duplicate. [flushBlocking] is called on shutdown and service stop.
 */
class OutboxEventSink(
    private val outbox: Outbox,
    private val clock: AgentClock,
    private val bootId: String,
    private val scope: CoroutineScope,
    private val flushDelayMs: Long = 3_000,
    private val maxPending: Int = 200,
    private val ulid: UlidGenerator = UlidGenerator(),
    recentCapacity: Int = 300,
) : EventSink, FlushableSink {
    private val lock = Any()
    private var pending = ArrayList<PendingEvent>()
    private var droppedInMemory = 0L
    private val urgent = AtomicBoolean(false)
    private val wake = Channel<Unit>(Channel.CONFLATED)
    private val flushMutex = Mutex()
    private var loop: Job? = null

    @Volatile
    var listener: FlushListener? = null

    /** Last emitted events, newest first (local event log, transparency). */
    val recent = RecentEvents(recentCapacity)

    private val _lastWriteError = MutableStateFlow<String?>(null)
    val lastWriteError: StateFlow<String?> = _lastWriteError.asStateFlow()

    fun start() {
        if (loop != null) return
        loop = scope.launch {
            while (isActive) {
                wake.receive()
                if (!urgent.get()) {
                    withTimeoutOrNull(flushDelayMs) {
                        while (!urgent.get()) wake.receive()
                    }
                }
                urgent.set(false)
                if (!flushNow()) {
                    delay(WRITE_RETRY_MS)
                    wake.trySend(Unit)
                }
            }
        }
    }

    override fun emit(type: String, sev: Int, data: JsonObject, originTsMs: Long?) {
        require(EventTypes.isValid(type)) { "invalid event type '$type'" }
        require(Severity.isValid(sev)) { "invalid severity $sev" }
        require(originTsMs == null || originTsMs > 0) { "invalid origin time $originTsMs" }
        val now = clock.nowMillis()
        val elapsedNow = clock.elapsedRealtime()
        val event = PendingEvent(
            // The ULID keeps the emission time: ids stay monotonic whatever the origin time.
            id = ulid.next(now),
            tsMs = originTsMs ?: now,
            elapsedMs = if (originTsMs == null) elapsedNow else OriginTime.elapsedAt(originTsMs, now, elapsedNow),
            bootId = bootId,
            type = type,
            sev = sev,
            data = stripNulls(data) as JsonObject,
        )
        val size: Int
        synchronized(lock) {
            if (pending.size >= MAX_IN_MEMORY) dropOneInMemory()
            pending.add(event)
            size = pending.size
        }
        if (sev >= Severity.WARNING || size >= maxPending) urgent.set(true)
        wake.trySend(Unit)
    }

    /** Lowest severity, oldest first: same rule as the outbox purge. Only reached if writes keep failing. */
    private fun dropOneInMemory() {
        var victim = 0
        for (i in pending.indices) {
            if (pending[i].sev < pending[victim].sev) victim = i
            if (pending[victim].sev == Severity.INFO) break
        }
        pending.removeAt(victim)
        droppedInMemory++
    }

    /** Writes everything pending now. Returns false if the write failed (events are kept in memory). */
    suspend fun flushNow(): Boolean = flushMutex.withLock {
        val batch: List<PendingEvent>
        val droppedNow: Long
        synchronized(lock) {
            batch = pending
            pending = ArrayList()
            droppedNow = droppedInMemory
            droppedInMemory = 0
        }
        if (batch.isEmpty() && droppedNow == 0L) return@withLock true
        var droppedCounted = droppedNow == 0L
        val events = try {
            if (!droppedCounted) {
                outbox.addDropped(droppedNow)
                droppedCounted = true
            }
            outbox.append(batch)
        } catch (e: CancellationException) {
            requeue(batch, if (droppedCounted) 0 else droppedNow)
            throw e
        } catch (e: Exception) {
            _lastWriteError.value = e.toString()
            requeue(batch, if (droppedCounted) 0 else droppedNow)
            return@withLock false
        }
        _lastWriteError.value = null
        recent.addAll(events)
        // From here the events are on disk with their seq: whatever the listener does (buffer limits,
        // upload request) must never put them back in the pending list, they would be written twice.
        try {
            listener?.onFlushed(events)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            _lastWriteError.value = "listener: $e"
        }
        true
    }

    /** Nothing was written: the events go back in front of the pending list, in order. */
    private fun requeue(batch: List<PendingEvent>, dropped: Long) {
        synchronized(lock) {
            droppedInMemory += dropped
            pending.addAll(0, batch)
            while (pending.size > MAX_IN_MEMORY) dropOneInMemory()
        }
    }

    /** For shutdown paths: blocks the calling thread for at most [timeoutMs]. */
    override fun flushBlocking(timeoutMs: Long): Boolean = runBlocking {
        withTimeoutOrNull(timeoutMs) { flushNow() } ?: false
    }

    fun pendingInMemory(): Int = synchronized(lock) { pending.size }

    private companion object {
        const val MAX_IN_MEMORY = 20_000
        const val WRITE_RETRY_MS = 5_000L
    }
}

/** Fixed-size in-memory ring of the latest events. */
class RecentEvents(private val capacity: Int) {
    private val _events = MutableStateFlow<List<Event>>(emptyList())
    val events: StateFlow<List<Event>> = _events.asStateFlow()

    fun addAll(newEvents: List<Event>) {
        if (newEvents.isEmpty()) return
        synchronized(this) {
            _events.value = (newEvents.asReversed() + _events.value).take(capacity)
        }
    }
}
