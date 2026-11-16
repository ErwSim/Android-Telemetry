package io.github.erwsim.watchpost.core.collector

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.SharedPreferences
import android.os.Handler
import android.os.Looper
import androidx.core.content.ContextCompat
import io.github.erwsim.watchpost.core.capability.Capabilities
import io.github.erwsim.watchpost.core.event.AgentClock
import io.github.erwsim.watchpost.core.event.EventDataBuilder
import io.github.erwsim.watchpost.core.event.Severity
import io.github.erwsim.watchpost.core.event.eventData
import io.github.erwsim.watchpost.core.settings.AgentSettings
import io.github.erwsim.watchpost.core.sink.EventSink
import io.github.erwsim.watchpost.core.sink.FlushableSink
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.serialization.json.JsonObject
import java.util.concurrent.Executor

/** Read-only view of the agent used by collectors that report on the agent itself (heartbeat). */
interface AgentStatusSource {
    val agentVersion: String
    fun queueDepth(): Long
    fun queueBytes(): Long
    suspend fun droppedTotal(): Long
    fun isDeviceOwner(): Boolean
    fun collectorStates(): Map<String, CollectorRunState>
    /** Wall time of the last acknowledged upload, null if none yet. */
    fun lastUploadMs(): Long?
}

/** Boot information computed once per process. */
data class BootInfo(val bootId: String, val isNewBoot: Boolean, val isFirstRun: Boolean)

/**
 * Everything a collector may use. One instance per collector start (a fresh one after each
 * restart); [scope] is cancelled and receivers registered through [registerReceiver] are
 * unregistered automatically when the collector stops.
 */
class CollectorContext internal constructor(
    val collectorId: String,
    val appContext: Context,
    private val rawSink: EventSink,
    val settings: AgentSettings,
    val capabilities: Capabilities,
    val clock: AgentClock,
    val boot: BootInfo,
    val status: AgentStatusSource,
    private val threading: CollectorThreading,
    /** Collector-scoped coroutines on the collectors' thread; exceptions are reported, not fatal. */
    val scope: CoroutineScope,
    private val errorReporter: (Throwable, String) -> Unit,
) {
    private val cleanups = ArrayList<() -> Unit>()

    /** Looper of the collectors' thread (bind Android callbacks to it). */
    val looper: Looper get() = threading.looper ?: error("no collectors Looper (JVM test)")

    /** Handler of the collectors' thread. */
    val handler: Handler get() = threading.handler ?: error("no collectors Handler (JVM test)")

    /** Private persistent state of this collector (not user settings). */
    val prefs: SharedPreferences by lazy {
        appContext.getSharedPreferences("collector_$collectorId", Context.MODE_PRIVATE)
    }

    /**
     * Dispatcher for blocking work (binder-heavy PackageManager calls, `getprop`, log retrieval):
     * `withContext(ctx.io) { … }` or `ctx.scope.launch(ctx.io) { … }`. `Dispatchers.IO` in
     * production; the test harness substitutes a tracked one, so never use `Dispatchers.IO` directly.
     */
    val io: CoroutineDispatcher get() = threading.io

    /** Sink that never throws: an invalid event is reported as `agent.collector_error`. */
    val sink: EventSink = object : EventSink {
        override fun emit(type: String, sev: Int, data: JsonObject, originTsMs: Long?) {
            try {
                rawSink.emit(type, sev, data, originTsMs)
            } catch (e: Exception) {
                errorReporter(e, "emit $type")
            }
        }
    }

    /**
     * Emits an event. [originTsMs]: wall-clock time given by the system for an event read after
     * the fact (`app.foreground`, `net.dns`, `net.connect`, `security.log`); it becomes `ts`.
     */
    fun emit(type: String, sev: Int = Severity.INFO, originTsMs: Long? = null, block: EventDataBuilder.() -> Unit) {
        val data = try {
            eventData(block)
        } catch (e: Exception) {
            errorReporter(e, "data $type")
            return
        }
        sink.emit(type, sev, data, originTsMs)
    }

    /**
     * Forces pending events to disk (e.g. on `ACTION_SHUTDOWN`). Blocks for at most [timeoutMs]:
     * use it only where losing the last seconds of events matters.
     */
    fun flushBlocking(timeoutMs: Long = 2_000): Boolean = (rawSink as? FlushableSink)?.flushBlocking(timeoutMs) ?: true

    /** Reports a non-fatal error (`agent.collector_error`, rate-limited). */
    fun reportError(error: Throwable, where: String = "") = errorReporter(error, where)

    /** Runs [block], reporting instead of propagating any exception. Use it in every callback. */
    inline fun guard(where: String, block: () -> Unit) {
        try {
            block()
        } catch (e: Exception) {
            reportError(e, where)
        }
    }

    /** Executor running on the collectors' thread with error isolation (for LocationManager, etc.). */
    val executor: Executor = Executor { r ->
        val h = threading.handler
        if (h != null) {
            h.post { guard("executor") { r.run() } }
        } else {
            guard("executor") { r.run() }
        }
    }

    /**
     * Registers a broadcast receiver whose callback runs guarded on the collectors' thread, and
     * unregisters it when the collector stops.
     *
     * [exported] = false (`RECEIVER_NOT_EXPORTED`) only delivers broadcasts sent by the system
     * server itself (uid 1000/root) or by this app. Broadcasts sent by system *apps* running under
     * another uid are dropped ("Exported Denial" in `BroadcastSkipPolicy`): Bluetooth
     * (`ACL_CONNECTED`…, uid bluetooth), NFC (`ADAPTER_STATE_CHANGED`, uid nfc), KeyChain
     * (`TRUST_STORE_CHANGED`), telephony. Those need [exported] = true, which is safe only for
     * actions declared `<protected-broadcast>` by the platform (no third-party app can send them):
     * check the framework manifest before using it.
     */
    fun registerReceiver(filter: IntentFilter, exported: Boolean = false, onReceive: (Intent) -> Unit): BroadcastReceiver {
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(context: Context, intent: Intent) {
                guard("receiver ${intent.action}") { onReceive(intent) }
            }
        }
        val flags = if (exported) ContextCompat.RECEIVER_EXPORTED else ContextCompat.RECEIVER_NOT_EXPORTED
        ContextCompat.registerReceiver(appContext, receiver, filter, null, threading.handler, flags)
        onStop {
            try {
                appContext.unregisterReceiver(receiver)
            } catch (_: IllegalArgumentException) {
                // Already unregistered.
            }
        }
        return receiver
    }

    /** Registers a cleanup action run (guarded, in reverse order) when the collector stops. */
    fun onStop(cleanup: () -> Unit) {
        synchronized(cleanups) { cleanups += cleanup }
    }

    internal fun runCleanups() {
        val list = synchronized(cleanups) { cleanups.toList().also { cleanups.clear() } }
        for (c in list.asReversed()) guard("cleanup") { c() }
    }
}
