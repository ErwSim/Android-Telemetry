package io.github.erwsim.vigie.collectors.notifications

import android.content.Context
import android.content.Intent
import android.os.SystemClock
import io.github.erwsim.vigie.collectors.notifications.NotificationEvents.fill
import io.github.erwsim.vigie.core.Agent
import io.github.erwsim.vigie.core.collector.CollectorContext
import io.github.erwsim.vigie.core.event.Severity
import io.github.erwsim.vigie.notifier.protocol.NotificationPayload
import io.github.erwsim.vigie.notifier.protocol.NotifierProtocol

/**
 * Process-wide link between [NotificationsProvider] (binder threads) and the running
 * [NotificationsCollector] (collectors' thread).
 *
 * While the collector runs, events are emitted with its context (error isolation, collector
 * errors). When it does not run although the agent accepts (process just restarted by the
 * provider call, before the agent service restarted the collectors), they go straight to the
 * agent's sink: they are buffered like any other event instead of being lost.
 */
object NotificationsBridge {
    @Volatile
    private var running: CollectorContext? = null

    /** What the companion last said about its listener since this process started (null: nothing). */
    @Volatile
    var companionConnected: Boolean? = null
        private set

    val endpoint: NotificationsEndpoint by lazy {
        NotificationsEndpoint(
            settings = { Agent.getOrNull()?.settings },
            emit = ::emit,
            elapsedMs = SystemClock::elapsedRealtime,
            onCompanionStatus = { connected ->
                val changed = companionConnected != connected
                companionConnected = connected
                // The collector becomes available (or not) now rather than at the next maintenance pass.
                if (changed) Agent.getOrNull()?.host?.reconcile()
            },
            onListsChanged = { Agent.getOrNull()?.context?.let(::notifyCompanion) },
        )
    }

    fun attach(ctx: CollectorContext) {
        running = ctx
    }

    fun detach(ctx: CollectorContext) {
        if (running === ctx) running = null
    }

    private fun emit(p: NotificationPayload): Boolean {
        val ctx = running
        if (ctx != null) {
            ctx.emit(NotificationEvents.TYPE, Severity.INFO) { fill(p) }
            return true
        }
        val sink = Agent.getOrNull()?.sink ?: return false
        return try {
            sink.emit(NotificationEvents.TYPE, Severity.INFO, NotificationEvents.data(p))
            true
        } catch (_: Exception) {
            false
        }
    }

    /**
     * Tells the companion that the settings changed (it reads them again before its next report).
     * Explicit broadcast to its package; only a holder of the signature permission receives it, and
     * its receiver only accepts it from a holder of the same permission.
     */
    fun notifyCompanion(context: Context) {
        try {
            context.sendBroadcast(
                Intent(NotifierProtocol.ACTION_CONFIG_CHANGED).setPackage(NotifierProtocol.NOTIFIER_PACKAGE),
                NotifierProtocol.PERMISSION,
            )
        } catch (_: Exception) {
            // Companion absent, or no Context (JVM tests): it falls back to re-reading the settings every minute.
        }
    }
}
