package io.github.erwsim.vigie.collectors.apps

import android.app.usage.UsageEvents
import android.app.usage.UsageStatsManager
import android.content.Intent
import android.content.IntentFilter
import android.os.PowerManager
import androidx.core.content.edit
import io.github.erwsim.vigie.collectors.R
import io.github.erwsim.vigie.collectors.common.hasUsageAccess
import io.github.erwsim.vigie.collectors.common.str
import io.github.erwsim.vigie.core.collector.Availability
import io.github.erwsim.vigie.core.collector.CollectReason
import io.github.erwsim.vigie.core.collector.Collector
import io.github.erwsim.vigie.core.collector.CollectorContext
import io.github.erwsim.vigie.core.collector.PeriodicSpec
import io.github.erwsim.vigie.core.event.Severity
import io.github.erwsim.vigie.core.event.eventData
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.JsonObject

/**
 * `app.foreground`: which app comes to / leaves the foreground, from
 * `UsageStatsManager.queryEvents` (needs "usage access"). Only app switches are reported (not
 * activity changes inside an app); the class is the first activity shown.
 *
 * Polling, screen on only: one query every [POLL_SECONDS] seconds while the screen is on, one at
 * screen off, plus a WorkManager safety net every 15 min. `ts` is the time of the usage event given
 * by the system (contract §2 "Précisions"), not the poll time. Typically 100 to 400 events per day.
 */
class ForegroundAppCollector : Collector {
    override val id = "foreground"
    override val titleRes = R.string.collector_foreground_title
    override val descriptionRes = R.string.collector_foreground_desc
    override val eventTypes = listOf(TYPE)
    override val periodic = PeriodicSpec(intervalMinutes = 15, runAtStart = true)

    private val mutex = Mutex()
    private var pollJob: Job? = null

    override fun checkAvailability(ctx: CollectorContext): Availability =
        if (ctx.hasUsageAccess()) Availability.Available else Availability.Unavailable(ctx.str(R.string.collectors_reason_usage_access))

    override suspend fun start(ctx: CollectorContext) {
        pollJob = null
        ctx.registerReceiver(
            IntentFilter().apply {
                addAction(Intent.ACTION_SCREEN_ON)
                addAction(Intent.ACTION_SCREEN_OFF)
            },
        ) { intent ->
            if (intent.action == Intent.ACTION_SCREEN_ON) {
                startPolling(ctx)
            } else {
                pollJob?.cancel()
                pollJob = null
                ctx.scope.launch { poll(ctx) }
            }
        }
        if (ctx.appContext.getSystemService(PowerManager::class.java)?.isInteractive == true) startPolling(ctx)
    }

    override suspend fun stop(ctx: CollectorContext) {
        pollJob = null
    }

    override suspend fun collectOnce(ctx: CollectorContext, reason: CollectReason) = poll(ctx)

    private fun startPolling(ctx: CollectorContext) {
        if (pollJob?.isActive == true) return
        pollJob = ctx.scope.launch {
            while (isActive) {
                poll(ctx)
                delay(POLL_SECONDS * 1000L)
            }
        }
    }

    private suspend fun poll(ctx: CollectorContext) = mutex.withLock {
        val usm = ctx.appContext.getSystemService(UsageStatsManager::class.java) ?: return@withLock
        val now = ctx.clock.nowMillis()
        val watermark = ctx.prefs.getLong(K_WATERMARK, 0)
        val from = if (watermark in (now - MAX_WINDOW_MS)..now) watermark else now - POLL_SECONDS * 1000L
        val tracker = ForegroundTracker(ctx.prefs.getString(K_PACKAGE, null), ctx.prefs.getString(K_CLASS, null))
        // Each change with the time of the usage event that caused it (becomes the event's `ts`).
        val changes = ArrayList<Pair<ForegroundTracker.Change, Long>>()
        var lastTs = watermark
        withContext(ctx.io) {
            val events = usm.queryEvents(from, now) ?: return@withContext
            val e = UsageEvents.Event()
            while (events.hasNextEvent() && events.getNextEvent(e)) {
                if (e.timeStamp <= watermark) continue
                lastTs = maxOf(lastTs, e.timeStamp)
                val at = e.timeStamp
                tracker.onEvent(kindOf(e.eventType), e.packageName, e.className).forEach { changes += it to at }
            }
        }
        changes.takeLast(MAX_PER_POLL).forEach { (c, at) -> ctx.sink.emit(TYPE, Severity.INFO, data(c), originTsMs = at.takeIf { it > 0 }) }
        ctx.prefs.edit {
            putLong(K_WATERMARK, if (lastTs > 0) lastTs else from)
            putString(K_PACKAGE, tracker.currentPackage)
            putString(K_CLASS, tracker.currentClass)
        }
    }

    companion object {
        const val TYPE = "app.foreground"
        const val POLL_SECONDS = 60
        private const val MAX_PER_POLL = 200
        private const val MAX_WINDOW_MS = 6 * 3_600_000L
        private const val K_WATERMARK = "watermark_ms"
        private const val K_PACKAGE = "current_package"
        private const val K_CLASS = "current_class"

        fun data(c: ForegroundTracker.Change): JsonObject = eventData {
            put("package", c.pkg)
            put("class", c.cls)
            put("event", c.event)
        }

        fun kindOf(eventType: Int): ForegroundTracker.Kind = when (eventType) {
            UsageEvents.Event.ACTIVITY_RESUMED -> ForegroundTracker.Kind.RESUMED
            UsageEvents.Event.ACTIVITY_PAUSED -> ForegroundTracker.Kind.PAUSED
            UsageEvents.Event.SCREEN_NON_INTERACTIVE, UsageEvents.Event.KEYGUARD_SHOWN -> ForegroundTracker.Kind.SCREEN_OFF
            else -> ForegroundTracker.Kind.OTHER
        }
    }
}
