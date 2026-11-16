package io.github.erwsim.watchpost.core.work

import android.content.Context
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.ExistingWorkPolicy
import androidx.work.NetworkType
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import androidx.work.workDataOf
import io.github.erwsim.watchpost.core.Agent
import io.github.erwsim.watchpost.core.collector.CollectReason
import io.github.erwsim.watchpost.core.collector.PeriodicScheduler
import io.github.erwsim.watchpost.core.collector.PeriodicSpec
import io.github.erwsim.watchpost.core.settings.CoreSettings
import java.util.concurrent.TimeUnit

/** WorkManager scheduling of uploads: periodic, on demand, and retries that wait for connectivity. */
class UploadScheduler(context: Context) {
    private val wm by lazy { WorkManager.getInstance(context) }

    private val connected = Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build()
    private val unmetered = Constraints.Builder().setRequiredNetworkType(NetworkType.UNMETERED).build()

    fun ensurePeriodic(intervalMinutes: Int) {
        wm.enqueueUniquePeriodicWork(
            PERIODIC,
            ExistingPeriodicWorkPolicy.UPDATE,
            PeriodicWorkRequestBuilder<UploadWorker>(intervalMinutes.toLong(), TimeUnit.MINUTES)
                .setConstraints(connected)
                .build(),
        )
    }

    /** As soon as a network is available. [force] ignores the current backoff (user action). */
    fun requestNow(force: Boolean) {
        wm.enqueueUniqueWork(
            ONESHOT,
            if (force) ExistingWorkPolicy.REPLACE else ExistingWorkPolicy.KEEP,
            OneTimeWorkRequestBuilder<UploadWorker>()
                .setConstraints(connected)
                .setInputData(workDataOf(KEY_FORCE to force))
                .build(),
        )
    }

    /**
     * Next attempt after [delayMs], and only once a (possibly unmetered) network is available:
     * this is what makes uploads resume when connectivity returns.
     */
    fun retryAfter(delayMs: Long, unmeteredOnly: Boolean, fromRetryWorker: Boolean) {
        wm.enqueueUniqueWork(
            RETRY,
            // A running retry worker cannot be replaced without cancelling itself: chain after it.
            if (fromRetryWorker) ExistingWorkPolicy.APPEND_OR_REPLACE else ExistingWorkPolicy.REPLACE,
            OneTimeWorkRequestBuilder<UploadWorker>()
                .setConstraints(if (unmeteredOnly) unmetered else connected)
                .setInitialDelay(delayMs.coerceAtLeast(0), TimeUnit.MILLISECONDS)
                .addTag(TAG_RETRY)
                .build(),
        )
    }

    fun cancelAll() {
        wm.cancelUniqueWork(PERIODIC)
        wm.cancelUniqueWork(ONESHOT)
        wm.cancelUniqueWork(RETRY)
    }

    companion object {
        const val PERIODIC = "watchpost-upload-periodic"
        const val ONESHOT = "watchpost-upload-now"
        const val RETRY = "watchpost-upload-retry"
        const val TAG_RETRY = "watchpost-upload-retry"
        const val KEY_FORCE = "force"
    }
}

class UploadWorker(context: Context, params: WorkerParameters) : CoroutineWorker(context, params) {
    override suspend fun doWork(): Result {
        val agent = Agent.getOrNull() ?: return Result.success()
        val outcome = agent.uploader.run(force = inputData.getBoolean(UploadScheduler.KEY_FORCE, false))
        agent.handleUploadOutcome(outcome, fromRetryWorker = UploadScheduler.TAG_RETRY in tags)
        return Result.success()
    }
}

/** Periodic collection for [io.github.erwsim.watchpost.core.collector.Collector.periodic]. */
class WorkPeriodicScheduler(context: Context) : PeriodicScheduler {
    private val wm by lazy { WorkManager.getInstance(context) }

    override fun schedule(collectorId: String, spec: PeriodicSpec) {
        wm.enqueueUniquePeriodicWork(
            name(collectorId),
            ExistingPeriodicWorkPolicy.UPDATE,
            PeriodicWorkRequestBuilder<CollectorWorker>(spec.intervalMinutes.coerceAtLeast(15), TimeUnit.MINUTES)
                .setInputData(workDataOf(CollectorWorker.KEY_ID to collectorId))
                .build(),
        )
    }

    override fun cancel(collectorId: String) {
        wm.cancelUniqueWork(name(collectorId))
    }

    private fun name(id: String) = "watchpost-collect-$id"
}

class CollectorWorker(context: Context, params: WorkerParameters) : CoroutineWorker(context, params) {
    override suspend fun doWork(): Result {
        val agent = Agent.getOrNull() ?: return Result.success()
        val id = inputData.getString(KEY_ID) ?: return Result.success()
        if (!agent.settings[CoreSettings.AGENT_ENABLED]) return Result.success()
        agent.host.collectOnce(id, CollectReason.PERIODIC)
        return Result.success()
    }

    companion object {
        const val KEY_ID = "collector_id"
    }
}

/** Every 15 min: age cap of the buffer, integrity checks, collector reconciliation, service watchdog. */
class MaintenanceWorker(context: Context, params: WorkerParameters) : CoroutineWorker(context, params) {
    override suspend fun doWork(): Result {
        val agent = Agent.getOrNull() ?: return Result.success()
        agent.maintenance()
        return Result.success()
    }

    companion object {
        const val NAME = "watchpost-maintenance"

        fun ensure(context: Context) {
            WorkManager.getInstance(context).enqueueUniquePeriodicWork(
                NAME,
                ExistingPeriodicWorkPolicy.UPDATE,
                PeriodicWorkRequestBuilder<MaintenanceWorker>(15, TimeUnit.MINUTES).build(),
            )
        }
    }
}
