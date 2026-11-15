package io.github.erwsim.vigie.core

import android.annotation.SuppressLint
import android.content.Context
import android.content.SharedPreferences
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.provider.Settings
import androidx.room.Room
import io.github.erwsim.vigie.core.capability.Capabilities
import io.github.erwsim.vigie.core.collector.AgentStatusSource
import io.github.erwsim.vigie.core.collector.BootInfo
import io.github.erwsim.vigie.core.collector.Collector
import io.github.erwsim.vigie.core.collector.CollectorHost
import io.github.erwsim.vigie.core.collector.CollectorRunState
import io.github.erwsim.vigie.core.enroll.AndroidKeystoreCredentials
import io.github.erwsim.vigie.core.enroll.AndroidKeystoreSecretBox
import io.github.erwsim.vigie.core.enroll.EnrollmentManager
import io.github.erwsim.vigie.core.enroll.EnrollmentStore
import io.github.erwsim.vigie.core.event.AgentClock
import io.github.erwsim.vigie.core.event.BootIdentity
import io.github.erwsim.vigie.core.event.Event
import io.github.erwsim.vigie.core.event.EventTypes
import io.github.erwsim.vigie.core.event.Rfc3339
import io.github.erwsim.vigie.core.event.Severity
import io.github.erwsim.vigie.core.integrity.IntegrityMonitor
import io.github.erwsim.vigie.core.outbox.Outbox
import io.github.erwsim.vigie.core.outbox.OutboxDatabase
import io.github.erwsim.vigie.core.settings.AgentSettings
import io.github.erwsim.vigie.core.settings.CoreSettings
import io.github.erwsim.vigie.core.sink.FlushListener
import io.github.erwsim.vigie.core.sink.OutboxEventSink
import io.github.erwsim.vigie.core.sink.emit
import io.github.erwsim.vigie.core.upload.NetState
import io.github.erwsim.vigie.core.upload.UploadLimits
import io.github.erwsim.vigie.core.upload.UploadOutcome
import io.github.erwsim.vigie.core.upload.UploadStatus
import io.github.erwsim.vigie.core.upload.UploadStatusStore
import io.github.erwsim.vigie.core.upload.Uploader
import io.github.erwsim.vigie.core.work.MaintenanceWorker
import io.github.erwsim.vigie.core.work.UploadScheduler
import io.github.erwsim.vigie.core.work.WorkPeriodicScheduler
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch

/**
 * Process-wide wiring of the agent (no DI framework). Created once in `Application.onCreate`
 * with the collectors of every module; workers and the service reach it through [get].
 */
class Agent private constructor(
    val context: Context,
    collectorsFactory: (Context) -> List<Collector>,
) : AgentStatusSource {
    val clock: AgentClock = AgentClock.System

    override val agentVersion: String = try {
        context.packageManager.getPackageInfo(context.packageName, 0).versionName ?: "0"
    } catch (_: Exception) {
        "0"
    }

    val settings = AgentSettings(prefs(PREFS_SETTINGS))
    private val bootIdentity = BootIdentity(prefs(PREFS_BOOT), clock, ::readBootCount)
    val boot = BootInfo(bootIdentity.bootId, bootIdentity.isNewBoot, bootIdentity.isFirstRun)

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    val database: OutboxDatabase = Room.databaseBuilder(context, OutboxDatabase::class.java, OutboxDatabase.NAME).build()
    val outbox = Outbox(database)
    val sink = OutboxEventSink(outbox, clock, boot.bootId, scope)
    val capabilities = Capabilities(context)
    val uploadStatus = UploadStatusStore(prefs(PREFS_UPLOAD))
    val enrollment = EnrollmentManager(
        store = EnrollmentStore(prefs(PREFS_ENROLLMENT), AndroidKeystoreSecretBox()),
        credentials = AndroidKeystoreCredentials(),
        clock = clock,
        agentVersion = agentVersion,
        sink = { sink },
    )
    val uploader = Uploader(outbox, enrollment::target, uploadStatus, clock, ::netState, ::uploadLimits)
    val uploadScheduler = UploadScheduler(context)
    val integrity = IntegrityMonitor(context, prefs(PREFS_INTEGRITY), capabilities, sink)
    val host = CollectorHost(
        appContext = context,
        collectors = collectorsFactory(context),
        sink = sink,
        settings = settings,
        capabilities = capabilities,
        clock = clock,
        boot = boot,
        statusSource = { this },
        periodicScheduler = WorkPeriodicScheduler(context),
    )

    /** Set by the app: makes sure the foreground service runs (called by the maintenance worker). */
    @Volatile
    var maintenanceHook: (() -> Unit)? = null

    @Volatile
    private var lastBulkRequestElapsed = 0L
    private var networkCallback: ConnectivityManager.NetworkCallback? = null

    init {
        settings.sink = sink
        sink.listener = FlushListener { onFlushed(it) }
        sink.start()
        scope.launch { outbox.refreshTotals() }
        scope.launch {
            settings.changes.collect { key ->
                when (key) {
                    CoreSettings.UPLOAD_INTERVAL_MIN.name -> uploadScheduler.ensurePeriodic(settings[CoreSettings.UPLOAD_INTERVAL_MIN])
                    CoreSettings.BUFFER_MAX_MB.name, CoreSettings.BUFFER_MAX_AGE_DAYS.name -> enforceBufferLimits()
                }
            }
        }
    }

    /** Schedules the background work that must exist whenever the app is installed. */
    fun ensureBackgroundWork() {
        uploadScheduler.ensurePeriodic(settings[CoreSettings.UPLOAD_INTERVAL_MIN])
        MaintenanceWorker.ensure(context)
    }

    private suspend fun onFlushed(events: List<Event>) {
        if (outbox.totals.value.bytes > maxBufferBytes()) enforceBufferLimits()
        if (events.any { it.sev >= Severity.WARNING }) {
            requestUpload(force = false)
        } else if (outbox.totals.value.count >= Uploader.MAX_BATCH_EVENTS) {
            val now = clock.elapsedRealtime()
            if (now - lastBulkRequestElapsed > BULK_REQUEST_INTERVAL_MS) {
                lastBulkRequestElapsed = now
                requestUpload(force = false)
            }
        }
    }

    private fun maxBufferBytes(): Long = settings[CoreSettings.BUFFER_MAX_MB] * 1024L * 1024L

    /** Applies the size and age caps and emits `agent.buffer_overflow` if anything was dropped. */
    suspend fun enforceBufferLimits() {
        val report = outbox.enforceLimits(
            maxBytes = maxBufferBytes(),
            maxAgeMs = settings[CoreSettings.BUFFER_MAX_AGE_DAYS] * 86_400_000L,
            nowMs = clock.nowMillis(),
        ) ?: return
        sink.emit(EventTypes.AGENT_BUFFER_OVERFLOW, Severity.WARNING) {
            put("dropped", report.dropped)
            put("oldest_ts", Rfc3339.format(report.oldestTsMs))
            put("newest_ts", Rfc3339.format(report.newestTsMs))
        }
    }

    fun requestUpload(force: Boolean) {
        if (enrollment.state.value == null) return
        if (!force && uploader.isRunning) uploader.requestRerun() else uploadScheduler.requestNow(force)
    }

    fun handleUploadOutcome(outcome: UploadOutcome, fromRetryWorker: Boolean) {
        val now = clock.nowMillis()
        when (outcome) {
            UploadOutcome.NotEnrolled -> Unit
            is UploadOutcome.Sent -> if (outcome.moreLeft) uploadScheduler.retryAfter(0, false, fromRetryWorker)
            is UploadOutcome.Deferred -> uploadScheduler.retryAfter(outcome.untilMs - now, false, fromRetryWorker)
            is UploadOutcome.Retry -> uploadScheduler.retryAfter(outcome.atMs - now, false, fromRetryWorker)
            is UploadOutcome.WaitingUnmetered -> uploadScheduler.retryAfter(0, true, fromRetryWorker)
        }
    }

    suspend fun maintenance() {
        enforceBufferLimits()
        integrity.checkPermissionsAndOwnership()
        host.reconcile()
        maintenanceHook?.invoke()
    }

    /** Called by the service: retry at once when a network comes back after a network failure. */
    fun startNetworkWatch() {
        if (networkCallback != null) return
        val cm = context.getSystemService(ConnectivityManager::class.java) ?: return
        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                val status = uploadStatus.status.value
                if (status.lastError?.startsWith("network") == true && status.nextAttemptAtMs > clock.nowMillis()) {
                    uploadStatus.update { it.copy(nextAttemptAtMs = 0) }
                    requestUpload(force = false)
                }
            }
        }
        try {
            cm.registerDefaultNetworkCallback(callback)
            networkCallback = callback
        } catch (_: Exception) {
            // Too many callbacks or missing permission: WorkManager constraints still cover it.
        }
    }

    fun stopNetworkWatch() {
        val callback = networkCallback ?: return
        networkCallback = null
        try {
            context.getSystemService(ConnectivityManager::class.java)?.unregisterNetworkCallback(callback)
        } catch (_: Exception) {
            // Already unregistered.
        }
    }

    /** Forgets the enrollment and deletes the events waiting for that server. */
    fun unenroll() {
        enrollment.unenroll()
        uploadScheduler.cancelAll()
        uploadStatus.update { UploadStatus() }
        scope.launch { outbox.clear() }
        uploadScheduler.ensurePeriodic(settings[CoreSettings.UPLOAD_INTERVAL_MIN])
    }

    private fun netState(): NetState {
        val cm = context.getSystemService(ConnectivityManager::class.java) ?: return NetState(false, true)
        val caps = cm.getNetworkCapabilities(cm.activeNetwork) ?: return NetState(false, true)
        return NetState(
            connected = caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET),
            metered = !caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED),
        )
    }

    private fun uploadLimits() = UploadLimits(
        wifiOnlyLarge = settings[CoreSettings.WIFI_ONLY_LARGE],
        largeThresholdBytes = settings[CoreSettings.LARGE_THRESHOLD_MB] * 1024L * 1024L,
    )

    private fun readBootCount(): Int? =
        Settings.Global.getInt(context.contentResolver, Settings.Global.BOOT_COUNT, -1).takeIf { it >= 0 }

    private fun prefs(name: String): SharedPreferences = context.getSharedPreferences(name, Context.MODE_PRIVATE)

    // AgentStatusSource (heartbeat).
    override fun queueDepth(): Long = outbox.totals.value.count
    override fun queueBytes(): Long = outbox.totals.value.bytes
    override suspend fun droppedTotal(): Long = outbox.droppedTotal()
    override fun isDeviceOwner(): Boolean = capabilities.isDeviceOwner()
    override fun collectorStates(): Map<String, CollectorRunState> = host.statuses.value.mapValues { it.value.state }
    override fun lastUploadMs(): Long? = uploadStatus.status.value.lastSuccessMs.takeIf { it > 0 }

    companion object {
        private const val PREFS_SETTINGS = "vigie_settings"
        private const val PREFS_BOOT = "vigie_boot"
        private const val PREFS_UPLOAD = "vigie_upload"
        private const val PREFS_ENROLLMENT = "vigie_enrollment"
        private const val PREFS_INTEGRITY = "vigie_integrity"
        private const val BULK_REQUEST_INTERVAL_MS = 5 * 60_000L

        // Holds only the application context (never an Activity): not a leak.
        @SuppressLint("StaticFieldLeak")
        @Volatile
        private var instance: Agent? = null

        /** Idempotent; call from `Application.onCreate` with every module's collectors. */
        fun init(context: Context, collectorsFactory: (Context) -> List<Collector>): Agent =
            instance ?: synchronized(this) {
                instance ?: Agent(context.applicationContext, collectorsFactory).also { instance = it }
            }

        fun get(): Agent = checkNotNull(instance) { "Agent.init() was not called" }

        fun getOrNull(): Agent? = instance
    }
}
