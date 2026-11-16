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
import io.github.erwsim.vigie.core.command.AndroidChannelPlatform
import io.github.erwsim.vigie.core.command.CommandChannel
import io.github.erwsim.vigie.core.command.CommandHistoryEntry
import io.github.erwsim.vigie.core.command.CommandKeyStore
import io.github.erwsim.vigie.core.command.CommandProcessor
import io.github.erwsim.vigie.core.command.CommandSettings
import io.github.erwsim.vigie.core.command.CommandStateStore
import io.github.erwsim.vigie.core.command.CommandTypes
import io.github.erwsim.vigie.core.command.LocateExecutor
import io.github.erwsim.vigie.core.command.RemoteCommands
import io.github.erwsim.vigie.core.enroll.AndroidKeystoreCredentials
import io.github.erwsim.vigie.core.enroll.AndroidKeystoreSecretBox
import io.github.erwsim.vigie.core.enroll.EnrollmentChange
import io.github.erwsim.vigie.core.enroll.EnrollmentManager
import io.github.erwsim.vigie.core.enroll.ParsedEnrollment
import io.github.erwsim.vigie.core.enroll.EnrollmentStore
import io.github.erwsim.vigie.core.event.AgentClock
import io.github.erwsim.vigie.core.event.BootIdentity
import io.github.erwsim.vigie.core.event.Event
import io.github.erwsim.vigie.core.event.EventTypes
import io.github.erwsim.vigie.core.event.Rfc3339
import io.github.erwsim.vigie.core.event.Severity
import io.github.erwsim.vigie.core.integrity.IntegrityMonitor
import io.github.erwsim.vigie.core.outbox.AgeHorizon
import io.github.erwsim.vigie.core.outbox.Outbox
import io.github.erwsim.vigie.core.outbox.OutboxDatabase
import io.github.erwsim.vigie.core.settings.AgentSettings
import io.github.erwsim.vigie.core.settings.CoreSettings
import io.github.erwsim.vigie.core.sink.FlushListener
import io.github.erwsim.vigie.core.sink.OutboxEventSink
import io.github.erwsim.vigie.core.sink.emit
import io.github.erwsim.vigie.core.upload.DroppedEvent
import io.github.erwsim.vigie.core.upload.NetState
import io.github.erwsim.vigie.core.upload.UploadLimits
import io.github.erwsim.vigie.core.upload.UploadOutcome
import io.github.erwsim.vigie.core.upload.UploadStatus
import io.github.erwsim.vigie.core.upload.UploadStatusStore
import io.github.erwsim.vigie.core.upload.Uploader
import io.github.erwsim.vigie.core.work.MaintenanceWorker
import io.github.erwsim.vigie.core.work.UploadScheduler
import io.github.erwsim.vigie.core.work.WorkPeriodicScheduler
import android.util.Log
import kotlinx.coroutines.CoroutineExceptionHandler
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeoutOrNull

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

    // A failing background task (database that cannot be opened, storage full…) must not crash the
    // process at every start: the app stays usable to see the error and for the ADB rescue.
    private val scope = CoroutineScope(
        SupervisorJob() + Dispatchers.Default + CoroutineExceptionHandler { _, e -> Log.e(TAG, "agent background task failed", e) },
    )

    val database: OutboxDatabase = Room.databaseBuilder(context, OutboxDatabase::class.java, OutboxDatabase.NAME).build()
    val outbox = Outbox(database, ageHorizon = AgeHorizon(prefs(PREFS_AGE), clock, boot.bootId))
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
    val uploader = Uploader(
        outbox, enrollment::target, uploadStatus, clock, ::netState, ::uploadLimits,
        onDropped = ::reportDroppedEvent,
    )
    val uploadScheduler = UploadScheduler(context)
    val integrity = IntegrityMonitor(context, prefs(PREFS_INTEGRITY), capabilities, sink, clock)
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

    // The command channel blocks on network reads: its own I/O scope, failures logged, never fatal.
    private val commandScope = CoroutineScope(
        SupervisorJob() + Dispatchers.IO + CoroutineExceptionHandler { _, e -> Log.e(TAG, "command channel task failed", e) },
    )

    /** Set by the app: shown to the user after each processed remote command (no stealth). */
    @Volatile
    var onCommandProcessed: ((CommandHistoryEntry) -> Unit)? = null

    /** Remote commands (contract §8): settings, command key, verification, channel. Executors are registered by the modules. */
    val commands: RemoteCommands = RemoteCommands(
        settings = settings,
        clock = clock,
        sink = sink,
        keys = CommandKeyStore(prefs(PREFS_COMMAND_KEY), AndroidKeystoreSecretBox(COMMAND_KEY_ALIAS)),
        state = CommandStateStore(prefs(PREFS_COMMANDS)),
        deviceId = { enrollment.state.value?.deviceId },
        isDeviceOwner = { capabilities.isDeviceOwner() },
        hooks = object : CommandProcessor.Hooks {
            override suspend fun beforeIrreversible(timeoutMs: Long) = sendNowBounded(timeoutMs)

            override fun onProcessed(entry: CommandHistoryEntry) {
                // locate: the fix and the result leave together, at once.
                if (entry.type == CommandTypes.LOCATE) {
                    scope.launch {
                        sink.flushNow()
                        requestUpload(force = true)
                    }
                }
                onCommandProcessed?.invoke(entry)
            }
        },
        channelFactory = { rc ->
            CommandChannel(
                scope = commandScope,
                clock = clock,
                target = enrollment::target,
                config = rc::channelConfig,
                processor = rc.processor,
                state = rc.state,
                platform = AndroidChannelPlatform(context),
            )
        },
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
        commands.register(CommandTypes.LOCATE, LocateExecutor({ host }))
        scope.launch {
            settings.changes.collect { key ->
                if (key in CommandSettings.KEYS) commands.channel.onConfigChanged()
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

    /** Traces an event the uploader deleted because the server refuses it alone (metadata only, never content). */
    private fun reportDroppedEvent(dropped: DroppedEvent) {
        sink.emit(EventTypes.AGENT_COLLECTOR_ERROR, Severity.NOTABLE) {
            put("collector", "upload")
            put("error", "event_dropped ${dropped.reason} type=${dropped.type} id=${dropped.id}")
        }
    }

    fun requestUpload(force: Boolean) {
        if (enrollment.state.value == null) return
        if (!force && uploader.isRunning) uploader.requestRerun() else uploadScheduler.requestNow(force)
    }

    /**
     * Before a factory reset (remote `wipe`): writes the pending events, uploads them and posts the
     * pending command results, waiting at most [timeoutMs]. The work is not waited for beyond that.
     */
    suspend fun sendNowBounded(timeoutMs: Long) {
        val job = commandScope.launch {
            sink.flushNow()
            uploader.run(force = true)
            enrollment.target()?.let { commands.channel.flushResults(it, force = true) }
        }
        withTimeoutOrNull(timeoutMs) { job.join() }
    }

    fun handleUploadOutcome(outcome: UploadOutcome, fromRetryWorker: Boolean) {
        if (outcome != UploadOutcome.NotEnrolled) commands.channel.onUploadCycle()
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
        commands.channel.tick()
        maintenanceHook?.invoke()
    }

    /** Called by the service: retry at once when a network comes back after a network failure. */
    fun startNetworkWatch() {
        if (networkCallback != null) return
        val cm = context.getSystemService(ConnectivityManager::class.java) ?: return
        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                commands.channel.onNetworkAvailable()
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

    /**
     * Enrolls, or re-enrolls without unenrolling (renewed certificate, new token…). The buffered
     * events are kept unless the file points to another server ([EnrollmentChange.NEW_SERVER]).
     * The upload backoff left by the expired credentials is forgotten and an upload is requested.
     * Blocking (Keystore, database): call from a background thread.
     */
    fun enroll(parsed: ParsedEnrollment): EnrollmentChange {
        val change = enrollment.import(parsed) {
            uploadScheduler.cancelAll()
            runBlocking { outbox.clear() }
        }
        uploadStatus.update { it.copy(lastError = null, consecutiveFailures = 0, nextAttemptAtMs = 0) }
        uploadScheduler.ensurePeriodic(settings[CoreSettings.UPLOAD_INTERVAL_MIN])
        requestUpload(force = true)
        // New credentials: a channel stopped by a 401 may try again.
        commands.channel.onConfigChanged()
        return change
    }

    /** Forgets the enrollment and deletes the events waiting for that server. */
    fun unenroll() {
        enrollment.unenroll()
        uploadScheduler.cancelAll()
        uploadStatus.update { UploadStatus() }
        scope.launch { outbox.clear() }
        uploadScheduler.ensurePeriodic(settings[CoreSettings.UPLOAD_INTERVAL_MIN])
        commands.channel.onConfigChanged()
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
        private const val TAG = "VigieAgent"
        private const val PREFS_SETTINGS = "vigie_settings"
        private const val PREFS_BOOT = "vigie_boot"
        private const val PREFS_UPLOAD = "vigie_upload"
        private const val PREFS_ENROLLMENT = "vigie_enrollment"
        private const val PREFS_INTEGRITY = "vigie_integrity"
        private const val PREFS_AGE = "vigie_age_horizon"
        private const val PREFS_COMMANDS = "vigie_commands"
        private const val PREFS_COMMAND_KEY = "vigie_command_key"
        private const val COMMAND_KEY_ALIAS = "vigie_command_key"
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
