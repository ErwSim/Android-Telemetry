package io.github.erwsim.vigie.policy.logs

import android.app.admin.ConnectEvent
import android.app.admin.DevicePolicyManager
import android.app.admin.DnsEvent
import android.app.admin.NetworkEvent
import android.content.ComponentName
import android.content.pm.PackageManager
import androidx.core.content.edit
import io.github.erwsim.vigie.core.collector.Collector
import io.github.erwsim.vigie.core.collector.CollectorContext
import io.github.erwsim.vigie.core.collector.Requirement
import io.github.erwsim.vigie.core.event.Severity
import io.github.erwsim.vigie.core.settings.SettingKey
import io.github.erwsim.vigie.core.settings.SettingSpec
import io.github.erwsim.vigie.policy.PolicyModule
import io.github.erwsim.vigie.policy.R
import io.github.erwsim.vigie.policy.VigieAdminReceiver
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

/**
 * Device Owner network logging (`net.dns`, `net.connect`): DNS lookups and TCP `connect()` per
 * app, delivered by the system in batches (≤ 1200 entries, at most every 1 h 30) through
 * `DeviceAdminReceiver.onNetworkLogsAvailable`. No polling.
 *
 * - The logging switch follows this collector's switch: enabled at start, disabled when the owner
 *   turns the collector off (not when the agent merely stops). Each switch emits `security.policy`.
 * - A batch notified while the agent was stopped is retrieved at the next start (the system keeps
 *   up to 5 unretrieved batches). Gaps in batch tokens or expired batches are reported as
 *   `agent.collector_error`.
 * - Emission in chunks of [CHUNK] events with a short pause, so a full batch never floods the
 *   in-memory buffer; optional aggregation of identical requests per window.
 */
class NetworkLogCollector : Collector {
    override val id = ID
    override val titleRes = R.string.collector_network_log_title
    override val descriptionRes = R.string.collector_network_log_desc
    override val eventTypes = listOf("net.dns", "net.connect", "security.policy")
    override val requirements = listOf(Requirement.DeviceOwner)
    override val settings = listOf(
        SettingSpec.BoolSpec(AGGREGATE, R.string.setting_network_log_aggregate, R.string.setting_network_log_aggregate_summary),
        SettingSpec.IntSpec(WINDOW_MIN, R.string.setting_network_log_window, R.string.setting_network_log_window_summary, "min"),
        SettingSpec.BoolSpec(CONNECT, R.string.setting_network_log_connect, R.string.setting_network_log_connect_summary),
    )

    @Volatile
    private var ctx: CollectorContext? = null
    private val mutex = Mutex()

    override suspend fun start(ctx: CollectorContext) {
        this.ctx = ctx
        withContext(ctx.io) { ensureLogging(ctx, true) }
        val notified = ctx.prefs.getLong(K_NOTIFIED, 0)
        if (notified > 0 && notified != ctx.prefs.getLong(K_PROCESSED, 0)) {
            ctx.scope.launch(ctx.io) { process(ctx, notified) }
        }
    }

    override suspend fun stop(ctx: CollectorContext) {
        this.ctx = null
        // Turned off by the owner (not an agent stop): stop the system logging as well.
        if (!ctx.settings[ctx.settings.collectorEnabledKey(id, defaultEnabled)]) {
            withContext(ctx.io) { ensureLogging(ctx, false) }
        }
    }

    /** From [VigieAdminReceiver] (main thread): must return fast. */
    fun onBatchAvailable(context: android.content.Context, token: Long) {
        context.getSharedPreferences("collector_$id", android.content.Context.MODE_PRIVATE)
            .edit { putLong(K_NOTIFIED, token) }
        val c = ctx
        if (c != null) {
            c.scope.launch(c.io) { process(c, token) }
        } else {
            PolicyModule.onLogsWhileStopped(context, id) { gw -> gw.setNetworkLoggingEnabled(false) }
        }
    }

    private suspend fun process(ctx: CollectorContext, token: Long) = mutex.withLock {
        val processed = ctx.prefs.getLong(K_PROCESSED, 0)
        if (token == processed) return@withLock
        // Batches finalized while logging was paused are not notified one by one: fetch every
        // token not yet processed that the system may still hold (at most 5).
        val plan = NetworkLogProcessor.tokensToFetch(processed, token)
        var missing = plan.lostBeforeWindow
        val events = ArrayList<NetworkEvent>()
        for (t in plan.tokens) {
            val batch: List<NetworkEvent>? = try {
                dpm(ctx)?.retrieveNetworkLogs(admin(ctx), t)
            } catch (e: SecurityException) {
                ctx.reportError(e, "retrieveNetworkLogs")
                null
            }
            // Tokens only advance for non-empty batches: an absent batch was dropped by the system.
            if (batch == null) missing++ else events += batch
        }
        ctx.prefs.edit { putLong(K_PROCESSED, token) }
        if (missing > 0) {
            ctx.reportError(IllegalStateException("$missing lot(s) de journaux réseau perdus (non récupérés à temps)"), "network_log")
        }
        if (events.isEmpty()) return@withLock
        val records = events.mapNotNull(::toRecord)
        val pm = ctx.appContext.packageManager
        val resolver = OwnerResolver(
            uidOf = { pkg -> pm.getPackageUid(pkg, PackageManager.PackageInfoFlags.of(0)) },
            packagesForUid = { uid -> pm.getPackagesForUid(uid)?.toList().orEmpty() },
        )
        val window = if (ctx.settings[AGGREGATE]) ctx.settings[WINDOW_MIN] * 60_000L else 0L
        val outputs = NetworkLogProcessor.process(records, resolver, window, ctx.settings[CONNECT])
        for (chunk in outputs.chunked(CHUNK)) {
            chunk.forEach { ctx.sink.emit(it.type, Severity.INFO, it.data, originTsMs = it.tsMs.takeIf { t -> t > 0 }) }
            delay(CHUNK_PAUSE_MS)
        }
    }

    private fun toRecord(e: NetworkEvent): NetRecord? = when (e) {
        is DnsEvent -> NetRecord.Dns(
            rawPackage = e.packageName,
            timeMs = e.timestamp,
            hostname = e.hostname ?: return null,
            addresses = e.inetAddresses.orEmpty().mapNotNull { it.hostAddress },
            addressCount = e.totalResolvedAddressCount,
        )
        is ConnectEvent -> NetRecord.Connect(
            rawPackage = e.packageName,
            timeMs = e.timestamp,
            ip = e.inetAddress?.hostAddress ?: return null,
            port = e.port,
        )
        else -> null
    }

    private fun ensureLogging(ctx: CollectorContext, enabled: Boolean) {
        val dpm = dpm(ctx) ?: return
        val admin = admin(ctx)
        try {
            if (!dpm.isDeviceOwnerApp(ctx.appContext.packageName) || dpm.isNetworkLoggingEnabled(admin) == enabled) return
            dpm.setNetworkLoggingEnabled(admin, enabled)
            val ok = dpm.isNetworkLoggingEnabled(admin) == enabled
            PolicyModule.logAction(ctx.appContext, "network_logging", if (enabled) "enabled" else "disabled", ok, if (ok) null else "aucun effet constaté")
        } catch (e: Exception) {
            PolicyModule.logAction(ctx.appContext, "network_logging", if (enabled) "enabled" else "disabled", false, e.toString())
            if (enabled) throw e
        }
    }

    private fun dpm(ctx: CollectorContext) = ctx.appContext.getSystemService(DevicePolicyManager::class.java)
    private fun admin(ctx: CollectorContext) = ComponentName(ctx.appContext, VigieAdminReceiver::class.java)

    companion object {
        const val ID = "network_log"
        val AGGREGATE = SettingKey.BoolKey("network_log.aggregate", true)
        val WINDOW_MIN = SettingKey.IntKey("network_log.window_min", 10, 1, 90)
        val CONNECT = SettingKey.BoolKey("network_log.connect", true)
        private const val K_NOTIFIED = "notified_token"
        private const val K_PROCESSED = "processed_token"
        private const val CHUNK = 100
        private const val CHUNK_PAUSE_MS = 250L
    }
}
