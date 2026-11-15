package io.github.erwsim.vigie.policy.logs

import android.app.admin.DevicePolicyManager
import android.app.admin.SecurityLog
import android.content.ComponentName
import android.content.Context
import io.github.erwsim.vigie.core.collector.Collector
import io.github.erwsim.vigie.core.collector.CollectorContext
import io.github.erwsim.vigie.core.collector.Requirement
import io.github.erwsim.vigie.core.settings.SettingKey
import io.github.erwsim.vigie.core.settings.SettingSpec
import io.github.erwsim.vigie.policy.PolicyModule
import io.github.erwsim.vigie.policy.R
import io.github.erwsim.vigie.policy.VigieAdminReceiver
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

/**
 * Device Owner security logging (`security.log`). The system polls logd every minute and notifies
 * at 1024 entries or every 2 h (`onSecurityLogsAvailable`); `retrieveSecurityLogs` is rate-limited
 * and only called from that callback. Logs from before the last reboot
 * (`retrievePreRebootSecurityLogs`, not supported everywhere) are read once per boot, keeping
 * only entries newer than the last one already sent.
 */
class SecurityLogCollector : Collector {
    override val id = ID
    override val titleRes = R.string.collector_security_log_title
    override val descriptionRes = R.string.collector_security_log_desc
    override val eventTypes = listOf("security.log", "security.policy")
    override val requirements = listOf(Requirement.DeviceOwner)
    override val settings = listOf(
        SettingSpec.BoolSpec(APP_PROCESS, R.string.setting_security_log_app_process, R.string.setting_security_log_app_process_summary),
        SettingSpec.BoolSpec(APP_PROCESS_AGGREGATE, R.string.setting_security_log_aggregate, R.string.setting_security_log_aggregate_summary),
        SettingSpec.BoolSpec(RADIO, R.string.setting_security_log_radio, R.string.setting_security_log_radio_summary),
    )

    @Volatile
    private var ctx: CollectorContext? = null
    private val mutex = Mutex()

    /** Called with the outputs of each batch (the posture collector re-checks user CAs on CA tags). */
    @Volatile
    var onBatch: ((List<SecurityOutput>) -> Unit)? = null

    override suspend fun start(ctx: CollectorContext) {
        this.ctx = ctx
        withContext(Dispatchers.IO) { ensureLogging(ctx, true) }
        if (ctx.prefs.getString(K_PRE_REBOOT_BOOT, null) != ctx.boot.bootId) {
            ctx.scope.launch(Dispatchers.IO) { preReboot(ctx) }
        }
    }

    override suspend fun stop(ctx: CollectorContext) {
        this.ctx = null
        if (!ctx.settings[ctx.settings.collectorEnabledKey(id, defaultEnabled)]) {
            withContext(Dispatchers.IO) { ensureLogging(ctx, false) }
        }
    }

    /** From [VigieAdminReceiver] (main thread). */
    fun onLogsAvailable(context: Context) {
        val c = ctx
        if (c != null) {
            c.scope.launch(Dispatchers.IO) { retrieve(c) }
        } else {
            PolicyModule.onLogsWhileStopped(context, id) { gw -> gw.setSecurityLoggingEnabled(false) }
        }
    }

    private suspend fun retrieve(ctx: CollectorContext) = mutex.withLock {
        val events = try {
            dpm(ctx)?.retrieveSecurityLogs(admin(ctx))
        } catch (e: SecurityException) {
            ctx.reportError(e, "retrieveSecurityLogs")
            null
        } ?: return@withLock // null: rate-limited or logging off
        emit(ctx, events.map(::raw), preReboot = false, afterNanos = Long.MIN_VALUE)
    }

    private suspend fun preReboot(ctx: CollectorContext) = mutex.withLock {
        val events = try {
            dpm(ctx)?.retrievePreRebootSecurityLogs(admin(ctx))
        } catch (e: Exception) {
            ctx.reportError(e, "retrievePreRebootSecurityLogs")
            null
        }
        ctx.prefs.edit().putString(K_PRE_REBOOT_BOOT, ctx.boot.bootId).apply()
        if (events.isNullOrEmpty()) return@withLock // null: not supported on this device
        val after = ctx.prefs.getLong(K_LAST_NANOS, Long.MIN_VALUE)
        // Without any previous retrieval, everything before the reboot would be a flood of old entries.
        if (after == Long.MIN_VALUE) return@withLock
        emit(ctx, events.map(::raw), preReboot = true, afterNanos = after)
    }

    private suspend fun emit(ctx: CollectorContext, raw: List<RawSecurityEvent>, preReboot: Boolean, afterNanos: Long) {
        if (raw.isEmpty()) return
        val filter = SecurityLogFilter(
            appProcessStart = ctx.settings[APP_PROCESS],
            aggregateAppProcess = ctx.settings[APP_PROCESS_AGGREGATE],
            radio = ctx.settings[RADIO],
        )
        val outputs = SecurityLogProcessor.process(raw, filter, afterNanos, preReboot)
        val newest = raw.maxOf { it.timeNanos }
        if (newest > ctx.prefs.getLong(K_LAST_NANOS, Long.MIN_VALUE)) ctx.prefs.edit().putLong(K_LAST_NANOS, newest).apply()
        for (chunk in outputs.chunked(CHUNK)) {
            chunk.forEach { ctx.sink.emit(SecurityLogProcessor.TYPE, it.sev, it.data) }
            delay(CHUNK_PAUSE_MS)
        }
        onBatch?.invoke(outputs)
    }

    private fun raw(e: SecurityLog.SecurityEvent) = RawSecurityEvent(e.tag, e.logLevel, e.id, e.timeNanos, e.data)

    private fun ensureLogging(ctx: CollectorContext, enabled: Boolean) {
        val dpm = dpm(ctx) ?: return
        val admin = admin(ctx)
        try {
            if (!dpm.isDeviceOwnerApp(ctx.appContext.packageName) || dpm.isSecurityLoggingEnabled(admin) == enabled) return
            dpm.setSecurityLoggingEnabled(admin, enabled)
            val ok = dpm.isSecurityLoggingEnabled(admin) == enabled
            PolicyModule.logAction(ctx.appContext, "security_logging", if (enabled) "enabled" else "disabled", ok, if (ok) null else "aucun effet constaté")
        } catch (e: Exception) {
            PolicyModule.logAction(ctx.appContext, "security_logging", if (enabled) "enabled" else "disabled", false, e.toString())
            if (enabled) throw e
        }
    }

    private fun dpm(ctx: CollectorContext) = ctx.appContext.getSystemService(DevicePolicyManager::class.java)
    private fun admin(ctx: CollectorContext) = ComponentName(ctx.appContext, VigieAdminReceiver::class.java)

    companion object {
        const val ID = "security_log"
        val APP_PROCESS = SettingKey.BoolKey("security_log.app_process", true)
        val APP_PROCESS_AGGREGATE = SettingKey.BoolKey("security_log.app_process_aggregate", true)
        val RADIO = SettingKey.BoolKey("security_log.radio", true)
        private const val K_LAST_NANOS = "last_time_nanos"
        private const val K_PRE_REBOOT_BOOT = "pre_reboot_read_for_boot"
        private const val CHUNK = 100
        private const val CHUNK_PAUSE_MS = 250L
    }
}
