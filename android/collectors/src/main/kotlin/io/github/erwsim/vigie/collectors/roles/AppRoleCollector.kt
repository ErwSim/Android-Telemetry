package io.github.erwsim.vigie.collectors.roles

import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.database.ContentObserver
import android.provider.Settings
import androidx.core.content.edit
import io.github.erwsim.vigie.collectors.R
import io.github.erwsim.vigie.collectors.apps.DefaultApps
import io.github.erwsim.vigie.core.collector.CollectReason
import io.github.erwsim.vigie.core.collector.Collector
import io.github.erwsim.vigie.core.collector.CollectorContext
import io.github.erwsim.vigie.core.collector.PeriodicSpec
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

/**
 * `app.role`: change of default app (SMS, dialer, browser, home, assistant, keyboard, autofill), with the
 * old and the new package. Only what a third-party app may read is reported (see [DefaultApps]: `RoleManager`
 * cannot list the holders of a role for another app, not even for a Device Owner).
 *
 * Same reader as `app.special_access.default_apps` (which states the current default apps): the two events
 * cannot contradict each other for one reading; this one adds the date and the previous value of a change.
 * The first reading only sets the baseline (no event).
 *
 * Checked after package changes, changes of the relevant secure settings (content observers), at most every
 * 15 min at screen off, and hourly. Each check is a few binder calls.
 */
class AppRoleCollector(private val reader: (Context) -> Map<String, String>? = ::readDefaultApps) : Collector {
    override val id = "app_role"
    override val titleRes = R.string.collector_app_role_title
    override val descriptionRes = R.string.collector_app_role_desc
    override val eventTypes = listOf(TYPE)
    override val periodic = PeriodicSpec(intervalMinutes = 60, runAtStart = true)

    private val mutex = Mutex()
    private var pending: Job? = null
    private var lastScreenOffCheck = Long.MIN_VALUE / 2

    override suspend fun start(ctx: CollectorContext) {
        pending = null
        lastScreenOffCheck = Long.MIN_VALUE / 2
        val filter = IntentFilter().apply {
            addAction(Intent.ACTION_PACKAGE_ADDED)
            addAction(Intent.ACTION_PACKAGE_REMOVED)
            addAction(Intent.ACTION_PACKAGE_REPLACED)
            addAction(Intent.ACTION_PACKAGE_CHANGED)
            addDataScheme("package")
        }
        ctx.registerReceiver(filter) { schedule(ctx) }
        ctx.registerReceiver(IntentFilter(Intent.ACTION_SCREEN_OFF)) {
            val now = ctx.clock.elapsedRealtime()
            if (now - lastScreenOffCheck >= SCREEN_OFF_CHECK_MS) {
                lastScreenOffCheck = now
                schedule(ctx)
            }
        }
        val resolver = ctx.appContext.contentResolver ?: return
        val observer = object : ContentObserver(ctx.handler) {
            override fun onChange(selfChange: Boolean) = ctx.guard("settings") { schedule(ctx) }
        }
        for (key in OBSERVED_SECURE_KEYS) {
            resolver.registerContentObserver(Settings.Secure.getUriFor(key) ?: continue, false, observer)
        }
        ctx.onStop { resolver.unregisterContentObserver(observer) }
    }

    override suspend fun stop(ctx: CollectorContext) {
        pending = null
    }

    override suspend fun collectOnce(ctx: CollectorContext, reason: CollectReason) = check(ctx)

    /** Coalesces bursts of triggers into one check 5 s later (a role change touches several settings). */
    private fun schedule(ctx: CollectorContext) {
        if (pending?.isActive == true) return
        pending = ctx.scope.launch {
            delay(5_000)
            check(ctx)
        }
    }

    private suspend fun check(ctx: CollectorContext) = mutex.withLock {
        // Null or empty = the reading failed (an Android phone always has a browser and a home app).
        val now = withContext(ctx.io) { reader(ctx.appContext) }?.takeIf { it.isNotEmpty() } ?: return@withLock
        val old = RoleLogic.decode(ctx.prefs.getString(K_STATE, null))
        if (old == null) {
            ctx.prefs.edit { putString(K_STATE, RoleLogic.encode(now)) } // Baseline.
            return@withLock
        }
        val (changes, next) = RoleLogic.diff(old, now)
        changes.forEach { ctx.sink.emit(TYPE, RoleLogic.severity(it), RoleLogic.data(it)) }
        if (next != old) ctx.prefs.edit { putString(K_STATE, RoleLogic.encode(next)) }
    }

    companion object {
        const val TYPE = "app.role"
        private const val K_STATE = "roles_state"

        private fun readDefaultApps(context: Context): Map<String, String>? =
            context.packageManager?.let { DefaultApps.read(context, it) }

        private const val SCREEN_OFF_CHECK_MS = 15 * 60_000L

        /** Secure settings behind the roles (`sms_default_application` and `dialer_default_application` are hidden keys). */
        private val OBSERVED_SECURE_KEYS = listOf(
            "sms_default_application",
            "dialer_default_application",
            Settings.Secure.DEFAULT_INPUT_METHOD,
            "assistant",
            "autofill_service",
        )
    }
}
