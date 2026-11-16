package io.github.erwsim.watchpost.collectors.risk

import android.content.Intent
import android.content.IntentFilter
import androidx.core.content.edit
import io.github.erwsim.watchpost.collectors.R
import io.github.erwsim.watchpost.core.collector.CollectReason
import io.github.erwsim.watchpost.core.collector.Collector
import io.github.erwsim.watchpost.core.collector.CollectorContext
import io.github.erwsim.watchpost.core.collector.PeriodicSpec
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

/**
 * `app.risk`: the risk profile of each app (score 0 to 100, level, reason codes), computed by the pure
 * function [RiskScorer] from what `PackageManager` exposes. Emitted at each installation and update, and
 * once a day only for the apps whose score or reasons changed (persistent state). The first scan reports
 * every app once. System apps and Watchpost itself are scored but capped at "low".
 *
 * Cost: one package scan and six component queries per day, one single-package read per install.
 */
class AppRiskCollector(private val source: FactsSource = PackageManagerFactsSource) : Collector {
    override val id = "app_risk"
    override val titleRes = R.string.collector_app_risk_title
    override val descriptionRes = R.string.collector_app_risk_desc
    override val eventTypes = listOf(TYPE)
    override val periodic = PeriodicSpec(intervalMinutes = 24 * 60, runAtStart = true)

    private val mutex = Mutex()

    override suspend fun start(ctx: CollectorContext) {
        val filter = IntentFilter().apply {
            addAction(Intent.ACTION_PACKAGE_ADDED)
            addAction(Intent.ACTION_PACKAGE_REPLACED)
            addAction(Intent.ACTION_PACKAGE_REMOVED)
            addDataScheme("package")
        }
        ctx.registerReceiver(filter) { intent ->
            val pkg = intent.data?.schemeSpecificPart ?: return@registerReceiver
            val action = intent.action
            val replacing = intent.getBooleanExtra(Intent.EXTRA_REPLACING, false)
            ctx.scope.launch { onPackage(ctx, action, pkg, replacing) }
        }
    }

    private suspend fun onPackage(ctx: CollectorContext, action: String?, pkg: String, replacing: Boolean) = mutex.withLock {
        val state = RiskLogic.decode(ctx.prefs.getString(K_STATE, null))?.toMutableMap() ?: mutableMapOf()
        when {
            // An update broadcasts ADDED (replacing) then REPLACED: report it once, on REPLACED.
            (action == Intent.ACTION_PACKAGE_ADDED && !replacing) || action == Intent.ACTION_PACKAGE_REPLACED -> {
                val facts = withContext(ctx.io) { source.read(ctx.appContext, pkg) } ?: return@withLock
                report(ctx, facts, state, RiskLogic.Trigger.INSTALL_OR_UPDATE)
            }
            // Hiding an app also broadcasts PACKAGE_REMOVED: only forget it if it is really gone.
            action == Intent.ACTION_PACKAGE_REMOVED && !replacing -> {
                if (withContext(ctx.io) { source.read(ctx.appContext, pkg) } != null) return@withLock
                if (state.remove(pkg) == null) return@withLock
            }
            else -> return@withLock
        }
        ctx.prefs.edit { putString(K_STATE, RiskLogic.encode(state)) }
    }

    override suspend fun collectOnce(ctx: CollectorContext, reason: CollectReason) = mutex.withLock {
        val all = withContext(ctx.io) { source.readAll(ctx.appContext) } ?: return@withLock
        if (all.isEmpty()) return@withLock // An empty list is a failed reading, not "no apps".
        val state = (RiskLogic.decode(ctx.prefs.getString(K_STATE, null)) ?: emptyMap()).toMutableMap()
        state.keys.retainAll(all.map { it.pkg }.toSet())
        all.sortedBy { it.pkg }.forEach { report(ctx, it, state, RiskLogic.Trigger.DAILY) }
        ctx.prefs.edit { putString(K_STATE, RiskLogic.encode(state)) }
    }

    private fun report(ctx: CollectorContext, facts: AppFacts, state: MutableMap<String, RiskEntry>, trigger: RiskLogic.Trigger) {
        val assessment = RiskScorer.score(facts)
        val entry = RiskLogic.entryOf(facts, assessment)
        if (RiskLogic.shouldEmit(state[facts.pkg], entry, trigger)) {
            ctx.sink.emit(TYPE, RiskLogic.severity(assessment.level), RiskLogic.data(facts, assessment))
        }
        state[facts.pkg] = entry
    }

    companion object {
        const val TYPE = "app.risk"
        private const val K_STATE = "risk_state"
    }
}
