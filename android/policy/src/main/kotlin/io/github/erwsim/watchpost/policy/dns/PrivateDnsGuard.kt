package io.github.erwsim.watchpost.policy.dns

import android.content.Context
import android.content.SharedPreferences
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import androidx.core.content.edit
import io.github.erwsim.watchpost.core.event.AgentClock
import io.github.erwsim.watchpost.policy.engine.AppliedRecord
import io.github.erwsim.watchpost.policy.engine.PolicyEngine
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

/** Inputs of one guard decision. */
data class DnsGuardInput(
    val record: AppliedRecord?,
    /** A default network exists. */
    val networkAvailable: Boolean,
    /** The default network passed Android's validation (DNS included). */
    val validated: Boolean,
    /** Result of our own DoT check of the host (null: not run). */
    val probeOk: Boolean?,
    val failingSinceMs: Long?,
    val nowMs: Long,
    val fallbackEnabled: Boolean,
    val fallbackAfterMs: Long,
    val autoRestore: Boolean,
)

sealed class DnsGuardDecision {
    /** Nothing wrong (or nothing to judge): forget any failure start. */
    data object Healthy : DnsGuardDecision()

    /** Cannot judge now (no network): keep the current failure start, if any. */
    data object Unknown : DnsGuardDecision()

    /** The DNS host is failing since [sinceMs]: check again at [recheckAtMs]. */
    data class Failing(val sinceMs: Long, val recheckAtMs: Long) : DnsGuardDecision()

    data class Fallback(val sinceMs: Long) : DnsGuardDecision()

    data object Reapply : DnsGuardDecision()
}

/**
 * Pure decision of the private DNS fallback (tested on the JVM).
 *
 * Trade-off (availability vs protection), tunable in the settings:
 * - strict private DNS + unreachable host = no DNS at all = no Internet. Android does not fall back
 *   by itself;
 * - "unreachable" means: the default network is NOT validated by Android AND our own DoT check of
 *   the host (by its last known addresses) fails, continuously for [DnsGuardInput.fallbackAfterMs]
 *   (default 15 min). A network that is simply down (no default network) or validated never counts;
 * - fallback = opportunistic mode (encrypted DNS of the network if available, else plain DNS): the
 *   phone keeps working but DNS filtering and the AdGuard log are lost until the host answers again.
 *   It is emitted with sev 2 (Wazuh alert): blocking port 853 to force a downgrade is visible;
 * - with auto-restore, the host is re-imposed (after a new check) as soon as it answers again.
 * Disabling the fallback favours protection: the phone stays without Internet until the server is
 * fixed or the user undoes the DNS from the app (or the ADB rescue).
 */
object DnsGuardLogic {
    fun decide(i: DnsGuardInput): DnsGuardDecision {
        val record = i.record ?: return DnsGuardDecision.Healthy
        if (record.dnsFallback) {
            return if (i.autoRestore && i.probeOk == true) DnsGuardDecision.Reapply else DnsGuardDecision.Unknown
        }
        if (!i.networkAvailable) return DnsGuardDecision.Unknown
        if (i.validated) return DnsGuardDecision.Healthy
        if (i.probeOk != false) return DnsGuardDecision.Healthy // the host answers: the problem is elsewhere
        // A start "in the future" was written by a clock that has moved back since: start again from now
        // (otherwise the fallback would wait until the clock catches up, the phone staying without DNS).
        val since = i.failingSinceMs?.takeIf { it <= i.nowMs } ?: i.nowMs
        return if (i.fallbackEnabled && i.nowMs - since >= i.fallbackAfterMs) {
            DnsGuardDecision.Fallback(since)
        } else {
            DnsGuardDecision.Failing(since, since + i.fallbackAfterMs)
        }
    }
}

/**
 * Watches the imposed private DNS: on default-network changes and at each maintenance pass
 * (15 min). No polling of its own beyond one delayed re-check while a failure is pending.
 */
class PrivateDnsGuard(
    private val context: Context,
    private val engine: () -> PolicyEngine?,
    private val prefs: SharedPreferences,
    private val probe: DnsProbe,
    private val clock: AgentClock,
    private val scope: CoroutineScope,
    private val fallbackEnabled: () -> Boolean,
    private val fallbackAfterMs: () -> Long,
    private val autoRestore: () -> Boolean,
) {
    @Volatile
    private var callback: ConnectivityManager.NetworkCallback? = null
    @Volatile
    private var recheck: Job? = null
    @Volatile
    private var lastCheckElapsed = 0L

    /** Registers the default-network callback (idempotent). */
    fun watch() {
        if (callback != null) return
        val cm = context.getSystemService(ConnectivityManager::class.java) ?: return
        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) {
                // Validation flips are rare; skip bursts of capability updates.
                if (clock.elapsedRealtime() - lastCheckElapsed > MIN_INTERVAL_MS) checkSoon()
            }

            override fun onAvailable(network: Network) = checkSoon()
        }
        try {
            cm.registerDefaultNetworkCallback(cb)
            callback = cb
        } catch (_: Exception) {
            // Too many callbacks: the maintenance pass still checks every 15 minutes.
        }
    }

    fun checkSoon() {
        scope.launch(Dispatchers.IO) { check() }
    }

    @Synchronized
    fun check() {
        lastCheckElapsed = clock.elapsedRealtime()
        val engine = engine() ?: return
        val record = engine.dnsRecord()
        if (record == null) {
            prefs.edit { remove(K_FAILING_SINCE) }
            return
        }
        val cm = context.getSystemService(ConnectivityManager::class.java)
        val network = cm?.activeNetwork
        val caps = network?.let { cm.getNetworkCapabilities(it) }
        val validated = caps?.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED) == true
        val needProbe = record.dnsFallback || (network != null && !validated)
        val probeOk = if (needProbe) probe.probe(record.target, record.dnsAddresses).ok else null
        val decision = DnsGuardLogic.decide(
            DnsGuardInput(
                record = record,
                networkAvailable = network != null,
                validated = validated,
                probeOk = probeOk,
                failingSinceMs = prefs.getLong(K_FAILING_SINCE, 0).takeIf { it > 0 },
                nowMs = clock.nowMillis(),
                fallbackEnabled = fallbackEnabled(),
                fallbackAfterMs = fallbackAfterMs(),
                autoRestore = autoRestore(),
            ),
        )
        when (decision) {
            DnsGuardDecision.Healthy -> prefs.edit { remove(K_FAILING_SINCE) }
            DnsGuardDecision.Unknown -> Unit
            is DnsGuardDecision.Failing -> {
                prefs.edit { putLong(K_FAILING_SINCE, decision.sinceMs) }
                scheduleRecheck(decision.recheckAtMs - clock.nowMillis())
            }
            is DnsGuardDecision.Fallback -> {
                val minutes = (clock.nowMillis() - decision.sinceMs) / 60_000
                engine.dnsFallback("host ${record.target} unreachable for $minutes min (network not validated, DoT check failing)")
                prefs.edit { remove(K_FAILING_SINCE) }
            }
            DnsGuardDecision.Reapply -> engine.dnsReapply()
        }
    }

    private fun scheduleRecheck(delayMs: Long) {
        recheck?.cancel()
        recheck = scope.launch(Dispatchers.IO) {
            delay(delayMs.coerceIn(10_000, 4 * 3_600_000L))
            check()
        }
    }

    private companion object {
        const val K_FAILING_SINCE = "dns_failing_since_ms"
        const val MIN_INTERVAL_MS = 60_000L
    }
}
