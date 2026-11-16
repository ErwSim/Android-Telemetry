package io.github.erwsim.vigie.policy

import android.annotation.SuppressLint
import android.content.Context
import android.util.Log
import io.github.erwsim.vigie.core.Agent
import io.github.erwsim.vigie.core.collector.Collector
import io.github.erwsim.vigie.core.event.AgentClock
import io.github.erwsim.vigie.core.settings.SettingKey
import io.github.erwsim.vigie.core.settings.SettingSpec
import io.github.erwsim.vigie.policy.dns.DotProbe
import io.github.erwsim.vigie.policy.dns.PrivateDnsGuard
import io.github.erwsim.vigie.policy.engine.AndroidDevicePolicyGateway
import io.github.erwsim.vigie.policy.engine.DevicePolicyGateway
import io.github.erwsim.vigie.policy.engine.PolicyCatalog
import io.github.erwsim.vigie.policy.engine.PolicyEngine
import io.github.erwsim.vigie.policy.engine.PolicyStore
import io.github.erwsim.vigie.policy.logs.NetworkLogCollector
import io.github.erwsim.vigie.policy.logs.SecurityLogCollector
import io.github.erwsim.vigie.policy.logs.SecurityLogProcessor
import io.github.erwsim.vigie.policy.posture.PostureCollector
import io.github.erwsim.vigie.policy.ui.PolicyController
import kotlinx.coroutines.CoroutineExceptionHandler
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch

/**
 * Entry point of the `:policy` module (everything that requires Device Owner):
 * - [collectors]: system security log, network log (DNS + TCP connections), posture;
 * - [onNetworkLogsAvailable] / [onSecurityLogsAvailable] / keyguard callbacks from [VigieAdminReceiver];
 * - [engine]: the local policy (private DNS, packages, permissions, restrictions, settings), applied
 *   only from the "Politique" screen, entirely reversible, also from ADB ([io.github.erwsim.vigie.policy.rescue.RescueReceiver]);
 * - [settings]: Device Owner settings rendered in the app's settings screen.
 * Nothing of the policy is applied automatically: only the force-stop protection and the
 * self-granted permissions (base agent) are.
 */
object PolicyModule {
    private const val TAG = "VigiePolicy"
    private const val PREFS_POLICY = "vigie_policy"
    private const val PREFS_DNS_GUARD = "vigie_policy_dns_guard"
    private const val PREFS_SELF_GRANT = "vigie_policy_self_grant"
    private const val K_GRANTED_ONCE = "granted_once"

    val FORCE_STOP_PROTECTION = SettingKey.BoolKey("policy.force_stop_protection", true)
    val DNS_FALLBACK = SettingKey.BoolKey("policy.dns_fallback", true)
    val DNS_FALLBACK_MIN = SettingKey.IntKey("policy.dns_fallback_min", 15, 5, 240)
    val DNS_AUTO_RESTORE = SettingKey.BoolKey("policy.dns_auto_restore", true)

    val settings: List<SettingSpec> = listOf(
        SettingSpec.BoolSpec(FORCE_STOP_PROTECTION, R.string.setting_force_stop_protection, R.string.setting_force_stop_protection_summary),
        SettingSpec.BoolSpec(DNS_FALLBACK, R.string.setting_dns_fallback, R.string.setting_dns_fallback_summary),
        SettingSpec.IntSpec(DNS_FALLBACK_MIN, R.string.setting_dns_fallback_min, R.string.setting_dns_fallback_min_summary, "min"),
        SettingSpec.BoolSpec(DNS_AUTO_RESTORE, R.string.setting_dns_auto_restore, R.string.setting_dns_auto_restore_summary),
    )

    val securityLog = SecurityLogCollector()
    val networkLog = NetworkLogCollector()
    val posture = PostureCollector()

    // Nothing launched here may crash the process (the ADB rescue runs in it): failures are logged.
    private val scope = CoroutineScope(
        SupervisorJob() + Dispatchers.Default + CoroutineExceptionHandler { _, e -> Log.e(TAG, "policy background task failed", e) },
    )
    private val reportedGrantFailures = java.util.Collections.synchronizedSet(HashSet<String>())

    @SuppressLint("StaticFieldLeak") // application context only
    @Volatile
    private var engineInstance: PolicyEngine? = null

    @SuppressLint("StaticFieldLeak") // application context only
    @Volatile
    private var guardInstance: PrivateDnsGuard? = null

    @SuppressLint("StaticFieldLeak") // application context only
    @Volatile
    private var controllerInstance: PolicyController? = null

    /** Display order in the app. */
    @Suppress("UNUSED_PARAMETER")
    fun collectors(context: Context): List<Collector> {
        securityLog.onBatch = { outputs -> if (SecurityLogProcessor.touchesCertificates(outputs)) posture.requestCheck() }
        return listOf(securityLog, networkLog, posture)
    }

    fun deviceOwner(agent: Agent) = DeviceOwnerManager(agent.context, agent.capabilities)

    /** The policy engine (one per process). */
    fun engine(context: Context): PolicyEngine = engineInstance ?: synchronized(this) {
        engineInstance ?: buildEngine(context.applicationContext).also { engineInstance = it }
    }

    private fun buildEngine(context: Context): PolicyEngine {
        val catalog = context.resources.openRawResource(R.raw.policy_catalog).bufferedReader().use { PolicyCatalog.parse(it.readText()) }
        return PolicyEngine(
            gateway = AndroidDevicePolicyGateway(context),
            store = PolicyStore(context.getSharedPreferences(PREFS_POLICY, Context.MODE_PRIVATE)),
            catalog = catalog,
            probe = DotProbe(),
            clock = AgentClock.System,
            sink = { Agent.getOrNull()?.sink },
            dnsHost = { Agent.getOrNull()?.enrollment?.state?.value?.privateDnsHost },
            // Voluntary removal (screen or ADB rescue): announced to the integrity monitor so that the
            // loss is not reported as agent.tamper; device_owner_cleared (security.policy) reports it.
            beforeClearOwner = {
                Agent.getOrNull()?.let { agent ->
                    agent.integrity.expectOwnershipLoss()
                    agent.sink.flushBlocking(2_000)
                }
            },
            afterClearOwner = { cleared ->
                Agent.getOrNull()?.let { agent ->
                    if (cleared) {
                        agent.integrity.checkPermissionsAndOwnership()
                        agent.host.reconcile()
                    } else {
                        agent.integrity.cancelOwnershipLossExpectation()
                    }
                }
            },
        )
    }

    fun gateway(context: Context): DevicePolicyGateway = AndroidDevicePolicyGateway(context.applicationContext)

    /** State holder of the "Politique" screen. */
    fun controller(agent: Agent): PolicyController = controllerInstance ?: synchronized(this) {
        controllerInstance ?: PolicyController(
            context = agent.context,
            engine = engine(agent.context),
            gateway = AndroidDevicePolicyGateway(agent.context),
            scope = scope,
            onApplied = { guard(agent).watch() },
        )
            .also { controllerInstance = it }
    }

    private fun guard(agent: Agent): PrivateDnsGuard = guardInstance ?: synchronized(this) {
        guardInstance ?: PrivateDnsGuard(
            context = agent.context,
            engine = { engine(agent.context) },
            prefs = agent.context.getSharedPreferences(PREFS_DNS_GUARD, Context.MODE_PRIVATE),
            probe = DotProbe(),
            clock = agent.clock,
            scope = scope,
            fallbackEnabled = { agent.settings[DNS_FALLBACK] },
            fallbackAfterMs = { agent.settings[DNS_FALLBACK_MIN] * 60_000L },
            autoRestore = { agent.settings[DNS_AUTO_RESTORE] },
        ).also { guardInstance = it }
    }

    /** Called once from `Application.onCreate`, after `Agent.init`. */
    fun install(agent: Agent) {
        scope.launch {
            agent.settings.changes.collect { key ->
                when (key) {
                    FORCE_STOP_PROTECTION.name -> applyForceStopProtection(agent)
                    DNS_FALLBACK.name, DNS_FALLBACK_MIN.name, DNS_AUTO_RESTORE.name -> guard(agent).checkSoon()
                }
            }
        }
        scope.launch(Dispatchers.IO) {
            if (engine(agent.context).dnsRecord() != null) guard(agent).watch()
        }
    }

    /**
     * Device Owner (re)activated: the self-granted permissions are granted afresh (a new activation
     * is an explicit act of the owner).
     */
    fun onOwnerEnabled(agent: Agent) {
        agent.context.getSharedPreferences(PREFS_SELF_GRANT, Context.MODE_PRIVATE).edit().clear().apply()
        onAgentStarted(agent)
    }

    /** Called at each agent (service) start, on Device Owner activation and by the maintenance worker (15 min). */
    fun onAgentStarted(agent: Agent) {
        val manager = deviceOwner(agent)
        if (!manager.isDeviceOwner()) return
        // Each permission is self-granted once: a later revocation by the owner is respected.
        val grantPrefs = agent.context.getSharedPreferences(PREFS_SELF_GRANT, Context.MODE_PRIVATE)
        val grantedOnce = grantPrefs.getStringSet(K_GRANTED_ONCE, emptySet()).orEmpty().toSet()
        val results = manager.selfGrantRuntimePermissions(grantedOnce)
        results.filter { it.granted }.map { it.permission }.takeIf { it.isNotEmpty() }?.let { newly ->
            grantPrefs.edit().putStringSet(K_GRANTED_ONCE, grantedOnce + newly).apply()
        }
        for (r in results) {
            if (r.granted) {
                logAction(agent.context, "permission_granted", r.permission, true, null)
            } else if (reportedGrantFailures.add(r.permission)) {
                Log.w(TAG, "self-grant failed: ${r.permission} ${r.error.orEmpty()}")
                logAction(agent.context, "permission_granted", r.permission, false, r.error ?: "refusé")
            }
        }
        if (results.any { it.granted }) {
            agent.integrity.checkPermissionsAndOwnership()
            agent.host.reconcile()
        }
        applyForceStopProtection(agent)
        scope.launch(Dispatchers.IO) {
            if (engine(agent.context).dnsRecord() != null) {
                guard(agent).watch()
                guard(agent).check()
            }
        }
    }

    private fun applyForceStopProtection(agent: Agent) {
        val manager = deviceOwner(agent)
        val wanted = agent.settings[FORCE_STOP_PROTECTION]
        if (manager.isDeviceOwner() && manager.isForceStopProtected() != wanted) {
            val ok = manager.setForceStopProtection(wanted) && manager.isForceStopProtected() == wanted
            if (!ok) Log.w(TAG, "setUserControlDisabledPackages failed")
            logAction(agent.context, "force_stop_protection", if (wanted) "enabled" else "disabled", ok, if (ok) null else "aucun effet constaté")
        }
    }

    /** `security.policy` + local journal for an action outside the engine's items (logging switches…). */
    fun logAction(context: Context, action: String, target: String, ok: Boolean, error: String?) {
        try {
            engine(context).logAction(action, target, null, ok, error)
        } catch (e: Exception) {
            Log.w(TAG, "policy journal failed", e)
        }
    }

    /** Device Owner network logging batch ready (main thread). */
    fun onNetworkLogsAvailable(context: Context, batchToken: Long, @Suppress("UNUSED_PARAMETER") count: Int) {
        networkLog.onBatchAvailable(context, batchToken)
    }

    /** Device Owner security logs ready (main thread). */
    fun onSecurityLogsAvailable(context: Context) {
        securityLog.onLogsAvailable(context)
    }

    /**
     * A log batch arrived while its collector is not running. If the owner turned the collector
     * off, the system logging is switched off too; if only the agent is stopped, the batch waits
     * (the system keeps it) and is retrieved at the next start.
     */
    fun onLogsWhileStopped(context: Context, collectorId: String, disable: (DevicePolicyGateway) -> Unit) {
        val agent = Agent.getOrNull() ?: return
        val collector = agent.host.collectors.firstOrNull { it.id == collectorId } ?: return
        if (agent.host.isEnabled(collector)) return
        scope.launch(Dispatchers.IO) {
            val gw = gateway(context)
            val action = if (collectorId == networkLog.id) "network_logging" else "security_logging"
            try {
                if (gw.isDeviceOwner()) {
                    disable(gw)
                    logAction(context, action, "disabled", true, null)
                }
            } catch (e: Exception) {
                logAction(context, action, "disabled", false, e.toString())
            }
        }
    }

    fun onPasswordFailed(failedAttempts: Int?) = posture.onKeyguard(succeeded = false, failedAttempts = failedAttempts)

    fun onPasswordSucceeded(failedAttempts: Int?) = posture.onKeyguard(succeeded = true, failedAttempts = failedAttempts)

    fun onPasswordChanged() = posture.requestCheck()
}
