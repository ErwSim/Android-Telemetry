package io.github.erwsim.watchpost.policy

import android.annotation.SuppressLint
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.telecom.TelecomManager
import android.util.Log
import io.github.erwsim.watchpost.core.Agent
import io.github.erwsim.watchpost.core.collector.Collector
import io.github.erwsim.watchpost.core.event.AgentClock
import io.github.erwsim.watchpost.core.settings.SettingKey
import io.github.erwsim.watchpost.core.settings.SettingSpec
import io.github.erwsim.watchpost.policy.dns.DotProbe
import io.github.erwsim.watchpost.policy.dns.PrivateDnsGuard
import io.github.erwsim.watchpost.policy.engine.AndroidDevicePolicyGateway
import io.github.erwsim.watchpost.policy.engine.DevicePolicyGateway
import io.github.erwsim.watchpost.policy.engine.GuardKey
import io.github.erwsim.watchpost.policy.engine.GuardNotice
import io.github.erwsim.watchpost.policy.engine.GuardPermissions
import io.github.erwsim.watchpost.policy.engine.PolicyCatalog
import io.github.erwsim.watchpost.policy.engine.PolicyEngine
import io.github.erwsim.watchpost.policy.engine.PolicyStore
import io.github.erwsim.watchpost.policy.logs.NetworkLogCollector
import io.github.erwsim.watchpost.policy.logs.SecurityLogCollector
import io.github.erwsim.watchpost.policy.logs.SecurityLogProcessor
import io.github.erwsim.watchpost.policy.posture.PostureCollector
import io.github.erwsim.watchpost.policy.remote.AndroidFactoryReset
import io.github.erwsim.watchpost.policy.remote.AndroidLockScreenGateway
import io.github.erwsim.watchpost.policy.remote.ClearLockMessageExecutor
import io.github.erwsim.watchpost.policy.remote.LockExecutor
import io.github.erwsim.watchpost.policy.remote.WipeExecutor
import io.github.erwsim.watchpost.core.command.CommandTypes
import io.github.erwsim.watchpost.policy.ui.PolicyController
import kotlinx.coroutines.CoroutineExceptionHandler
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

/**
 * Entry point of the `:policy` module (everything that requires Device Owner):
 * - [collectors]: system security log, network log (DNS + TCP connections), posture;
 * - [onNetworkLogsAvailable] / [onSecurityLogsAvailable] / keyguard callbacks from [WatchpostAdminReceiver];
 * - [engine]: the local policy (private DNS, packages, permissions, restrictions, settings), applied
 *   only from the "Politique" screen, entirely reversible, also from ADB ([io.github.erwsim.watchpost.policy.rescue.RescueReceiver]);
 * - [settings]: Device Owner settings rendered in the app's settings screen.
 * Nothing of the policy is applied automatically: only the force-stop protection and the
 * self-granted permissions (base agent) are.
 */
object PolicyModule {
    private const val TAG = "WatchpostPolicy"
    private const val PREFS_POLICY = "watchpost_policy"
    private const val PREFS_DNS_GUARD = "watchpost_policy_dns_guard"
    private const val PREFS_SELF_GRANT = "watchpost_policy_self_grant"
    private const val K_GRANTED_ONCE = "granted_once"

    val FORCE_STOP_PROTECTION = SettingKey.BoolKey("policy.force_stop_protection", true)
    val DNS_FALLBACK = SettingKey.BoolKey("policy.dns_fallback", true)
    val DNS_FALLBACK_MIN = SettingKey.IntKey("policy.dns_fallback_min", 15, 5, 240)
    val DNS_AUTO_RESTORE = SettingKey.BoolKey("policy.dns_auto_restore", true)

    /** Exception lists of the guards (contract §11.1): edited in the "Gardes" section, applied after a preview. */
    val GUARD_LISTS: Map<GuardKey, SettingKey.PackageListKey> = listOf(GuardKey.SMS, GuardKey.CALLS, GuardKey.ACCESSIBILITY, GuardKey.INPUT_METHODS)
        .associateWith { SettingKey.PackageListKey("policy.guard.${it.wire}.allowed") }

    /** "Also deny…" options of the SMS and calls guards (pending choice; the applied one is in the guard record). */
    val GUARD_EXTENDED: Map<GuardKey, SettingKey.BoolKey> = listOf(GuardKey.SMS, GuardKey.CALLS)
        .associateWith { SettingKey.BoolKey("policy.guard.${it.wire}.extended", false) }

    /** How each list is edited (picker of installed apps, narrowed to the services for accessibility/keyboards). */
    val GUARD_LIST_SPECS: Map<GuardKey, SettingSpec.PackageListSpec> = mapOf(
        GuardKey.SMS to SettingSpec.PackageListSpec(GUARD_LISTS.getValue(GuardKey.SMS), R.string.guard_list_sms, R.string.guard_list_sms_summary, candidates = { requesting(it, GuardPermissions.of(GuardKey.SMS, true)) }),
        GuardKey.CALLS to SettingSpec.PackageListSpec(GUARD_LISTS.getValue(GuardKey.CALLS), R.string.guard_list_calls, R.string.guard_list_calls_summary, candidates = { requesting(it, GuardPermissions.of(GuardKey.CALLS, true)) }),
        GuardKey.ACCESSIBILITY to SettingSpec.PackageListSpec(GUARD_LISTS.getValue(GuardKey.ACCESSIBILITY), R.string.guard_list_accessibility, R.string.guard_list_accessibility_summary, candidates = { services(it, accessibility = true) }),
        GuardKey.INPUT_METHODS to SettingSpec.PackageListSpec(GUARD_LISTS.getValue(GuardKey.INPUT_METHODS), R.string.guard_list_input_methods, R.string.guard_list_input_methods_summary, candidates = { services(it, accessibility = false) }),
    )

    private fun requesting(context: Context, permissions: List<String>): Collection<String> = try {
        AndroidDevicePolicyGateway(context.applicationContext).installedApps()
            .filter { !it.system && it.requested.any(permissions::contains) }.map { it.pkg }
    } catch (_: Exception) {
        emptyList()
    }

    private fun services(context: Context, accessibility: Boolean): Collection<String> = try {
        val gw = AndroidDevicePolicyGateway(context.applicationContext)
        (if (accessibility) gw.accessibilityServices() else gw.inputMethods()).filter { !it.system }.map { it.pkg }
    } catch (_: Exception) {
        emptyList()
    }

    /** Set by the app: shows what a guard did on its own (quarantine, role change) as a notification. */
    @Volatile
    var guardNoticeListener: ((GuardNotice) -> Unit)? = null

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
            onGuardNotice = { notice -> guardNoticeListener?.invoke(notice) },
            // "the list follows": the new default SMS app / dialer joins the exception list the user edits.
            onGuardListFollow = { key, pkg ->
                val agent = Agent.getOrNull()
                val listKey = GUARD_LISTS[key]
                if (agent != null && listKey != null) agent.settings.set(listKey, agent.settings[listKey] + pkg)
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
            settings = agent.settings,
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

    /**
     * Remote commands that need the Device Owner (contract §8): `lock`, `clear_lock_message`, `wipe`.
     * This is the only place where the real factory reset ([AndroidFactoryReset]) is built, and it is
     * handed only to [WipeExecutor], which checks every condition again before calling it.
     */
    fun registerCommandExecutors(agent: Agent) {
        val lockScreen = AndroidLockScreenGateway(agent.context)
        agent.commands.register(CommandTypes.LOCK, LockExecutor(lockScreen))
        agent.commands.register(CommandTypes.CLEAR_LOCK_MESSAGE, ClearLockMessageExecutor(lockScreen))
        agent.commands.register(
            CommandTypes.WIPE,
            WipeExecutor(
                live = agent.commands::wipeLive,
                isDeviceOwner = lockScreen::isDeviceOwner,
                reset = AndroidFactoryReset(agent.context),
            ),
        )
    }

    /** Lock-screen message currently set by a remote `lock` (null if none), for the app. */
    fun lockScreenMessage(agent: Agent): String? = AndroidLockScreenGateway(agent.context).lockScreenInfo()

    /** Local removal of the lock-screen message from the app (reversibility, principle 6). */
    fun clearLockScreenMessage(agent: Agent): Boolean = try {
        val gw = AndroidLockScreenGateway(agent.context)
        gw.isDeviceOwner() && run {
            gw.setLockScreenInfo(null)
            true
        }
    } catch (e: Exception) {
        Log.w(TAG, "clear lock screen info failed", e)
        false
    }

    private val reconcileRequests = Channel<Unit>(Channel.CONFLATED)

    /**
     * Asks for a reconciliation of the guards (new install, update, role change…). Requests are coalesced:
     * a burst of package broadcasts gives one pass. Nothing is done when no per-package guard is on.
     */
    fun requestGuardReconcile() {
        reconcileRequests.trySend(Unit)
    }

    private fun startGuardWatch(agent: Agent) {
        val context = agent.context
        scope.launch(Dispatchers.IO) {
            for (request in reconcileRequests) {
                try {
                    engine(context).guards.reconcile()
                } catch (e: Exception) {
                    Log.w(TAG, "guard reconciliation failed", e)
                }
            }
        }
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(c: Context, intent: Intent) = requestGuardReconcile()
        }
        // Package broadcasts come from the system (uid 1000): a non-exported receiver gets them. They are
        // delivered while the process lives (foreground service); the maintenance pass catches up otherwise.
        val packages = IntentFilter().apply {
            addAction(Intent.ACTION_PACKAGE_ADDED)
            addAction(Intent.ACTION_PACKAGE_REPLACED)
            addAction(Intent.ACTION_PACKAGE_REMOVED)
            addDataScheme("package")
        }
        context.registerReceiver(receiver, packages, Context.RECEIVER_NOT_EXPORTED)
        // Default dialer changed (sent by Telecom; exported: a forged one only triggers a harmless, coalesced pass).
        context.registerReceiver(receiver, IntentFilter(TelecomManager.ACTION_DEFAULT_DIALER_CHANGED), Context.RECEIVER_EXPORTED)
        requestGuardReconcile()
        // No broadcast tells a third-party app that the default SMS app, the keyboard or the home screen
        // changed (`DEFAULT_SMS_PACKAGE_CHANGED` only goes to the old and new SMS apps). Until the next
        // pass, a new default SMS app that a guard had denied can neither send nor (with the option)
        // receive: Android's role grant skips a permission denied by policy. So the role holders are read
        // again every few seconds while a per-package guard is on; a change triggers a pass. `delay` does
        // not wake the device: this only runs while it is awake, which a change of default app requires.
        scope.launch(Dispatchers.IO) {
            val gateway = AndroidDevicePolicyGateway(context)
            var last: io.github.erwsim.watchpost.policy.engine.DeviceRoles? = null
            while (true) {
                delay(ROLE_POLL_MS)
                try {
                    val guards = engine(context).guards
                    if (GuardKey.entries.none { it.perPackage && guards.isActive(it) }) {
                        last = null
                        continue
                    }
                    val now = gateway.roles()
                    if (last != null && now != last) requestGuardReconcile()
                    last = now
                } catch (e: Exception) {
                    Log.w(TAG, "role watch failed", e)
                }
            }
        }
    }

    /** Period of the role watch above (four binder reads; nothing when no per-package guard is on). */
    private const val ROLE_POLL_MS = 10_000L

    /** Called once from `Application.onCreate`, after `Agent.init`. */
    fun install(agent: Agent) {
        registerCommandExecutors(agent)
        try {
            startGuardWatch(agent)
        } catch (e: Exception) {
            Log.w(TAG, "guard watch not started", e)
        }
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
     * is an explicit act of the user).
     */
    fun onOwnerEnabled(agent: Agent) {
        agent.context.getSharedPreferences(PREFS_SELF_GRANT, Context.MODE_PRIVATE).edit().clear().apply()
        onAgentStarted(agent)
    }

    /** Called at each agent (service) start, on Device Owner activation and by the maintenance worker (15 min). */
    fun onAgentStarted(agent: Agent) {
        val manager = deviceOwner(agent)
        if (!manager.isDeviceOwner()) return
        // Each permission is self-granted once: a later revocation by the user is respected.
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
                logAction(agent.context, "permission_granted", r.permission, false, r.error ?: "refused")
            }
        }
        if (results.any { it.granted }) {
            agent.integrity.checkPermissionsAndOwnership()
            agent.host.reconcile()
        }
        applyForceStopProtection(agent)
        // Catch-up for installs, updates and role changes that happened while the process was not running.
        requestGuardReconcile()
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
            logAction(agent.context, "force_stop_protection", if (wanted) "enabled" else "disabled", ok, if (ok) null else "no observed effect")
        }
    }

    /** `security.policy` + local action log for an action outside the engine's items (logging switches…). */
    fun logAction(context: Context, action: String, target: String, ok: Boolean, error: String?) {
        try {
            engine(context).logAction(action, target, null, ok, error)
        } catch (e: Exception) {
            Log.w(TAG, "policy action log failed", e)
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
     * A log batch arrived while its collector is not running. If the user turned the collector
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
