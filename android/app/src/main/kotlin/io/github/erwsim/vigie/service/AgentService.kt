package io.github.erwsim.vigie.service

import android.Manifest
import android.app.NotificationManager
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.os.IBinder
import android.util.Log
import io.github.erwsim.vigie.core.Agent
import io.github.erwsim.vigie.core.event.EventTypes
import io.github.erwsim.vigie.core.sink.emit
import io.github.erwsim.vigie.policy.PolicyModule
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

/**
 * Permanent foreground service hosting the real-time collectors.
 *
 * Types: `specialUse` always, plus `location` when a location permission is granted (the
 * `location` type cannot be started without it). `dataSync` is avoided (6 h/24 h limit).
 * `START_STICKY` + boot receiver + the 15-minute maintenance worker restart it after a kill.
 */
class AgentService : Service() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    private var started = false
    private var lastText: String? = null

    override fun onCreate() {
        super.onCreate()
        goForeground(Agent.get())
        _running.value = true
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val agent = Agent.get()
        when (intent?.action) {
            ACTION_REFRESH -> {
                goForeground(agent)
                agent.host.reconcile()
                return START_STICKY
            }
        }
        if (!started) {
            started = true
            startAgent(agent, intent?.getStringExtra(EXTRA_REASON) ?: REASON_RESTART)
        }
        return START_STICKY
    }

    private fun startAgent(agent: Agent, reason: String) {
        agent.sink.emit(EventTypes.AGENT_STARTED) {
            put("reason", reason)
            put("agent_version", agent.agentVersion)
        }
        scope.launch(Dispatchers.IO) {
            agent.integrity.checkExitReasons()
            agent.integrity.checkPermissionsAndOwnership()
        }
        PolicyModule.onAgentStarted(agent)
        agent.host.startAll()
        agent.startNetworkWatch()
        agent.ensureBackgroundWork()
        scope.launch {
            while (isActive) {
                updateNotification(agent)
                delay(NOTIFICATION_REFRESH_MS)
            }
        }
    }

    private fun updateNotification(agent: Agent) {
        val text = AgentNotifications.text(this, agent)
        if (text == lastText) return
        lastText = text
        getSystemService(NotificationManager::class.java)
            ?.notify(AgentNotifications.NOTIFICATION_ID, AgentNotifications.build(this, text))
    }

    private fun goForeground(agent: Agent) {
        val text = AgentNotifications.text(this, agent)
        lastText = text
        val notification = AgentNotifications.build(this, text)
        val hasLocation = checkSelfPermission(Manifest.permission.ACCESS_FINE_LOCATION) == PackageManager.PERMISSION_GRANTED ||
            checkSelfPermission(Manifest.permission.ACCESS_COARSE_LOCATION) == PackageManager.PERMISSION_GRANTED
        val special = ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
        try {
            startForeground(
                AgentNotifications.NOTIFICATION_ID,
                notification,
                if (hasLocation) special or ServiceInfo.FOREGROUND_SERVICE_TYPE_LOCATION else special,
            )
        } catch (e: SecurityException) {
            // Location type refused (e.g. started from background without the right): degrade.
            Log.w(TAG, "location FGS type refused, using specialUse only", e)
            startForeground(AgentNotifications.NOTIFICATION_ID, notification, special)
        }
    }

    override fun onDestroy() {
        val agent = Agent.get()
        if (started) {
            agent.sink.emit(EventTypes.AGENT_STOPPED) {
                put("reason", pendingStopReason ?: "system")
                put("agent_version", agent.agentVersion)
            }
            agent.host.stopAll()
            agent.stopNetworkWatch()
            agent.sink.flushBlocking(2_000)
        }
        pendingStopReason = null
        scope.cancel()
        _running.value = false
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    companion object {
        private const val TAG = "VigieService"
        private const val EXTRA_REASON = "reason"
        private const val ACTION_REFRESH = "io.github.erwsim.vigie.action.REFRESH"
        private const val NOTIFICATION_REFRESH_MS = 60_000L

        const val REASON_BOOT = "boot"
        const val REASON_APP = "app"
        const val REASON_UPDATE = "update"
        const val REASON_WATCHDOG = "watchdog"
        const val REASON_RESTART = "restart"

        private val _running = MutableStateFlow(false)
        val running: StateFlow<Boolean> = _running.asStateFlow()

        @Volatile
        private var pendingStopReason: String? = null

        /** Returns false if the system refused the start (background start restrictions). */
        fun start(context: Context, reason: String): Boolean = try {
            context.startForegroundService(Intent(context, AgentService::class.java).putExtra(EXTRA_REASON, reason))
            true
        } catch (e: Exception) {
            Log.w(TAG, "cannot start the agent service ($reason)", e)
            false
        }

        /** User-requested stop from the app ("agent.stopped" reason `user`). */
        fun stop(context: Context) {
            pendingStopReason = "user"
            context.stopService(Intent(context, AgentService::class.java))
        }

        /** Re-evaluates the foreground service type and the collectors (after a permission grant). */
        fun refresh(context: Context) {
            if (!running.value) return
            try {
                context.startService(Intent(context, AgentService::class.java).setAction(ACTION_REFRESH))
            } catch (e: Exception) {
                Log.w(TAG, "refresh failed", e)
            }
        }
    }
}
