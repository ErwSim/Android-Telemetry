package io.github.erwsim.watchpost.notifier

import android.app.Activity
import android.app.NotificationManager
import android.content.ActivityNotFoundException
import android.content.ComponentName
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import android.text.format.DateFormat
import android.view.View
import android.view.WindowInsets
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import io.github.erwsim.watchpost.notifier.protocol.NotifierConfig
import io.github.erwsim.watchpost.notifier.protocol.NotifierProtocol as P
import io.github.erwsim.watchpost.notifier.protocol.PackageLists
import java.util.Date

/**
 * The companion's only screen: what it does, its state, the package lists (stored by the
 * agent), how to withdraw the access. Framework views only (no AndroidX). Calls to the agent run
 * on a background thread.
 */
class MainActivity : Activity() {
    private val main = Handler(Looper.getMainLooper())
    private var resumed = false
    private var listsShown = false

    private lateinit var access: TextView
    private lateinit var listener: TextView
    private lateinit var agent: TextView
    private lateinit var collect: TextView
    private lateinit var content: TextView
    private lateinit var last: TextView
    private lateinit var counters: TextView
    private lateinit var excluded: EditText
    private lateinit var ignored: EditText
    private lateinit var listsResult: TextView

    private val tick = object : Runnable {
        override fun run() {
            if (!resumed) return
            render()
            main.postDelayed(this, 2_000)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        Relay.init(this)
        setContentView(R.layout.activity_main)
        // Edge-to-edge is enforced (targetSdk 35+): keep the content clear of the bars and the keyboard.
        findViewById<View>(R.id.root).setOnApplyWindowInsetsListener { v, insets ->
            val bars = insets.getInsets(WindowInsets.Type.systemBars() or WindowInsets.Type.displayCutout() or WindowInsets.Type.ime())
            v.setPadding(bars.left, bars.top, bars.right, bars.bottom)
            WindowInsets.CONSUMED
        }
        access = findViewById(R.id.state_access)
        listener = findViewById(R.id.state_listener)
        agent = findViewById(R.id.state_agent)
        collect = findViewById(R.id.state_collect)
        content = findViewById(R.id.state_content)
        last = findViewById(R.id.state_last)
        counters = findViewById(R.id.state_counters)
        excluded = findViewById(R.id.edit_excluded)
        ignored = findViewById(R.id.edit_ignored)
        listsResult = findViewById(R.id.lists_result)

        findViewById<Button>(R.id.button_refresh).setOnClickListener { refreshFromAgent() }
        findViewById<Button>(R.id.button_access).setOnClickListener { openAccessSettings() }
        findViewById<Button>(R.id.button_app_info).setOnClickListener {
            startSafely(Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.fromParts("package", packageName, null)))
        }
        findViewById<Button>(R.id.button_save).setOnClickListener { saveLists(reset = false) }
        findViewById<Button>(R.id.button_reset).setOnClickListener { saveLists(reset = true) }
    }

    override fun onResume() {
        super.onResume()
        resumed = true
        refreshFromAgent()
        main.post(tick)
    }

    override fun onPause() {
        resumed = false
        main.removeCallbacks(tick)
        super.onPause()
    }

    private fun refreshFromAgent() {
        background {
            Relay.fetchConfig()
            ui {
                render()
                if (!listsShown) NotifierState.config?.let { showLists(it) }
            }
        }
    }

    private fun showLists(c: NotifierConfig) {
        excluded.setText(c.contentExcluded.sorted().joinToString("\n"))
        ignored.setText(c.ignored.sorted().joinToString("\n"))
        listsShown = true
    }

    private fun saveLists(reset: Boolean) {
        val ex = PackageLists.parseText(excluded.text.toString())
        val ig = PackageLists.parseText(ignored.text.toString())
        listsResult.setText(R.string.lists_working)
        background {
            val values: Map<String, Any?> = if (reset) {
                mapOf(P.KEY_RESET to true)
            } else {
                mapOf(P.KEY_CONTENT_EXCLUDED to ex.packages, P.KEY_IGNORED to ig.packages)
            }
            val reply = AgentChannel(applicationContext).call(P.METHOD_SET_LISTS, values)
            Relay.invalidateConfig()
            Relay.fetchConfig()
            val config = (reply as? AgentChannel.Reply.Ok)?.let { NotifierConfig.fromValues(it.values) }
            val rejected = (ex.rejected + ig.rejected + ((reply as? AgentChannel.Reply.Ok)?.values?.strings(P.KEY_REJECTED).orEmpty())).distinct()
            ui {
                if (config == null) {
                    listsResult.setText(R.string.lists_failed)
                } else {
                    showLists(config)
                    var msg = getString(R.string.lists_saved, config.contentExcluded.size, config.ignored.size)
                    if (rejected.isNotEmpty()) msg += "\n" + getString(R.string.lists_rejected, rejected.joinToString(", "))
                    listsResult.text = msg
                }
                render()
            }
        }
    }

    private fun render() {
        val granted = try {
            getSystemService(NotificationManager::class.java)?.isNotificationListenerAccessGranted(listenerComponent()) == true
        } catch (_: Exception) {
            false
        }
        access.setText(if (granted) R.string.state_access_on else R.string.state_access_off)
        listener.setText(if (NotifierState.listenerConnected) R.string.state_listener_on else R.string.state_listener_off)

        val installed = try {
            packageManager.getPackageInfo(P.AGENT_PACKAGE, PackageManager.PackageInfoFlags.of(0))
            true
        } catch (_: Exception) {
            false
        }
        val sameKey = installed && try {
            packageManager.checkSignatures(packageName, P.AGENT_PACKAGE) == PackageManager.SIGNATURE_MATCH
        } catch (_: Exception) {
            false
        }
        agent.setText(
            when {
                !installed -> R.string.state_agent_absent
                !sameKey -> R.string.state_agent_other_key
                else -> when (NotifierState.agent) {
                    NotifierState.Agent.UNKNOWN -> R.string.state_agent_unknown
                    NotifierState.Agent.OK -> R.string.state_agent_ok
                    NotifierState.Agent.ABSENT -> R.string.state_agent_absent
                    NotifierState.Agent.DENIED -> R.string.state_agent_denied
                    NotifierState.Agent.STARTING -> R.string.state_agent_starting
                    NotifierState.Agent.INCOMPATIBLE -> R.string.state_agent_incompatible
                    NotifierState.Agent.UNREACHABLE -> R.string.state_agent_unreachable
                }
            },
        )

        val c = NotifierState.config
        collect.setText(
            when {
                c == null -> R.string.state_collect_unknown
                c.accepting -> R.string.state_collect_on
                else -> R.string.state_collect_off
            },
        )
        content.text = when {
            c == null -> getString(R.string.state_content_unknown)
            c.contentEnabled -> getString(
                R.string.state_content_on,
                getString(if (c.redactCodes) R.string.state_redact_on else R.string.state_redact_off),
                c.contentExcluded.size,
                c.ignored.size,
            )
            else -> getString(R.string.state_content_off, c.ignored.size)
        }

        val at = NotifierState.lastRelayMs
        last.text = if (at == 0L) {
            getString(R.string.state_last_none)
        } else {
            getString(
                R.string.state_last,
                DateFormat.getTimeFormat(this).format(Date(at)) + " " + DateFormat.getDateFormat(this).format(Date(at)),
                NotifierState.lastRelayPackage.orEmpty(),
            )
        }
        counters.text = getString(
            R.string.state_counters,
            NotifierState.relayed.get(),
            NotifierState.filtered.get(),
            NotifierState.notDelivered.get(),
            NotifierState.overflow.get(),
        )
    }

    private fun listenerComponent() = ComponentName(this, NotifierListenerService::class.java)

    private fun openAccessSettings() {
        val detail = Intent(Settings.ACTION_NOTIFICATION_LISTENER_DETAIL_SETTINGS)
            .putExtra(Settings.EXTRA_NOTIFICATION_LISTENER_COMPONENT_NAME, listenerComponent().flattenToString())
        if (!startSafely(detail)) startSafely(Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS))
    }

    private fun startSafely(intent: Intent): Boolean = try {
        startActivity(intent)
        true
    } catch (_: ActivityNotFoundException) {
        false
    }

    private fun background(block: () -> Unit) {
        Thread({
            try {
                block()
            } catch (_: Exception) {
                // The screen only shows state; nothing to report.
            }
        }, "watchpost-notifier-ui").start()
    }

    private fun ui(block: () -> Unit) {
        runOnUiThread { if (!isDestroyed) block() }
    }
}
