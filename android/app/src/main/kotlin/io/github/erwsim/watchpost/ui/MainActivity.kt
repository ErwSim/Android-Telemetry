package io.github.erwsim.watchpost.ui

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.BackHandler
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.List
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LifecycleEventEffect
import androidx.compose.ui.unit.dp
import io.github.erwsim.watchpost.R
import io.github.erwsim.watchpost.WatchpostApplication
import io.github.erwsim.watchpost.core.Agent

/** Top-level destinations; [Policy] is the slot reserved for the `:policy` module's screen. */
enum class Screen(val titleRes: Int, val topLevel: Boolean) {
    Home(R.string.nav_home, true),
    Collectors(R.string.nav_collectors, true),
    Journal(R.string.nav_journal, true),
    Settings(R.string.nav_settings, true),
    Enrollment(R.string.screen_enrollment, false),
    Policy(R.string.screen_policy, false),
    Commands(R.string.screen_commands, false),
    Quarantine(R.string.screen_quarantine, false),
}

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
        // This app releases quarantined apps and switches guards off: no other app may draw over it to steer
        // a tap ("tapjacking"). Needs the normal permission HIDE_OVERLAY_WINDOWS; best effort.
        try {
            window.setHideOverlayWindows(true)
        } catch (_: Exception) {
        }
        if (Agent.getOrNull() == null) {
            // The agent could not be built (see WatchpostApplication): say so instead of crashing, the ADB
            // rescue stays available.
            setContent {
                WatchpostTheme {
                    Scaffold { padding ->
                        Text(
                            stringResource(R.string.startup_failed, WatchpostApplication.startupError.orEmpty()),
                            Modifier.padding(padding).padding(24.dp),
                        )
                    }
                }
            }
            return
        }
        openRequest.value = intent?.getStringExtra(EXTRA_OPEN)
        setContent { WatchpostTheme { WatchpostApp(openRequest) } }
    }

    override fun onNewIntent(intent: android.content.Intent) {
        super.onNewIntent(intent)
        openRequest.value = intent.getStringExtra(EXTRA_OPEN)
    }

    /** Screen asked for by a notification (e.g. a new app in quarantine). */
    private val openRequest = androidx.compose.runtime.mutableStateOf<String?>(null)

    companion object {
        /** Extra of the launch intent: name of a [Screen] to open (notifications). */
        const val EXTRA_OPEN = "io.github.erwsim.watchpost.extra.OPEN"
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun WatchpostApp(openRequest: androidx.compose.runtime.MutableState<String?> = remember { mutableStateOf(null) }) {
    val agent = remember { Agent.get() }
    var screen by rememberSaveable { mutableStateOf(Screen.Home) }
    var previous by rememberSaveable { mutableStateOf(Screen.Home) }
    // Incremented on every resume: screens re-read non-observable state (permissions, Device Owner…).
    var resumeTick by remember { mutableIntStateOf(0) }
    LifecycleEventEffect(Lifecycle.Event.ON_RESUME) {
        resumeTick++
        agent.host.reconcile()
    }

    fun navigate(to: Screen) {
        if (!to.topLevel) previous = screen
        screen = to
    }

    val requested = openRequest.value
    LaunchedEffect(requested) {
        if (requested != null) {
            openRequest.value = null
            Screen.entries.firstOrNull { it.name == requested }?.let { navigate(it) }
        }
    }

    BackHandler(enabled = screen != Screen.Home) {
        screen = if (screen.topLevel) Screen.Home else previous
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(if (screen == Screen.Home) R.string.app_name else screen.titleRes)) },
                navigationIcon = {
                    if (!screen.topLevel) {
                        IconButton(onClick = { screen = previous }) {
                            Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = stringResource(R.string.action_back))
                        }
                    }
                },
            )
        },
        bottomBar = {
            NavigationBar {
                listOf(
                    Screen.Home to Icons.Filled.Home,
                    Screen.Collectors to Icons.AutoMirrored.Filled.List,
                    Screen.Journal to Icons.Filled.Info,
                    Screen.Settings to Icons.Filled.Settings,
                ).forEach { (s, icon) ->
                    NavigationBarItem(
                        selected = screen == s,
                        onClick = { screen = s },
                        icon = { Icon(icon, contentDescription = null) },
                        label = { Text(stringResource(s.titleRes)) },
                    )
                }
            }
        },
    ) { padding ->
        val modifier = Modifier.padding(padding)
        when (screen) {
            Screen.Home -> HomeScreen(agent, resumeTick, modifier, ::navigate)
            Screen.Collectors -> CollectorsScreen(agent, resumeTick, modifier)
            Screen.Journal -> JournalScreen(agent, modifier)
            Screen.Settings -> SettingsScreen(agent, resumeTick, modifier, ::navigate)
            Screen.Enrollment -> EnrollmentScreen(agent, modifier)
            Screen.Policy -> PolicyScreen(agent, resumeTick, modifier, ::navigate)
            Screen.Quarantine -> QuarantineScreen(agent, resumeTick, modifier)
            Screen.Commands -> CommandsScreen(agent, resumeTick, modifier)
        }
    }
}
