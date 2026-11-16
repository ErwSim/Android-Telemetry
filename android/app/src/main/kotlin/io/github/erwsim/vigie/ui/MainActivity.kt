package io.github.erwsim.vigie.ui

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
import io.github.erwsim.vigie.R
import io.github.erwsim.vigie.VigieApplication
import io.github.erwsim.vigie.core.Agent

/** Top-level destinations; [Policy] is the slot reserved for the `:policy` module's screen. */
enum class Screen(val titleRes: Int, val topLevel: Boolean) {
    Home(R.string.nav_home, true),
    Collectors(R.string.nav_collectors, true),
    Journal(R.string.nav_journal, true),
    Settings(R.string.nav_settings, true),
    Enrollment(R.string.screen_enrollment, false),
    Policy(R.string.screen_policy, false),
    Commands(R.string.screen_commands, false),
}

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
        if (Agent.getOrNull() == null) {
            // The agent could not be built (see VigieApplication): say so instead of crashing, the ADB
            // rescue stays available.
            setContent {
                VigieTheme {
                    Scaffold { padding ->
                        Text(
                            stringResource(R.string.startup_failed, VigieApplication.startupError.orEmpty()),
                            Modifier.padding(padding).padding(24.dp),
                        )
                    }
                }
            }
            return
        }
        setContent { VigieTheme { VigieApp() } }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun VigieApp() {
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
            Screen.Policy -> PolicyScreen(agent, resumeTick, modifier)
            Screen.Commands -> CommandsScreen(agent, resumeTick, modifier)
        }
    }
}
