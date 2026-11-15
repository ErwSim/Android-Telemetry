package io.github.erwsim.vigie.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.PrimaryTabRow
import androidx.compose.material3.Tab
import androidx.compose.material3.Text
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
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import io.github.erwsim.vigie.R
import io.github.erwsim.vigie.core.Agent
import io.github.erwsim.vigie.core.event.Event
import io.github.erwsim.vigie.core.event.Rfc3339
import io.github.erwsim.vigie.core.event.VigieJson

/** "Journal local": exactly what the agent emitted, as sent (transparency). */
@Composable
fun JournalScreen(agent: Agent, modifier: Modifier) {
    var tab by rememberSaveable { mutableIntStateOf(0) }
    val recent by agent.sink.recent.events.collectAsStateWithLifecycle()
    val totals by agent.outbox.totals.collectAsStateWithLifecycle()
    var pending by remember { mutableStateOf<List<Event>>(emptyList()) }
    LaunchedEffect(tab, totals.count) {
        if (tab == 1) {
            pending = agent.outbox.newest(PENDING_SHOWN).mapNotNull {
                runCatching { VigieJson.decodeFromString(Event.serializer(), it.json) }.getOrNull()
            }
        }
    }

    Column(modifier.fillMaxSize()) {
        PrimaryTabRow(selectedTabIndex = tab) {
            Tab(selected = tab == 0, onClick = { tab = 0 }, text = { Text(stringResource(R.string.journal_tab_recent)) })
            Tab(selected = tab == 1, onClick = { tab = 1 }, text = { Text(stringResource(R.string.journal_tab_pending, totals.count)) })
        }
        val events = if (tab == 0) recent else pending
        LazyColumn(contentPadding = PaddingValues(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            item {
                Text(
                    stringResource(if (tab == 0) R.string.journal_recent_intro else R.string.journal_pending_intro),
                    style = MaterialTheme.typography.bodySmall,
                    modifier = Modifier.padding(bottom = 8.dp),
                )
            }
            if (events.isEmpty()) {
                item { Text(stringResource(R.string.journal_empty), style = MaterialTheme.typography.bodyMedium) }
            }
            items(events, key = { it.id }) { EventRow(it) }
        }
    }
}

@Composable
private fun EventRow(event: Event) {
    var expanded by remember { mutableStateOf(false) }
    Column(
        Modifier.fillMaxWidth().clickable { expanded = !expanded }.padding(vertical = 6.dp),
        verticalArrangement = Arrangement.spacedBy(2.dp),
    ) {
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(
                Rfc3339.parseOrNull(event.ts)?.let(Format::clockSeconds) ?: event.ts,
                style = MaterialTheme.typography.labelMedium,
                fontFamily = FontFamily.Monospace,
            )
            Text(
                event.type,
                style = MaterialTheme.typography.labelLarge,
                fontWeight = FontWeight.SemiBold,
                color = toneColor(
                    when (event.sev) {
                        0 -> Tone.NEUTRAL
                        1 -> Tone.OK
                        2 -> Tone.WARN
                        else -> Tone.ERROR
                    },
                ),
            )
            Text("#${event.seq}", style = MaterialTheme.typography.labelSmall)
        }
        Text(
            event.data.toString(),
            style = MaterialTheme.typography.bodySmall,
            fontFamily = FontFamily.Monospace,
            maxLines = if (expanded) Int.MAX_VALUE else 2,
            overflow = TextOverflow.Ellipsis,
        )
        HorizontalDivider()
    }
}

private const val PENDING_SHOWN = 200
