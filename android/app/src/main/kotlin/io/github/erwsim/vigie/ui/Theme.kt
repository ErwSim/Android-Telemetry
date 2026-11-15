package io.github.erwsim.vigie.ui

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp

@Composable
fun VigieTheme(content: @Composable () -> Unit) {
    val context = LocalContext.current
    val dark = isSystemInDarkTheme()
    val scheme = try {
        if (dark) dynamicDarkColorScheme(context) else dynamicLightColorScheme(context)
    } catch (_: Exception) {
        if (dark) darkColorScheme() else lightColorScheme()
    }
    MaterialTheme(colorScheme = scheme) {
        Surface(color = MaterialTheme.colorScheme.background, content = content)
    }
}

/** A titled card used by every screen. */
@Composable
fun SectionCard(title: String, modifier: Modifier = Modifier, content: @Composable () -> Unit) {
    Card(
        modifier = modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainerLow),
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(title, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
            content()
        }
    }
}

enum class Tone { OK, NEUTRAL, WARN, ERROR }

@Composable
fun toneColor(tone: Tone): Color = when (tone) {
    Tone.OK -> MaterialTheme.colorScheme.primary
    Tone.NEUTRAL -> MaterialTheme.colorScheme.onSurfaceVariant
    Tone.WARN -> MaterialTheme.colorScheme.tertiary
    Tone.ERROR -> MaterialTheme.colorScheme.error
}

/** "Label : value" line with a coloured value. */
@Composable
fun StatusLine(label: String, value: String, tone: Tone = Tone.NEUTRAL) {
    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.Top, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        Text(label, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.weight(0.45f))
        Text(
            value,
            style = MaterialTheme.typography.bodyMedium,
            color = toneColor(tone),
            fontWeight = FontWeight.Medium,
            modifier = Modifier.weight(0.55f),
        )
    }
}
