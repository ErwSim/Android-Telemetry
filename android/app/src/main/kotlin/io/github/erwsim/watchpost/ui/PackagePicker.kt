package io.github.erwsim.watchpost.ui

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.graphics.Canvas
import android.util.LruCache
import androidx.compose.foundation.Image
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Checkbox
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import io.github.erwsim.watchpost.R
import io.github.erwsim.watchpost.core.settings.AgentSettings
import io.github.erwsim.watchpost.core.settings.SettingSpec
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * An app chooses its own name: one line, bounded, no control or formatting characters (a name made of line
 * breaks or right-to-left overrides must not push the package name away or disguise it). The package name
 * is always shown next to it.
 */
fun safeLabel(raw: String): String =
    raw.map { if (it.isWhitespace() || it.isISOControl()) ' ' else it }
        .filter { Character.getType(it) != Character.FORMAT.toInt() }
        .joinToString("").replace(Regex(" +"), " ").trim().take(MAX_SAFE_LABEL)

private const val MAX_SAFE_LABEL = 60

/** Names and icons of installed applications, for lists and pickers (cached, read off the main thread). */
object Apps {
    private const val ICON_PX = 96
    private val labels = LruCache<String, String>(512)
    private val icons = LruCache<String, ImageBitmap>(128)

    data class Entry(val pkg: String, val label: String, val system: Boolean)

    fun isInstalled(context: Context, pkg: String): Boolean = try {
        context.packageManager.getApplicationInfo(pkg, PackageManager.ApplicationInfoFlags.of(0))
        true
    } catch (_: Exception) {
        false
    }

    /** Display name (the package name when the app is not installed). */
    fun label(context: Context, pkg: String): String = labels.get(pkg) ?: try {
        val pm = context.packageManager
        safeLabel(pm.getApplicationLabel(pm.getApplicationInfo(pkg, PackageManager.ApplicationInfoFlags.of(0))).toString()).ifEmpty { pkg }.also { labels.put(pkg, it) }
    } catch (_: Exception) {
        pkg
    }

    fun icon(context: Context, pkg: String): ImageBitmap? = icons.get(pkg) ?: try {
        val drawable = context.packageManager.getApplicationIcon(pkg)
        val bitmap = Bitmap.createBitmap(ICON_PX, ICON_PX, Bitmap.Config.ARGB_8888)
        drawable.setBounds(0, 0, ICON_PX, ICON_PX)
        drawable.draw(Canvas(bitmap))
        bitmap.asImageBitmap().also { icons.put(pkg, it) }
    } catch (_: Exception) {
        null
    }

    /** Every installed application, by name. Blocking: call from a background thread. */
    fun installed(context: Context): List<Entry> = try {
        context.packageManager.getInstalledApplications(PackageManager.ApplicationInfoFlags.of(0)).map {
            Entry(it.packageName, label(context, it.packageName), it.flags and ApplicationInfo.FLAG_SYSTEM != 0)
        }.sortedBy { it.label.lowercase() }
    } catch (_: Exception) {
        emptyList()
    }
}

/** Icon of an installed app (blank square while loading or when absent). */
@Composable
fun AppIcon(pkg: String, modifier: Modifier = Modifier.size(32.dp)) {
    val context = LocalContext.current
    val icon by produceState<ImageBitmap?>(null, pkg) { value = withContext(Dispatchers.IO) { Apps.icon(context, pkg) } }
    Box(modifier) { icon?.let { Image(it, contentDescription = null, modifier = Modifier.size(32.dp)) } }
}

/** One application: icon, name, package name, optional note. */
@Composable
fun AppRow(pkg: String, note: String? = null, trailing: @Composable () -> Unit = {}) {
    val context = LocalContext.current
    val label by produceState(pkg, pkg) { value = withContext(Dispatchers.IO) { Apps.label(context, pkg) } }
    Row(Modifier.fillMaxWidth().padding(vertical = 2.dp), verticalAlignment = Alignment.CenterVertically) {
        AppIcon(pkg)
        Column(Modifier.weight(1f).padding(start = 8.dp, end = 8.dp)) {
            Text(label, style = MaterialTheme.typography.bodyMedium, maxLines = 2)
            Text(pkg, style = MaterialTheme.typography.labelSmall, fontFamily = FontFamily.Monospace)
            note?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
        }
        trailing()
    }
}

/** Rendering of a [SettingSpec.PackageListSpec]: the list (name and icon) and "Modifier" (picker). */
@Composable
fun PackageListRow(settings: AgentSettings, spec: SettingSpec.PackageListSpec, tick: Int, onChanged: () -> Unit = {}) {
    val context = LocalContext.current
    var version by remember { mutableStateOf(0) }
    val current = remember(tick, version) { settings[spec.key] }
    val locked by produceState(emptySet<String>(), spec) { value = withContext(Dispatchers.IO) { spec.locked?.invoke(context)?.toSet().orEmpty() } }
    var editing by rememberSaveable { mutableStateOf(false) }
    Column(Modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Text(stringResource(spec.titleRes), style = MaterialTheme.typography.bodyLarge)
        spec.summaryRes?.let { Text(stringResource(it), style = MaterialTheme.typography.bodySmall) }
        if (current.isEmpty()) Text(stringResource(R.string.packages_none), style = MaterialTheme.typography.bodySmall)
        current.forEach { pkg ->
            AppRow(pkg, note = stringResource(R.string.packages_absent).takeIf { !Apps.isInstalled(context, pkg) })
        }
        OutlinedButton(onClick = { editing = true }) { Text(stringResource(R.string.packages_edit)) }
    }
    if (editing) {
        PackagePickerDialog(
            title = stringResource(spec.titleRes),
            selected = current,
            candidates = spec.candidates,
            locked = locked,
            onDismiss = { editing = false },
        ) { chosen ->
            settings.set(spec.key, chosen)
            editing = false
            version++
            onChanged()
        }
    }
}

/**
 * Picker among the installed applications (name, icon, search). [candidates] narrows the list (e.g. the apps
 * that provide an accessibility service), with "Montrer toutes les applications" to widen it; packages already
 * selected but not installed stay listed so that they can be removed.
 */
@Composable
fun PackagePickerDialog(
    title: String,
    selected: Set<String>,
    candidates: ((Context) -> Collection<String>)?,
    locked: Set<String> = emptySet(),
    onDismiss: () -> Unit,
    onConfirm: (Set<String>) -> Unit,
) {
    val context = LocalContext.current
    var chosen by remember { mutableStateOf(selected) }
    var query by rememberSaveable { mutableStateOf("") }
    var all by rememberSaveable { mutableStateOf(candidates == null) }
    val entries by produceState<List<Apps.Entry>?>(null, all) {
        value = withContext(Dispatchers.IO) {
            val installed = Apps.installed(context)
            val narrowed = if (all) installed else candidates?.invoke(context)?.toSet()?.let { set -> installed.filter { it.pkg in set } } ?: installed
            val known = narrowed.map { it.pkg }.toSet()
            narrowed + selected.filter { it !in known }.map { Apps.Entry(it, it, false) }
        }
    }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(title) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(value = query, onValueChange = { query = it.take(60) }, singleLine = true, label = { Text(stringResource(R.string.packages_search)) })
                if (!all) TextButton(onClick = { all = true }) { Text(stringResource(R.string.packages_show_all)) }
                val list = entries
                if (list == null) {
                    Text("…")
                } else {
                    val q = query.trim().lowercase()
                    val shown = list.filter { q.isEmpty() || q in it.label.lowercase() || q in it.pkg.lowercase() }
                    LazyColumn(Modifier.heightIn(max = 420.dp)) {
                        items(shown, key = { it.pkg }) { e ->
                            val isLocked = e.pkg in locked
                            Row(
                                Modifier.fillMaxWidth().clickable(enabled = !isLocked) {
                                    chosen = if (e.pkg in chosen) chosen - e.pkg else chosen + e.pkg
                                },
                                verticalAlignment = Alignment.CenterVertically,
                            ) {
                                Checkbox(checked = isLocked || e.pkg in chosen, onCheckedChange = null, enabled = !isLocked)
                                Box(Modifier.weight(1f)) {
                                    AppRow(e.pkg, note = stringResource(R.string.packages_locked).takeIf { isLocked })
                                }
                            }
                        }
                    }
                }
                Text(stringResource(R.string.packages_count, chosen.size), style = MaterialTheme.typography.labelMedium)
            }
        },
        confirmButton = { TextButton(onClick = { onConfirm(chosen - locked) }) { Text(stringResource(R.string.action_save)) } },
        dismissButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.action_cancel)) } },
    )
}
