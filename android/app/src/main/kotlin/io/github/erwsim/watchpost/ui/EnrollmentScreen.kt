package io.github.erwsim.watchpost.ui

import android.content.Context
import android.content.res.Resources
import android.net.Uri
import android.provider.DocumentsContract
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalResources
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import io.github.erwsim.watchpost.R
import io.github.erwsim.watchpost.core.Agent
import io.github.erwsim.watchpost.core.enroll.EnrollmentChange
import io.github.erwsim.watchpost.core.enroll.EnrollmentError
import io.github.erwsim.watchpost.core.enroll.EnrollmentException
import io.github.erwsim.watchpost.core.enroll.EnrollmentParser
import io.github.erwsim.watchpost.core.enroll.ParsedEnrollment
import io.github.erwsim.watchpost.core.upload.PingResult
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Import of the `.watchpost` file through the system file picker (contract §4): the private key goes
 * into the Android Keystore (non-exportable), the token is sealed, the PEM is not kept.
 */
@Composable
fun EnrollmentScreen(agent: Agent, modifier: Modifier) {
    val context = LocalContext.current
    val resources = LocalResources.current
    val scope = rememberCoroutineScope()
    val enrollment by agent.enrollment.state.collectAsStateWithLifecycle()
    val totals by agent.outbox.totals.collectAsStateWithLifecycle()
    var parsed by remember { mutableStateOf<ParsedEnrollment?>(null) }
    var sourceUri by remember { mutableStateOf<Uri?>(null) }
    var message by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }
    var confirmUnenroll by remember { mutableStateOf(false) }

    fun ping() {
        busy = true
        scope.launch {
            message = pingMessage(resources, agent.enrollment.ping())
            busy = false
        }
    }

    val picker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri == null) return@rememberLauncherForActivityResult
        busy = true
        message = null
        scope.launch {
            try {
                val bytes = withContext(Dispatchers.IO) { readLimited(context, uri) }
                parsed = withContext(Dispatchers.Default) { agent.enrollment.parse(bytes) }
                sourceUri = uri
            } catch (e: EnrollmentException) {
                message = resources.getString(R.string.enroll_error, errorText(resources, e.error), e.detail.orEmpty())
            } catch (e: Exception) {
                message = resources.getString(R.string.enroll_read_error, e.toString())
            } finally {
                busy = false
            }
        }
    }

    Column(
        modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        val current = enrollment
        val candidate = parsed
        when {
            candidate != null -> SectionCard(stringResource(R.string.enroll_confirm_title)) {
                StatusLine(stringResource(R.string.enroll_url), candidate.ingestUrl)
                StatusLine(stringResource(R.string.enroll_device_id), candidate.deviceId)
                candidate.deviceName?.let { StatusLine(stringResource(R.string.enroll_device_name), it) }
                StatusLine(stringResource(R.string.enroll_cert_expiry), Format.dateTime(candidate.clientChain.first().notAfter.time))
                StatusLine(
                    stringResource(R.string.enroll_ca),
                    stringResource(if (candidate.serverCa.isEmpty()) R.string.enroll_ca_system else R.string.enroll_ca_pinned),
                )
                candidate.privateDnsHost?.let { StatusLine(stringResource(R.string.enroll_dns), it) }
                // Re-enrollment: say what happens to the events waiting in the buffer.
                when (remember(candidate, current) { agent.enrollment.changeFor(candidate) }) {
                    EnrollmentChange.FIRST -> Unit
                    EnrollmentChange.RENEWAL -> Text(stringResource(R.string.enroll_change_renewal, totals.count), style = MaterialTheme.typography.bodySmall)
                    EnrollmentChange.NEW_IDENTITY -> Text(
                        stringResource(R.string.enroll_change_identity, current?.deviceId.orEmpty(), candidate.deviceId, totals.count),
                        color = toneColor(Tone.WARN), style = MaterialTheme.typography.bodySmall,
                    )
                    EnrollmentChange.NEW_SERVER -> Text(
                        stringResource(R.string.enroll_change_server, current?.ingestUrl.orEmpty(), candidate.ingestUrl, totals.count),
                        color = toneColor(Tone.ERROR), style = MaterialTheme.typography.bodySmall,
                    )
                }
                candidate.warnings.forEach {
                    Text(stringResource(R.string.enroll_warning, it), color = toneColor(Tone.WARN), style = MaterialTheme.typography.bodySmall)
                }
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(enabled = !busy, onClick = {
                        busy = true
                        scope.launch {
                            try {
                                // Also the re-enrollment path: the buffer is kept unless the server changes.
                                withContext(Dispatchers.IO) { agent.enroll(candidate) }
                                parsed = null
                                val deleted = sourceUri?.let { deleteSource(context, it) } == true
                                sourceUri = null
                                val ping = pingMessage(resources, agent.enrollment.ping())
                                message = resources.getString(
                                    if (deleted) R.string.enroll_done_deleted else R.string.enroll_done_not_deleted,
                                ) + "\n" + ping
                            } catch (e: Exception) {
                                message = resources.getString(R.string.enroll_import_error, e.toString())
                            } finally {
                                busy = false
                            }
                        }
                    }) { Text(stringResource(R.string.action_enroll)) }
                    OutlinedButton(onClick = {
                        parsed = null
                        sourceUri = null
                    }) { Text(stringResource(R.string.action_cancel)) }
                }
            }

            current != null -> SectionCard(stringResource(R.string.enroll_current_title)) {
                StatusLine(stringResource(R.string.enroll_url), current.ingestUrl)
                StatusLine(stringResource(R.string.enroll_device_id), current.deviceId)
                current.deviceName?.let { StatusLine(stringResource(R.string.enroll_device_name), it) }
                StatusLine(stringResource(R.string.enroll_date), Format.dateTime(current.enrolledAtMs))
                StatusLine(
                    stringResource(R.string.enroll_cert_expiry),
                    Format.dateTime(current.certNotAfterMs),
                    if (current.certNotAfterMs < System.currentTimeMillis() + 30L * 86_400_000) Tone.WARN else Tone.NEUTRAL,
                )
                StatusLine(
                    stringResource(R.string.enroll_ca),
                    stringResource(if (current.serverCaPem == null) R.string.enroll_ca_system else R.string.enroll_ca_pinned),
                )
                current.privateDnsHost?.let { StatusLine(stringResource(R.string.enroll_dns), it) }
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(enabled = !busy, onClick = ::ping) { Text(stringResource(R.string.action_test_connection)) }
                    OutlinedButton(enabled = !busy, onClick = { confirmUnenroll = true }) { Text(stringResource(R.string.action_unenroll)) }
                }
                HorizontalDivider()
                Text(stringResource(R.string.enroll_reenroll_desc), style = MaterialTheme.typography.bodySmall)
                OutlinedButton(enabled = !busy, onClick = { picker.launch(arrayOf("*/*")) }) { Text(stringResource(R.string.action_reenroll)) }
            }

            else -> SectionCard(stringResource(R.string.enroll_new_title)) {
                Text(stringResource(R.string.enroll_explanation), style = MaterialTheme.typography.bodyMedium)
                Button(enabled = !busy, onClick = { picker.launch(arrayOf("*/*")) }) {
                    Text(stringResource(R.string.action_import_file))
                }
            }
        }
        if (busy) CircularProgressIndicator()
        message?.let { SectionCard(stringResource(R.string.enroll_result_title)) { Text(it, style = MaterialTheme.typography.bodyMedium) } }
        SectionCard(stringResource(R.string.enroll_security_title)) {
            Text(stringResource(R.string.enroll_security), style = MaterialTheme.typography.bodySmall)
        }
    }

    if (confirmUnenroll) {
        AlertDialog(
            onDismissRequest = { confirmUnenroll = false },
            title = { Text(stringResource(R.string.action_unenroll)) },
            text = { Text(pluralStringResource(R.plurals.enroll_unenroll_confirm, totals.count.toInt(), totals.count)) },
            confirmButton = {
                TextButton(onClick = {
                    confirmUnenroll = false
                    scope.launch {
                        withContext(Dispatchers.IO) { agent.unenroll() }
                        message = resources.getString(R.string.enroll_unenrolled)
                    }
                }) { Text(stringResource(R.string.action_unenroll)) }
            },
            dismissButton = { TextButton(onClick = { confirmUnenroll = false }) { Text(stringResource(R.string.action_cancel)) } },
        )
    }
}

private fun readLimited(context: Context, uri: Uri): ByteArray {
    val input = context.contentResolver.openInputStream(uri) ?: error("no stream")
    return input.use { stream ->
        val buffer = stream.readNBytes(EnrollmentParser.MAX_FILE_BYTES + 1)
        buffer
    }
}

/** The file holds secrets: delete it once imported, if the provider allows it. */
private fun deleteSource(context: Context, uri: Uri): Boolean = try {
    DocumentsContract.deleteDocument(context.contentResolver, uri)
} catch (_: Exception) {
    false
}

private fun pingMessage(resources: Resources, result: PingResult): String = when (result) {
    is PingResult.Ok -> if (result.deviceIdMatches) {
        resources.getString(R.string.ping_ok, result.serverTime ?: "?")
    } else {
        resources.getString(R.string.ping_device_mismatch)
    }
    is PingResult.HttpError -> if (result.code == 401 || result.code == 403) {
        resources.getString(R.string.ping_unauthorized, result.code)
    } else {
        resources.getString(R.string.ping_http_error, result.code)
    }
    is PingResult.NetworkError -> resources.getString(R.string.ping_network_error, result.message)
    PingResult.NotEnrolled -> resources.getString(R.string.ping_not_enrolled)
}

private fun errorText(resources: Resources, error: EnrollmentError): String = resources.getString(
    when (error) {
        EnrollmentError.TOO_LARGE -> R.string.enroll_err_too_large
        EnrollmentError.NOT_JSON -> R.string.enroll_err_not_json
        EnrollmentError.UNSUPPORTED_VERSION -> R.string.enroll_err_version
        EnrollmentError.MISSING_FIELD -> R.string.enroll_err_missing
        EnrollmentError.BAD_URL -> R.string.enroll_err_url
        EnrollmentError.INSECURE_URL -> R.string.enroll_err_insecure
        EnrollmentError.BAD_CLIENT_CERT -> R.string.enroll_err_cert
        EnrollmentError.CLIENT_CERT_EXPIRED -> R.string.enroll_err_cert_expired
        EnrollmentError.BAD_CLIENT_KEY -> R.string.enroll_err_key
        EnrollmentError.KEY_NOT_P256 -> R.string.enroll_err_key_curve
        EnrollmentError.KEY_CERT_MISMATCH -> R.string.enroll_err_mismatch
        EnrollmentError.BAD_SERVER_CA -> R.string.enroll_err_ca
        EnrollmentError.BAD_DNS_HOST -> R.string.enroll_err_dns
        EnrollmentError.BAD_TOKEN -> R.string.enroll_err_token
        EnrollmentError.BAD_DEVICE_ID -> R.string.enroll_err_device_id
    },
)
