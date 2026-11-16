package io.github.erwsim.watchpost.policy.logs

import android.app.admin.SecurityLog
import io.github.erwsim.watchpost.core.event.Severity
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/** A security log entry reduced to plain values (built from `SecurityLog.SecurityEvent`, or by tests). */
data class RawSecurityEvent(
    val tag: Int,
    val level: Int,
    val id: Long,
    val timeNanos: Long,
    /** `getData()`: null, a single value, or an `Object[]`. */
    val data: Any?,
)

/** A translated entry: `security.log` data (contract §2, "Précisions" table). */
data class TranslatedSecurityEvent(
    val tag: String,
    val level: String,
    val logId: Long,
    val fields: JsonObject,
    val timeMs: Long,
    val sev: Int,
)

/**
 * Translation of `SecurityLog` entries into `security.log` (`tag`, `level`, `log_id`, `fields`).
 * `tag` is the constant name without `TAG_`, lowercase. `fields` follows the contract table; 0/1
 * success flags become booleans `success`; MAC addresses are lowercase; any other tag (or extra
 * payload items) uses `arg0`, `arg1`… in payload order. Pure (tested on the JVM).
 */
object SecurityLogTranslator {
    /** Constant value → contract tag name. Values are compile-time constants of the SDK. */
    val TAG_NAMES: Map<Int, String> = mapOf(
        SecurityLog.TAG_ADB_SHELL_INTERACTIVE to "adb_shell_interactive",
        SecurityLog.TAG_ADB_SHELL_CMD to "adb_shell_cmd",
        SecurityLog.TAG_SYNC_RECV_FILE to "sync_recv_file",
        SecurityLog.TAG_SYNC_SEND_FILE to "sync_send_file",
        SecurityLog.TAG_APP_PROCESS_START to "app_process_start",
        SecurityLog.TAG_KEYGUARD_DISMISSED to "keyguard_dismissed",
        SecurityLog.TAG_KEYGUARD_DISMISS_AUTH_ATTEMPT to "keyguard_dismiss_auth_attempt",
        SecurityLog.TAG_KEYGUARD_SECURED to "keyguard_secured",
        SecurityLog.TAG_KEYGUARD_DISABLED_FEATURES_SET to "keyguard_disabled_features_set",
        SecurityLog.TAG_OS_STARTUP to "os_startup",
        SecurityLog.TAG_OS_SHUTDOWN to "os_shutdown",
        SecurityLog.TAG_LOGGING_STARTED to "logging_started",
        SecurityLog.TAG_LOGGING_STOPPED to "logging_stopped",
        SecurityLog.TAG_LOG_BUFFER_SIZE_CRITICAL to "log_buffer_size_critical",
        SecurityLog.TAG_MEDIA_MOUNT to "media_mount",
        SecurityLog.TAG_MEDIA_UNMOUNT to "media_unmount",
        SecurityLog.TAG_CRYPTO_SELF_TEST_COMPLETED to "crypto_self_test_completed",
        SecurityLog.TAG_KEY_GENERATED to "key_generated",
        SecurityLog.TAG_KEY_IMPORT to "key_import",
        SecurityLog.TAG_KEY_DESTRUCTION to "key_destruction",
        SecurityLog.TAG_KEY_INTEGRITY_VIOLATION to "key_integrity_violation",
        SecurityLog.TAG_CERT_AUTHORITY_INSTALLED to "cert_authority_installed",
        SecurityLog.TAG_CERT_AUTHORITY_REMOVED to "cert_authority_removed",
        SecurityLog.TAG_CERT_VALIDATION_FAILURE to "cert_validation_failure",
        SecurityLog.TAG_USER_RESTRICTION_ADDED to "user_restriction_added",
        SecurityLog.TAG_USER_RESTRICTION_REMOVED to "user_restriction_removed",
        SecurityLog.TAG_PASSWORD_CHANGED to "password_changed",
        SecurityLog.TAG_PASSWORD_EXPIRATION_SET to "password_expiration_set",
        SecurityLog.TAG_PASSWORD_COMPLEXITY_SET to "password_complexity_set",
        SecurityLog.TAG_PASSWORD_HISTORY_LENGTH_SET to "password_history_length_set",
        SecurityLog.TAG_PASSWORD_COMPLEXITY_REQUIRED to "password_complexity_required",
        SecurityLog.TAG_MAX_SCREEN_LOCK_TIMEOUT_SET to "max_screen_lock_timeout_set",
        SecurityLog.TAG_MAX_PASSWORD_ATTEMPTS_SET to "max_password_attempts_set",
        SecurityLog.TAG_REMOTE_LOCK to "remote_lock",
        SecurityLog.TAG_WIPE_FAILURE to "wipe_failure",
        SecurityLog.TAG_CAMERA_POLICY_SET to "camera_policy_set",
        SecurityLog.TAG_BACKUP_SERVICE_TOGGLED to "backup_service_toggled",
        SecurityLog.TAG_WIFI_CONNECTION to "wifi_connection",
        SecurityLog.TAG_WIFI_DISCONNECTION to "wifi_disconnection",
        SecurityLog.TAG_BLUETOOTH_CONNECTION to "bluetooth_connection",
        SecurityLog.TAG_BLUETOOTH_DISCONNECTION to "bluetooth_disconnection",
        SecurityLog.TAG_NFC_ENABLED to "nfc_enabled",
        SecurityLog.TAG_NFC_DISABLED to "nfc_disabled",
        SecurityLog.TAG_PACKAGE_INSTALLED to "package_installed",
        SecurityLog.TAG_PACKAGE_UPDATED to "package_updated",
        SecurityLog.TAG_PACKAGE_UNINSTALLED to "package_uninstalled",
    )

    private enum class Conv { RAW, SUCCESS, MAC }

    private data class Field(val name: String, val conv: Conv = Conv.RAW)

    private fun f(name: String) = Field(name)
    private val SUCCESS = Field("success", Conv.SUCCESS)

    /** Contract table: payload index → field name. Tags absent from this map use argN. */
    val FIELD_TABLE: Map<String, List<String>> get() = FIELDS.mapValues { (_, v) -> v.map { it.name } }

    private val FIELDS: Map<String, List<Field>> = mapOf(
        "adb_shell_interactive" to emptyList(),
        "adb_shell_cmd" to listOf(f("command")),
        "sync_recv_file" to listOf(f("path")),
        "sync_send_file" to listOf(f("path")),
        "app_process_start" to listOf(f("process"), f("start_time"), f("uid"), f("pid"), f("seinfo"), f("apk_sha256")),
        "keyguard_dismissed" to emptyList(),
        "keyguard_secured" to emptyList(),
        "keyguard_dismiss_auth_attempt" to listOf(SUCCESS, f("strength")),
        "os_startup" to listOf(f("verified_boot_state"), f("dm_verity_mode")),
        "os_shutdown" to emptyList(),
        "logging_started" to emptyList(),
        "logging_stopped" to emptyList(),
        "log_buffer_size_critical" to emptyList(),
        "media_mount" to listOf(f("mount_point"), f("label")),
        "media_unmount" to listOf(f("mount_point"), f("label")),
        "crypto_self_test_completed" to listOf(SUCCESS),
        "key_generated" to listOf(SUCCESS, f("alias"), f("uid")),
        "key_import" to listOf(SUCCESS, f("alias"), f("uid")),
        "key_destruction" to listOf(SUCCESS, f("alias"), f("uid")),
        "key_integrity_violation" to listOf(f("alias"), f("uid")),
        "cert_authority_installed" to listOf(SUCCESS, f("subject"), f("user_id")),
        "cert_authority_removed" to listOf(SUCCESS, f("subject"), f("user_id")),
        "cert_validation_failure" to listOf(f("reason")),
        "user_restriction_added" to listOf(f("admin_package"), f("user_id"), f("restriction")),
        "user_restriction_removed" to listOf(f("admin_package"), f("user_id"), f("restriction")),
        "password_changed" to listOf(f("complexity"), f("user_id")),
        "wifi_connection" to listOf(Field("bssid", Conv.MAC), f("event_type"), f("reason")),
        "wifi_disconnection" to listOf(Field("bssid", Conv.MAC), f("reason")),
        "bluetooth_connection" to listOf(Field("address", Conv.MAC), SUCCESS, f("reason")),
        "bluetooth_disconnection" to listOf(Field("address", Conv.MAC), f("reason")),
        "package_installed" to listOf(f("package"), f("version_code"), f("user_id")),
        "package_updated" to listOf(f("package"), f("version_code"), f("user_id")),
        "package_uninstalled" to listOf(f("package"), f("version_code"), f("user_id")),
    )

    fun tagName(tag: Int): String = TAG_NAMES[tag] ?: "tag_$tag"

    fun levelName(level: Int): String = when (level) {
        SecurityLog.LEVEL_INFO -> "info"
        SecurityLog.LEVEL_WARNING -> "warning"
        SecurityLog.LEVEL_ERROR -> "error"
        else -> "level_$level"
    }

    fun translate(e: RawSecurityEvent): TranslatedSecurityEvent {
        val tag = tagName(e.tag)
        val payload: List<Any?> = when (val d = e.data) {
            null -> emptyList()
            is Array<*> -> d.toList()
            else -> listOf(d)
        }
        val spec = FIELDS[tag]
        val fields = LinkedHashMap<String, JsonElement>()
        payload.forEachIndexed { i, value ->
            val field = spec?.getOrNull(i)
            val name = field?.name ?: "arg$i"
            val json = when (field?.conv) {
                Conv.SUCCESS -> successOf(value)?.let(::JsonPrimitive)
                Conv.MAC -> (value as? String)?.lowercase()?.let(::JsonPrimitive)
                else -> toJson(value)
            }
            if (json != null) fields[name] = json
        }
        val obj = JsonObject(fields)
        return TranslatedSecurityEvent(tag, levelName(e.level), e.id, obj, e.timeNanos / 1_000_000, severity(tag, obj, e.level))
    }

    private fun successOf(value: Any?): Boolean? = when (value) {
        is Number -> value.toInt() != 0
        is Boolean -> value
        is String -> value == "1" || value.equals("true", ignoreCase = true)
        else -> null
    }

    private fun toJson(value: Any?): JsonElement? = when (value) {
        null -> null
        is String -> JsonPrimitive(value)
        is Boolean -> JsonPrimitive(value)
        is Double -> if (value.isFinite()) JsonPrimitive(value) else null
        is Float -> if (value.isFinite()) JsonPrimitive(value.toString().toDouble()) else null
        is Number -> JsonPrimitive(value)
        is ByteArray -> JsonPrimitive(value.joinToString("") { "%02x".format(it) })
        else -> JsonPrimitive(value.toString())
    }

    private fun bool(fields: JsonObject, name: String): Boolean? = (fields[name] as? JsonPrimitive)?.content?.toBooleanStrictOrNull()

    /** Device-side severity hint (contract §1). */
    fun severity(tag: String, fields: JsonObject, level: Int): Int = when (tag) {
        "key_integrity_violation", "log_buffer_size_critical", "logging_stopped", "wipe_failure" -> Severity.WARNING
        "crypto_self_test_completed" -> if (bool(fields, "success") == false) Severity.WARNING else Severity.INFO
        "os_startup" -> {
            val state = (fields["verified_boot_state"] as? JsonPrimitive)?.content
            val verity = (fields["dm_verity_mode"] as? JsonPrimitive)?.content
            if ((state != null && !state.equals("green", true)) || (verity != null && !verity.equals("enforcing", true))) {
                Severity.WARNING
            } else {
                Severity.INFO
            }
        }
        "adb_shell_interactive", "adb_shell_cmd", "sync_recv_file", "sync_send_file", "cert_authority_installed",
        "user_restriction_removed", "password_changed" -> Severity.NOTABLE
        "keyguard_dismiss_auth_attempt", "key_generated", "key_import", "key_destruction" ->
            if (bool(fields, "success") == false) Severity.NOTABLE else Severity.INFO
        else -> if (level == SecurityLog.LEVEL_ERROR) Severity.NOTABLE else Severity.INFO
    }
}
