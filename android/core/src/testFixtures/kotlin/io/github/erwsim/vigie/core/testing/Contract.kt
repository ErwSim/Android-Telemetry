package io.github.erwsim.vigie.core.testing

import io.github.erwsim.vigie.core.event.EventTypes
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.junit.Assert.assertTrue
import org.junit.Assert.fail

/**
 * The single test reference of `docs/contrat/contrat.md` §2 and its "Précisions": every event type,
 * its field names and the JSON type of each value. Shared by the tests of every module (testFixtures
 * of `:core`); [check] fails on an unknown type, an unknown key, a JSON null, a value of the wrong
 * type, or a value outside a closed list of the contract.
 *
 * Where the contract names a field without a type, the type retained by the agent is written here
 * (and should be added to the contract): `net.cell.mcc`/`mnc` strings (leading zeros), `ci` integer;
 * `sensor.microphone.source` string; `security.posture.always_on_vpn` boolean; USB ids integers.
 */
object Contract {
    enum class Kind { STRING, INT, NUMBER, BOOL, TS, MAC, SHA256, STRINGS, OBJECT, OBJECTS }

    /** A field: its [kind], an optional closed list of [values], the [item] fields of an object or array of objects. */
    data class Field(val kind: Kind, val values: Set<String>? = null, val item: Map<String, Field>? = null)

    private val S = Field(Kind.STRING)
    private val I = Field(Kind.INT)
    private val N = Field(Kind.NUMBER)
    private val B = Field(Kind.BOOL)
    private val T = Field(Kind.TS)
    private val MAC = Field(Kind.MAC)
    private val SHA = Field(Kind.SHA256)
    private val LIST = Field(Kind.STRINGS)
    private val OBJ = Field(Kind.OBJECT)
    private fun oneOf(vararg v: String) = Field(Kind.STRING, v.toSet())
    private fun obj(vararg f: Pair<String, Field>) = Field(Kind.OBJECT, item = f.toMap())
    private fun objs(vararg f: Pair<String, Field>) = Field(Kind.OBJECTS, item = f.toMap())

    val COLLECTOR_STATES = setOf("running", "disabled", "unavailable")

    /** Contract §8: the closed list of commands and the refusal reasons (`command.result.detail` when refused). */
    val COMMAND_TYPES = setOf("ring", "vibrate", "stop_ring", "locate", "lock", "clear_lock_message", "wipe")
    val COMMAND_REFUSALS = setOf(
        "disabled", "malformed", "wrong_device", "unknown_type", "no_code_configured", "bad_signature", "expired", "replay",
        "bad_params", "not_device_owner", "locked_out",
    )

    /** `security.policy.action`: §2 plus the three lists of "Précisions". */
    val POLICY_ACTIONS = setOf(
        "private_dns_set", "package_disabled", "package_enabled", "permission_denied", "restriction_set", "restriction_cleared",
        "network_logging", "security_logging",
        "permission_granted", "force_stop_protection", "always_on_vpn", "backup_service", "policy_reverted", "device_owner_cleared",
        "permission_restored", "setting_changed", "setting_restored",
    )

    private val appChange = mapOf("package" to S, "version_name" to S, "version_code" to I, "installer" to S, "signer_sha256" to SHA)
    private val aggregation = arrayOf("count" to I, "last_event_ts" to T)

    val TYPES: Map<String, Map<String, Field>> = mapOf(
        // agent.*
        "agent.started" to mapOf("reason" to oneOf("boot", "app", "update", "watchdog", "restart"), "agent_version" to S),
        "agent.stopped" to mapOf("reason" to oneOf("user", "system"), "agent_version" to S),
        "agent.heartbeat" to mapOf(
            "battery_pct" to I, "charging" to B, "uptime_ms" to I, "queue_depth" to I, "queue_bytes" to I, "dropped_total" to I,
            "device_owner" to B, "collectors" to Field(Kind.OBJECT, COLLECTOR_STATES), "last_upload_ts" to T,
        ),
        "agent.buffer_overflow" to mapOf("dropped" to I, "oldest_ts" to T, "newest_ts" to T),
        "agent.collector_error" to mapOf("collector" to S, "error" to S),
        "agent.config_changed" to mapOf("key" to S, "old" to S, "new" to S),
        "agent.tamper" to mapOf(
            "kind" to oneOf("admin_disable_requested", "admin_disabled", "permission_revoked", "force_stop", "device_owner_lost"),
            "detail" to S,
        ),
        // device.*
        "device.inventory" to mapOf(
            "manufacturer" to S, "model" to S, "android_release" to S, "sdk_int" to I, "security_patch" to S, "build_fingerprint" to S,
            "one_ui" to S, "kernel" to S, "bootloader" to S, "verified_boot_state" to S, "total_storage_bytes" to I, "total_ram_bytes" to I,
        ),
        "device.boot" to mapOf("reason" to S),
        "device.shutdown" to mapOf("reason" to oneOf("shutdown", "reboot")),
        "device.screen" to mapOf("state" to oneOf("on", "off", "unlocked")),
        "device.battery" to mapOf(
            "pct" to I, "plugged" to oneOf("none", "ac", "usb", "wireless"), "status" to S, "temperature_c" to N, "health" to S,
        ),
        "device.power_save" to mapOf("enabled" to B),
        "device.storage" to mapOf("free_bytes" to I, "total_bytes" to I),
        "device.thermal" to mapOf("status" to S),
        "device.time_changed" to mapOf("delta_ms" to I),
        "device.timezone_changed" to mapOf("tz" to S),
        "device.usb" to mapOf(
            "connected" to B, "configured" to B, "functions" to LIST,
            "accessory" to obj("manufacturer" to S, "model" to S, "version" to S),
            "device" to obj("vendor_id" to I, "product_id" to I, "device_class" to I, "manufacturer" to S, "product" to S),
        ),
        "device.airplane_mode" to mapOf("enabled" to B),
        // location.*
        "location.fix" to mapOf(
            "lat" to N, "lon" to N, "acc_m" to N, "alt_m" to N, "speed_mps" to N, "bearing_deg" to N, "provider" to S, "mock" to B,
            "fix_ts" to T,
        ),
        "location.provider" to mapOf("provider" to S, "enabled" to B),
        // net.*
        "net.connectivity" to mapOf(
            "transports" to LIST, "validated" to B, "metered" to B, "vpn" to B, "private_dns_active" to B, "private_dns_server" to S,
            "dns_servers" to LIST, "interface" to S,
        ),
        "net.wifi" to mapOf(
            "event" to oneOf("connected", "disconnected"), "ssid" to S, "bssid" to MAC, "rssi" to I, "freq_mhz" to I, "security" to S,
            "standard" to S,
        ),
        "net.wifi_scan" to mapOf("aps" to objs("ssid" to S, "bssid" to MAC, "rssi" to I, "freq_mhz" to I, "security" to S)),
        "net.cell" to mapOf(
            "tech" to S, "mcc" to S, "mnc" to S, "tac" to I, "ci" to I, "pci" to I, "band" to I, "signal_dbm" to I, "roaming" to B,
            "operator" to S,
        ),
        "net.cell_security" to mapOf("kind" to oneOf("downgrade_2g", "null_cipher", "identifier_disclosure"), "detail" to S),
        "net.dns" to mapOf("package" to S, "uid" to I, "hostname" to S, "addresses" to LIST, "address_count" to I, *aggregation),
        "net.connect" to mapOf("package" to S, "uid" to I, "ip" to S, "port" to I, *aggregation),
        "net.usage" to mapOf(
            "from" to T, "to" to T,
            "apps" to objs("package" to S, "uid" to I, "rx_bytes" to I, "tx_bytes" to I, "transport" to S),
        ),
        "net.bluetooth" to mapOf(
            "event" to oneOf("state", "connected", "disconnected"), "enabled" to B, "name" to S, "address" to MAC, "type" to S,
        ),
        "net.ble_tracker" to mapOf(
            "address" to MAC, "kind" to oneOf("airtag", "smarttag", "tile", "unknown"), "rssi" to I, "first_seen" to T, "sightings" to I,
        ),
        "net.hotspot" to mapOf("enabled" to B),
        "net.nfc" to mapOf("enabled" to B),
        // app.*
        "app.inventory" to mapOf(
            "inventory_id" to S, "part" to I, "parts" to I,
            "apps" to objs(
                "package" to S, "label" to S, "version_name" to S, "version_code" to I, "installer" to S, "system" to B, "enabled" to B,
                "suspended" to B, "hidden" to B, "target_sdk" to I, "first_install" to T, "last_update" to T, "signer_sha256" to SHA,
                "granted_dangerous" to LIST,
            ),
        ),
        "app.installed" to appChange,
        "app.updated" to appChange,
        "app.removed" to appChange,
        "app.foreground" to mapOf("package" to S, "class" to S, "event" to oneOf("resumed", "paused")),
        "app.permission_changed" to mapOf("package" to S, "permission" to S, "granted" to B),
        "app.special_access" to mapOf(
            "accessibility_services" to LIST, "notification_listeners" to LIST, "device_admins" to LIST, "overlay_apps" to LIST,
            "unknown_sources_apps" to LIST, "usage_access_apps" to LIST, "vpn_apps" to LIST, "default_apps" to OBJ,
        ),
        "app.notification" to mapOf(
            "package" to S, "event" to oneOf("posted", "removed"), "category" to S, "channel" to S, "ongoing" to B, "title" to S, "text" to S,
        ),
        // sensor.*
        "sensor.camera" to mapOf("camera_id" to S, "in_use" to B, "package" to S, "screen_on" to B, "locked" to B),
        "sensor.microphone" to mapOf("recording" to B, "source" to S, "package" to S, "silenced" to B, "screen_on" to B, "locked" to B),
        // security.*
        "security.log" to mapOf(
            "tag" to S, "level" to oneOf("info", "warning", "error"), "log_id" to I, "fields" to OBJ, "pre_reboot" to B, *aggregation,
        ),
        "security.posture" to mapOf(
            "security_patch" to S, "patch_age_days" to I, "encrypted" to B, "lock_secure" to B, "adb_enabled" to B,
            "adb_wifi_enabled" to B, "dev_options" to B, "unknown_sources" to B, "private_dns_mode" to S, "private_dns_host" to S,
            "always_on_vpn" to B, "device_owner" to B, "verified_boot_state" to S, "user_ca_certs" to LIST, "play_protect" to B,
            "usb_data_signaling" to B,
        ),
        "security.posture_change" to mapOf("field" to S, "old" to S, "new" to S),
        "security.keyguard" to mapOf("event" to oneOf("unlock_failed", "unlock_succeeded"), "failed_attempts" to I),
        "security.ca_cert" to mapOf("event" to oneOf("added", "removed"), "sha256" to SHA, "subject" to S),
        "security.policy" to mapOf(
            "action" to Field(Kind.STRING, POLICY_ACTIONS), "target" to S, "profile" to S, "ok" to B, "error" to S,
        ),
        // command.* (contract §8; `type` = the closed list, or "unknown" when the payload's type is unreadable or not in it)
        "command.result" to mapOf(
            "command_id" to S,
            "type" to Field(Kind.STRING, COMMAND_TYPES + "unknown"),
            "status" to oneOf("executed", "failed", "refused"),
            "detail" to S,
            "signed" to B,
        ),
    )

    /** `security.log.fields` per tag (contract table); a tag not listed uses `arg0`, `arg1`… */
    val SECURITY_LOG_FIELDS: Map<String, Set<String>> = mapOf(
        "adb_shell_interactive" to emptySet(),
        "adb_shell_cmd" to setOf("command"),
        "sync_recv_file" to setOf("path"),
        "sync_send_file" to setOf("path"),
        "app_process_start" to setOf("process", "start_time", "uid", "pid", "seinfo", "apk_sha256"),
        "keyguard_dismissed" to emptySet(),
        "keyguard_secured" to emptySet(),
        "keyguard_dismiss_auth_attempt" to setOf("success", "strength"),
        "os_startup" to setOf("verified_boot_state", "dm_verity_mode"),
        "os_shutdown" to emptySet(),
        "logging_started" to emptySet(),
        "logging_stopped" to emptySet(),
        "log_buffer_size_critical" to emptySet(),
        "media_mount" to setOf("mount_point", "label"),
        "media_unmount" to setOf("mount_point", "label"),
        "crypto_self_test_completed" to setOf("success"),
        "key_generated" to setOf("success", "alias", "uid"),
        "key_import" to setOf("success", "alias", "uid"),
        "key_destruction" to setOf("success", "alias", "uid"),
        "key_integrity_violation" to setOf("alias", "uid"),
        "cert_authority_installed" to setOf("success", "subject", "user_id"),
        "cert_authority_removed" to setOf("success", "subject", "user_id"),
        "cert_validation_failure" to setOf("reason"),
        "user_restriction_added" to setOf("admin_package", "user_id", "restriction"),
        "user_restriction_removed" to setOf("admin_package", "user_id", "restriction"),
        "password_changed" to setOf("complexity", "user_id"),
        "wifi_connection" to setOf("bssid", "event_type", "reason"),
        "wifi_disconnection" to setOf("bssid", "reason"),
        "bluetooth_connection" to setOf("address", "success", "reason"),
        "bluetooth_disconnection" to setOf("address", "reason"),
        "package_installed" to setOf("package", "version_code", "user_id"),
        "package_updated" to setOf("package", "version_code", "user_id"),
        "package_uninstalled" to setOf("package", "version_code", "user_id"),
    )

    /** Field names of [type] (for tests that only need the names). */
    fun fields(type: String): Set<String> = TYPES[type]?.keys ?: emptySet()

    private val RFC3339_MS = Regex("^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}\\.\\d{3}Z$")
    private val MAC_RE = Regex("^([0-9a-f]{2}:){5}[0-9a-f]{2}$")
    private val SHA_RE = Regex("^[0-9a-f]{64}$")
    private val ARG_RE = Regex("^arg[0-9]+$")

    /** Fails if [data] does not follow the contract for [type]. */
    fun check(type: String, data: JsonObject) {
        assertTrue("invalid type $type", EventTypes.isValid(type))
        val spec = TYPES[type] ?: return fail("type $type is not in the contract catalogue")
        checkObject(type, data, spec)
        if (type == "security.log") checkSecurityLogFields(data)
        if (type == "security.posture_change") {
            val field = (data["field"] as? JsonPrimitive)?.content
            assertTrue("security.posture_change.field '$field' is not a posture field", field in fields("security.posture"))
        }
        if ("count" in data) assertTrue("$type.count must be >= 1", (data["count"] as JsonPrimitive).content.toLong() >= 1)
        if (type == "command.result" && (data["status"] as? JsonPrimitive)?.content == "refused") {
            val detail = (data["detail"] as? JsonPrimitive)?.content
            assertTrue("command.result.detail '$detail' is not a refusal reason of §8", detail in COMMAND_REFUSALS)
        }
    }

    private fun checkObject(path: String, data: JsonObject, spec: Map<String, Field>) {
        for ((key, value) in data) {
            val field = spec[key] ?: return fail("$path: key '$key' is not in the contract (${spec.keys})")
            checkValue("$path.$key", value, field)
        }
    }

    private fun checkValue(path: String, value: JsonElement, field: Field) {
        assertTrue("$path is JSON null (absent rather than null)", value !is JsonNull)
        when (field.kind) {
            Kind.STRING, Kind.TS, Kind.MAC, Kind.SHA256 -> {
                val p = value as? JsonPrimitive
                assertTrue("$path must be a string: $value", p != null && p.isString)
                val s = p!!.content
                when (field.kind) {
                    Kind.TS -> assertTrue("$path must be RFC 3339 UTC with ms: $s", RFC3339_MS.matches(s))
                    Kind.MAC -> assertTrue("$path must be a lowercase MAC with ':': $s", MAC_RE.matches(s))
                    Kind.SHA256 -> assertTrue("$path must be lowercase hex SHA-256: $s", SHA_RE.matches(s))
                    else -> Unit
                }
                field.values?.let { assertTrue("$path = '$s' is not one of $it", s in it) }
            }
            Kind.INT -> {
                val p = value as? JsonPrimitive
                assertTrue("$path must be an integer: $value", p != null && !p.isString && p.content.toLongOrNull() != null)
            }
            Kind.NUMBER -> {
                val p = value as? JsonPrimitive
                assertTrue("$path must be a number: $value", p != null && !p.isString && p.content.toDoubleOrNull() != null)
            }
            Kind.BOOL -> {
                val p = value as? JsonPrimitive
                assertTrue("$path must be a boolean: $value", p != null && !p.isString && (p.content == "true" || p.content == "false"))
            }
            Kind.STRINGS -> {
                assertTrue("$path must be an array of strings: $value", value is JsonArray && value.all { it is JsonPrimitive && it.isString })
            }
            Kind.OBJECT -> {
                assertTrue("$path must be an object: $value", value is JsonObject)
                val obj = value as JsonObject
                field.item?.let { checkObject(path, obj, it) }
                field.values?.let { allowed ->
                    obj.forEach { (k, v) -> assertTrue("$path.$k = $v is not one of $allowed", v is JsonPrimitive && v.isString && v.content in allowed) }
                }
                obj.values.forEach { assertTrue("$path contains a JSON null", it !is JsonNull) }
            }
            Kind.OBJECTS -> {
                assertTrue("$path must be an array of objects: $value", value is JsonArray && value.all { it is JsonObject })
                (value as JsonArray).forEachIndexed { i, item -> field.item?.let { checkObject("$path[$i]", item as JsonObject, it) } }
            }
        }
    }

    private fun checkSecurityLogFields(data: JsonObject) {
        val tag = (data["tag"] as JsonPrimitive).content
        val fields = data["fields"] as? JsonObject ?: return
        val named = SECURITY_LOG_FIELDS[tag]
        for (key in fields.keys) {
            if (named != null) {
                assertTrue("security.log $tag: field '$key' not in the contract table ($named)", key in named)
            } else {
                assertTrue("security.log $tag (not in the table): field '$key' must be argN", ARG_RE.matches(key))
            }
        }
        // Success flags are booleans (contract: "les indicateurs 0/1 de réussite deviennent des booléens").
        (fields["success"] as? JsonPrimitive)?.let { assertTrue("security.log $tag: success must be a boolean", !it.isString && it.content in setOf("true", "false")) }
    }
}
