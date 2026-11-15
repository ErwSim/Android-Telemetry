package io.github.erwsim.vigie.collectors

import io.github.erwsim.vigie.core.event.EventTypes
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import org.junit.Assert.assertTrue
import org.junit.Assert.fail

/**
 * Field names of `docs/contrat/contrat.md` §2 (and its "Précisions") for the types emitted by this
 * module, copied by hand: a test fails if a collector emits a key the contract does not list.
 */
object Contract {
    val FIELDS: Map<String, Set<String>> = mapOf(
        "device.usb" to setOf("connected", "configured", "functions", "accessory", "device"),
        "net.connectivity" to setOf("transports", "validated", "metered", "vpn", "private_dns_active", "private_dns_server", "dns_servers", "interface"),
        "net.wifi" to setOf("event", "ssid", "bssid", "rssi", "freq_mhz", "security", "standard"),
        "net.wifi_scan" to setOf("aps"),
        "net.cell" to setOf("tech", "mcc", "mnc", "tac", "ci", "pci", "band", "signal_dbm", "roaming", "operator"),
        "net.cell_security" to setOf("kind", "detail"),
        "net.usage" to setOf("from", "to", "apps"),
        "net.bluetooth" to setOf("event", "enabled", "name", "address", "type"),
        "net.ble_tracker" to setOf("address", "kind", "rssi", "first_seen", "sightings"),
        "net.hotspot" to setOf("enabled"),
        "net.nfc" to setOf("enabled"),
        "app.inventory" to setOf("inventory_id", "part", "parts", "apps"),
        "app.installed" to setOf("package", "version_name", "version_code", "installer", "signer_sha256"),
        "app.updated" to setOf("package", "version_name", "version_code", "installer", "signer_sha256"),
        "app.removed" to setOf("package", "version_name", "version_code", "installer", "signer_sha256"),
        "app.foreground" to setOf("package", "class", "event"),
        "app.permission_changed" to setOf("package", "permission", "granted"),
        "app.special_access" to setOf(
            "accessibility_services", "notification_listeners", "device_admins", "overlay_apps",
            "unknown_sources_apps", "usage_access_apps", "vpn_apps", "default_apps",
        ),
        "sensor.camera" to setOf("camera_id", "in_use", "package", "screen_on", "locked"),
        "sensor.microphone" to setOf("recording", "source", "package", "silenced", "screen_on", "locked"),
    )

    /** Keys of the objects inside arrays of objects (`apps`, `aps`). */
    val ITEM_FIELDS: Map<Pair<String, String>, Set<String>> = mapOf(
        ("net.wifi_scan" to "aps") to setOf("ssid", "bssid", "rssi", "freq_mhz", "security"),
        ("net.usage" to "apps") to setOf("package", "uid", "rx_bytes", "tx_bytes", "transport"),
        ("app.inventory" to "apps") to setOf(
            "package", "label", "version_name", "version_code", "installer", "system", "enabled", "suspended",
            "hidden", "target_sdk", "first_install", "last_update", "signer_sha256", "granted_dangerous",
        ),
    )

    /** Fails if [data] has a key the contract does not define for [type] (or a JSON null). */
    fun check(type: String, data: JsonObject) {
        assertTrue("invalid type $type", EventTypes.isValid(type))
        val allowed = FIELDS[type] ?: return fail("type $type is not in the contract catalogue")
        for ((key, value) in data) {
            assertTrue("$type: key '$key' is not in the contract ($allowed)", key in allowed)
            assertTrue("$type.$key is JSON null", value !is kotlinx.serialization.json.JsonNull)
            val itemAllowed = ITEM_FIELDS[type to key] ?: continue
            (value as JsonArray).forEach { item ->
                (item as JsonObject).keys.forEach { k -> assertTrue("$type.$key[]: '$k' not in the contract", k in itemAllowed) }
            }
        }
    }
}
