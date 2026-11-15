package io.github.erwsim.vigie.collectors.apps

import io.github.erwsim.vigie.core.event.EventDataBuilder
import io.github.erwsim.vigie.core.event.eventData
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/** Pure value of `app.special_access`. A null list means "not readable" (field absent). */
data class SpecialAccessSnapshot(
    val accessibilityServices: List<String>?,
    val notificationListeners: List<String>?,
    val deviceAdmins: List<String>?,
    val overlayApps: List<String>?,
    val unknownSourcesApps: List<String>?,
    val usageAccessApps: List<String>?,
    val vpnApps: List<String>?,
    val defaultApps: Map<String, String>,
) {
    fun writeTo(b: EventDataBuilder) {
        b.putStrings("accessibility_services", accessibilityServices)
        b.putStrings("notification_listeners", notificationListeners)
        b.putStrings("device_admins", deviceAdmins)
        b.putStrings("overlay_apps", overlayApps)
        b.putStrings("unknown_sources_apps", unknownSourcesApps)
        b.putStrings("usage_access_apps", usageAccessApps)
        b.putStrings("vpn_apps", vpnApps)
        b.putMap("default_apps", defaultApps)
    }

    /**
     * True if an accessibility service, a notification listener or a device admin appeared since
     * [previous]: the accesses abused by stalkerware and banking trojans.
     */
    fun gainedCritical(previous: SpecialAccessSnapshot): Boolean =
        gained(accessibilityServices, previous.accessibilityServices) ||
            gained(notificationListeners, previous.notificationListeners) ||
            gained(deviceAdmins, previous.deviceAdmins)

    fun encode(): String = eventData { writeTo(this) }.toString()

    companion object {
        private fun gained(now: List<String>?, before: List<String>?): Boolean =
            now != null && before != null && (now - before.toSet()).isNotEmpty()

        /** `pkg/cls:pkg2/cls2` (secure settings format) → sorted short component names. */
        fun splitComponents(raw: String?): List<String> =
            raw.orEmpty().split(':').map { it.trim() }.filter { it.isNotEmpty() }.map(::shortComponent).sorted()

        /** `com.app/com.app.Service` → `com.app/.Service` (ComponentName.flattenToShortString). */
        fun shortComponent(flat: String): String {
            val pkg = flat.substringBefore('/', "")
            val cls = flat.substringAfter('/', "")
            if (pkg.isEmpty() || cls.isEmpty()) return flat
            return if (cls.startsWith("$pkg.")) "$pkg/${cls.removePrefix(pkg)}" else flat
        }

        fun decode(text: String?): SpecialAccessSnapshot? {
            if (text.isNullOrEmpty()) return null
            return try {
                val o = Json.parseToJsonElement(text).jsonObject
                fun list(k: String) = (o[k] as? JsonArray)?.map { it.jsonPrimitive.content }
                SpecialAccessSnapshot(
                    accessibilityServices = list("accessibility_services"),
                    notificationListeners = list("notification_listeners"),
                    deviceAdmins = list("device_admins"),
                    overlayApps = list("overlay_apps"),
                    unknownSourcesApps = list("unknown_sources_apps"),
                    usageAccessApps = list("usage_access_apps"),
                    vpnApps = list("vpn_apps"),
                    defaultApps = (o["default_apps"] as? JsonObject)?.mapNotNull { (k, v) -> (v as? JsonPrimitive)?.content?.let { k to it } }?.toMap().orEmpty(),
                )
            } catch (_: Exception) {
                null
            }
        }
    }
}
