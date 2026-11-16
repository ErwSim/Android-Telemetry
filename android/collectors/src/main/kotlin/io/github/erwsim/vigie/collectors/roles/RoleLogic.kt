package io.github.erwsim.vigie.collectors.roles

import io.github.erwsim.vigie.core.event.Severity
import io.github.erwsim.vigie.core.event.eventData
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/** One change of default app: [old] and [new] are packages, null = none (or not readable). */
data class RoleChange(val role: String, val old: String?, val new: String?)

/** Pure logic of the `app_role` collector. */
object RoleLogic {
    /**
     * Roles whose reading is reliable (public API, or a public setting): their disappearance is a real
     * change. `assistant` and `autofill` come from hidden settings that some builds refuse to read: for
     * them an absent value is "unknown", never "removed" (the previous value is kept).
     */
    val RELIABLE = setOf("sms", "dialer", "browser", "home", "keyboard")

    /**
     * Roles abused to read messages, calls or keystrokes or to trick the user: a change is a warning.
     * The browser and the home app only matter as notable events.
     */
    private val WARNING_ROLES = setOf("sms", "dialer", "assistant", "keyboard", "autofill")

    /**
     * Changes from [old] to [now]. Returns the changes and the state to remember (which differs from
     * [now] only for the roles whose absence is not trustworthy).
     */
    fun diff(old: Map<String, String>, now: Map<String, String>): Pair<List<RoleChange>, Map<String, String>> {
        val changes = ArrayList<RoleChange>()
        val next = LinkedHashMap<String, String>()
        val roles = (old.keys + now.keys).toSortedSet()
        for (role in roles) {
            val before = old[role]
            val after = now[role] ?: before.takeIf { role !in RELIABLE }
            if (after != null) next[role] = after
            if (before != after) changes += RoleChange(role, before, after)
        }
        return changes to next
    }

    fun severity(c: RoleChange): Int = if (c.role in WARNING_ROLES) Severity.WARNING else Severity.NOTABLE

    /** `app.role` data: `role`, `old`, `new` (each package absent when none). */
    fun data(c: RoleChange): JsonObject = eventData {
        put("role", c.role)
        put("old", c.old)
        put("new", c.new)
    }

    fun encode(state: Map<String, String>): String =
        JsonObject(state.toSortedMap().mapValues { JsonPrimitive(it.value) }).toString()

    /** Null if absent or unreadable: the next reading only sets a new baseline. */
    fun decode(text: String?): Map<String, String>? {
        if (text.isNullOrEmpty()) return null
        return try {
            Json.parseToJsonElement(text).jsonObject.mapValues { it.value.jsonPrimitive.content }
        } catch (_: Exception) {
            null
        }
    }
}
