package io.github.erwsim.watchpost.core.event

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/**
 * Builds the `data` object of an event. Every `put` with a null value is a no-op, so optional
 * fields are naturally absent (contract §1: "champs absents plutôt que null").
 *
 * Keys must be snake_case (`[a-z0-9_]+`); a bad key is a programming error and throws.
 */
class EventDataBuilder {
    private val content = LinkedHashMap<String, JsonElement>()

    fun put(key: String, value: String?) = putElement(key, value?.let(::JsonPrimitive))
    fun put(key: String, value: Number?) = putElement(key, value?.let { numberPrimitive(it) })
    fun put(key: String, value: Boolean?) = putElement(key, value?.let(::JsonPrimitive))
    fun put(key: String, value: JsonElement?) = putElement(key, value?.let(::stripNulls))

    /** List of scalars (strings). Null list → absent; empty list → `[]`. */
    fun putStrings(key: String, values: Iterable<String>?) =
        putElement(key, values?.let { list -> JsonArray(list.map(::JsonPrimitive)) })

    /** Nested object built with the same null-dropping rules. */
    fun putObject(key: String, block: EventDataBuilder.() -> Unit) =
        putElement(key, EventDataBuilder().apply(block).build())

    /** List of objects (e.g. `apps`, `aps`). */
    fun <T> putObjects(key: String, items: Iterable<T>?, block: EventDataBuilder.(T) -> Unit) =
        putElement(key, items?.let { list -> JsonArray(list.map { EventDataBuilder().apply { block(it) }.build() }) })

    /**
     * Map whose keys are free-form identifiers (collector ids, package names…). Only the
     * outer key is checked for snake_case; null values are dropped.
     */
    fun putMap(key: String, values: Map<String, String?>?) =
        putElement(key, values?.let { m -> JsonObject(m.filterValues { it != null }.mapValues { JsonPrimitive(it.value) }) })

    private fun putElement(key: String, value: JsonElement?) {
        require(KEY_REGEX.matches(key)) { "data key must be snake_case: '$key'" }
        if (value == null || value is JsonNull) {
            content.remove(key)
        } else {
            content[key] = value
        }
    }

    fun build(): JsonObject = JsonObject(LinkedHashMap(content))

    private companion object {
        val KEY_REGEX = Regex("^[a-z0-9_]+$")

        /** NaN/Infinity are not valid JSON numbers: they become absent fields. */
        fun numberPrimitive(n: Number): JsonPrimitive? = when (n) {
            is Double -> if (n.isFinite()) JsonPrimitive(n) else null
            // Shortest decimal form (0.1f must not become 0.10000000149011612).
            is Float -> if (n.isFinite()) JsonPrimitive(n.toString().toDouble()) else null
            else -> JsonPrimitive(n)
        }
    }
}

inline fun eventData(block: EventDataBuilder.() -> Unit): JsonObject = EventDataBuilder().apply(block).build()

/** Recursively removes JSON nulls (object members are dropped, array items too). */
fun stripNulls(element: JsonElement): JsonElement = when (element) {
    is JsonObject -> JsonObject(element.filterValues { it !is JsonNull }.mapValues { stripNulls(it.value) })
    is JsonArray -> JsonArray(element.filter { it !is JsonNull }.map(::stripNulls))
    else -> element
}

val EmptyData: JsonObject = JsonObject(emptyMap())
