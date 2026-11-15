package io.github.erwsim.vigie.core.event

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject

/** Device-side severity hint (contract §1, field `sev`). */
object Severity {
    const val INFO = 0
    const val NOTABLE = 1
    const val WARNING = 2
    const val CRITICAL = 3

    fun isValid(sev: Int): Boolean = sev in INFO..CRITICAL
}

/**
 * One event exactly as described in contract §1. Field order matches the contract.
 * `data` never contains JSON nulls: absent fields are omitted (see [EventDataBuilder]).
 */
@Serializable
data class Event(
    val id: String,
    val ts: String,
    val seq: Long,
    @SerialName("boot_id") val bootId: String,
    @SerialName("elapsed_ms") val elapsedMs: Long,
    val type: String,
    val sev: Int,
    val data: JsonObject,
)

object EventTypes {
    /** Contract §1: `<domain>.<name>`, lowercase, `[a-z0-9_.]`. */
    private val TYPE_REGEX = Regex("^[a-z0-9_]+(\\.[a-z0-9_]+)+$")

    fun isValid(type: String): Boolean = type.length <= 128 && TYPE_REGEX.matches(type)

    const val AGENT_STARTED = "agent.started"
    const val AGENT_STOPPED = "agent.stopped"
    const val AGENT_HEARTBEAT = "agent.heartbeat"
    const val AGENT_BUFFER_OVERFLOW = "agent.buffer_overflow"
    const val AGENT_COLLECTOR_ERROR = "agent.collector_error"
    const val AGENT_CONFIG_CHANGED = "agent.config_changed"
    const val AGENT_TAMPER = "agent.tamper"
}

/** Shared JSON configuration: absent rather than null, unknown keys tolerated when reading. */
val VigieJson: Json = Json {
    explicitNulls = false
    encodeDefaults = true
    ignoreUnknownKeys = true
}
