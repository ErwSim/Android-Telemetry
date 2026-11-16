package io.github.erwsim.vigie.core.command

import io.github.erwsim.vigie.core.event.AgentClock
import io.github.erwsim.vigie.core.event.Rfc3339
import io.github.erwsim.vigie.core.event.VigieJson
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull

/**
 * The checks of contract §8, **in the contract's order**, each with its refusal reason:
 *
 *  1. channel enabled (`disabled`);
 *  2. `payload` parsable, `v` = 1, same `id` inside and outside (`malformed`);
 *  3. `device_id` is this device's (`wrong_device`);
 *  4. `type` in the closed list (`unknown_type`);
 *  5. sensitive type: a code is set (`no_code_configured`), no lock-out in progress (`locked_out`), valid
 *     HMAC-SHA256 over the exact payload bytes, compared in constant time (`bad_signature`); a simple type
 *     must not carry `sig` (`malformed`);
 *  6. `wipe` allowed locally (`disabled`);
 *  7. not expired, 5 min clock tolerance (`expired`);
 *  8. `id` never seen, persistent window of 500 (`replay`);
 *  9. parameters within bounds, no extra parameter (`bad_params`);
 * 10. Device Owner for `lock`, `clear_lock_message`, `wipe` (`not_device_owner`).
 *
 * Before the signature, only the routing fields (`v`, `id`, `device_id`, `type`) are read, and only to
 * refuse: the content (`params`, dates, other keys) of a sensitive command is analysed only once its
 * signature is verified. Five `bad_signature` within an hour lock sensitive commands out for an hour.
 *
 * Choices where the contract is silent (documented in `ARCHITECTURE-CODE.md`): an unknown top-level key
 * of the payload or an `expires_at` before `issued_at` is `malformed`; a validity above 30 days or an
 * `issued_at` more than 5 min in the future is `expired` (outside the validity the contract allows).
 */
class CommandVerifier(
    private val clock: AgentClock,
    private val state: CommandStateStore,
    private val keys: CommandKeyStore,
) {
    /** What the verifier needs to know about the device, read at the time of each verification. */
    data class Environment(
        val channelEnabled: Boolean,
        /** Enrolled device id, null when not enrolled. */
        val deviceId: String?,
        val wipeAllowed: Boolean,
        val isDeviceOwner: () -> Boolean,
    )

    sealed class Verification {
        abstract val id: String
        abstract val type: String
        abstract val signed: Boolean

        data class Accepted(val command: AcceptedCommand) : Verification() {
            override val id get() = command.id
            override val type get() = command.type
            override val signed get() = command.signatureVerified
        }

        /** [id] is the outer id when it is a valid ULID, else [INVALID_ID]; [type] is in the closed list or [CommandTypes.UNKNOWN]. */
        data class Refused(override val id: String, override val type: String, val reason: String, override val signed: Boolean) : Verification()
    }

    fun verify(envelope: CommandEnvelope, env: Environment): Verification {
        val outerId = envelope.id.takeIf { ULID.matches(it) }
        val reportId = outerId ?: INVALID_ID
        // Routing view, used only to refuse (and to name the type in command.result).
        val root: JsonObject? = if (envelope.payload.length <= MAX_PAYLOAD_CHARS) {
            try {
                VigieJson.parseToJsonElement(envelope.payload) as? JsonObject
            } catch (_: Exception) {
                null
            }
        } else {
            null
        }
        val rawType = root?.string("type")
        val reportType = rawType?.takeIf { it in CommandTypes.ALL } ?: CommandTypes.UNKNOWN
        fun refuse(reason: String, signed: Boolean = false) = Verification.Refused(reportId, reportType, reason, signed)

        // 1. Channel.
        if (!env.channelEnabled) return refuse(Refusal.DISABLED)
        // 2. Shape.
        if (outerId == null || root == null) return refuse(Refusal.MALFORMED)
        val v = root["v"] as? JsonPrimitive
        if (v == null || v.isString || v.content != "1") return refuse(Refusal.MALFORMED)
        if (root.string("id") != outerId) return refuse(Refusal.MALFORMED)
        // 3. Device.
        val deviceId = env.deviceId
        if (deviceId == null || root.string("device_id") != deviceId) return refuse(Refusal.WRONG_DEVICE)
        // 4. Type.
        val type = rawType?.takeIf { it in CommandTypes.ALL } ?: return refuse(Refusal.UNKNOWN_TYPE)
        val sensitive = CommandTypes.isSensitive(type)

        // 5. Signature, over the exact bytes, before the content is read.
        if (sensitive) {
            val key = keys.key(deviceId) ?: return refuse(Refusal.NO_CODE_CONFIGURED)
            try {
                if (state.lockedOutUntil(clock.nowMillis()) > 0) return refuse(Refusal.LOCKED_OUT)
                if (!CommandCrypto.verify(key, envelope.payload, envelope.sig)) {
                    state.recordBadSignature(clock.nowMillis())
                    return refuse(Refusal.BAD_SIGNATURE)
                }
            } finally {
                key.fill(0)
            }
        } else if (envelope.sig != null) {
            // The collector only relays `sig` for a sensitive type: a signed simple command is not something to guess about.
            return refuse(Refusal.MALFORMED)
        }
        val signed = sensitive

        // Content (authenticated for a sensitive type from here on).
        if (root.keys.any { it !in PAYLOAD_KEYS }) return refuse(Refusal.MALFORMED, signed)
        val issuedAt = root.string("issued_at")?.let(Rfc3339::parseOrNull) ?: return refuse(Refusal.MALFORMED, signed)
        val expiresAt = root.string("expires_at")?.let(Rfc3339::parseOrNull) ?: return refuse(Refusal.MALFORMED, signed)
        if (expiresAt < issuedAt) return refuse(Refusal.MALFORMED, signed)

        // 6. Wipe allowed on the phone.
        if (type == CommandTypes.WIPE && !env.wipeAllowed) return refuse(Refusal.DISABLED, signed)

        // 7. Validity window.
        val now = clock.nowMillis()
        val notExpired = now <= expiresAt + CLOCK_TOLERANCE_MS &&
            issuedAt <= now + CLOCK_TOLERANCE_MS &&
            expiresAt - issuedAt <= MAX_VALIDITY_MS
        if (!notExpired) return refuse(Refusal.EXPIRED, signed)

        // 8. Replay (checked and recorded atomically, persisted before anything runs).
        if (!state.markSeen(outerId, signed)) return refuse(Refusal.REPLAY, signed)

        // 9. Parameters.
        val params = parseParams(type, root["params"]) ?: return refuse(Refusal.BAD_PARAMS, signed)

        // 10. Device Owner.
        if (type in CommandTypes.DEVICE_OWNER && !env.isDeviceOwner()) return refuse(Refusal.NOT_DEVICE_OWNER, signed)

        val gate = WipeGate.Conditions(
            channelEnabled = true,
            codeConfigured = sensitive,
            signatureValid = signed,
            wipeAllowed = env.wipeAllowed,
            notExpired = true,
            neverSeen = true,
        )
        return Verification.Accepted(AcceptedCommand(outerId, type, params, issuedAt, expiresAt, signed, gate))
    }

    companion object {
        const val INVALID_ID = "invalid"
        const val CLOCK_TOLERANCE_MS = 5 * 60_000L
        const val MAX_VALIDITY_MS = 30 * 86_400_000L
        const val MAX_PAYLOAD_CHARS = 8 * 1024
        const val LOCK_MESSAGE_MAX = 200
        val ULID = Regex("^[0-9A-HJKMNP-TV-Z]{26}$")
        private val PAYLOAD_KEYS = setOf("v", "id", "device_id", "type", "params", "issued_at", "expires_at")
        private val INTEGER = Regex("^-?[0-9]{1,9}$")

        private fun JsonObject.string(key: String): String? = (this[key] as? JsonPrimitive)?.takeIf { it.isString }?.content

        /** Closed parameter lists of contract §8; anything extra, of the wrong JSON type or out of bounds → null. */
        fun parseParams(type: String, element: JsonElement?): CommandParams? {
            val p: JsonObject = when (element) {
                null -> JsonObject(emptyMap())
                is JsonObject -> element
                else -> return null
            }
            fun allowOnly(vararg keys: String) = p.keys.all { it in keys }
            fun int(key: String, default: Int, range: IntRange): Int? {
                val e = p[key] ?: return default
                val prim = e as? JsonPrimitive ?: return null
                if (prim.isString || !INTEGER.matches(prim.content)) return null
                return prim.content.toIntOrNull()?.takeIf { it in range }
            }
            fun bool(key: String, default: Boolean): Boolean? {
                val e = p[key] ?: return default
                val prim = e as? JsonPrimitive ?: return null
                return if (prim.isString) null else prim.booleanOrNull
            }
            return when (type) {
                CommandTypes.RING -> {
                    if (!allowOnly("duration_s", "vibrate")) return null
                    CommandParams.Ring(int("duration_s", 60, 1..300) ?: return null, bool("vibrate", true) ?: return null)
                }
                CommandTypes.VIBRATE -> {
                    if (!allowOnly("duration_s")) return null
                    CommandParams.Vibrate(int("duration_s", 10, 1..60) ?: return null)
                }
                CommandTypes.LOCK -> {
                    if (!allowOnly("message")) return null
                    val e = p["message"]
                    val message = if (e == null) {
                        null
                    } else {
                        val prim = e as? JsonPrimitive ?: return null
                        if (!prim.isString) return null
                        // "200 caractères" counted in UTF-16 units, as the console does (the strictest count).
                        if (prim.content.length > LOCK_MESSAGE_MAX) return null
                        // Control characters are shown as spaces on the lock screen (displayed, never interpreted).
                        prim.content.map { if (it.isISOControl()) ' ' else it }.joinToString("").trim().ifEmpty { null }
                    }
                    CommandParams.Lock(message)
                }
                CommandTypes.STOP_RING, CommandTypes.LOCATE, CommandTypes.CLEAR_LOCK_MESSAGE, CommandTypes.WIPE ->
                    if (p.isEmpty()) CommandParams.None else null
                else -> null
            }
        }
    }
}

/**
 * The conditions that must **all** hold for a factory reset (the only irreversible action of the app):
 * channel enabled, command code set, valid signature, "Autoriser l'effacement à distance" on, command
 * not expired and never seen. The verifier establishes them; the wipe executor (`:policy`) checks them
 * again against the live state right before calling the platform.
 */
object WipeGate {
    data class Conditions(
        val channelEnabled: Boolean,
        val codeConfigured: Boolean,
        val signatureValid: Boolean,
        val wipeAllowed: Boolean,
        val notExpired: Boolean,
        val neverSeen: Boolean,
    ) {
        fun all(): Boolean = channelEnabled && codeConfigured && signatureValid && wipeAllowed && notExpired && neverSeen
    }

    /** Live state at execution time, provided by the agent. */
    data class Live(val channelEnabled: Boolean, val codeConfigured: Boolean, val wipeAllowed: Boolean, val nowMs: Long)

    /** True only for a verified, signed `wipe` whose conditions still hold now. */
    fun allows(command: AcceptedCommand, live: Live): Boolean =
        command.type == CommandTypes.WIPE &&
            command.signatureVerified &&
            command.gate.all() &&
            live.channelEnabled &&
            live.codeConfigured &&
            live.wipeAllowed &&
            live.nowMs <= command.expiresAtMs + CommandVerifier.CLOCK_TOLERANCE_MS
}
