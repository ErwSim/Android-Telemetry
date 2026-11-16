package io.github.erwsim.watchpost.core.command

import io.github.erwsim.watchpost.core.event.AgentClock
import io.github.erwsim.watchpost.core.event.Rfc3339
import io.github.erwsim.watchpost.core.event.WatchpostJson
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
 *  6. `wipe` allowed locally (`disabled`); the id of a signed, still valid `wipe` refused here is consumed
 *     (a later delivery of the same command is a `replay`, even after the switch is turned on);
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
 * of the payload or an `expires_at` before `issued_at` is `malformed`; a validity above 30 days (24 h for
 * `wipe`, contract review of v1.1) or an `issued_at` more than 5 min in the future is `expired`.
 * A sensitive command refused `disabled` or `no_code_configured` is consumed (unverified window).
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
        val root: JsonObject? = if (envelope.payload.length <= MAX_PAYLOAD_CHARS && !JsonNesting.deeperThan(envelope.payload, JsonNesting.MAX_PAYLOAD_DEPTH)) {
            try {
                WatchpostJson.parseToJsonElement(envelope.payload) as? JsonObject
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
        if (!env.channelEnabled) {
            consumeUnverified(root, outerId, env.deviceId, rawType)
            return refuse(Refusal.DISABLED)
        }
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
            val key = keys.key(deviceId) ?: run {
                consumeUnverified(root, outerId, deviceId, type)
                return refuse(Refusal.NO_CODE_CONFIGURED)
            }
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
        if (JsonDuplicateKeys.found(envelope.payload)) return refuse(Refusal.MALFORMED, signed)
        val issuedAt = root.string("issued_at")?.let(Rfc3339::parseOrNull) ?: return refuse(Refusal.MALFORMED, signed)
        val expiresAt = root.string("expires_at")?.let(Rfc3339::parseOrNull) ?: return refuse(Refusal.MALFORMED, signed)
        if (expiresAt < issuedAt) return refuse(Refusal.MALFORMED, signed)

        val now = clock.nowMillis()
        val notExpired = withinValidity(type, issuedAt, expiresAt, now)

        // 6. Wipe allowed on the phone.
        if (type == CommandTypes.WIPE && !env.wipeAllowed) {
            // This refusal is final for this command: its id is consumed in the signed anti-replay window. Otherwise
            // the server, which keeps the signed command until it expires (7 days by default), could deliver it
            // again once the user switches "Allow remote erase" on, and it would then run. An
            // expired command is not recorded (it can no longer run, and must not fill the window).
            if (notExpired) state.markSeen(outerId, signed)
            return refuse(Refusal.DISABLED, signed)
        }

        // 7. Validity window.
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

    /**
     * Contract §8 (review of v1.1): a sensitive command refused `disabled` (channel off) or
     * `no_code_configured` is consumed, so that it never runs once the channel is switched on or a code
     * is set. Its signature cannot be checked here, so it goes to the separate unverified window
     * ([CommandStateStore.consumeUnverified]), and only when its routing fields are this device's and
     * its (unauthenticated) dates are still valid: an expired command can no longer run anyway.
     */
    private fun consumeUnverified(root: JsonObject?, outerId: String?, deviceId: String?, type: String?) {
        if (root == null || outerId == null || deviceId == null || type == null || !CommandTypes.isSensitive(type)) return
        if (type !in CommandTypes.ALL || root.string("id") != outerId || root.string("device_id") != deviceId) return
        val issuedAt = root.string("issued_at")?.let(Rfc3339::parseOrNull) ?: return
        val expiresAt = root.string("expires_at")?.let(Rfc3339::parseOrNull) ?: return
        if (expiresAt < issuedAt || !withinValidity(type, issuedAt, expiresAt, clock.nowMillis())) return
        state.consumeUnverified(outerId)
    }

    companion object {
        const val INVALID_ID = "invalid"
        const val CLOCK_TOLERANCE_MS = 5 * 60_000L
        const val MAX_VALIDITY_MS = 30 * 86_400_000L

        /** `wipe`: 24 h at most (contract §8, review of v1.1), whatever the server and the console allowed. */
        const val MAX_WIPE_VALIDITY_MS = 86_400_000L

        /** Not expired (5 min clock tolerance), not issued in the future, validity within the type's maximum. */
        fun withinValidity(type: String, issuedAt: Long, expiresAt: Long, now: Long): Boolean =
            now <= expiresAt + CLOCK_TOLERANCE_MS &&
                issuedAt <= now + CLOCK_TOLERANCE_MS &&
                expiresAt - issuedAt <= (if (type == CommandTypes.WIPE) MAX_WIPE_VALIDITY_MS else MAX_VALIDITY_MS)
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
                        // "200 characters" = 200 UTF-16 units; no control character except the line feed (contract §8,
                        // checked here too: the server is not trusted).
                        if (prim.content.length > LOCK_MESSAGE_MAX) return null
                        // U+2028/U+2029 (line/paragraph separators) are refused like control characters (review of v1.1).
                        if (prim.content.any { (it.isISOControl() && it != '\n') || it == '\u2028' || it == '\u2029' }) return null
                        prim.content.trim().ifEmpty { null }
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
 * Nesting depth of a JSON text, measured without recursion BEFORE the text is given to the JSON parser.
 *
 * Everything the server sends on the command channel is parsed by kotlinx.serialization's tree reader, which
 * reads nested arrays recursively (`JsonTreeReader.readArray`) and only refuses them after several hundred
 * levels. Measured on the test JVM (1.13.0): 500 nested `[` are refused with a `JsonDecodingException` on a
 * 512 KiB stack but overflow a 256 KiB one. A `StackOverflowError` is not an `Exception`: it would end the
 * command worker or the channel loop until the service restarts. Rather than depend on the frame size of the
 * phone's runtime, the depth is bounded here first; nothing the contract defines nests deeper than 3 levels.
 */
internal object JsonNesting {
    /** `payload`: root → `params` → values. */
    const val MAX_PAYLOAD_DEPTH = 16

    /** Command object, or poll answer `{ "commands": [ { … } ] }` (payloads are strings: they add no depth). */
    const val MAX_ENVELOPE_DEPTH = 8

    /** True when [text] opens more than [max] objects or arrays inside one another (strings are skipped). */
    fun deeperThan(text: String, max: Int): Boolean {
        var depth = 0
        var inString = false
        var i = 0
        while (i < text.length) {
            val c = text[i]
            if (inString) {
                if (c == '\\') i++ else if (c == '"') inString = false
            } else {
                when (c) {
                    '"' -> inString = true
                    '{', '[' -> if (++depth > max) return true
                    '}', ']' -> depth--
                }
            }
            i++
        }
        return false
    }
}

/**
 * Detects an object with the same key twice anywhere in a JSON text that already parsed (the parser keeps
 * the last one silently; contract §8: a payload with a duplicate key is refused). Keys are compared once
 * their escapes are decoded (`"type"` and `"\u0074ype"` are the same key).
 *
 * The scan is recursive: nesting deeper than [MAX_DEPTH] counts as "found" (the verifier refuses such a
 * payload before, see [JsonNesting]).
 */
internal object JsonDuplicateKeys {
    const val MAX_DEPTH = JsonNesting.MAX_PAYLOAD_DEPTH

    fun found(text: String): Boolean = try {
        Scanner(text).value()
    } catch (_: Exception) {
        true // unreadable here although the parser accepted it, or nested too deep: refuse rather than guess
    }

    private class Scanner(private val s: String) {
        private var i = 0
        private var depth = 0

        private fun enter() {
            if (++depth > MAX_DEPTH) throw IllegalArgumentException("nested too deep")
        }

        private fun ws() {
            while (i < s.length && s[i].isWhitespace()) i++
        }

        /** Scans one value; true if a duplicate key was found in it. */
        fun value(): Boolean {
            ws()
            return when (s[i]) {
                '{' -> {
                    enter()
                    obj().also { depth-- }
                }
                '[' -> {
                    enter()
                    arr().also { depth-- }
                }
                '"' -> {
                    string()
                    false
                }
                else -> {
                    while (i < s.length && s[i] !in ",]} \t\r\n") i++
                    false
                }
            }
        }

        private fun obj(): Boolean {
            i++ // {
            val keys = HashSet<String>()
            ws()
            if (s[i] == '}') {
                i++
                return false
            }
            while (true) {
                ws()
                if (!keys.add(string())) return true
                ws()
                i++ // :
                if (value()) return true
                ws()
                if (s[i++] == '}') return false // else ','
            }
        }

        private fun arr(): Boolean {
            i++ // [
            ws()
            if (s[i] == ']') {
                i++
                return false
            }
            while (true) {
                if (value()) return true
                ws()
                if (s[i++] == ']') return false
            }
        }

        private fun string(): String {
            val out = StringBuilder()
            i++ // opening quote
            while (true) {
                val c = s[i++]
                when (c) {
                    '"' -> return out.toString()
                    '\\' -> {
                        when (val e = s[i++]) {
                            'u' -> {
                                out.append(s.substring(i, i + 4).toInt(16).toChar())
                                i += 4
                            }
                            'n' -> out.append('\n')
                            't' -> out.append('\t')
                            'r' -> out.append('\r')
                            'b' -> out.append('\b')
                            'f' -> out.append('\u000c')
                            else -> out.append(e)
                        }
                    }
                    else -> out.append(c)
                }
            }
        }
    }
}

/**
 * The conditions that must **all** hold for a factory reset (the only irreversible action of the app):
 * channel enabled, command passphrase set, valid signature, "Allow remote erase" on, command
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
