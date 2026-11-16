package io.github.erwsim.watchpost.core.command

/**
 * Remote commands, contract §8: a **closed** list. Anything else is refused, never interpreted.
 * Nothing in a command can change a setting, the policy or the enrollment: the types below are the
 * only effects a command can have.
 */
object CommandTypes {
    const val RING = "ring"
    const val VIBRATE = "vibrate"
    const val STOP_RING = "stop_ring"
    const val LOCATE = "locate"
    const val LOCK = "lock"
    const val CLEAR_LOCK_MESSAGE = "clear_lock_message"
    const val WIPE = "wipe"

    val ALL: Set<String> = setOf(RING, VIBRATE, STOP_RING, LOCATE, LOCK, CLEAR_LOCK_MESSAGE, WIPE)

    /** Signed with the user's command passphrase (HMAC), verified before the content is read. */
    val SENSITIVE: Set<String> = setOf(LOCK, CLEAR_LOCK_MESSAGE, WIPE)

    /** Executed only by the Device Owner (`not_device_owner` otherwise). */
    val DEVICE_OWNER: Set<String> = setOf(LOCK, CLEAR_LOCK_MESSAGE, WIPE)

    /** `command.result.type` for a payload whose type is unreadable or not in the list. */
    const val UNKNOWN = "unknown"

    fun isSensitive(type: String) = type in SENSITIVE
}

/** Refusal reasons of contract §8 (`command.result.detail` when `status = refused`). */
object Refusal {
    const val DISABLED = "disabled"
    const val MALFORMED = "malformed"
    const val WRONG_DEVICE = "wrong_device"
    const val UNKNOWN_TYPE = "unknown_type"
    const val NO_CODE_CONFIGURED = "no_code_configured"
    const val BAD_SIGNATURE = "bad_signature"
    const val EXPIRED = "expired"
    const val REPLAY = "replay"
    const val BAD_PARAMS = "bad_params"
    const val NOT_DEVICE_OWNER = "not_device_owner"
    const val LOCKED_OUT = "locked_out"
}

enum class CommandStatus(val wire: String) {
    EXECUTED("executed"),
    FAILED("failed"),
    REFUSED("refused"),
    ;

    companion object {
        fun fromWire(s: String?): CommandStatus? = entries.firstOrNull { it.wire == s }
    }
}

/** What arrives from the server (stream or poll): `{ "id", "payload", "sig" }`. */
data class CommandEnvelope(val id: String, val payload: String, val sig: String?)

/** Validated parameters: only these fields can reach an executor. */
sealed class CommandParams {
    data object None : CommandParams()
    data class Ring(val durationS: Int, val vibrate: Boolean) : CommandParams()
    data class Vibrate(val durationS: Int) : CommandParams()
    data class Lock(val message: String?) : CommandParams()
}

/**
 * A command that passed every check of contract §8. Only [CommandVerifier] creates one (internal
 * constructor): an executor in another module cannot fabricate an accepted command.
 */
class AcceptedCommand internal constructor(
    val id: String,
    val type: String,
    val params: CommandParams,
    val issuedAtMs: Long,
    val expiresAtMs: Long,
    /** The HMAC of the payload was verified with the user's key (always true for a sensitive type). */
    val signatureVerified: Boolean,
    /** Conditions observed by the verifier; the wipe executor checks them again (see [WipeGate]). */
    val gate: WipeGate.Conditions,
) {
    override fun toString() = "AcceptedCommand($id, $type, $params)"
}

/** Outcome of an executor. [detail] is a short ASCII code (`ok`, `no_fix`…), never free text from the payload. */
data class ExecutionResult(val status: CommandStatus, val detail: String) {
    companion object {
        fun executed(detail: String = "ok") = ExecutionResult(CommandStatus.EXECUTED, detail)
        fun failed(detail: String) = ExecutionResult(CommandStatus.FAILED, detail)
        fun refused(reason: String) = ExecutionResult(CommandStatus.REFUSED, reason)
    }
}

/** Executes one accepted command type. Implementations live in `:app` (ring, vibrate), `:core` (locate), `:policy` (lock, wipe). */
fun interface CommandExecutor {
    suspend fun execute(command: AcceptedCommand): ExecutionResult
}
