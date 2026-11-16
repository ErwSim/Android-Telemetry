package io.github.erwsim.vigie.core.command

import io.github.erwsim.vigie.core.event.AgentClock
import io.github.erwsim.vigie.core.event.Severity
import io.github.erwsim.vigie.core.sink.EventSink
import io.github.erwsim.vigie.core.sink.emit
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/**
 * Handles every command delivered by the channel, one at a time:
 * verification ([CommandVerifier]) → execution (one [CommandExecutor] per type) → `command.result`
 * event (contract §8) → local history → result queued for `POST …/result`.
 *
 * A command whose result is still waiting to be acknowledged by the server is a redelivery (stream
 * and poll can both deliver it): it is skipped silently, the queued result answers it.
 *
 * `wipe`: the event is emitted and the result queued **before** the reset, then [Hooks.beforeIrreversible]
 * tries to send them (10 s at most), then the executor runs. Executors never see a refused command.
 */
class CommandProcessor(
    private val clock: AgentClock,
    private val verifier: CommandVerifier,
    private val state: CommandStateStore,
    private val sink: EventSink,
    private val environment: () -> CommandVerifier.Environment,
    private val executors: () -> Map<String, CommandExecutor>,
    private val hooks: Hooks,
) {
    interface Hooks {
        /** Flushes the events and tries to upload them and the pending results, for at most [timeoutMs]. */
        suspend fun beforeIrreversible(timeoutMs: Long)

        /** After each processed command (visible notification, result flush). */
        fun onProcessed(entry: CommandHistoryEntry) = Unit
    }

    private val mutex = Mutex()

    /** Parses one command object (`{ "id", "payload", "sig" }`); null when it is not one. */
    fun parseEnvelope(element: JsonElement): CommandEnvelope? {
        val o = element as? JsonObject ?: return null
        val id = (o["id"] as? JsonPrimitive)?.takeIf { it.isString }?.content ?: return null
        val payload = (o["payload"] as? JsonPrimitive)?.takeIf { it.isString }?.content ?: return null
        val sig = when (val s = o["sig"]) {
            null -> null
            is JsonPrimitive -> if (s.isString) s.content else return null
            else -> return null
        }
        return CommandEnvelope(id, payload, sig)
    }

    /** A delivery that is not even a command object: traced (`malformed`), nothing posted (no usable id). */
    suspend fun processUnreadable(): CommandHistoryEntry = mutex.withLock {
        finish(CommandVerifier.INVALID_ID, CommandTypes.UNKNOWN, ExecutionResult.refused(Refusal.MALFORMED), signed = false)
    }

    /** Returns the history entry, or null for a redelivery skipped because its result is still pending. */
    suspend fun process(envelope: CommandEnvelope): CommandHistoryEntry? = mutex.withLock {
        if (CommandVerifier.ULID.matches(envelope.id) && state.hasPendingResult(envelope.id)) return@withLock null
        when (val v = verifier.verify(envelope, environment())) {
            is CommandVerifier.Verification.Refused -> finish(v.id, v.type, ExecutionResult.refused(v.reason), v.signed)
            is CommandVerifier.Verification.Accepted -> execute(v.command)
        }
    }

    private suspend fun execute(command: AcceptedCommand): CommandHistoryEntry {
        val executor = executors()[command.type]
            ?: return finish(command.id, command.type, ExecutionResult.failed("unsupported"), command.signatureVerified)
        if (command.type == CommandTypes.WIPE) {
            // Announced as executed first: once the reset starts, nothing more can be sent.
            val announced = finish(command.id, command.type, ExecutionResult.executed(), command.signatureVerified)
            safely { hooks.beforeIrreversible(WIPE_UPLOAD_BUDGET_MS) }
            val result = run(executor, command)
            // Only reached if the reset did not happen (refused by the platform, or the gate said no).
            return if (result.status == CommandStatus.EXECUTED) announced else finish(command.id, command.type, result, command.signatureVerified)
        }
        return finish(command.id, command.type, run(executor, command), command.signatureVerified)
    }

    private suspend fun run(executor: CommandExecutor, command: AcceptedCommand): ExecutionResult = try {
        executor.execute(command)
    } catch (e: CancellationException) {
        throw e
    } catch (e: Exception) {
        ExecutionResult.failed("error_${e.javaClass.simpleName}".take(80))
    }

    private suspend inline fun safely(block: () -> Unit) {
        try {
            block()
        } catch (e: CancellationException) {
            throw e
        } catch (_: Exception) {
            // Best effort: the reset must not depend on the network.
        }
    }

    private fun finish(id: String, type: String, result: ExecutionResult, signed: Boolean): CommandHistoryEntry {
        val now = clock.nowMillis()
        sink.emit(EVENT_TYPE, severity(type, result)) {
            put("command_id", id)
            put("type", type)
            put("status", result.status.wire)
            put("detail", result.detail)
            put("signed", signed)
        }
        val entry = CommandHistoryEntry(id, type, result.status.wire, result.detail, signed, now)
        state.addHistory(entry)
        if (id != CommandVerifier.INVALID_ID) state.addPendingResult(PendingResult(id, result.status.wire, result.detail, now))
        try {
            hooks.onProcessed(entry)
        } catch (_: Exception) {
            // Display only.
        }
        return entry
    }

    companion object {
        const val EVENT_TYPE = "command.result"
        const val WIPE_UPLOAD_BUDGET_MS = 10_000L

        /**
         * Contract §8: 0 simple command executed, 2 `lock`/`wipe` executed, 3 `bad_signature` and `locked_out`,
         * 1 other refusals. Not fixed by the contract: `clear_lock_message` executed and every `failed` → 1.
         */
        fun severity(type: String, result: ExecutionResult): Int = when (result.status) {
            CommandStatus.EXECUTED -> when (type) {
                CommandTypes.LOCK, CommandTypes.WIPE -> Severity.WARNING
                CommandTypes.CLEAR_LOCK_MESSAGE -> Severity.NOTABLE
                else -> Severity.INFO
            }
            CommandStatus.REFUSED ->
                if (result.detail == Refusal.BAD_SIGNATURE || result.detail == Refusal.LOCKED_OUT) Severity.CRITICAL else Severity.NOTABLE
            CommandStatus.FAILED -> Severity.NOTABLE
        }
    }
}
