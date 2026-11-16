package io.github.erwsim.vigie.core.command

import android.annotation.SuppressLint
import android.content.SharedPreferences
import io.github.erwsim.vigie.core.enroll.SecretBox
import io.github.erwsim.vigie.core.event.VigieJson
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ListSerializer
import java.util.Base64

/**
 * The command key `K` (contract §8), sealed at rest by [SecretBox] (AES-GCM, non-exportable Keystore
 * key on the device). The command code itself is never stored: only `K`, derived from it and from the
 * device id. `K` is bound to the device id it was derived for: after an enrollment under another id it
 * no longer counts as configured (`no_code_configured`) and must be entered again.
 */
@SuppressLint("ApplySharedPref") // commit(): the key must be on disk before the app says it is set.
class CommandKeyStore(private val prefs: SharedPreferences, private val box: SecretBox) {
    private val _configuredFor = MutableStateFlow(prefs.getString(K_DEVICE, null))

    /** Device id the stored key was derived for, null when no code is set. */
    val configuredFor: StateFlow<String?> = _configuredFor.asStateFlow()

    fun isConfigured(deviceId: String?): Boolean = deviceId != null && _configuredFor.value == deviceId && prefs.contains(K_KEY)

    /** The key for [deviceId], or null if none (or bound to another id, or unreadable). Caller zeroes it after use. */
    fun key(deviceId: String): ByteArray? {
        if (!isConfigured(deviceId)) return null
        val sealed = prefs.getString(K_KEY, null) ?: return null
        return try {
            box.open(Base64.getDecoder().decode(sealed))
        } catch (_: Exception) {
            null
        }
    }

    /** Stores an already derived key (see [CommandCrypto.deriveKey]); [key] is zeroed. */
    fun save(deviceId: String, key: ByteArray, nowMs: Long) {
        try {
            val sealed = Base64.getEncoder().encodeToString(box.seal(key))
            prefs.edit().putString(K_KEY, sealed).putString(K_DEVICE, deviceId).putLong(K_SET_AT, nowMs).commit()
            _configuredFor.value = deviceId
        } finally {
            key.fill(0)
        }
    }

    fun setAtMs(): Long = prefs.getLong(K_SET_AT, 0)

    fun clear() {
        prefs.edit().remove(K_KEY).remove(K_DEVICE).remove(K_SET_AT).commit()
        _configuredFor.value = null
        try {
            box.destroy()
        } catch (_: Exception) {
            // Nothing left to protect.
        }
    }

    private companion object {
        const val K_KEY = "key_sealed"
        const val K_DEVICE = "key_device_id"
        const val K_SET_AT = "key_set_at_ms"
    }
}

/** One line of the local history shown in the app. */
@Serializable
data class CommandHistoryEntry(
    val id: String,
    val type: String,
    val status: String,
    val detail: String,
    val signed: Boolean,
    @SerialName("at_ms") val atMs: Long,
)

/** A result waiting to be posted to `POST /api/v1/commands/{id}/result`. */
@Serializable
data class PendingResult(
    val id: String,
    val status: String,
    val detail: String,
    @SerialName("at_ms") val atMs: Long,
    val attempts: Int = 0,
)

/**
 * Persistent state of the command channel (SharedPreferences, written with `commit()` so that what
 * guards an execution is on disk before the execution):
 * - two anti-replay windows of [REPLAY_WINDOW] ids each, one for commands whose signature was verified
 *   and one for simple commands: unsigned traffic (which a compromised server can generate at will)
 *   can never push a signed id out of its window;
 * - the recent `bad_signature` times and the lock-out deadline;
 * - the local history and the results not yet acknowledged by the server.
 */
@SuppressLint("ApplySharedPref")
class CommandStateStore(private val prefs: SharedPreferences) {
    private val lock = Any()
    private val _history = MutableStateFlow(readHistory())
    val history: StateFlow<List<CommandHistoryEntry>> = _history.asStateFlow()

    /**
     * Records [id] as seen. Returns false if it was already in its window (replay). Check and insert are
     * atomic and persisted before returning.
     */
    fun markSeen(id: String, signed: Boolean): Boolean = synchronized(lock) {
        val key = if (signed) K_SEEN_SIGNED else K_SEEN_SIMPLE
        val seen = ids(key)
        // Both windows are checked: an id first seen unsigned and replayed signed (or the reverse) is a replay too.
        if (id in seen || id in ids(if (signed) K_SEEN_SIMPLE else K_SEEN_SIGNED)) return false
        seen += id
        while (seen.size > REPLAY_WINDOW) seen.removeAt(0)
        prefs.edit().putString(key, seen.joinToString(",")).commit()
        true
    }

    fun wasSeen(id: String): Boolean = synchronized(lock) { id in ids(K_SEEN_SIGNED) || id in ids(K_SEEN_SIMPLE) }

    private fun ids(key: String): MutableList<String> =
        prefs.getString(key, null)?.split(',')?.filter { it.isNotEmpty() }?.toMutableList() ?: ArrayList()

    /** Lock-out deadline (wall clock ms) or 0. A deadline more than [LOCKOUT_MS] ahead (clock moved back) is capped. */
    fun lockedOutUntil(nowMs: Long): Long = synchronized(lock) {
        val until = prefs.getLong(K_LOCKED_UNTIL, 0)
        if (until <= nowMs) 0 else minOf(until, nowMs + LOCKOUT_MS)
    }

    /** Counts a `bad_signature`; returns true when this one starts a lock-out (5 within an hour). */
    fun recordBadSignature(nowMs: Long): Boolean = synchronized(lock) {
        val recent = (prefs.getString(K_BAD_SIGS, null)?.split(',')?.mapNotNull { it.toLongOrNull() } ?: emptyList())
            .filter { it in (nowMs - BAD_SIG_WINDOW_MS)..nowMs } + nowMs
        return if (recent.size >= MAX_BAD_SIGNATURES) {
            prefs.edit().putLong(K_LOCKED_UNTIL, nowMs + LOCKOUT_MS).remove(K_BAD_SIGS).commit()
            true
        } else {
            prefs.edit().putString(K_BAD_SIGS, recent.joinToString(",")).commit()
            false
        }
    }

    fun addHistory(entry: CommandHistoryEntry) = synchronized(lock) {
        val list = (listOf(entry) + _history.value).take(HISTORY_SIZE)
        prefs.edit().putString(K_HISTORY, VigieJson.encodeToString(ListSerializer(CommandHistoryEntry.serializer()), list)).commit()
        _history.value = list
    }

    private fun readHistory(): List<CommandHistoryEntry> = try {
        prefs.getString(K_HISTORY, null)?.let { VigieJson.decodeFromString(ListSerializer(CommandHistoryEntry.serializer()), it) } ?: emptyList()
    } catch (_: Exception) {
        emptyList()
    }

    fun pendingResults(): List<PendingResult> = synchronized(lock) {
        try {
            prefs.getString(K_RESULTS, null)?.let { VigieJson.decodeFromString(ListSerializer(PendingResult.serializer()), it) } ?: emptyList()
        } catch (_: Exception) {
            emptyList()
        }
    }

    fun hasPendingResult(id: String): Boolean = pendingResults().any { it.id == id }

    fun addPendingResult(result: PendingResult) = synchronized(lock) {
        // A later result of the same command (wipe announced then failed) replaces the earlier one.
        writeResults((pendingResults().filter { it.id != result.id } + result).takeLast(MAX_PENDING_RESULTS))
    }

    fun removePendingResult(id: String) = synchronized(lock) { writeResults(pendingResults().filter { it.id != id }) }

    fun bumpAttempts(id: String) = synchronized(lock) {
        writeResults(pendingResults().map { if (it.id == id) it.copy(attempts = it.attempts + 1) else it })
    }

    private fun writeResults(list: List<PendingResult>) {
        prefs.edit().putString(K_RESULTS, VigieJson.encodeToString(ListSerializer(PendingResult.serializer()), list)).commit()
    }

    companion object {
        const val REPLAY_WINDOW = 500
        const val MAX_BAD_SIGNATURES = 5
        const val BAD_SIG_WINDOW_MS = 3_600_000L
        const val LOCKOUT_MS = 3_600_000L
        const val HISTORY_SIZE = 50
        const val MAX_PENDING_RESULTS = 100
        private const val K_SEEN_SIGNED = "seen_signed"
        private const val K_SEEN_SIMPLE = "seen_simple"
        private const val K_BAD_SIGS = "bad_signature_times"
        private const val K_LOCKED_UNTIL = "locked_out_until_ms"
        private const val K_HISTORY = "history"
        private const val K_RESULTS = "pending_results"
    }
}
