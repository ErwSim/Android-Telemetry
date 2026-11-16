package io.github.erwsim.watchpost.notifier.protocol

import io.github.erwsim.watchpost.notifier.protocol.NotifierProtocol as P

/**
 * The notification settings, owned by the agent (collector `notifications`) and read by the
 * companion, which applies them BEFORE anything crosses the channel.
 *
 * [CLOSED] is what the companion assumes while it has not read the agent's settings: nothing is
 * relayed, and content would be off anyway.
 */
data class NotifierConfig(
    /** The agent runs and the `notifications` collector is enabled. */
    val accepting: Boolean,
    /** "Notification content" (off by default): title and text are relayed. */
    val contentEnabled: Boolean,
    /** Masking of 4-to-8-digit codes (on by default). */
    val redactCodes: Boolean,
    /** Apps whose title and text are never relayed. */
    val contentExcluded: Set<String>,
    /** Apps never reported at all. */
    val ignored: Set<String>,
) {
    /** Stable fingerprint of the settings (FNV-1a 64 of a canonical form): tells the companion to read them again. */
    val version: Long = fnv1a64(
        buildString {
            append(accepting).append('|').append(contentEnabled).append('|').append(redactCodes).append('|')
            contentExcluded.sorted().joinTo(this, ",")
            append('|')
            ignored.sorted().joinTo(this, ",")
        },
    )

    fun allowsContent(packageName: String): Boolean = contentEnabled && packageName !in contentExcluded

    fun toValues(): Map<String, Any?> = mapOf(
        P.KEY_PROTOCOL to P.VERSION,
        P.KEY_STATUS to P.STATUS_OK,
        P.KEY_ACCEPTING to accepting,
        P.KEY_CONTENT to contentEnabled,
        P.KEY_REDACT to redactCodes,
        P.KEY_CONTENT_EXCLUDED to contentExcluded.sorted(),
        P.KEY_IGNORED to ignored.sorted(),
        P.KEY_CONFIG_VERSION to version,
    )

    companion object {
        val CLOSED = NotifierConfig(
            accepting = false,
            contentEnabled = false,
            redactCodes = true,
            contentExcluded = emptySet(),
            ignored = emptySet(),
        )

        /**
         * Reads the agent's answer. Anything missing or malformed falls back to the safe side:
         * not accepting, content off, masking on.
         */
        fun fromValues(r: ValueReader): NotifierConfig? {
            if (r.int(P.KEY_PROTOCOL) != P.VERSION || r.string(P.KEY_STATUS) != P.STATUS_OK) return null
            return NotifierConfig(
                accepting = r.bool(P.KEY_ACCEPTING) == true,
                contentEnabled = r.bool(P.KEY_CONTENT) == true,
                redactCodes = r.bool(P.KEY_REDACT) != false,
                contentExcluded = PackageLists.parse(r.strings(P.KEY_CONTENT_EXCLUDED).orEmpty()).packages.toSet(),
                ignored = PackageLists.parse(r.strings(P.KEY_IGNORED).orEmpty()).packages.toSet(),
            )
        }

        fun fnv1a64(s: String): Long {
            var h = -0x340d631b7bdddcdbL // 0xcbf29ce484222325
            for (byte in s.toByteArray(Charsets.UTF_8)) {
                h = h xor (byte.toLong() and 0xff)
                h *= 0x100000001b3L
            }
            return h
        }
    }
}
