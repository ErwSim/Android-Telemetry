package io.github.erwsim.vigie.core.event

import java.security.SecureRandom

/**
 * Monotonic ULID generator (26 Crockford base32 characters: 48-bit milliseconds + 80 random bits).
 * Within the same millisecond the random part is incremented so ids stay strictly ordered.
 */
class UlidGenerator(private val random: SecureRandom = SecureRandom()) {
    private var lastMs = -1L
    private val lastRandom = ByteArray(10)

    @Synchronized
    fun next(timeMs: Long): String {
        require(timeMs in 0..MAX_TIME) { "timestamp out of ULID range" }
        if (timeMs <= lastMs) {
            // Same (or earlier, after a clock step back) millisecond: keep ordering by incrementing.
            if (!increment(lastRandom)) {
                lastMs += 1
                random.nextBytes(lastRandom)
            }
        } else {
            lastMs = timeMs
            random.nextBytes(lastRandom)
        }
        return encode(lastMs, lastRandom)
    }

    private fun increment(bytes: ByteArray): Boolean {
        for (i in bytes.indices.reversed()) {
            val v = (bytes[i].toInt() and 0xFF) + 1
            bytes[i] = v.toByte()
            if (v <= 0xFF) return true
        }
        return false // overflow of 80 bits: astronomically unlikely
    }

    companion object {
        private const val ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
        private const val MAX_TIME = (1L shl 48) - 1
        private val ULID_REGEX = Regex("^[0-7][0-9A-HJKMNP-TV-Z]{25}$")

        fun isValid(s: String): Boolean = ULID_REGEX.matches(s)

        internal fun encode(timeMs: Long, randomBytes: ByteArray): String {
            val out = CharArray(26)
            var t = timeMs
            for (i in 9 downTo 0) {
                out[i] = ALPHABET[(t and 31).toInt()]
                t = t ushr 5
            }
            // 80 random bits → 16 characters.
            var bitBuffer = 0L
            var bitCount = 0
            var pos = 10
            for (b in randomBytes) {
                bitBuffer = (bitBuffer shl 8) or (b.toLong() and 0xFF)
                bitCount += 8
                while (bitCount >= 5) {
                    bitCount -= 5
                    out[pos++] = ALPHABET[((bitBuffer ushr bitCount) and 31).toInt()]
                }
            }
            return String(out)
        }
    }
}
