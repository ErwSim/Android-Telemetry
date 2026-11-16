package io.github.erwsim.vigie.core.command

import java.security.MessageDigest
import java.util.Base64
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Contract §8 cryptography:
 * `K = PBKDF2-HMAC-SHA256(code, salt = "vigie-cmd-v1:" + device_id, 600 000 iterations, 32 bytes)` and
 * `sig = base64(HMAC-SHA256(K, UTF-8 bytes of payload))`.
 *
 * PBKDF2 is written out on top of `Mac("HmacSHA256")` instead of `SecretKeyFactory("PBKDF2WithHmacSHA256")`:
 * the password encoding of the providers differs (UTF-8, ASCII-only or "8 bit" depending on provider and
 * Android version), while WebCrypto in the console uses the UTF-8 bytes of the code. Here the code is
 * always encoded in UTF-8, without Unicode normalisation (TextEncoder does none either).
 */
object CommandCrypto {
    const val ITERATIONS = 600_000
    const val KEY_BYTES = 32
    const val SALT_PREFIX = "vigie-cmd-v1:"
    private const val HMAC = "HmacSHA256"

    /** Minimum length of the command code, in Unicode code points (as the console counts it). */
    const val MIN_CODE_CODE_POINTS = 12

    fun codeLength(code: String): Int = code.codePointCount(0, code.length)

    /** K for this device. Slow on purpose (about a second on a phone): never on the main thread. */
    fun deriveKey(code: String, deviceId: String, iterations: Int = ITERATIONS): ByteArray {
        val password = code.toByteArray(Charsets.UTF_8)
        try {
            return pbkdf2HmacSha256(password, (SALT_PREFIX + deviceId).toByteArray(Charsets.UTF_8), iterations, KEY_BYTES)
        } finally {
            password.fill(0)
        }
    }

    /** RFC 8018 §5.2 with HMAC-SHA256. */
    fun pbkdf2HmacSha256(password: ByteArray, salt: ByteArray, iterations: Int, length: Int): ByteArray {
        require(iterations >= 1 && length >= 1)
        val mac = Mac.getInstance(HMAC)
        // An empty password is a valid PBKDF2 input but not a valid SecretKeySpec: never used here (12+ characters).
        mac.init(SecretKeySpec(password, HMAC))
        val hLen = mac.macLength
        val blocks = (length + hLen - 1) / hLen
        val out = ByteArray(length)
        val u = ByteArray(hLen)
        val t = ByteArray(hLen)
        for (i in 1..blocks) {
            mac.update(salt)
            mac.update(byteArrayOf((i ushr 24).toByte(), (i ushr 16).toByte(), (i ushr 8).toByte(), i.toByte()))
            mac.doFinal(u, 0)
            u.copyInto(t)
            repeat(iterations - 1) {
                mac.update(u)
                mac.doFinal(u, 0)
                for (j in 0 until hLen) t[j] = (t[j].toInt() xor u[j].toInt()).toByte()
            }
            val offset = (i - 1) * hLen
            t.copyInto(out, offset, 0, minOf(hLen, length - offset))
        }
        u.fill(0)
        t.fill(0)
        return out
    }

    fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray {
        val mac = Mac.getInstance(HMAC)
        mac.init(SecretKeySpec(key, HMAC))
        return mac.doFinal(data)
    }

    fun sign(key: ByteArray, payload: String): String =
        Base64.getEncoder().encodeToString(hmacSha256(key, payload.toByteArray(Charsets.UTF_8)))

    /**
     * Verifies `sig` over the exact UTF-8 bytes of [payload], before anything of the payload is read.
     * The comparison is constant-time ([MessageDigest.isEqual]); an absent, non-base64 or wrong-length
     * signature is simply invalid.
     */
    fun verify(key: ByteArray, payload: String, sig: String?): Boolean {
        if (sig == null || sig.length > 128) return false
        val given = try {
            Base64.getDecoder().decode(sig.trim())
        } catch (_: IllegalArgumentException) {
            return false
        }
        val expected = hmacSha256(key, payload.toByteArray(Charsets.UTF_8))
        // isEqual is constant-time for equal lengths; a length mismatch reveals only the (public) length.
        return given.size == expected.size && MessageDigest.isEqual(expected, given)
    }
}
