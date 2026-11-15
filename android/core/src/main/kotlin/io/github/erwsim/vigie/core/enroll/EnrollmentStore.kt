package io.github.erwsim.vigie.core.enroll

import android.annotation.SuppressLint
import android.content.SharedPreferences
import java.util.Base64

/** Non-secret part of the enrollment, persisted in clear. */
data class Enrollment(
    val ingestUrl: String,
    val deviceId: String,
    val deviceName: String?,
    val serverCaPem: String?,
    val privateDnsHost: String?,
    val enrolledAtMs: Long,
    val certNotAfterMs: Long,
)

/**
 * Persists the enrollment. The device token is stored only sealed by [SecretBox]
 * (Keystore AES-GCM key on the device); the client key lives in [ClientCredentialStore].
 */
@SuppressLint("ApplySharedPref") // commit(): enrollment changes are synchronous and rare.
class EnrollmentStore(
    private val prefs: SharedPreferences,
    private val secretBox: SecretBox,
) {
    @Volatile
    private var cachedToken: String? = null

    fun load(): Enrollment? {
        val url = prefs.getString(K_URL, null) ?: return null
        val deviceId = prefs.getString(K_DEVICE_ID, null) ?: return null
        return Enrollment(
            ingestUrl = url,
            deviceId = deviceId,
            deviceName = prefs.getString(K_DEVICE_NAME, null),
            serverCaPem = prefs.getString(K_SERVER_CA, null),
            privateDnsHost = prefs.getString(K_DNS_HOST, null),
            enrolledAtMs = prefs.getLong(K_ENROLLED_AT, 0),
            certNotAfterMs = prefs.getLong(K_CERT_NOT_AFTER, 0),
        )
    }

    fun token(): String? {
        cachedToken?.let { return it }
        val sealed = prefs.getString(K_TOKEN, null) ?: return null
        return try {
            String(secretBox.open(Base64.getDecoder().decode(sealed)), Charsets.UTF_8).also { cachedToken = it }
        } catch (_: Exception) {
            null
        }
    }

    fun save(enrollment: Enrollment, token: String) {
        val sealed = Base64.getEncoder().encodeToString(secretBox.seal(token.toByteArray(Charsets.UTF_8)))
        prefs.edit()
            .putString(K_URL, enrollment.ingestUrl)
            .putString(K_DEVICE_ID, enrollment.deviceId)
            .putString(K_DEVICE_NAME, enrollment.deviceName)
            .putString(K_SERVER_CA, enrollment.serverCaPem)
            .putString(K_DNS_HOST, enrollment.privateDnsHost)
            .putLong(K_ENROLLED_AT, enrollment.enrolledAtMs)
            .putLong(K_CERT_NOT_AFTER, enrollment.certNotAfterMs)
            .putString(K_TOKEN, sealed)
            .commit()
        cachedToken = token
    }

    fun clear() {
        prefs.edit().clear().commit()
        cachedToken = null
        try {
            secretBox.destroy()
        } catch (_: Exception) {
            // Key already gone: nothing to protect anymore.
        }
    }

    private companion object {
        const val K_URL = "ingest_url"
        const val K_DEVICE_ID = "device_id"
        const val K_DEVICE_NAME = "device_name"
        const val K_SERVER_CA = "server_ca_pem"
        const val K_DNS_HOST = "private_dns_host"
        const val K_ENROLLED_AT = "enrolled_at_ms"
        const val K_CERT_NOT_AFTER = "cert_not_after_ms"
        const val K_TOKEN = "device_token_sealed"
    }
}
