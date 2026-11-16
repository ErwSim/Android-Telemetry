package io.github.erwsim.watchpost.core.enroll

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.Signature
import java.security.cert.X509Certificate
import java.security.interfaces.ECKey
import java.security.interfaces.ECPublicKey

/** Raw `.watchpost` file (contract §4). */
@Serializable
internal data class EnrollmentFileJson(
    val version: Int? = null,
    @SerialName("ingest_url") val ingestUrl: String? = null,
    @SerialName("device_id") val deviceId: String? = null,
    @SerialName("device_name") val deviceName: String? = null,
    @SerialName("device_token") val deviceToken: String? = null,
    @SerialName("client_cert_pem") val clientCertPem: String? = null,
    @SerialName("client_key_pem") val clientKeyPem: String? = null,
    @SerialName("server_ca_pem") val serverCaPem: String? = null,
    @SerialName("private_dns_host") val privateDnsHost: String? = null,
)

enum class EnrollmentError {
    TOO_LARGE,
    NOT_JSON,
    UNSUPPORTED_VERSION,
    MISSING_FIELD,
    BAD_URL,
    INSECURE_URL,
    BAD_CLIENT_CERT,
    CLIENT_CERT_EXPIRED,
    BAD_CLIENT_KEY,
    KEY_NOT_P256,
    KEY_CERT_MISMATCH,
    BAD_SERVER_CA,
    BAD_DNS_HOST,
    BAD_TOKEN,
    BAD_DEVICE_ID,
}

class EnrollmentException(val error: EnrollmentError, val detail: String? = null) :
    Exception("${error.name}${detail?.let { ": $it" } ?: ""}")

/** Validated enrollment, still holding the private key in memory (until imported into the Keystore). */
class ParsedEnrollment(
    /** Validated `https` base URL. */
    val ingestUrl: String,
    val deviceId: String,
    val deviceName: String?,
    val deviceToken: String,
    val clientChain: List<X509Certificate>,
    val privateKey: PrivateKey,
    val serverCa: List<X509Certificate>,
    val privateDnsHost: String?,
    /** Non-blocking inconsistencies, shown to the user (e.g. CN different from device_id). */
    val warnings: List<String>,
)

object EnrollmentParser {
    const val MAX_FILE_BYTES = 256 * 1024
    private val json = Json { ignoreUnknownKeys = true }
    /** Visible ASCII without spaces, at most 512 characters (the collector's own limit). */
    private val TOKEN_REGEX = Regex("^[\\x21-\\x7e]{1,512}$")
    private val DEVICE_ID_REGEX = Regex("^[A-Za-z0-9._:-]{1,128}$")
    private val HOST_REGEX = Regex("^(?=.{1,253}$)([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\\.)+[a-zA-Z]{2,63}$")

    /** Parses and validates a `.watchpost` file. [nowMs] is used for the certificate expiry check. */
    fun parse(bytes: ByteArray, nowMs: Long = System.currentTimeMillis()): ParsedEnrollment {
        if (bytes.size > MAX_FILE_BYTES) throw EnrollmentException(EnrollmentError.TOO_LARGE)
        val raw = try {
            json.decodeFromString(EnrollmentFileJson.serializer(), bytes.toString(Charsets.UTF_8))
        } catch (e: SerializationException) {
            throw EnrollmentException(EnrollmentError.NOT_JSON, e.message)
        } catch (e: IllegalArgumentException) {
            throw EnrollmentException(EnrollmentError.NOT_JSON, e.message)
        }
        if (raw.version == null) throw EnrollmentException(EnrollmentError.MISSING_FIELD, "version")
        if (raw.version != 1) throw EnrollmentException(EnrollmentError.UNSUPPORTED_VERSION, raw.version.toString())

        val urlText = required(raw.ingestUrl, "ingest_url")
        val deviceId = required(raw.deviceId, "device_id")
        val token = required(raw.deviceToken, "device_token")
        // The token is sent in an HTTP header and the device id in every batch: only what can be sent.
        if (!TOKEN_REGEX.matches(token)) throw EnrollmentException(EnrollmentError.BAD_TOKEN)
        if (!DEVICE_ID_REGEX.matches(deviceId)) throw EnrollmentException(EnrollmentError.BAD_DEVICE_ID, deviceId.take(40))
        val certPem = required(raw.clientCertPem, "client_cert_pem")
        val keyPem = required(raw.clientKeyPem, "client_key_pem")

        val url = urlText.toHttpUrlOrNull() ?: throw EnrollmentException(EnrollmentError.BAD_URL, urlText)
        if (!url.isHttps) throw EnrollmentException(EnrollmentError.INSECURE_URL, urlText)
        if (url.query != null || url.fragment != null) throw EnrollmentException(EnrollmentError.BAD_URL, urlText)

        val chain = try {
            Pem.certificates(certPem)
        } catch (e: Exception) {
            throw EnrollmentException(EnrollmentError.BAD_CLIENT_CERT, e.message)
        }
        val leaf = chain.first()
        if (leaf.notAfter.time < nowMs) {
            throw EnrollmentException(EnrollmentError.CLIENT_CERT_EXPIRED, leaf.notAfter.toString())
        }

        val key = try {
            Pem.ecPrivateKey(keyPem)
        } catch (e: Exception) {
            throw EnrollmentException(EnrollmentError.BAD_CLIENT_KEY, e.message)
        }
        if ((key as? ECKey)?.params?.curve?.field?.fieldSize != 256) {
            throw EnrollmentException(EnrollmentError.KEY_NOT_P256)
        }
        val pub = leaf.publicKey as? ECPublicKey
            ?: throw EnrollmentException(EnrollmentError.KEY_CERT_MISMATCH, "certificate key is not EC")
        if (!keyMatches(key, leaf)) throw EnrollmentException(EnrollmentError.KEY_CERT_MISMATCH)
        check(pub.params.curve.field.fieldSize == 256)

        val ca = raw.serverCaPem?.takeIf { it.isNotBlank() }?.let {
            try {
                Pem.certificates(it)
            } catch (e: Exception) {
                throw EnrollmentException(EnrollmentError.BAD_SERVER_CA, e.message)
            }
        } ?: emptyList()

        val dnsHost = raw.privateDnsHost?.trim()?.takeIf { it.isNotEmpty() }
        if (dnsHost != null && !HOST_REGEX.matches(dnsHost)) {
            throw EnrollmentException(EnrollmentError.BAD_DNS_HOST, dnsHost)
        }

        val warnings = buildList {
            val cn = commonName(leaf)
            if (cn != deviceId) add("CN=$cn ≠ device_id=$deviceId")
            if (leaf.notBefore.time > nowMs) add("notBefore=${leaf.notBefore}")
        }

        return ParsedEnrollment(
            ingestUrl = url.toString(),
            deviceId = deviceId,
            deviceName = raw.deviceName?.takeIf { it.isNotBlank() },
            deviceToken = token,
            clientChain = chain,
            privateKey = key,
            serverCa = ca,
            privateDnsHost = dnsHost,
            warnings = warnings,
        )
    }

    private fun required(value: String?, name: String): String =
        value?.trim()?.takeIf { it.isNotEmpty() } ?: throw EnrollmentException(EnrollmentError.MISSING_FIELD, name)

    private fun keyMatches(key: PrivateKey, cert: X509Certificate): Boolean = try {
        val challenge = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val signature = Signature.getInstance("SHA256withECDSA").run {
            initSign(key)
            update(challenge)
            sign()
        }
        Signature.getInstance("SHA256withECDSA").run {
            initVerify(cert.publicKey)
            update(challenge)
            verify(signature)
        }
    } catch (_: Exception) {
        false
    }

    internal fun commonName(cert: X509Certificate): String? =
        Regex("(?:^|,)\\s*CN=([^,]+)").find(cert.subjectX500Principal.getName("RFC2253"))?.groupValues?.get(1)
}
