package io.github.erwsim.vigie.core.enroll

import io.github.erwsim.vigie.core.testing.FakeClock
import io.github.erwsim.vigie.core.testing.MemoryPrefs
import io.github.erwsim.vigie.core.upload.IngestHttp
import io.github.erwsim.vigie.core.upload.IngestTarget
import io.github.erwsim.vigie.core.upload.PingResult
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import mockwebserver3.MockResponse
import mockwebserver3.MockWebServer
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.tls.HandshakeCertificates
import okhttp3.tls.HeldCertificate
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.util.concurrent.TimeUnit

/** Contract §4: parsing and validation of `.vigie` files, Keystore import abstraction, mTLS. */
class EnrollmentTest {
    private val clientCa = HeldCertificate.Builder().commonName("Vigie client CA").certificateAuthority(0).build()
    private val clientCert = HeldCertificate.Builder()
        .commonName("dev_8f3a")
        .ecdsa256()
        .signedBy(clientCa)
        .build()
    private val serverCa = HeldCertificate.Builder().commonName("Vigie server CA").certificateAuthority(0).build()
    private val now = System.currentTimeMillis()
    private val servers = ArrayList<MockWebServer>()

    @After
    fun tearDown() {
        servers.forEach { it.close() }
    }

    private fun file(
        version: Any? = 1,
        url: String? = "https://ingest.exemple.fr",
        deviceId: String? = "dev_8f3a",
        token: String? = "tok-123",
        certPem: String? = clientCert.certificatePem(),
        keyPem: String? = clientCert.privateKeyPkcs8Pem(),
        caPem: String? = null,
        dns: String? = "dns.exemple.fr",
    ): ByteArray {
        val map = linkedMapOf<String, kotlinx.serialization.json.JsonElement>()
        version?.let { map["version"] = if (it is Int) JsonPrimitive(it) else JsonPrimitive(it.toString()) }
        url?.let { map["ingest_url"] = JsonPrimitive(it) }
        deviceId?.let { map["device_id"] = JsonPrimitive(it) }
        map["device_name"] = JsonPrimitive("s25")
        token?.let { map["device_token"] = JsonPrimitive(it) }
        certPem?.let { map["client_cert_pem"] = JsonPrimitive(it) }
        keyPem?.let { map["client_key_pem"] = JsonPrimitive(it) }
        caPem?.let { map["server_ca_pem"] = JsonPrimitive(it) }
        dns?.let { map["private_dns_host"] = JsonPrimitive(it) }
        map["future_field"] = JsonPrimitive("ignored")
        return JsonObject(map).toString().toByteArray()
    }

    private fun expectError(expected: EnrollmentError, bytes: ByteArray) {
        try {
            EnrollmentParser.parse(bytes, now)
            fail("expected $expected")
        } catch (e: EnrollmentException) {
            assertEquals(expected, e.error)
        }
    }

    @Test
    fun aTokenOrDeviceIdThatCannotBeSentIsRefusedAtImport() {
        // The token goes into an HTTP header, the device id into every batch: a value OkHttp would
        // refuse to send must be rejected when the file is read, not at every upload.
        expectError(EnrollmentError.BAD_TOKEN, file(token = "tok\nInjected: 1"))
        expectError(EnrollmentError.BAD_TOKEN, file(token = "tok é"))
        expectError(EnrollmentError.BAD_TOKEN, file(token = "x".repeat(513)))
        expectError(EnrollmentError.BAD_DEVICE_ID, file(deviceId = "dev\u0000x"))
        expectError(EnrollmentError.BAD_DEVICE_ID, file(deviceId = "d".repeat(200)))
        // What the collector really issues (base64url token, dev_<hex>) passes.
        EnrollmentParser.parse(file(token = "Zm9vYmFyLV9hYmM", deviceId = "dev_8f3a"), now)
    }

    @Test
    fun parsesAValidFile() {
        val parsed = EnrollmentParser.parse(file(caPem = serverCa.certificatePem()), now)
        assertEquals("https://ingest.exemple.fr/", parsed.ingestUrl)
        assertEquals("dev_8f3a", parsed.deviceId)
        assertEquals("s25", parsed.deviceName)
        assertEquals("tok-123", parsed.deviceToken)
        assertEquals(clientCert.certificate, parsed.clientChain.single())
        assertEquals(serverCa.certificate, parsed.serverCa.single())
        assertEquals("dns.exemple.fr", parsed.privateDnsHost)
        assertTrue(parsed.warnings.isEmpty())
    }

    @Test
    fun serverCaIsOptional() {
        val parsed = EnrollmentParser.parse(file(caPem = null, dns = null), now)
        assertTrue(parsed.serverCa.isEmpty())
        assertNull(parsed.privateDnsHost)
    }

    @Test
    fun rejectsMalformedFiles() {
        expectError(EnrollmentError.NOT_JSON, "not json".toByteArray())
        expectError(EnrollmentError.NOT_JSON, "[1,2]".toByteArray())
        expectError(EnrollmentError.TOO_LARGE, ByteArray(EnrollmentParser.MAX_FILE_BYTES + 1) { ' '.code.toByte() })
        expectError(EnrollmentError.MISSING_FIELD, file(version = null))
        expectError(EnrollmentError.UNSUPPORTED_VERSION, file(version = 2))
        expectError(EnrollmentError.MISSING_FIELD, file(url = null))
        expectError(EnrollmentError.MISSING_FIELD, file(deviceId = " "))
        expectError(EnrollmentError.MISSING_FIELD, file(token = null))
        expectError(EnrollmentError.MISSING_FIELD, file(certPem = null))
        expectError(EnrollmentError.MISSING_FIELD, file(keyPem = null))
    }

    @Test
    fun rejectsUnsafeOrInvalidUrls() {
        expectError(EnrollmentError.INSECURE_URL, file(url = "http://ingest.exemple.fr"))
        expectError(EnrollmentError.BAD_URL, file(url = "ingest.exemple.fr"))
        expectError(EnrollmentError.BAD_URL, file(url = "https://ingest.exemple.fr/?x=1"))
    }

    @Test
    fun rejectsBadCertificatesAndKeys() {
        expectError(EnrollmentError.BAD_CLIENT_CERT, file(certPem = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----"))
        expectError(EnrollmentError.BAD_CLIENT_CERT, file(certPem = "garbage"))
        expectError(EnrollmentError.BAD_CLIENT_KEY, file(keyPem = "garbage"))
        // A key that does not belong to the certificate.
        val other = HeldCertificate.Builder().ecdsa256().build()
        expectError(EnrollmentError.KEY_CERT_MISMATCH, file(keyPem = other.privateKeyPkcs8Pem()))
        // RSA is not accepted (contract: ECDSA P-256).
        val rsa = HeldCertificate.Builder().commonName("dev_8f3a").rsa2048().build()
        expectError(EnrollmentError.BAD_CLIENT_KEY, file(certPem = rsa.certificatePem(), keyPem = rsa.privateKeyPkcs8Pem()))
        // P-384 is not accepted either.
        val p384 = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp384r1")) }.generateKeyPair()
        val p384Pem = "-----BEGIN PRIVATE KEY-----\n" +
            java.util.Base64.getMimeEncoder().encodeToString(p384.private.encoded) + "\n-----END PRIVATE KEY-----\n"
        expectError(EnrollmentError.KEY_NOT_P256, file(keyPem = p384Pem))
        expectError(EnrollmentError.BAD_SERVER_CA, file(caPem = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----"))
        expectError(EnrollmentError.BAD_DNS_HOST, file(dns = "not a host"))
    }

    @Test
    fun rejectsAnExpiredCertificate() {
        val expired = HeldCertificate.Builder()
            .commonName("dev_8f3a")
            .validityInterval(now - 10 * 86_400_000L, now - 86_400_000L)
            .build()
        expectError(EnrollmentError.CLIENT_CERT_EXPIRED, file(certPem = expired.certificatePem(), keyPem = expired.privateKeyPkcs8Pem()))
    }

    @Test
    fun commonNameMismatchIsAWarningNotAnError() {
        val parsed = EnrollmentParser.parse(file(deviceId = "dev_other"), now)
        assertEquals(1, parsed.warnings.size)
        assertTrue(parsed.warnings.single().contains("dev_8f3a"))
    }

    @Test
    fun managerImportsSealsTheTokenAndUnenrolls() {
        val prefs = MemoryPrefs()
        val credentials = MemoryCredentials()
        val manager = EnrollmentManager(EnrollmentStore(prefs, ReversingBox()), credentials, FakeClock(), "1.0.0", { null })
        val bytes = file(caPem = serverCa.certificatePem())
        val parsed = manager.parse(bytes)
        assertTrue("source buffer wiped", bytes.all { it == 0.toByte() })
        manager.import(parsed)
        assertEquals("dev_8f3a", manager.state.value?.deviceId)
        assertNotNull(credentials.key)
        assertFalse("token never stored in clear", prefs.all.values.any { it.toString().contains("tok-123") })
        assertFalse("private key never stored in prefs", prefs.all.values.any { it.toString().contains("PRIVATE KEY") })
        val (_, target) = manager.target()!!
        assertEquals("tok-123", target.token)
        assertEquals("https://ingest.exemple.fr/api/v1/ingest", target.ingestUrl.toString())

        manager.unenroll()
        assertNull(manager.state.value)
        assertNull(manager.target())
        assertNull(credentials.key)
        assertTrue(prefs.all.isEmpty())
    }

    // --- mTLS against a real TLS server -----------------------------------------------------

    private fun tlsServer(requireClientCert: Boolean = true): MockWebServer {
        val serverCert = HeldCertificate.Builder()
            .commonName("localhost")
            .addSubjectAlternativeName("localhost")
            .addSubjectAlternativeName("127.0.0.1")
            .signedBy(serverCa)
            .build()
        val certificates = HandshakeCertificates.Builder()
            .heldCertificate(serverCert)
            .addTrustedCertificate(clientCa.certificate)
            .build()
        return MockWebServer().also {
            it.useHttps(certificates.sslSocketFactory())
            if (requireClientCert) it.requireClientAuth()
            it.start()
            servers += it
        }
    }

    private fun keyManager(held: HeldCertificate = clientCert) =
        SingleKeyManager("vigie", { held.keyPair.private }, { listOf(held.certificate, clientCa.certificate) })

    @Test
    fun pingSucceedsWithClientCertificateAndPinnedServerCa() {
        val server = tlsServer()
        server.enqueue(MockResponse.Builder().code(200).body("""{"server_time":"2026-11-15T21:45:00.000Z","device_id":"dev_8f3a"}""").build())
        val client = IngestHttp.build(keyManager(), listOf(serverCa.certificate), "1.0.0")
        val result = IngestHttp.ping(client, IngestTarget(server.url("/"), "dev_8f3a", "tok", "1.0.0"))
        assertEquals(PingResult.Ok("2026-11-15T21:45:00.000Z", deviceIdMatches = true), result)
        val request = server.takeRequest(5, TimeUnit.SECONDS)!!
        assertEquals("/api/v1/ping", request.url.encodedPath)
        assertEquals("Bearer tok", request.headers["Authorization"])
        assertEquals(clientCert.certificate, request.handshake!!.peerCertificates.first())
    }

    @Test
    fun anotherServerCaIsRefused() {
        val server = tlsServer()
        val otherCa = HeldCertificate.Builder().certificateAuthority(0).build()
        val client = IngestHttp.build(keyManager(), listOf(otherCa.certificate), "1.0.0")
        val result = IngestHttp.ping(client, IngestTarget(server.url("/"), "dev_8f3a", "tok", "1.0.0"))
        assertTrue(result.toString(), result is PingResult.NetworkError)
        assertEquals(0, server.requestCount)
    }

    @Test
    fun noClientCertificateIsRefusedByTheServer() {
        val server = tlsServer()
        val client = IngestHttp.build(null, listOf(serverCa.certificate), "1.0.0")
        val result = IngestHttp.ping(client, IngestTarget(server.url("/"), "dev_8f3a", "tok", "1.0.0"))
        assertTrue(result.toString(), result is PingResult.NetworkError)
    }

    @Test
    fun unauthorizedAndRedirectsAreReported() {
        val server = tlsServer()
        server.enqueue(MockResponse.Builder().code(401).build())
        server.enqueue(MockResponse.Builder().code(302).addHeader("Location", "https://elsewhere.example/").build())
        val client = IngestHttp.build(keyManager(), listOf(serverCa.certificate), "1.0.0")
        val target = IngestTarget(server.url("/"), "dev_8f3a", "tok", "1.0.0")
        assertEquals(PingResult.HttpError(401), IngestHttp.ping(client, target))
        // Redirects are never followed: data only goes to the enrolled URL.
        assertEquals(PingResult.HttpError(302), IngestHttp.ping(client, target))
        assertEquals(2, server.requestCount)
    }

    @Test
    fun endToEndEnrollmentThenPing() = runBlocking {
        val server = tlsServer()
        server.enqueue(MockResponse.Builder().code(200).body("""{"server_time":"t","device_id":"dev_8f3a"}""").build())
        val manager = EnrollmentManager(EnrollmentStore(MemoryPrefs(), ReversingBox()), MemoryCredentials(), FakeClock(), "1.0.0", { null })
        val url = server.url("/").toString()
        manager.import(manager.parse(file(url = url, caPem = serverCa.certificatePem() + clientCa.certificatePem())))
        assertEquals(PingResult.Ok("t", deviceIdMatches = true), manager.ping())
        assertEquals(url.toHttpUrl().host, server.takeRequest(5, TimeUnit.SECONDS)!!.url.host)
    }
}

/** In-memory stand-in for the Android Keystore. */
private class MemoryCredentials : ClientCredentialStore {
    var key: PrivateKey? = null
    private var certs: List<X509Certificate> = emptyList()
    override fun import(privateKey: PrivateKey, chain: List<X509Certificate>) {
        key = privateKey
        certs = chain
    }
    override fun keyManager() = key?.let { k -> SingleKeyManager("vigie", { k }, { certs }) }
    override fun chain() = certs
    override fun delete() {
        key = null
        certs = emptyList()
    }
}

/** Not encryption: only proves that what is stored is the sealed form. */
private class ReversingBox : SecretBox {
    override fun seal(plain: ByteArray) = byteArrayOf(1) + plain.reversedArray()
    override fun open(sealed: ByteArray) = sealed.copyOfRange(1, sealed.size).reversedArray()
    override fun destroy() = Unit
}
