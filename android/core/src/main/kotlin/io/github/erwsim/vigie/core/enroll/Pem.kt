package io.github.erwsim.vigie.core.enroll

import java.io.ByteArrayInputStream
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.PKCS8EncodedKeySpec
import java.util.Base64

/** Minimal PEM helpers (pure JCA, so they run in JVM unit tests). */
object Pem {
    private val BLOCK = Regex("-----BEGIN ([A-Z0-9 ]+)-----([\\s\\S]*?)-----END \\1-----")

    data class Block(val label: String, val der: ByteArray)

    fun blocks(pem: String): List<Block> = BLOCK.findAll(pem).map { m ->
        val body = m.groupValues[2].replace(Regex("\\s"), "")
        Block(m.groupValues[1], Base64.getDecoder().decode(body))
    }.toList()

    /** All certificates of a PEM bundle, in order. Throws if none or if one is malformed. */
    fun certificates(pem: String): List<X509Certificate> {
        val factory = CertificateFactory.getInstance("X.509")
        val certs = blocks(pem).filter { it.label == "CERTIFICATE" }.map {
            factory.generateCertificate(ByteArrayInputStream(it.der)) as X509Certificate
        }
        require(certs.isNotEmpty()) { "no CERTIFICATE block" }
        return certs
    }

    /** PKCS#8 (`BEGIN PRIVATE KEY`) EC private key. */
    fun ecPrivateKey(pem: String): PrivateKey {
        val block = blocks(pem).firstOrNull { it.label == "PRIVATE KEY" }
            ?: throw IllegalArgumentException("no PKCS#8 PRIVATE KEY block")
        return KeyFactory.getInstance("EC").generatePrivate(PKCS8EncodedKeySpec(block.der))
    }

    fun encodeCertificates(certs: List<X509Certificate>): String = buildString {
        val encoder = Base64.getMimeEncoder(64, "\n".toByteArray())
        for (c in certs) {
            append("-----BEGIN CERTIFICATE-----\n")
            append(encoder.encodeToString(c.encoded))
            append("\n-----END CERTIFICATE-----\n")
        }
    }
}
