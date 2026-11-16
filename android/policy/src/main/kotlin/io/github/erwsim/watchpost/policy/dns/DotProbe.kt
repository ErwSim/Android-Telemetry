package io.github.erwsim.watchpost.policy.dns

import java.io.DataInputStream
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

/** Result of a DNS-over-TLS check. [addresses] are the addresses of the DoT host that answered. */
data class ProbeResult(val ok: Boolean, val addresses: List<String> = emptyList(), val error: String? = null)

/** "Does this host really serve DNS over TLS (RFC 7858) right now?" Blocking. */
fun interface DnsProbe {
    /**
     * @param knownAddresses addresses tried first (and only, if [host] cannot be resolved): while a
     *   strict private DNS is failing, the host name itself may not resolve any more.
     */
    fun probe(host: String, knownAddresses: List<String>): ProbeResult
}

/**
 * Minimal DNS wire format (RFC 1035) for the probe: one question, no compression on the way out,
 * only the header is checked on the way back.
 */
object DnsMessage {
    const val TYPE_A = 1

    fun query(id: Int, name: String, type: Int = TYPE_A): ByteArray {
        require(id in 0..0xFFFF)
        val out = java.io.ByteArrayOutputStream()
        out.write(id ushr 8); out.write(id and 0xFF)
        out.write(0x01); out.write(0x00) // RD=1
        out.write(0); out.write(1) // QDCOUNT=1
        repeat(6) { out.write(0) } // AN, NS, AR = 0
        for (label in name.trimEnd('.').split('.')) {
            val bytes = label.toByteArray(Charsets.US_ASCII)
            require(bytes.size in 1..63) { "bad label in $name" }
            out.write(bytes.size); out.write(bytes)
        }
        out.write(0)
        out.write(type ushr 8); out.write(type and 0xFF)
        out.write(0); out.write(1) // class IN
        return out.toByteArray()
    }

    /**
     * Null when [response] is a valid answer to query [id] (NOERROR or NXDOMAIN: the server
     * resolves), otherwise the reason.
     */
    fun checkResponse(response: ByteArray, id: Int): String? {
        if (response.size < 12) return "truncated DNS response (${response.size} bytes)"
        val rid = ((response[0].toInt() and 0xFF) shl 8) or (response[1].toInt() and 0xFF)
        if (rid != id) return "unexpected response ID"
        if (response[2].toInt() and 0x80 == 0) return "the message received is not a response"
        return when (val rcode = response[3].toInt() and 0x0F) {
            0, 3 -> null
            2 -> "SERVFAIL: the server cannot resolve"
            5 -> "REFUSED: the server refuses this device (ClientID? access list?)"
            else -> "DNS response code $rcode"
        }
    }

    /** RFC 7858 framing: two-byte length prefix. */
    fun frame(message: ByteArray): ByteArray =
        byteArrayOf((message.size ushr 8).toByte(), (message.size and 0xFF).toByte()) + message
}

/**
 * Real probe: TLS to port 853 with the system trust store and host name verification, then one
 * DNS query (the host's own name) inside the TLS session. Used before imposing the private DNS so
 * that a host that does not answer can never cut the phone's Internet access, and by the
 * fallback guard.
 */
class DotProbe(
    private val timeoutMs: Int = 5_000,
    private val socketFactory: () -> SSLSocketFactory = { SSLSocketFactory.getDefault() as SSLSocketFactory },
    private val resolve: (String) -> List<InetAddress> = { InetAddress.getAllByName(it).toList() },
) : DnsProbe {
    override fun probe(host: String, knownAddresses: List<String>): ProbeResult {
        val candidates = LinkedHashSet<InetAddress>()
        knownAddresses.forEach { a -> runCatching { InetAddress.getByName(a) }.getOrNull()?.let(candidates::add) }
        val resolveError = try {
            candidates += resolve(host)
            null
        } catch (e: IOException) {
            "cannot resolve $host: ${e.message}"
        }
        if (candidates.isEmpty()) return ProbeResult(false, error = resolveError ?: "no address for $host")
        var lastError: String? = null
        for (address in candidates.take(MAX_ADDRESSES)) {
            val error = tryOne(host, address)
            if (error == null) {
                return ProbeResult(true, candidates.map { it.hostAddress.orEmpty() }.filter { it.isNotEmpty() })
            }
            lastError = "${address.hostAddress} : $error"
        }
        return ProbeResult(false, error = lastError)
    }

    private fun tryOne(host: String, address: InetAddress): String? = try {
        Socket().use { plain ->
            plain.connect(InetSocketAddress(address, PORT), timeoutMs)
            plain.soTimeout = timeoutMs
            (socketFactory().createSocket(plain, host, PORT, true) as SSLSocket).use { tls ->
                tls.sslParameters = tls.sslParameters.apply {
                    endpointIdentificationAlgorithm = "HTTPS" // host name verification
                    serverNames = listOf(SNIHostName(host))
                }
                tls.startHandshake()
                val id = (System.nanoTime() and 0xFFFF).toInt()
                tls.outputStream.apply { write(DnsMessage.frame(DnsMessage.query(id, host))); flush() }
                val input = DataInputStream(tls.inputStream)
                val length = input.readUnsignedShort()
                if (length !in 12..65_535) return "invalid response length ($length)"
                val response = ByteArray(length).also { input.readFully(it) }
                DnsMessage.checkResponse(response, id)
            }
        }
    } catch (e: Exception) {
        "${e.javaClass.simpleName} : ${e.message.orEmpty()}".trim()
    }

    private companion object {
        const val PORT = 853
        const val MAX_ADDRESSES = 4
    }
}
