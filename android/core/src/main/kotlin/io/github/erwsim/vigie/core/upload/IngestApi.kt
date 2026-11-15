package io.github.erwsim.vigie.core.upload

import io.github.erwsim.vigie.core.event.VigieJson
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import okhttp3.HttpUrl
import okhttp3.Interceptor
import okhttp3.OkHttpClient
import okhttp3.Request
import java.io.IOException
import java.security.KeyStore
import java.security.cert.X509Certificate
import java.util.concurrent.TimeUnit
import javax.net.ssl.KeyManager
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509KeyManager
import javax.net.ssl.X509TrustManager

/** Where and as whom to upload. Built from the enrollment only: there is no other destination. */
class IngestTarget(
    val baseUrl: HttpUrl,
    val deviceId: String,
    val token: String,
    val agentVersion: String,
) {
    val ingestUrl: HttpUrl = baseUrl.newBuilder().addPathSegments("api/v1/ingest").build()
    val pingUrl: HttpUrl = baseUrl.newBuilder().addPathSegments("api/v1/ping").build()
}

@Serializable
data class IngestResponse(
    val accepted: Int = 0,
    val duplicates: Int = 0,
    val rejected: List<Rejected> = emptyList(),
    @SerialName("server_time") val serverTime: String? = null,
) {
    @Serializable
    data class Rejected(val id: String? = null, val reason: String? = null)
}

@Serializable
data class PingResponse(
    @SerialName("server_time") val serverTime: String? = null,
    @SerialName("device_id") val deviceId: String? = null,
)

sealed class PingResult {
    data class Ok(val serverTime: String?, val deviceIdMatches: Boolean) : PingResult()
    data class HttpError(val code: Int) : PingResult()
    data class NetworkError(val message: String) : PingResult()
    data object NotEnrolled : PingResult()
}

object IngestHttp {
    /**
     * HTTPS client presenting the enrolled client certificate. When [serverCa] is not empty, only
     * that CA is trusted for the server (pinning); otherwise the system CAs (user-installed CAs are
     * excluded by network_security_config). Redirects are refused: data never leaves for another URL.
     */
    fun build(keyManager: X509KeyManager?, serverCa: List<X509Certificate>, agentVersion: String): OkHttpClient {
        val trustManager = trustManager(serverCa)
        val ssl = SSLContext.getInstance("TLS")
        ssl.init(keyManager?.let { arrayOf<KeyManager>(it) }, arrayOf(trustManager), null)
        return baseBuilder(agentVersion)
            .sslSocketFactory(ssl.socketFactory, trustManager)
            .build()
    }

    fun baseBuilder(agentVersion: String): OkHttpClient.Builder = OkHttpClient.Builder()
        .connectTimeout(20, TimeUnit.SECONDS)
        .writeTimeout(60, TimeUnit.SECONDS)
        .readTimeout(60, TimeUnit.SECONDS)
        .callTimeout(3, TimeUnit.MINUTES)
        .followRedirects(false)
        .followSslRedirects(false)
        .addInterceptor(Interceptor { chain ->
            chain.proceed(chain.request().newBuilder().header("User-Agent", "VigieAgent/$agentVersion").build())
        })

    fun trustManager(serverCa: List<X509Certificate>): X509TrustManager {
        val factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
        if (serverCa.isEmpty()) {
            factory.init(null as KeyStore?)
        } else {
            val ks = KeyStore.getInstance(KeyStore.getDefaultType()).apply { load(null, null) }
            serverCa.forEachIndexed { i, cert -> ks.setCertificateEntry("vigie-server-ca-$i", cert) }
            factory.init(ks)
        }
        return factory.trustManagers.filterIsInstance<X509TrustManager>().first()
    }

    fun ping(client: OkHttpClient, target: IngestTarget): PingResult {
        val request = Request.Builder()
            .url(target.pingUrl)
            .header("Authorization", "Bearer ${target.token}")
            .get()
            .build()
        return try {
            client.newCall(request).execute().use { response ->
                if (response.code != 200) return PingResult.HttpError(response.code)
                val body = try {
                    VigieJson.decodeFromString(PingResponse.serializer(), response.body.string())
                } catch (_: Exception) {
                    PingResponse()
                }
                PingResult.Ok(body.serverTime, body.deviceId == null || body.deviceId == target.deviceId)
            }
        } catch (e: IOException) {
            PingResult.NetworkError(e.message ?: e.javaClass.simpleName)
        }
    }
}
