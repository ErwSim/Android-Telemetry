package io.github.erwsim.vigie.core.enroll

import io.github.erwsim.vigie.core.event.AgentClock
import io.github.erwsim.vigie.core.event.EventTypes
import io.github.erwsim.vigie.core.sink.EventSink
import io.github.erwsim.vigie.core.sink.emit
import io.github.erwsim.vigie.core.upload.IngestHttp
import io.github.erwsim.vigie.core.upload.IngestTarget
import io.github.erwsim.vigie.core.upload.PingResult
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.OkHttpClient

/** What a `.vigie` import changes, and what happens to the events waiting in the buffer. */
enum class EnrollmentChange {
    /** Not enrolled yet. */
    FIRST,

    /** Same server, same device id (new certificate, key or token): the buffer is kept. */
    RENEWAL,

    /** Same server, other device id: the buffer is kept and sent under the new id. */
    NEW_IDENTITY,

    /** Other ingest address: the buffer collected for the previous server is deleted. */
    NEW_SERVER,
}

/**
 * Enrollment lifecycle: parse a `.vigie` file, import its key into the Keystore and seal the
 * token, build the mTLS client, test it, and unenroll.
 */
class EnrollmentManager(
    private val store: EnrollmentStore,
    private val credentials: ClientCredentialStore,
    private val clock: AgentClock,
    private val agentVersion: String,
    private val sink: () -> EventSink?,
    /** Builds the HTTP client; replaced in tests. */
    private val clientFactory: (Enrollment, ClientCredentialStore) -> OkHttpClient = { e, c ->
        IngestHttp.build(c.keyManager(), e.serverCaPem?.let(Pem::certificates).orEmpty(), agentVersion)
    },
) {
    private val _state = MutableStateFlow(store.load())
    val state: StateFlow<Enrollment?> = _state.asStateFlow()

    @Volatile
    private var cached: Pair<OkHttpClient, IngestTarget>? = null

    fun parse(bytes: ByteArray): ParsedEnrollment = try {
        EnrollmentParser.parse(bytes, clock.nowMillis())
    } finally {
        bytes.fill(0)
    }

    /** What importing [parsed] would change, compared with the current enrollment. */
    fun changeFor(parsed: ParsedEnrollment): EnrollmentChange {
        val current = _state.value ?: return EnrollmentChange.FIRST
        return when {
            current.ingestUrl != parsed.ingestUrl -> EnrollmentChange.NEW_SERVER
            current.deviceId != parsed.deviceId -> EnrollmentChange.NEW_IDENTITY
            else -> EnrollmentChange.RENEWAL
        }
    }

    /**
     * Imports the key (non-exportable) and stores the sealed token. After this call the parsed
     * object should be dropped: the PEM key is not kept anywhere by the agent.
     *
     * Also the way to renew an enrollment (the client certificate lasts two years) without
     * unenrolling: the buffered events are kept, see [EnrollmentChange]. [clearPending] is called
     * only for another server ([EnrollmentChange.NEW_SERVER]), once the new key is in place and
     * before the new address is used: what was collected for a server is never sent to another.
     */
    @Synchronized
    fun import(parsed: ParsedEnrollment, clearPending: () -> Unit = {}): EnrollmentChange {
        val previous = _state.value
        val change = changeFor(parsed)
        credentials.import(parsed.privateKey, parsed.clientChain)
        if (change == EnrollmentChange.NEW_SERVER) clearPending()
        val enrollment = Enrollment(
            ingestUrl = parsed.ingestUrl,
            deviceId = parsed.deviceId,
            deviceName = parsed.deviceName,
            serverCaPem = parsed.serverCa.takeIf { it.isNotEmpty() }?.let(Pem::encodeCertificates),
            privateDnsHost = parsed.privateDnsHost,
            enrolledAtMs = clock.nowMillis(),
            certNotAfterMs = parsed.clientChain.first().notAfter.time,
        )
        store.save(enrollment, parsed.deviceToken)
        cached = null
        _state.value = enrollment
        sink()?.emit(EventTypes.AGENT_CONFIG_CHANGED) {
            put("key", "enrollment.device_id")
            put("old", previous?.deviceId ?: "none")
            put("new", enrollment.deviceId)
        }
        return change
    }

    /** HTTP client and target for uploads, or null when not enrolled. */
    fun target(): Pair<OkHttpClient, IngestTarget>? {
        cached?.let { return it }
        val e = _state.value ?: return null
        val token = store.token() ?: return null
        val pair = synchronized(this) {
            cached ?: (clientFactory(e, credentials) to IngestTarget(e.ingestUrl.toHttpUrl(), e.deviceId, token, agentVersion))
                .also { cached = it }
        }
        return pair
    }

    suspend fun ping(): PingResult = withContext(Dispatchers.IO) {
        val t = try {
            target()
        } catch (e: Exception) {
            return@withContext PingResult.NetworkError(e.toString())
        } ?: return@withContext PingResult.NotEnrolled
        IngestHttp.ping(t.first, t.second)
    }

    @Synchronized
    fun unenroll() {
        val previous = _state.value ?: return
        try {
            credentials.delete()
        } finally {
            store.clear()
            cached = null
            _state.value = null
        }
        sink()?.emit(EventTypes.AGENT_CONFIG_CHANGED) {
            put("key", "enrollment.device_id")
            put("old", previous.deviceId)
            put("new", "none")
        }
    }
}
