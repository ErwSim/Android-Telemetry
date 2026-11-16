package io.github.erwsim.vigie.core.testing

import io.github.erwsim.vigie.core.command.CommandCrypto
import io.github.erwsim.vigie.core.command.CommandEnvelope
import io.github.erwsim.vigie.core.command.CommandKeyStore
import io.github.erwsim.vigie.core.command.CommandStateStore
import io.github.erwsim.vigie.core.command.CommandVerifier
import io.github.erwsim.vigie.core.enroll.SecretBox
import io.github.erwsim.vigie.core.event.Rfc3339
import io.github.erwsim.vigie.core.event.UlidGenerator
import io.github.erwsim.vigie.core.sink.EventSink
import kotlinx.serialization.json.JsonObject
import java.util.concurrent.CopyOnWriteArrayList

/** Contract §8 test vector, to the byte (UTF-8, accented characters). */
object CommandVector {
    const val CODE = "correct horse battery staple"
    const val DEVICE_ID = "dev_0123456789abcdef"
    const val KEY_HEX = "072a4a8b76845668eff857e6412bd6bde57cf158cf89b2fb9c844a7d66037492"
    const val ID = "01JCQ8Z3K4M5N6P7Q8R9S0T1V2"
    const val PAYLOAD =
        """{"v":1,"id":"01JCQ8Z3K4M5N6P7Q8R9S0T1V2","device_id":"dev_0123456789abcdef","type":"lock","params":{"message":"Téléphone perdu, appelez le 01 23 45 67 89"},"issued_at":"2026-11-16T10:00:00.000Z","expires_at":"2026-11-23T10:00:00.000Z"}"""
    const val SIG = "GWiiJjYxiBHlG1lba410Zxb0kDHsINh4nS9u/GE/OaE="

    /** 2026-11-16T10:30:00Z: inside the vector's validity. */
    const val NOW_MS = 1_794_825_000_000L

    /** K of the vector (derived once per test JVM: 600 000 iterations). */
    val key: ByteArray by lazy { CommandCrypto.deriveKey(CODE, DEVICE_ID) }
}

/** Identity "sealing" for JVM tests (the device uses the Keystore). */
class PlainSecretBox : SecretBox {
    var destroyed = false
    override fun seal(plain: ByteArray): ByteArray = plain.copyOf()
    override fun open(sealed: ByteArray): ByteArray = sealed.copyOf()
    override fun destroy() {
        destroyed = true
    }
}

/** Records emitted events. */
class RecordingSink : EventSink {
    data class Emitted(val type: String, val sev: Int, val data: JsonObject)

    val events = CopyOnWriteArrayList<Emitted>()
    override fun emit(type: String, sev: Int, data: JsonObject, originTsMs: Long?) {
        events += Emitted(type, sev, data)
    }

    fun of(type: String) = events.filter { it.type == type }
}

/**
 * Builds signed or simple commands for [deviceId] and a verifier with a configured key: the tests of
 * `:core` (verification, channel) and `:policy` (wipe guard matrix) go through the real verifier.
 */
class CommandKit(
    val clock: FakeClock = FakeClock(now = CommandVector.NOW_MS),
    val deviceId: String = CommandVector.DEVICE_ID,
    val statePrefs: MemoryPrefs = MemoryPrefs(),
    val keyPrefs: MemoryPrefs = MemoryPrefs(),
    configureKey: Boolean = true,
) {
    val box = PlainSecretBox()
    val keys = CommandKeyStore(keyPrefs, box)
    val state = CommandStateStore(statePrefs)
    val verifier = CommandVerifier(clock, state, keys)
    private val ulid = UlidGenerator()

    init {
        if (configureKey) keys.save(deviceId, CommandVector.key.copyOf(), clock.now)
    }

    fun newId(): String = ulid.next(clock.now)

    fun payload(
        type: String,
        params: String = "{}",
        id: String = newId(),
        device: String = deviceId,
        issuedAtMs: Long = clock.now - 60_000,
        expiresAtMs: Long = clock.now + 3_600_000,
    ): Pair<String, String> = id to
        """{"v":1,"id":"$id","device_id":"$device","type":"$type","params":$params,"issued_at":"${Rfc3339.format(issuedAtMs)}","expires_at":"${Rfc3339.format(expiresAtMs)}"}"""

    fun simple(type: String, params: String = "{}", id: String = newId()): CommandEnvelope {
        val (i, p) = payload(type, params, id)
        return CommandEnvelope(i, p, null)
    }

    fun signed(type: String, params: String = "{}", id: String = newId(), key: ByteArray = CommandVector.key): CommandEnvelope {
        val (i, p) = payload(type, params, id)
        return CommandEnvelope(i, p, CommandCrypto.sign(key, p))
    }

    fun sign(id: String, payload: String, key: ByteArray = CommandVector.key) = CommandEnvelope(id, payload, CommandCrypto.sign(key, payload))

    fun env(
        channelEnabled: Boolean = true,
        deviceId: String? = this.deviceId,
        wipeAllowed: Boolean = false,
        deviceOwner: Boolean = true,
    ) = CommandVerifier.Environment(channelEnabled, deviceId, wipeAllowed) { deviceOwner }

    /** JSON of a command object as the server sends it (stream `data:` or poll item). */
    fun json(envelope: CommandEnvelope): String = buildString {
        append("{\"id\":").append(kotlinx.serialization.json.JsonPrimitive(envelope.id))
        append(",\"payload\":").append(kotlinx.serialization.json.JsonPrimitive(envelope.payload))
        envelope.sig?.let { append(",\"sig\":").append(kotlinx.serialization.json.JsonPrimitive(it)) }
        append('}')
    }
}
