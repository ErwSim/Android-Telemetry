package io.github.erwsim.vigie

import io.github.erwsim.vigie.core.command.ChannelConfig
import io.github.erwsim.vigie.core.command.ChannelMode
import io.github.erwsim.vigie.core.command.ChannelPhase
import io.github.erwsim.vigie.core.command.ChannelPlatform
import io.github.erwsim.vigie.core.command.CommandChannel
import io.github.erwsim.vigie.core.command.CommandCrypto
import io.github.erwsim.vigie.core.command.CommandExecutor
import io.github.erwsim.vigie.core.command.CommandKeyStore
import io.github.erwsim.vigie.core.command.CommandProcessor
import io.github.erwsim.vigie.core.command.CommandStateStore
import io.github.erwsim.vigie.core.command.CommandTypes
import io.github.erwsim.vigie.core.command.CommandVerifier
import io.github.erwsim.vigie.core.command.ExecutionResult
import io.github.erwsim.vigie.core.command.WipeGate
import io.github.erwsim.vigie.core.enroll.EnrollmentParser
import io.github.erwsim.vigie.core.event.AgentClock
import io.github.erwsim.vigie.core.event.Rfc3339
import io.github.erwsim.vigie.core.event.UlidGenerator
import io.github.erwsim.vigie.core.event.VigieJson
import io.github.erwsim.vigie.core.testing.Contract
import io.github.erwsim.vigie.core.testing.MemoryPrefs
import io.github.erwsim.vigie.core.testing.PlainSecretBox
import io.github.erwsim.vigie.core.testing.RecordingSink
import io.github.erwsim.vigie.core.upload.IngestHttp
import io.github.erwsim.vigie.core.upload.IngestTarget
import io.github.erwsim.vigie.policy.remote.WipeExecutor
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.Interceptor
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File
import java.security.MessageDigest
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicInteger

/**
 * Cross-check of the command channel with the REAL collector (`server/collector`, contract §8): commands
 * created through the real console API (payload and signature built exactly as the console builds them),
 * delivered by the real SSE stream and by the real poll endpoint to the real [CommandChannel], verified by
 * the real [CommandVerifier] (key derived from the command code by the real PBKDF2), results posted back
 * and read again from the console API. Platform effects are faked (nothing rings, nothing is wiped).
 *
 * Skipped unless these are set (development server in `http://`, see `server/collector/README.md`):
 * `VIGIE_CROSS_ENROLL` (`.vigie` file), `VIGIE_CROSS_URL` (e.g. `http://127.0.0.1:8080`, ingestion and console
 * on the same listener), `VIGIE_CROSS_CONSOLE_USER`, `VIGIE_CROSS_CONSOLE_PASSWORD`.
 */
class CrossCommandsTest {
    private val enrollPath: String? = System.getenv("VIGIE_CROSS_ENROLL")
    private val url: String? = System.getenv("VIGIE_CROSS_URL")
    private val user: String? = System.getenv("VIGIE_CROSS_CONSOLE_USER")
    private val password: String? = System.getenv("VIGIE_CROSS_CONSOLE_PASSWORD")

    private object WallClock : AgentClock {
        private val start = System.nanoTime()
        override fun nowMillis(): Long = System.currentTimeMillis()
        override fun elapsedRealtime(): Long = 3_600_000L + (System.nanoTime() - start) / 1_000_000
    }

    private val json = "application/json".toMediaType()
    private val consoleClient = OkHttpClient()
    private var cookie = ""

    private fun console(method: String, path: String, body: JsonObject? = null): Pair<Int, String> {
        val b = Request.Builder().url(url!!.trimEnd('/') + "/api/console" + path)
            .header("X-Requested-With", "vigie")
            .apply { if (cookie.isNotEmpty()) header("Cookie", cookie) }
        if (body != null) b.method(method, body.toString().toRequestBody(json)) else b.method(method, null)
        consoleClient.newCall(b.build()).execute().use { r ->
            r.headers("Set-Cookie").firstOrNull()?.let { cookie = it.substringBefore(';') }
            return r.code to r.body.string()
        }
    }

    private fun eventually(what: String, timeoutMs: Long = 20_000, condition: () -> Boolean) {
        val end = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < end) {
            if (condition()) return
            Thread.sleep(100)
        }
        throw AssertionError("timeout: $what")
    }

    @Test
    fun theRealCollectorDeliversCommandsAndRecordsTheResults() {
        assumeTrue(
            "VIGIE_CROSS_ENROLL / VIGIE_CROSS_URL / VIGIE_CROSS_CONSOLE_USER / VIGIE_CROSS_CONSOLE_PASSWORD not set: skipped",
            enrollPath != null && url != null && user != null && password != null,
        )
        val parsed = EnrollmentParser.parse(File(enrollPath!!).readBytes())
        val deviceId = parsed.deviceId
        val fingerprint = MessageDigest.getInstance("SHA-256").digest(parsed.clientChain.first().encoded).joinToString("") { "%02x".format(it) }
        val client = IngestHttp.baseBuilder("0.1.0-cross")
            .addInterceptor(Interceptor { chain -> chain.proceed(chain.request().newBuilder().header("X-Vigie-Client-Cert-Sha256", fingerprint).build()) })
            .build()
        val target = IngestTarget(url!!.toHttpUrl(), deviceId, parsed.deviceToken, "0.1.0-cross")

        // The phone side: real key derivation, verifier, processor and channel; faked platform effects.
        val code = "Phrase de passe très longue 2026"
        val keys = CommandKeyStore(MemoryPrefs(), PlainSecretBox()).also { it.save(deviceId, CommandCrypto.deriveKey(code, deviceId), WallClock.nowMillis()) }
        val state = CommandStateStore(MemoryPrefs())
        val sink = RecordingSink()
        val executed = CopyOnWriteArrayList<String>()
        val wipes = AtomicInteger()
        val config = java.util.concurrent.atomic.AtomicReference(ChannelConfig(enabled = true, mode = ChannelMode.STREAM, pollIntervalMin = 1))
        val env = { CommandVerifier.Environment(true, deviceId, wipeAllowed = true) { true } }
        val processor = CommandProcessor(
            clock = WallClock,
            verifier = CommandVerifier(WallClock, state, keys),
            state = state,
            sink = sink,
            environment = env,
            executors = {
                mapOf(
                    CommandTypes.RING to CommandExecutor { executed += "ring:${it.id}"; ExecutionResult.executed() },
                    CommandTypes.LOCK to CommandExecutor { executed += "lock:${it.id}:${it.params}"; ExecutionResult.executed("ok_message") },
                    CommandTypes.WIPE to WipeExecutor({ WipeGate.Live(true, true, true, WallClock.nowMillis()) }, { true }, { wipes.incrementAndGet() }),
                )
            },
            hooks = object : CommandProcessor.Hooks {
                override suspend fun beforeIrreversible(timeoutMs: Long) = Unit
            },
        )
        val platform = object : ChannelPlatform {
            override fun isNetworkAvailable() = true
            override fun networkKey() = "cross"
            override fun scheduleWakeup(atElapsedMs: Long) = Unit
            override fun cancelWakeup() = Unit
            override suspend fun <T> withWakeLock(timeoutMs: Long, block: suspend () -> T): T = block()
        }
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        val channel = CommandChannel(scope, WallClock, { client to target }, { config.get() }, processor, state, platform)

        // The console side: login, then commands built as the console builds them.
        assertEquals(204, console("POST", "/login", buildJsonObject { put("username", user); put("password", password) }).first)
        val ulid = UlidGenerator()
        fun create(type: String, params: String, signed: Boolean): String {
            val id = ulid.next(WallClock.nowMillis())
            val now = WallClock.nowMillis()
            val validity = if (signed) 7 * 86_400_000L else 3_600_000L
            val payload = """{"v":1,"id":"$id","device_id":"$deviceId","type":"$type","params":$params,"issued_at":"${Rfc3339.format(now)}","expires_at":"${Rfc3339.format(now + validity)}"}"""
            val body = buildJsonObject {
                put("device_id", deviceId)
                put("payload", payload)
                if (signed) put("sig", CommandCrypto.sign(CommandCrypto.deriveKey(code, deviceId), payload))
            }
            val (status, answer) = console("POST", "/commands", body)
            assertEquals("create $type: $answer", 201, status)
            return id
        }
        fun serverStatus(id: String): String? {
            val (_, body) = console("GET", "/commands?device_id=$deviceId&limit=50")
            return (VigieJson.parseToJsonElement(body).jsonObject["commands"] as JsonArray)
                .map { it.jsonObject }.firstOrNull { it["id"]!!.jsonPrimitive.content == id }?.get("status")?.jsonPrimitive?.content
        }

        try {
            val ring = create("ring", """{"duration_s":5,"vibrate":true}""", signed = false)
            val lock = create("lock", """{"message":"Téléphone perdu,\nappelez le 01 23 45 67 89"}""", signed = true)
            channel.start()
            eventually("stream connected") { channel.channelState.value.phase == ChannelPhase.CONNECTED }
            eventually("ring and lock executed") { executed.size == 2 }
            assertTrue(executed.toString(), executed.any { it.startsWith("lock:$lock") && "Téléphone perdu,\nappelez" in it })
            eventually("results recorded by the server") { serverStatus(ring) == "executed" && serverStatus(lock) == "executed" }

            // A command created while the stream is open arrives at once.
            val wipe = create("wipe", "{}", signed = true)
            eventually("wipe executed (fake reset)") { wipes.get() == 1 }
            eventually("wipe recorded") { serverStatus(wipe) == "executed" }

            // A command signed with another code is refused by the phone, and the server records the refusal.
            val forged = run {
                val id = ulid.next(WallClock.nowMillis())
                val now = WallClock.nowMillis()
                val payload = """{"v":1,"id":"$id","device_id":"$deviceId","type":"lock","params":{},"issued_at":"${Rfc3339.format(now)}","expires_at":"${Rfc3339.format(now + 86_400_000L)}"}"""
                val body = buildJsonObject {
                    put("device_id", deviceId)
                    put("payload", payload)
                    put("sig", CommandCrypto.sign(CommandCrypto.deriveKey("un autre code que le bon", deviceId), payload))
                }
                assertEquals(201, console("POST", "/commands", body).first)
                id
            }
            eventually("forged command refused") { serverStatus(forged) == "refused" }

            // Poll mode.
            config.set(config.get().copy(mode = ChannelMode.POLL))
            channel.onConfigChanged()
            eventually("polling") { channel.channelState.value.phase == ChannelPhase.POLL_IDLE }
            val ring2 = create("ring", """{"duration_s":3,"vibrate":false}""", signed = false)
            channel.onUploadCycle() // as after an upload; the spacing rule may delay it by up to a minute
            eventually("polled ring executed", timeoutMs = 90_000) { executed.any { it == "ring:$ring2" } }
            eventually("polled ring recorded") { serverStatus(ring2) == "executed" }

            // Nothing was executed twice, every event follows the contract, nothing is left to post.
            assertEquals(executed.size, executed.toSet().size)
            assertEquals(1, wipes.get())
            sink.of("command.result").forEach { Contract.check(it.type, it.data) }
            eventually("results all acknowledged") { state.pendingResults().isEmpty() }
            val refused = sink.of("command.result").single { (it.data["status"] as JsonPrimitive).content == "refused" }
            assertEquals("bad_signature", (refused.data["detail"] as JsonPrimitive).content)
            System.getenv("VIGIE_CROSS_OUT")?.let { path ->
                File(path).appendText(
                    "commands: stream+poll ok, executed=${executed.size}, wipe(fake)=${wipes.get()}, refused=${refused.data}, " +
                        "server statuses ring=${serverStatus(ring)} lock=${serverStatus(lock)} wipe=${serverStatus(wipe)} forged=${serverStatus(forged)} ring2=${serverStatus(ring2)}\n",
                )
            }
        } finally {
            channel.stop()
            scope.cancel()
        }
    }
}
