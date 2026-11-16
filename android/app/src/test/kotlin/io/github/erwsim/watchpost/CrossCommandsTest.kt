package io.github.erwsim.watchpost

import io.github.erwsim.watchpost.core.command.ChannelConfig
import io.github.erwsim.watchpost.core.command.ChannelMode
import io.github.erwsim.watchpost.core.command.ChannelPhase
import io.github.erwsim.watchpost.core.command.ChannelPlatform
import io.github.erwsim.watchpost.core.command.CommandChannel
import io.github.erwsim.watchpost.core.command.CommandCrypto
import io.github.erwsim.watchpost.core.command.CommandExecutor
import io.github.erwsim.watchpost.core.command.CommandKeyStore
import io.github.erwsim.watchpost.core.command.CommandParams
import io.github.erwsim.watchpost.core.command.CommandProcessor
import io.github.erwsim.watchpost.core.command.CommandStateStore
import io.github.erwsim.watchpost.core.command.CommandTypes
import io.github.erwsim.watchpost.core.command.CommandVerifier
import io.github.erwsim.watchpost.core.command.ExecutionResult
import io.github.erwsim.watchpost.core.command.WipeGate
import io.github.erwsim.watchpost.core.enroll.EnrollmentParser
import io.github.erwsim.watchpost.core.event.AgentClock
import io.github.erwsim.watchpost.core.event.Rfc3339
import io.github.erwsim.watchpost.core.event.UlidGenerator
import io.github.erwsim.watchpost.core.event.WatchpostJson
import io.github.erwsim.watchpost.core.testing.Contract
import io.github.erwsim.watchpost.core.testing.MemoryPrefs
import io.github.erwsim.watchpost.core.testing.PlainSecretBox
import io.github.erwsim.watchpost.core.testing.RecordingSink
import io.github.erwsim.watchpost.core.upload.IngestHttp
import io.github.erwsim.watchpost.core.upload.IngestTarget
import io.github.erwsim.watchpost.policy.remote.WipeExecutor
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
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
import okhttp3.Protocol
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import okhttp3.ResponseBody.Companion.toResponseBody
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File
import java.io.IOException
import java.security.MessageDigest
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

/**
 * Cross-check of the command channel with the REAL collector (`server/collector`, contract §8): commands
 * created through the real console API (payload and signature built exactly as the console builds them),
 * delivered by the real SSE stream and by the real poll endpoint to the real [CommandChannel], verified by
 * the real [CommandVerifier] (key derived from the command passphrase by the real PBKDF2), results posted back
 * and read again from the console API. Platform effects are faked (nothing rings, nothing is wiped).
 *
 * Skipped unless these are set (development server in `http://`, see `server/collector/README.md`):
 * `WATCHPOST_CROSS_ENROLL` (`.watchpost` file), `WATCHPOST_CROSS_URL` (e.g. `http://127.0.0.1:8080`, ingestion and console
 * on the same listener), `WATCHPOST_CROSS_CONSOLE_USER`, `WATCHPOST_CROSS_CONSOLE_PASSWORD`.
 *
 * Two more tests, each with its own enrollment (the collector accepts 20 commands per hour and device):
 * - `WATCHPOST_CROSS_TS_ENROLL` + `WATCHPOST_CROSS_TS_VECTORS`: commands built and signed by the real console code
 *   (`node server/console/scripts/command-vectors.ts <device_id> > vectors.json`, at most 10 minutes before)
 *   go through the real collector to the real verifier;
 * - `WATCHPOST_CROSS_REDELIVERY_ENROLL` (and `WATCHPOST_CROSS_REDELIVERY_ENROLL_2`, a second device, for the case of a
 *   result that cannot be posted): the real collector delivers again, after 5 minutes, commands whose result
 *   did not reach it; nothing runs twice and the original result comes back (takes 6 to 15 minutes; start the
 *   collector with `WATCHPOST_CMD_KEEPALIVE_S=10` to shorten the wait after the 5 minutes).
 */
class CrossCommandsTest {
    private val enrollPath: String? = System.getenv("WATCHPOST_CROSS_ENROLL")
    private val url: String? = System.getenv("WATCHPOST_CROSS_URL")
    private val user: String? = System.getenv("WATCHPOST_CROSS_CONSOLE_USER")
    private val password: String? = System.getenv("WATCHPOST_CROSS_CONSOLE_PASSWORD")

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
            .header("X-Requested-With", "watchpost")
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
            "WATCHPOST_CROSS_ENROLL / WATCHPOST_CROSS_URL / WATCHPOST_CROSS_CONSOLE_USER / WATCHPOST_CROSS_CONSOLE_PASSWORD not set: skipped",
            enrollPath != null && url != null && user != null && password != null,
        )
        val parsed = EnrollmentParser.parse(File(enrollPath!!).readBytes())
        val deviceId = parsed.deviceId
        val fingerprint = MessageDigest.getInstance("SHA-256").digest(parsed.clientChain.first().encoded).joinToString("") { "%02x".format(it) }
        val client = IngestHttp.baseBuilder("0.1.0-cross")
            .addInterceptor(Interceptor { chain -> chain.proceed(chain.request().newBuilder().header("X-Watchpost-Client-Cert-Sha256", fingerprint).build()) })
            .build()
        val target = IngestTarget(url!!.toHttpUrl(), deviceId, parsed.deviceToken, "0.1.0-cross")

        // The phone side: real key derivation, verifier, processor and channel; faked platform effects.
        val code = "A long and unusual passphrase 2026"
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
            return (WatchpostJson.parseToJsonElement(body).jsonObject["commands"] as JsonArray)
                .map { it.jsonObject }.firstOrNull { it["id"]!!.jsonPrimitive.content == id }?.get("status")?.jsonPrimitive?.content
        }

        try {
            val ring = create("ring", """{"duration_s":5,"vibrate":true}""", signed = false)
            val lock = create("lock", """{"message":"Lost phone —\nplease call +1 555 0100"}""", signed = true)
            channel.start()
            eventually("stream connected") { channel.channelState.value.phase == ChannelPhase.CONNECTED }
            eventually("ring and lock executed") { executed.size == 2 }
            assertTrue(executed.toString(), executed.any { it.startsWith("lock:$lock") && "Lost phone —\nplease" in it })
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
                    put("sig", CommandCrypto.sign(CommandCrypto.deriveKey("another passphrase than the right one", deviceId), payload))
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
            System.getenv("WATCHPOST_CROSS_OUT")?.let { path ->
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

    // ------------------------------------------------------------------------------------------------
    // Shared rig of the two tests below: the real phone-side code, platform effects recorded instead of run.

    private class Rig(enrollFile: String, baseUrl: String, resultInterceptor: Interceptor? = null) {
        val parsed = EnrollmentParser.parse(File(enrollFile).readBytes())
        val deviceId: String = parsed.deviceId
        private val fingerprint = MessageDigest.getInstance("SHA-256").digest(parsed.clientChain.first().encoded).joinToString("") { "%02x".format(it) }
        private val client = IngestHttp.baseBuilder("0.1.0-cross")
            .addInterceptor(Interceptor { chain -> chain.proceed(chain.request().newBuilder().header("X-Watchpost-Client-Cert-Sha256", fingerprint).build()) })
            .apply { if (resultInterceptor != null) addInterceptor(resultInterceptor) }
            .build()
        private val target = IngestTarget(baseUrl.toHttpUrl(), deviceId, parsed.deviceToken, "0.1.0-cross")
        val keys = CommandKeyStore(MemoryPrefs(), PlainSecretBox())
        val state = CommandStateStore(MemoryPrefs())
        val sink = RecordingSink()

        /** One line per execution: `type:id:params`. */
        val executed = CopyOnWriteArrayList<String>()
        val lockMessages = ConcurrentHashMap<String, String>()
        val wipes = AtomicInteger()
        private fun record(detail: String = "ok") = CommandExecutor {
            executed += "${it.type}:${it.id}:${it.params}"
            (it.params as? CommandParams.Lock)?.let { p -> lockMessages[it.id] = p.message ?: "<none>" }
            ExecutionResult.executed(detail)
        }
        private val processor = CommandProcessor(
            clock = WallClock,
            verifier = CommandVerifier(WallClock, state, keys),
            state = state,
            sink = sink,
            environment = { CommandVerifier.Environment(true, deviceId, wipeAllowed = true) { true } },
            executors = {
                mapOf(
                    CommandTypes.RING to record(),
                    CommandTypes.VIBRATE to record(),
                    CommandTypes.STOP_RING to record("not_ringing"),
                    CommandTypes.LOCATE to record("fix_gps_5m"),
                    CommandTypes.LOCK to record("ok_message"),
                    CommandTypes.CLEAR_LOCK_MESSAGE to record(),
                    CommandTypes.WIPE to WipeExecutor({ WipeGate.Live(true, true, true, WallClock.nowMillis()) }, { true }, { wipes.incrementAndGet() }),
                )
            },
            hooks = object : CommandProcessor.Hooks {
                override suspend fun beforeIrreversible(timeoutMs: Long) = Unit
            },
        )
        private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        private val alarms = Executors.newSingleThreadScheduledExecutor()

        // Like the Android alarm: one pending wake-up, which ticks the channel (retry of the results, watchdog).
        private val platform = object : ChannelPlatform {
            @Volatile var pending: java.util.concurrent.ScheduledFuture<*>? = null
            override fun isNetworkAvailable() = true
            override fun networkKey() = "cross"
            override fun scheduleWakeup(atElapsedMs: Long) {
                pending?.cancel(false)
                pending = alarms.schedule({ channel.tick() }, (atElapsedMs - WallClock.elapsedRealtime()).coerceAtLeast(0), TimeUnit.MILLISECONDS)
            }
            override fun cancelWakeup() {
                pending?.cancel(false)
            }
            override suspend fun <T> withWakeLock(timeoutMs: Long, block: suspend () -> T): T = block()
        }
        val channel: CommandChannel = CommandChannel(
            scope, WallClock, { client to target }, { ChannelConfig(enabled = true, mode = ChannelMode.STREAM, pollIntervalMin = 1) }, processor, state, platform,
        )

        fun useCode(code: String) = keys.save(deviceId, CommandCrypto.deriveKey(code, deviceId), WallClock.nowMillis())

        fun close() {
            channel.stop()
            scope.cancel()
            alarms.shutdownNow()
        }
    }

    private fun login() = assertEquals(204, console("POST", "/login", buildJsonObject { put("username", user); put("password", password) }).first)

    private fun listed(deviceId: String, id: String): JsonObject? {
        val (_, body) = console("GET", "/commands?device_id=$deviceId&limit=100")
        return (WatchpostJson.parseToJsonElement(body).jsonObject["commands"] as JsonArray).map { it.jsonObject }.firstOrNull { it["id"]!!.jsonPrimitive.content == id }
    }

    private fun JsonObject.text(key: String): String? = (this[key] as? JsonPrimitive)?.takeIf { it !is JsonNull }?.content

    /**
     * The signature computed by the real console code (TypeScript, WebCrypto) on hard cases — accents, emojis,
     * quotes, line feeds, bidirectional text, non-ASCII and decomposed command passphrases — survives the real
     * collector (payload relayed to the byte) and is accepted by the real verifier, with the exact message.
     */
    @Test
    fun commandsSignedByTheRealConsoleCodePassThroughTheRealCollector() {
        val enroll = System.getenv("WATCHPOST_CROSS_TS_ENROLL")
        val vectorsPath = System.getenv("WATCHPOST_CROSS_TS_VECTORS")
        assumeTrue("WATCHPOST_CROSS_TS_ENROLL / WATCHPOST_CROSS_TS_VECTORS not set: skipped", enroll != null && vectorsPath != null && url != null && user != null && password != null)
        val rig = Rig(enroll!!, url!!)
        val vectors = (WatchpostJson.parseToJsonElement(File(vectorsPath!!).readText(Charsets.UTF_8)) as JsonArray).map { it.jsonObject }
        assertTrue("vectors", vectors.size >= 12)
        login()
        try {
            rig.channel.start()
            eventually("stream connected") { rig.channel.channelState.value.phase == ChannelPhase.CONNECTED }
            var currentCode: String? = null
            for (v in vectors) {
                val name = v.text("name")!!
                assertEquals("$name: vectors generated for another device", rig.deviceId, v.text("device_id"))
                val payload = v.text("payload")!!
                val id = (WatchpostJson.parseToJsonElement(payload) as JsonObject).text("id")!!
                val code = v.text("code")
                if (code != null && code != currentCode) {
                    rig.useCode(code)
                    currentCode = code
                }
                val body = buildJsonObject {
                    put("device_id", rig.deviceId)
                    put("payload", payload)
                    v.text("sig")?.let { put("sig", it) }
                }
                val (status, answer) = console("POST", "/commands", body)
                assertEquals("$name: $answer", 201, status)
                eventually("$name: result recorded by the server") { listed(rig.deviceId, id)?.text("status") in setOf("executed", "refused", "failed") }
                val result = listed(rig.deviceId, id)!!
                assertEquals("$name: ${result.text("detail")}", "executed", result.text("status"))
                val expect = v["expect"]!!.jsonObject
                val type = v.text("type")!!
                when (type) {
                    "lock" -> assertEquals(name, expect.text("message") ?: "<none>", rig.lockMessages[id])
                    "wipe" -> assertEquals(name, 1, rig.wipes.get())
                    "ring" -> assertTrue(name, rig.executed.any { it == "ring:$id:${CommandParams.Ring(300, false)}" })
                    "vibrate" -> assertTrue(name, rig.executed.any { it == "vibrate:$id:${CommandParams.Vibrate(10)}" })
                    else -> assertTrue(name, rig.executed.any { it.startsWith("$type:$id:") })
                }
            }
            // Every result event says whether the command was signed, nothing was refused, nothing ran twice.
            val results = rig.sink.of("command.result")
            assertEquals(vectors.size, results.size)
            results.forEach { Contract.check(it.type, it.data) }
            assertEquals(vectors.count { it.text("sig") != null }, results.count { (it.data["signed"] as JsonPrimitive).content == "true" })
            assertEquals(rig.executed.size, rig.executed.toSet().size)
            System.getenv("WATCHPOST_CROSS_OUT")?.let { File(it).appendText("console vectors through the real collector: ${vectors.size} accepted (${results.count { (it.data["signed"] as JsonPrimitive).content == "true" }} signed)\n") }
        } finally {
            rig.close()
        }
    }

    /**
     * Contract §8 redelivery, against the real collector: a command whose result did not reach the server is
     * delivered again after 5 minutes. The phone must not run it again and the server must end up with the
     * ORIGINAL result. Two situations, on two enrolled devices (results are posted in order, so a result
     * that cannot leave holds the following ones back: the two cases would disturb each other on one device):
     * - first device — `lock` (signed) and `wipe` (signed, fake reset): the phone believes its result was
     *   acknowledged, the server never received it (something on the way answered 204 for it);
     * - second device (`WATCHPOST_CROSS_REDELIVERY_ENROLL_2`, optional) — `ring`: the result cannot be posted at
     *   all (network error) until after the redelivery.
     */
    @Test
    fun aCommandDeliveredAgainAfterFiveMinutesIsNotRunAgainAndItsOriginalResultComesBack() {
        val enroll = System.getenv("WATCHPOST_CROSS_REDELIVERY_ENROLL")
        val enroll2 = System.getenv("WATCHPOST_CROSS_REDELIVERY_ENROLL_2")
        assumeTrue("WATCHPOST_CROSS_REDELIVERY_ENROLL not set: skipped", enroll != null && url != null && user != null && password != null)
        val posts = ConcurrentHashMap<String, CopyOnWriteArrayList<Long>>() // command id -> times of the POST …/result attempts
        val drop = ConcurrentHashMap.newKeySet<String>() // ids whose result cannot be posted for now
        val swallowOnce = ConcurrentHashMap.newKeySet<String>() // ids whose first result is "acknowledged" without reaching the server
        val interceptor = Interceptor { chain ->
            val request = chain.request()
            val segments = request.url.pathSegments
            if (request.method != "POST" || segments.lastOrNull() != "result") return@Interceptor chain.proceed(request)
            val id = segments[segments.size - 2]
            posts.getOrPut(id) { CopyOnWriteArrayList() } += System.currentTimeMillis()
            when {
                id in drop -> throw IOException("simulated network failure")
                swallowOnce.remove(id) -> Response.Builder().request(request).protocol(Protocol.HTTP_1_1).code(204).message("No Content").body("".toResponseBody()).build()
                else -> chain.proceed(request)
            }
        }
        val code = "A long and unusual passphrase 2026"
        val rig = Rig(enroll!!, url!!, interceptor).also { it.useCode(code) }
        val rig2 = enroll2?.let { Rig(it, url, interceptor) }
        login()
        val ulid = UlidGenerator()
        fun create(r: Rig, type: String, params: String, signed: Boolean, before: (String) -> Unit): String {
            val id = ulid.next(WallClock.nowMillis())
            val now = WallClock.nowMillis()
            val payload = """{"v":1,"id":"$id","device_id":"${r.deviceId}","type":"$type","params":$params,"issued_at":"${Rfc3339.format(now)}","expires_at":"${Rfc3339.format(now + 3_600_000L)}"}"""
            val body = buildJsonObject {
                put("device_id", r.deviceId)
                put("payload", payload)
                if (signed) put("sig", CommandCrypto.sign(CommandCrypto.deriveKey(code, r.deviceId), payload))
            }
            before(id)
            val (status, answer) = console("POST", "/commands", body)
            assertEquals("create $type: $answer", 201, status)
            return id
        }
        fun status(r: Rig, id: String) = listed(r.deviceId, id)?.text("status")
        try {
            rig.channel.start()
            rig2?.channel?.start()
            eventually("streams connected") {
                rig.channel.channelState.value.phase == ChannelPhase.CONNECTED && (rig2 == null || rig2.channel.channelState.value.phase == ChannelPhase.CONNECTED)
            }
            val lock = create(rig, "lock", """{"message":"Redelivered after 5 min"}""", signed = true) { swallowOnce += it }
            val wipe = create(rig, "wipe", "{}", signed = true) { swallowOnce += it }
            val ring = rig2?.let { r -> create(r, "ring", """{"duration_s":5,"vibrate":false}""", signed = false) { drop += it } }
            val start = System.currentTimeMillis()
            eventually("lock and wipe ran once") { rig.executed.size == 1 && rig.wipes.get() == 1 }
            eventually("first results of lock and wipe posted") { posts[lock]?.size == 1 && posts[wipe]?.size == 1 }
            if (rig2 != null) eventually("ring ran once, its result could not leave") { rig2.executed.size == 1 && (posts[ring]?.size ?: 0) >= 1 }
            Thread.sleep(3_000)
            // The server has no result: the commands stay "delivered"; the first phone believes lock and wipe are done.
            assertEquals("delivered", status(rig, lock))
            assertEquals("delivered", status(rig, wipe))
            assertTrue(rig.state.pendingResults().toString(), rig.state.pendingResults().isEmpty())
            val firstDelivery = listed(rig.deviceId, lock)!!.text("delivered_at")!!
            val ringFirstDelivery = rig2?.let {
                assertEquals("delivered", status(it, ring!!))
                assertEquals(listOf(ring), it.state.pendingResults().map { p -> p.id })
                listed(it.deviceId, ring)!!.text("delivered_at")!!
            }

            // The real server delivers them again 5 minutes after the first delivery (at its next keep-alive).
            eventually("lock and wipe redelivered, original results recorded", timeoutMs = 9 * 60_000L) { status(rig, lock) == "executed" && status(rig, wipe) == "executed" }
            val waited = System.currentTimeMillis() - start
            assertTrue("results came back after ${waited / 1000} s: not a redelivery", waited >= 295_000)
            val lockRow = listed(rig.deviceId, lock)!!
            assertEquals("ok_message", lockRow.text("detail"))
            assertTrue("delivered_at unchanged (${lockRow.text("delivered_at")}): the server did not deliver it again", lockRow.text("delivered_at") != firstDelivery)
            assertEquals(2, posts[lock]!!.size)
            assertEquals(2, posts[wipe]!!.size)
            assertTrue(posts[lock]!![1] - posts[lock]!![0] >= 295_000)
            // Nothing ran twice; one command.result event per command; nothing left to post.
            assertEquals(listOf("lock:$lock:${CommandParams.Lock("Redelivered after 5 min")}"), rig.executed.toList())
            assertEquals(1, rig.wipes.get())
            assertEquals(2, rig.sink.of("command.result").size)
            eventually("results all acknowledged") { rig.state.pendingResults().isEmpty() }
            var summary = "redelivery by the real collector: lock and wipe redelivered after ${(posts[lock]!![1] - posts[lock]!![0]) / 1000} s, executed once " +
                "(wipe(fake)=${rig.wipes.get()}), original results recorded (lock detail=${lockRow.text("detail")}, statuses lock=${status(rig, lock)} wipe=${status(rig, wipe)})"

            if (rig2 != null) {
                // The ring was delivered again too while its result still could not leave: skipped, not rung again.
                eventually("ring redelivered by the server", timeoutMs = 2 * 60_000L) { listed(rig2.deviceId, ring!!)!!.text("delivered_at") != ringFirstDelivery }
                Thread.sleep(3_000)
                assertEquals("delivered", status(rig2, ring!!))
                assertEquals(1, rig2.executed.size)
                val failedAttempts = posts[ring]!!.size
                drop -= ring
                eventually("ring result finally posted (backoff of the results)", timeoutMs = 12 * 60_000L) { status(rig2, ring) == "executed" }
                assertEquals(listOf("ring:$ring:${CommandParams.Ring(5, false)}"), rig2.executed.toList())
                assertEquals(1, rig2.sink.of("command.result").size)
                eventually("ring result acknowledged") { rig2.state.pendingResults().isEmpty() }
                summary += "; ring (result blocked by $failedAttempts failed posts, redelivered meanwhile) rung once, status=${status(rig2, ring)}"
            }
            System.getenv("WATCHPOST_CROSS_OUT")?.let { File(it).appendText(summary + "\n") }
        } finally {
            rig.close()
            rig2?.close()
        }
    }
}
