package io.github.erwsim.vigie

import io.github.erwsim.vigie.collectors.CollectorsModule
import io.github.erwsim.vigie.core.enroll.EnrollmentParser
import io.github.erwsim.vigie.core.enroll.SingleKeyManager
import io.github.erwsim.vigie.core.event.AgentClock
import io.github.erwsim.vigie.core.event.eventData
import io.github.erwsim.vigie.core.outbox.Outbox
import io.github.erwsim.vigie.core.sink.OutboxEventSink
import io.github.erwsim.vigie.core.testing.Contract
import io.github.erwsim.vigie.core.testing.MemoryPrefs
import io.github.erwsim.vigie.core.testing.TestContext
import io.github.erwsim.vigie.core.testing.openTestDatabase
import io.github.erwsim.vigie.core.upload.IngestHttp
import io.github.erwsim.vigie.core.upload.IngestTarget
import io.github.erwsim.vigie.core.upload.NetState
import io.github.erwsim.vigie.core.upload.PingResult
import io.github.erwsim.vigie.core.upload.UploadLimits
import io.github.erwsim.vigie.core.upload.UploadOutcome
import io.github.erwsim.vigie.core.upload.UploadStatusStore
import io.github.erwsim.vigie.core.upload.Uploader
import io.github.erwsim.vigie.policy.PolicyModule
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.runBlocking
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.Interceptor
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File
import java.nio.file.Files
import java.security.MessageDigest
import java.security.interfaces.ECKey

/**
 * Cross-check with the REAL collector (`server/collector`): the events the APK produces
 * ([ApkSamples]), written to the real outbox (Room), batched, gzipped and sent by the real
 * [Uploader] with the credentials of a `.vigie` file produced by the real `vigie-collector enroll`
 * and read by the real [EnrollmentParser]. Everything must be accepted, nothing rejected.
 *
 * Skipped unless the environment names an enrollment file:
 * - `VIGIE_CROSS_ENROLL`: path of the `.vigie` file;
 * - `VIGIE_CROSS_URL` (optional): base URL to use instead of the file's `ingest_url`. With an
 *   `http://` URL (collector reached directly, as its simulator does in development) the test sets
 *   the `X-Vigie-Client-Cert-Sha256` header itself; with `https://` the client certificate of the
 *   file is presented (mTLS through the reverse proxy) and the server CA of the file is pinned;
 * - `VIGIE_CROSS_OUT` (optional): file receiving a summary (device id, counts, time base).
 *
 *     VIGIE_CROSS_ENROLL=/tmp/s25.vigie ./gradlew :app:testDebugUnitTest --tests '*CrossServerTest*' --rerun
 *
 * The Android Keystore does not exist on the JVM: the key is held by [SingleKeyManager] in memory
 * (same key manager class as on the device, different key storage).
 */
class CrossServerTest {
    private val enrollPath: String? = System.getenv("VIGIE_CROSS_ENROLL")
    private val urlOverride: String? = System.getenv("VIGIE_CROSS_URL")

    private object WallClock : AgentClock {
        private val start = System.nanoTime()
        override fun nowMillis(): Long = System.currentTimeMillis()
        override fun elapsedRealtime(): Long = 3_600_000L + (System.nanoTime() - start) / 1_000_000
    }

    @Test
    fun theRealCollectorAcceptsEverythingTheApkSends() {
        assumeTrue("VIGIE_CROSS_ENROLL not set: cross-check with the real collector skipped", enrollPath != null)
        val parsed = EnrollmentParser.parse(File(enrollPath!!).readBytes())
        // What `vigie-collector enroll` issues: ECDSA P-256 key matching the certificate, CN = device id.
        assertEquals(256, (parsed.privateKey as ECKey).params.curve.field.fieldSize)
        assertTrue(parsed.clientChain.first().subjectX500Principal.name, "CN=${parsed.deviceId}" in parsed.clientChain.first().subjectX500Principal.name)
        assertTrue("warnings: ${parsed.warnings}", parsed.warnings.isEmpty())

        val version = "0.1.0-cross"
        val base = (urlOverride ?: parsed.ingestUrl).toHttpUrl()
        val client = if (base.isHttps) {
            IngestHttp.build(SingleKeyManager("vigie_client", { parsed.privateKey }, { parsed.clientChain }), parsed.serverCa, version)
        } else {
            val fingerprint = MessageDigest.getInstance("SHA-256").digest(parsed.clientChain.first().encoded).joinToString("") { "%02x".format(it) }
            IngestHttp.baseBuilder(version)
                .addInterceptor(Interceptor { chain -> chain.proceed(chain.request().newBuilder().header("X-Vigie-Client-Cert-Sha256", fingerprint).build()) })
                .build()
        }
        val target = IngestTarget(base, parsed.deviceId, parsed.deviceToken, version)

        val ping = IngestHttp.ping(client, target)
        assertTrue("ping: $ping", ping is PingResult.Ok && ping.deviceIdMatches)

        val dir = Files.createTempDirectory("vigie-cross").toFile()
        val context = TestContext(dir)
        val all = CollectorsModule.all(context) + PolicyModule.collectors(context)
        // Recent origin times, on an hour boundary so that the statistics fall in one known hour.
        val t0 = (System.currentTimeMillis() - 2 * 3_600_000L) / 3_600_000L * 3_600_000L + 600_000L
        val samples = ApkSamples(all, t0).produce() + mirrored()
        samples.forEach { Contract.check(it.type, it.data) }

        val db = openTestDatabase(dir)
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
        try {
            val outbox = Outbox(db)
            val sink = OutboxEventSink(outbox, WallClock, "b7e1c0de-cross-${System.currentTimeMillis()}", scope, flushDelayMs = 600_000, maxPending = 1_000_000)
            // Enough events for several batches (500 per batch): the samples, then everything but the
            // inventory again (a real inventory has its own id each time).
            val rounds = 24
            samples.forEach { s -> sink.emit(s.type, s.sev, s.data, s.originTsMs) }
            val repeated = samples.filter { it.type != "app.inventory" }
            repeat(rounds - 1) { repeated.forEach { s -> sink.emit(s.type, s.sev, s.data, s.originTsMs) } }
            val status = UploadStatusStore(MemoryPrefs())
            val uploader = Uploader(outbox, { client to target }, status, WallClock, { NetState(connected = true, metered = false) }, { UploadLimits(false, Long.MAX_VALUE) })
            val total = samples.size + repeated.size * (rounds - 1)
            assertTrue("several batches ($total events)", total > 2 * Uploader.MAX_BATCH_EVENTS)
            val outcome = runBlocking {
                assertTrue(sink.flushNow())
                assertEquals(total.toLong(), outbox.totals.value.count)
                uploader.run(force = true)
            }
            assertEquals("everything sent in one run: ${status.status.value}", UploadOutcome.Sent(total, moreLeft = false), outcome)
            assertEquals("no event rejected by the collector: ${status.status.value.lastRejectReason}", 0L, status.status.value.rejectedTotal)
            assertEquals(0L, outbox.totals.value.count)

            System.getenv("VIGIE_CROSS_OUT")?.let { path ->
                val byType = samples.groupingBy { it.type }.eachCount().toSortedMap()
                File(path).writeText(
                    buildString {
                        appendLine("device_id=${parsed.deviceId}")
                        appendLine("t0_ms=$t0")
                        appendLine("sent=$total")
                        appendLine("rounds=$rounds")
                        appendLine("types=${byType.size}")
                        appendLine("inventory_apps=${ApkSamples.INVENTORY_APPS}")
                        appendLine("transport=${if (base.isHttps) "https+mTLS, pinned CA=${parsed.serverCa.isNotEmpty()}" else "http (header)"}")
                        byType.forEach { (type, n) -> appendLine("type $type $n") }
                    },
                )
            }
        } finally {
            scope.cancel()
            db.close()
        }
    }

    /**
     * Types emitted only from Android callbacks (no data builder to call on the JVM): written here
     * field for field as `DeviceCollector`, `HotspotCollector`, `NfcCollector` and
     * `LocationCollector.providerChanged` write them, and checked against the contract like the rest.
     */
    private fun mirrored(): List<ApkSamples.Sample> = listOf(
        ApkSamples.Sample("device", "device.screen", eventData { put("state", "on") }),
        ApkSamples.Sample("device", "device.screen", eventData { put("state", "unlocked") }),
        ApkSamples.Sample(
            "device", "device.battery",
            eventData {
                put("pct", 83); put("plugged", "usb"); put("status", "charging"); put("temperature_c", 31.5); put("health", "good")
            },
        ),
        ApkSamples.Sample("device", "device.power_save", eventData { put("enabled", false) }),
        ApkSamples.Sample("device", "device.thermal", eventData { put("status", "light") }),
        ApkSamples.Sample("device", "device.boot", eventData { put("reason", "reboot,userrequested") }, sev = 1),
        ApkSamples.Sample("device", "device.shutdown", eventData { put("reason", "shutdown") }, sev = 1),
        ApkSamples.Sample("device", "device.time_changed", eventData { put("delta_ms", -1_250L) }),
        ApkSamples.Sample("device", "device.timezone_changed", eventData { put("tz", "Europe/Paris") }),
        ApkSamples.Sample("device", "device.airplane_mode", eventData { put("enabled", true) }),
        ApkSamples.Sample("location", "location.provider", eventData { put("provider", "gps"); put("enabled", false) }, sev = 1),
        ApkSamples.Sample("hotspot", "net.hotspot", eventData { put("enabled", true) }, sev = 1),
        ApkSamples.Sample("nfc", "net.nfc", eventData { put("enabled", true) }),
    )
}
