package io.github.erwsim.watchpost

import io.github.erwsim.watchpost.collectors.apps.AppDetails
import io.github.erwsim.watchpost.collectors.apps.AppInventoryLogic
import io.github.erwsim.watchpost.collectors.apps.AppRecord
import io.github.erwsim.watchpost.collectors.apps.PermissionChange
import io.github.erwsim.watchpost.collectors.apps.SpecialAccessSnapshot
import io.github.erwsim.watchpost.collectors.ops.AppOpsLogic
import io.github.erwsim.watchpost.collectors.ops.AppOpsParser
import io.github.erwsim.watchpost.collectors.ops.HistoryResult
import io.github.erwsim.watchpost.collectors.risk.AppFacts
import io.github.erwsim.watchpost.collectors.risk.RiskLevel
import io.github.erwsim.watchpost.collectors.risk.RiskLogic
import io.github.erwsim.watchpost.collectors.risk.RiskScorer
import io.github.erwsim.watchpost.collectors.roles.RoleLogic
import io.github.erwsim.watchpost.core.enroll.EnrollmentParser
import io.github.erwsim.watchpost.core.event.AgentClock
import io.github.erwsim.watchpost.core.event.Severity
import io.github.erwsim.watchpost.core.event.eventData
import io.github.erwsim.watchpost.core.outbox.Outbox
import io.github.erwsim.watchpost.core.sink.OutboxEventSink
import io.github.erwsim.watchpost.core.testing.Contract
import io.github.erwsim.watchpost.core.testing.MemoryPrefs
import io.github.erwsim.watchpost.core.testing.openTestDatabase
import io.github.erwsim.watchpost.core.upload.IngestHttp
import io.github.erwsim.watchpost.core.upload.IngestTarget
import io.github.erwsim.watchpost.core.upload.NetState
import io.github.erwsim.watchpost.core.upload.UploadLimits
import io.github.erwsim.watchpost.core.upload.UploadOutcome
import io.github.erwsim.watchpost.core.upload.UploadStatusStore
import io.github.erwsim.watchpost.core.upload.Uploader
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonObject
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.Interceptor
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File
import java.nio.file.Files
import java.security.MessageDigest

/**
 * Cross-check of contract §11.2 → §11.3 with the REAL collector: an SMS-fraud story told by the real code of
 * the `app_risk`, `app_role` and `app_ops` collectors (scorer, role diff, `dumpsys appops` parser and
 * deltas) and of the `apps` / `special_access` collectors, sent by the real [Uploader]. The collector must
 * accept everything; its detections are then read in the console (`GET /api/console/detections`): expected
 * `detect.new_app_risky` (high risk + SEND_SMS for the fraud app; default keyboard for the new keyboard),
 * `detect.sms_abuse` (the fraud app, not Play services: a system app) and `detect.sensor_background`.
 *
 * Skipped unless `WATCHPOST_CROSS_ENROLL` names the `.watchpost` file of a fresh device and `WATCHPOST_CROSS_URL` the
 * `http://` address of a development collector (the test then sets `X-Watchpost-Client-Cert-Sha256` itself, as
 * the simulator does); `WATCHPOST_CROSS_OUT` receives a summary.
 *
 *     WATCHPOST_CROSS_ENROLL=/tmp/phone.watchpost WATCHPOST_CROSS_URL=http://127.0.0.1:8080 \
 *         ./gradlew :app:testDebugUnitTest --tests '*CrossDetectionsTest*' --rerun
 */
class CrossDetectionsTest {
    private val enrollPath: String? = System.getenv("WATCHPOST_CROSS_ENROLL")

    private object WallClock : AgentClock {
        private val start = System.nanoTime()
        override fun nowMillis(): Long = System.currentTimeMillis()
        override fun elapsedRealtime(): Long = 3_600_000L + (System.nanoTime() - start) / 1_000_000
    }

    private data class Sample(val type: String, val data: JsonObject, val sev: Int, val ts: Long)

    private val fraud = "org.review.coupons"
    private val keyboard = "org.review.keyboard"
    private val recorder = "org.review.recorder"
    private val messages = "com.google.android.apps.messaging"
    private val gms = "com.google.android.gms"

    /** `dumpsys appops --history --op <OP>` as AOSP prints it (see [AppOpsParser]). */
    private fun history(op: String, vararg entries: Pair<String, String>) = buildString {
        appendLine("History:  mode=HISTORICAL_MODE_ENABLED_ACTIVE")
        appendLine()
        appendLine("  snapshot:")
        appendLine("    begin = 1970-01-01 01:00:00.000  (-56y)")
        entries.forEachIndexed { i, (pkg, line) ->
            appendLine("    Uid u0a${200 + i}:")
            appendLine("      Package $pkg:")
            appendLine("        Attribution null:")
            appendLine("          $op:")
            appendLine("            $line")
        }
    }

    private fun counts(text: String, op: String) = (AppOpsParser.parseHistory(text, op) as HistoryResult.Ok).counts

    private fun story(t0: Long): List<Sample> {
        val out = ArrayList<Sample>()
        fun add(type: String, data: JsonObject, sev: Int = Severity.INFO, ts: Long = t0) {
            Contract.check(type, data)
            out += Sample(type, data, sev, ts)
        }
        // The phone before the story: the default SMS app and the system apps.
        add(
            "app.special_access",
            eventData { SpecialAccessSnapshot(emptyList(), emptyList(), emptyList(), emptyList(), emptyList(), emptyList(), emptyList(), mapOf("sms" to messages, "keyboard" to "com.samsung.android.honeyboard")).writeTo(this) },
            ts = t0 - 600_000,
        )
        val system = listOf(messages to "Messages", gms to "Google Play services", "com.samsung.android.honeyboard" to "Samsung Keyboard").map { (pkg, label) ->
            AppInventoryLogic.inventoryItem(AppDetails(pkg, label, true, false, false, 36, t0 - 86_400_000L * 300, t0 - 86_400_000L), AppRecord(pkg, "1", 1, "c".repeat(64), emptySet(), "com.android.vending", system = true))
        }
        AppInventoryLogic.inventoryParts(system, "01JCROSSDETECTIONS00000000", 16 * 1024).forEach { add("app.inventory", it, ts = t0 - 500_000) }

        // 1. A sideloaded app without an icon that declares SEND_SMS and starts at boot.
        val record = AppRecord(fraud, "2.1", 21, "ab".repeat(32), emptySet(), installer = null)
        add("app.installed", AppInventoryLogic.changeData(record), AppInventoryLogic.changeSeverity("app.installed", record, false))
        val facts = AppFacts(
            fraud, label = "Promo Coupons", versionCode = 21, installer = null,
            requested = setOf("android.permission.SEND_SMS", "android.permission.READ_CONTACTS", "android.permission.RECEIVE_BOOT_COMPLETED", "android.permission.INTERNET"),
            bootReceiver = true, launcherActivity = false,
        )
        // At installation nothing is granted yet: the scorer only counts SEND_SMS once it is granted (android/README,
        // `sms_send`: SEND_SMS granted), so the first note is only "medium" and has no SMS reason.
        val atInstall = RiskScorer.score(facts)
        assertEquals("at installation: ${atInstall.reasonCodes}", RiskLevel.MEDIUM, atInstall.level)
        assertTrue(atInstall.reasonCodes.toString(), "sms_send" !in atInstall.reasonCodes)
        add("app.risk", RiskLogic.data(facts, atInstall), RiskLogic.severity(atInstall.level), t0 + 5_000)
        // 2. It obtains SEND_SMS three minutes later (seen by the hourly scan of `apps`)…
        add("app.permission_changed", AppInventoryLogic.permissionData(PermissionChange(fraud, "android.permission.SEND_SMS", true)), Severity.NOTABLE, t0 + 180_000)
        // … and the next daily pass of `app_risk` rates it again: high, SMS fraud combination.
        val granted = facts.copy(granted = setOf("android.permission.SEND_SMS"))
        val risk = RiskScorer.score(granted)
        assertEquals("once SEND_SMS is granted: ${risk.reasonCodes}", RiskLevel.HIGH, risk.level)
        assertTrue(risk.reasonCodes.toString(), "combo_sms_fraud" in risk.reasonCodes)
        add("app.risk", RiskLogic.data(granted, risk), RiskLogic.severity(risk.level), t0 + 3_000_000)
        // 3. A new keyboard is installed and becomes the keyboard in use (real role diff).
        val kb = AppRecord(keyboard, "1.0", 1, "cd".repeat(32), emptySet(), installer = "com.android.vending")
        add("app.installed", AppInventoryLogic.changeData(kb), AppInventoryLogic.changeSeverity("app.installed", kb, false), t0 + 300_000)
        val (changes, _) = RoleLogic.diff(mapOf("sms" to messages, "keyboard" to "com.samsung.android.honeyboard"), mapOf("sms" to messages, "keyboard" to keyboard))
        assertEquals(1, changes.size)
        changes.forEach { add("app.role", RoleLogic.data(it), RoleLogic.severity(it), t0 + 600_000) }
        // 4. One hour of use, read twice from `dumpsys appops` by the real parser.
        val items = ArrayList<io.github.erwsim.watchpost.collectors.ops.OpUsage>()
        val send = AppOpsLogic.OPS.first { it.wire == "send_sms" }
        items += AppOpsLogic.deltas(
            send,
            counts(history("SEND_SMS", messages to "[top-s] = access=40"), "SEND_SMS"),
            counts(history("SEND_SMS", messages to "[top-s] = access=43", fraud to "[bg-s] = access=85", gms to "[cch-s] = access=1"), "SEND_SMS"),
            mapOf(fraud to t0 + 3_500_000),
        )
        val audio = AppOpsLogic.OPS.first { it.wire == "record_audio" }
        items += AppOpsLogic.deltas(
            audio,
            counts(history("RECORD_AUDIO", recorder to "[bg-s] = access=2, duration=+1m0s0ms"), "RECORD_AUDIO"),
            counts(history("RECORD_AUDIO", recorder to "[bg-s] = access=14, duration=+9m0s0ms"), "RECORD_AUDIO"),
            emptyMap(),
        )
        assertEquals(85L, items.first { it.pkg == fraud }.count)
        assertEquals(85L, items.first { it.pkg == fraud }.backgroundCount)
        assertEquals(12L, items.first { it.pkg == recorder }.backgroundCount)
        AppOpsLogic.events(t0, t0 + 3_600_000, items).forEach { add("app.ops", it, ts = t0 + 3_600_000) }
        return out
    }

    @Test
    fun theRealCollectorAcceptsTheStoryOfAnSmsFraudApp() {
        assumeTrue("WATCHPOST_CROSS_ENROLL not set: cross-check with the real collector skipped", enrollPath != null)
        val parsed = EnrollmentParser.parse(File(enrollPath!!).readBytes())
        val base = (System.getenv("WATCHPOST_CROSS_URL") ?: parsed.ingestUrl).toHttpUrl()
        assumeTrue("WATCHPOST_CROSS_URL must be the http:// address of a development collector", !base.isHttps)
        val version = "1.2.0-cross"
        val fingerprint = MessageDigest.getInstance("SHA-256").digest(parsed.clientChain.first().encoded).joinToString("") { "%02x".format(it) }
        val client = IngestHttp.baseBuilder(version)
            .addInterceptor(Interceptor { chain -> chain.proceed(chain.request().newBuilder().header("X-Watchpost-Client-Cert-Sha256", fingerprint).build()) })
            .build()
        val target = IngestTarget(base, parsed.deviceId, parsed.deviceToken, version)
        // Two hours ago, on an hour boundary: the whole story is in the past, in known hours.
        val t0 = (System.currentTimeMillis() - 2 * 3_600_000L) / 3_600_000L * 3_600_000L
        val samples = story(t0)

        val dir = Files.createTempDirectory("watchpost-cross-detect").toFile()
        val db = openTestDatabase(dir)
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
        try {
            val outbox = Outbox(db)
            val sink = OutboxEventSink(outbox, WallClock, "b7e1c0de-detect-${System.currentTimeMillis()}", scope, flushDelayMs = 600_000, maxPending = 1_000_000)
            samples.forEach { s -> sink.emit(s.type, s.sev, s.data, s.ts) }
            val status = UploadStatusStore(MemoryPrefs())
            val uploader = Uploader(outbox, { client to target }, status, WallClock, { NetState(connected = true, metered = false) }, { UploadLimits(false, Long.MAX_VALUE) })
            val outcome = runBlocking {
                assertTrue(sink.flushNow())
                uploader.run(force = true)
            }
            assertEquals("everything sent: ${status.status.value}", UploadOutcome.Sent(samples.size, moreLeft = false), outcome)
            assertEquals("no event rejected by the collector: ${status.status.value.lastRejectReason}", 0L, status.status.value.rejectedTotal)
            System.getenv("WATCHPOST_CROSS_OUT")?.let { path ->
                File(path).writeText(
                    buildString {
                        appendLine("device_id=${parsed.deviceId}")
                        appendLine("t0_ms=$t0")
                        appendLine("sent=${samples.size}")
                        samples.forEach { appendLine("${it.type} ${it.data}") }
                    },
                )
            }
        } finally {
            scope.cancel()
            db.close()
        }
    }
}
