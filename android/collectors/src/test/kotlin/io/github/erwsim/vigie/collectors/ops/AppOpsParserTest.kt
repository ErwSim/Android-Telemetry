package io.github.erwsim.vigie.collectors.ops

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.TimeZone

class AppOpsParserTest {
    private fun ok(text: String, op: String) = AppOpsParser.parseHistory(text, op) as HistoryResult.Ok
    private fun failed(text: String, op: String = "SEND_SMS") = (AppOpsParser.parseHistory(text, op) as HistoryResult.Failed).failure

    @Test
    fun historySumsAccessesPerPackageOverEverySnapshotAndAttribution() {
        val r = ok(OpsSamples.HISTORY_SEND_SMS, "SEND_SMS")
        assertEquals(3, r.snapshots)
        assertEquals("HISTORICAL_MODE_ENABLED_ACTIVE", r.mode)
        assertEquals(
            mapOf(
                "com.android.phone" to OpCounts(4, 0),
                // bg 37 + fg 2, then cch 120 + bg 11 (reject=3 and duration are not accesses).
                "com.example.fastsms" to OpCounts(37 + 2 + 120 + 11, 37 + 120 + 11),
                // Another attribution tag of another package of the same uid; fgsvc is not background.
                "com.example.fastsms.helper" to OpCounts(5, 0),
                // top-s 1 + top-tp 2 (proxied flags are accesses too).
                "org.thoughtcrime.sms" to OpCounts(3, 0),
            ),
            r.counts,
        )
    }

    @Test
    fun historyOnlyCountsTheRequestedOp() {
        val r = ok(OpsSamples.HISTORY_SEND_SMS, "READ_SMS")
        assertEquals(
            mapOf(
                "com.example.fastsms.helper" to OpCounts(99, 0),
                "org.thoughtcrime.sms" to OpCounts(8, 0),
                "com.example.onlyreads" to OpCounts(3, 0),
            ),
            r.counts,
        )
        assertTrue(ok(OpsSamples.HISTORY_SEND_SMS, "CAMERA").counts.isEmpty())
    }

    @Test
    fun anOpNobodyUsedIsAnEmptyResultNotAFailure() {
        val r = ok(OpsSamples.HISTORY_EMPTY_FOR_OP, "SEND_SMS")
        assertTrue(r.counts.isEmpty())
        assertEquals(1, r.snapshots)
    }

    @Test
    fun historyToleratesIndentationBlankLinesUnknownLinesAndMissingLevels() {
        val text = """
            History:  mode=HISTORICAL_MODE_ENABLED_ACTIVE
            snapshot:
            Uid 10123:
            Package com.a:
            SEND_SMS:
            [bg-s] = access=2
            some future line we do not know = 12
            [fg-s|tp] = access=1, reject=7, duration=3s
            [fg-s] = reject=4
            Package com.b:
            Attribution x:
            SEND_SMS:
            [unknown-s] = access=9
            [gone-up] = access=1
        """.trimIndent()
        val r = ok(text, "SEND_SMS")
        assertEquals(OpCounts(3, 2), r.counts["com.a"])
        // Unknown and "gone" states count as accesses, not as background.
        assertEquals(OpCounts(10, 0), r.counts["com.b"])
    }

    @Test
    fun historyIgnoresWindowsLineEndingsAndSurroundingNoise() {
        val text = "garbage before\r\n" + OpsSamples.HISTORY_SEND_SMS.replace("\n", "\r\n") + "\r\nlogcat noise\r\n"
        assertEquals(4, ok(text, "SEND_SMS").counts.size)
    }

    @Test
    fun everyKnownFailureIsRecognisedAndNeverThrows() {
        assertEquals(OpsFailure.PERMISSION_DENIED, failed(OpsSamples.PERMISSION_DENIED))
        assertEquals(OpsFailure.PERMISSION_DENIED, failed(OpsSamples.PERMISSION_DENIED_USAGE))
        assertEquals(OpsFailure.UNKNOWN_OPTION, failed(OpsSamples.UNKNOWN_OPTION))
        assertEquals(OpsFailure.UNKNOWN_OPTION, failed(OpsSamples.UNKNOWN_OP))
        assertEquals(OpsFailure.EMPTY_OUTPUT, failed(""))
        assertEquals(OpsFailure.EMPTY_OUTPUT, failed("  \n\n  "))
        assertEquals(OpsFailure.NO_HISTORY, failed(OpsSamples.HISTORY_ABSENT_ANDROID16_SQL))
        assertEquals(OpsFailure.HISTORY_DISABLED, failed(OpsSamples.HISTORY_DISABLED))
        assertEquals(OpsFailure.HISTORY_DISABLED, failed(OpsSamples.HISTORY_DISABLED.replace("DISABLED", "ENABLED_PASSIVE")))
        assertEquals(OpsFailure.NO_HISTORY, failed("something completely different\nwith lines"))
        // A History section without any snapshot is another layout.
        assertEquals(OpsFailure.UNRECOGNIZED, failed("History:  mode=HISTORICAL_MODE_ENABLED_ACTIVE\n  Empty"))
        // Binary garbage and huge lines.
        assertEquals(OpsFailure.NO_HISTORY, failed("\u0000\u0001\u0002".repeat(1000)))
        assertEquals(OpsFailure.NO_HISTORY, failed("x".repeat(500_000)))
    }

    @Test
    fun aFutureLayoutWithoutTheStateKeyYieldsNoCountRatherThanAWrongOne() {
        // Plausible future change: entries no longer keyed by "[state-flags]". Nothing is attributed.
        val text = """
            History:  mode=HISTORICAL_MODE_ENABLED_ACTIVE
              snapshot:
                Uid u0a1:
                  Package com.a:
                    SEND_SMS:
                      fg/self -> accessCount: 5
        """.trimIndent()
        assertTrue(ok(text, "SEND_SMS").counts.isEmpty())
    }

    // ---- Current state: last access time ----

    private val now = 1_763_298_245_246L // Any fixed instant.

    @Test
    fun lastAccessUsesTheRelativeDurationAndKeepsTheMostRecent() {
        val m = AppOpsParser.parseLastAccess(OpsSamples.STATE_SEND_SMS, "SEND_SMS", now, TimeZone.getTimeZone("UTC"))
        // cch -5m3s123ms is more recent than bg -11m8s246ms; the Reject line is not an access.
        assertEquals(now - (5 * 60_000L + 3_123), m["com.example.fastsms"])
        assertEquals(now - 3_500, m["com.example.fastsms.helper"])
        assertEquals(now - (5 * 3_600_000L + 8 * 60_000L + 5_246), m["org.thoughtcrime.sms"])
        assertEquals(3, m.size)
    }

    @Test
    fun lastAccessFallsBackToTheDateWhenTheDurationIsMissingOrMalformed() {
        val text = """
            Uid u0a1:
              Package com.a:
                SEND_SMS (allow):
                  null=[
                    Access: [bg-s] 2026-11-16 13:04:05.123 (garbage)
                  ]
              Package com.b:
                SEND_SMS (ignore):
                  null=[
                    Access: [bg-s] 2026-11-16 13:00:00.000
                  ]
        """.trimIndent()
        val m = AppOpsParser.parseLastAccess(text, "SEND_SMS", java.time.Instant.parse("2026-11-16T13:10:00Z").toEpochMilli(), TimeZone.getTimeZone("UTC"))
        // 2026-11-16T13:04:05.123Z and 13:00:00.000Z.
        assertEquals(java.time.Instant.parse("2026-11-16T13:04:05.123Z").toEpochMilli(), m["com.a"])
        assertEquals(java.time.Instant.parse("2026-11-16T13:00:00.000Z").toEpochMilli(), m["com.b"])
    }

    @Test
    fun lastAccessOnlyReadsTheRequestedOpAndNeverThrows() {
        assertTrue(AppOpsParser.parseLastAccess(OpsSamples.STATE_SEND_SMS, "READ_SMS", now).isEmpty())
        assertTrue(AppOpsParser.parseLastAccess("", "SEND_SMS", now).isEmpty())
        assertTrue(AppOpsParser.parseLastAccess(OpsSamples.PERMISSION_DENIED, "SEND_SMS", now).isEmpty())
        // An access dated far in the future (clock quirk) is ignored.
        val future = "Package a:\n  SEND_SMS (allow):\n    Access: [fg-s] 2030-01-01 00:00:00.000 (+3y)\n"
        assertTrue(AppOpsParser.parseLastAccess(future, "SEND_SMS", now).isEmpty())
    }

    @Test
    fun durationsAreThoseOfTimeUtilsFormatDuration() {
        assertEquals(-(5 * 60_000L + 3_123), AppOpsParser.parseDuration("-5m3s123ms"))
        assertEquals(-(86_400_000L + 3 * 3_600_000L + 14 * 60_000L + 50_000L + 312), AppOpsParser.parseDuration("-1d3h14m50s312ms"))
        assertEquals(-100L, AppOpsParser.parseDuration("-100ms"))
        assertEquals(1_000L, AppOpsParser.parseDuration("+1s0ms"))
        assertEquals(0L, AppOpsParser.parseDuration("0"))
        assertEquals(-(3_600_000L + 5 * 60_000L + 5), AppOpsParser.parseDuration("-1h05m00s005ms"))
        assertNull(AppOpsParser.parseDuration("garbage"))
        assertNull(AppOpsParser.parseDuration("5m"))
        assertNull(AppOpsParser.parseDuration("-"))
        assertNull(AppOpsParser.parseDuration("-5x"))
    }
}
