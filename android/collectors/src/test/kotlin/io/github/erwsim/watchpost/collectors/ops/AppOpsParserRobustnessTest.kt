package io.github.erwsim.watchpost.collectors.ops

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Random

/**
 * The parser reads a system output never observed on the target phone: whatever comes in, it must answer
 * (a result or a failure), never throw, never invent a count, and stay fast on a large input.
 */
class AppOpsParserRobustnessTest {
    private val sample = """
        History:  mode=HISTORICAL_MODE_ENABLED_ACTIVE

          snapshot:
            begin = 1970-01-01 01:00:00.000  (-56y)
            Uid u0a123:
              Package com.example.app:
                Attribution null:
                  SEND_SMS:
                    [fg-s] = access=3, duration=+1s0ms
                    [bg-s] = access=2, reject=1
    """.trimIndent()

    @Test
    fun `mutilated, shuffled and random inputs never throw and never give a negative or absurd count`() {
        val random = Random(20261116)
        val alphabet = "[]()=:,-|\n\t \u0000\uFFFDaccess=reject=PackageUidHistory:snapshot:SEND_SMS0123456789999999999999999999"
        repeat(3_000) { round ->
            val text = when (round % 4) {
                0 -> sample.take(random.nextInt(sample.length + 1)) // truncated anywhere
                1 -> sample.lines().shuffled(random).joinToString("\n")
                2 -> buildString { repeat(random.nextInt(400)) { append(alphabet[random.nextInt(alphabet.length)]) } }
                else -> sample.map { if (random.nextInt(25) == 0) alphabet[random.nextInt(alphabet.length)] else it }.joinToString("")
            }
            when (val r = AppOpsParser.parseHistory(text, "SEND_SMS")) {
                is HistoryResult.Ok -> r.counts.values.forEach { c ->
                    assertTrue("$round: $c", c.total >= 0 && c.background >= 0 && c.rejected >= 0 && c.background <= c.total)
                }
                is HistoryResult.Failed -> Unit
            }
            AppOpsParser.parseLastAccess(text, "SEND_SMS", 1_800_000_000_000L).values.forEach { assertTrue(it <= 1_800_000_000_000L + 60_000) }
        }
    }

    @Test
    fun `numbers too large for a long, other layouts and huge outputs fail cleanly`() {
        val overflow = sample.replace("access=3", "access=99999999999999999999999999")
        assertEquals(2L, (AppOpsParser.parseHistory(overflow, "SEND_SMS") as HistoryResult.Ok).counts.getValue("com.example.app").total)
        // Android 16 keeps the history elsewhere: no "History:" section at all.
        assertEquals(OpsFailure.NO_HISTORY, (AppOpsParser.parseHistory("Current AppOps Service state:\n  Settings:\n", "SEND_SMS") as HistoryResult.Failed).failure)
        assertEquals(OpsFailure.EMPTY_OUTPUT, (AppOpsParser.parseHistory(" \n\n", "SEND_SMS") as HistoryResult.Failed).failure)
        // 3 MiB (the collector's bound) of one endless line, then of 100 000 entries: a few hundred ms at most.
        val start = System.nanoTime()
        AppOpsParser.parseHistory("History:\n" + "[fg-s] = ".repeat(330_000), "SEND_SMS")
        val many = buildString {
            append("History:  mode=HISTORICAL_MODE_ENABLED_ACTIVE\n  snapshot:\n")
            repeat(100_000) { append("    Package p$it:\n      SEND_SMS:\n        [bg-s] = access=1\n") }
        }
        assertEquals(100_000, (AppOpsParser.parseHistory(many, "SEND_SMS") as HistoryResult.Ok).counts.size)
        assertTrue("parsing took ${(System.nanoTime() - start) / 1_000_000} ms", System.nanoTime() - start < 10_000_000_000L)
    }
}
