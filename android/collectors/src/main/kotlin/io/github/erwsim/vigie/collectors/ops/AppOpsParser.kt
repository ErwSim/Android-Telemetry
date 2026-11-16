package io.github.erwsim.vigie.collectors.ops

import java.text.SimpleDateFormat
import java.util.Locale
import java.util.TimeZone

/** Why a reading of `dumpsys appops` is unusable (each one has a French reason in the resources). */
enum class OpsFailure(val code: String) {
    /** `Permission Denial: can't dump appops … missing android.permission.DUMP / PACKAGE_USAGE_STATS`. */
    PERMISSION_DENIED("permission_denied"),

    /** The service did not understand an option (`Unknown option:`, `No argument for`…): the format changed. */
    UNKNOWN_OPTION("unknown_option"),

    /** Nothing at all came out of the dump. */
    EMPTY_OUTPUT("empty_output"),

    /** No `History:` section (history stored elsewhere, e.g. the SQLite store of Android 16, or disabled). */
    NO_HISTORY("no_history"),

    /** `History:  mode=HISTORICAL_MODE_DISABLED` (or `_PASSIVE`: nothing is counted either). */
    HISTORY_DISABLED("history_disabled"),

    /** Text received but none of the expected structure found. */
    UNRECOGNIZED("unrecognized"),

    /** Output larger than the bound: partial sums would be wrong, so it is not used. */
    TRUNCATED("truncated"),

    /** The service did not answer in time. */
    TIMEOUT("timeout"),

    /** `Debug.dumpService` returned false (service not reachable: SELinux, missing service…). */
    DUMP_FAILED("dump_failed"),
}

/** Accesses of one package for one op, summed over every snapshot of the history. */
data class OpCounts(val total: Long, val background: Long)

sealed interface HistoryResult {
    /** [counts]: package → accesses (empty is legitimate: nobody used the op). [snapshots]: `snapshot:` blocks read. */
    data class Ok(val counts: Map<String, OpCounts>, val snapshots: Int, val mode: String?) : HistoryResult

    data class Failed(val failure: OpsFailure, val detail: String? = null) : HistoryResult
}

/**
 * Tolerant parser of `dumpsys appops`. The text is not an API; the formats below were read in the AOSP
 * sources of Android 14, 15 and 16 (`AppOpsService.dump`, `HistoricalRegistry`/`LegacyHistoricalRegistry`
 * `StringDumpVisitor`, `AppOpsManager.keyToString`), NOT observed on the Samsung phone.
 *
 * 1. History (`dumpsys appops --history --op SEND_SMS`), the only place with COUNTS:
 * ```
 *   History:  mode=HISTORICAL_MODE_ENABLED_ACTIVE
 *
 *     snapshot:
 *       begin = 1970-01-01 01:00:00.000  (-56y…)      <- relative to the history epoch: never used
 *       end = …
 *
 *       Uid u0a123:
 *         Package com.example.app:
 *           Attribution null:
 *             SEND_SMS:
 *               [fg-s] = access=3, duration=…
 *               [bg-s] = access=2, reject=1
 * ```
 * The entry key is `[<uid state>-<flags>]` (`pers top fgsvcl fgsvc fg bg cch gone`; flags `s tp up tpd upd`
 * joined by `|`). Counts are summed over all snapshots, attributions and flags of a package; "background" =
 * the states `bg` and `cch`. A header at another indentation, an unknown line, a missing `Attribution` level
 * are all tolerated: the parser tracks only the nearest `Package` line and `OP:` line above an entry.
 *
 * 2. Current state (`dumpsys appops --op SEND_SMS`), used only for the last access time:
 * ```
 *     Package com.example.app:
 *       SEND_SMS (allow):
 *         null=[
 *           Access: [bg-s] 2026-11-16 13:04:05.123 (-5m3s123ms)
 *           Reject: [fg-s]2026-11-16 12:00:00.000 (-1h4m5s0ms)      <- yes, no space: a quirk of the source
 *         ]
 * ```
 *
 * Counts are only valid as DIFFERENCES between two readings (see [AppOpsLogic.deltas]): the absolute dates of
 * history snapshots are not reliable, the sums are.
 */
object AppOpsParser {
    private val PACKAGE_LINE = Regex("^Package (\\S+):$")
    private val UID_LINE = Regex("^Uid \\S+:$")
    private val HISTORY_HEADER = Regex("^History:(?:\\s+mode=(\\S+))?")
    private val HISTORY_OP_LINE = Regex("^([A-Z][A-Z0-9_]*):$")
    private val STATE_OP_LINE = Regex("^([A-Z][A-Z0-9_]*) \\([^)]*\\):$")
    private val ENTRY_LINE = Regex("^\\[([a-z]+)(?:-([a-z|]*))?]\\s*=\\s*(.*)$")
    private val ACCESS = Regex("(?:^|[ ,])access=(\\d+)")
    private val ACCESS_LINE = Regex("^Access:\\s*\\[([a-z]+)(?:-([a-z|]*))?]\\s*(\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2}\\.\\d{3})?\\s*(?:\\(([^)]*)\\))?")
    private val DURATION_TOKEN = Regex("(\\d+)(ms|d|h|m|s)")

    /** Uid states counted as "background". */
    val BACKGROUND_STATES = setOf("bg", "cch")

    private val ERROR_PREFIXES = listOf("Unknown option", "Unknown command", "No argument for", "Wrong parameter", "Unknown package", "Error:")

    /** Counts of [op] (a simple name such as `SEND_SMS`) in the output of `--history --op`. Never throws. */
    fun parseHistory(text: String, op: String): HistoryResult {
        try {
            failureOf(text)?.let { return it }
            var mode: String? = null
            var headerSeen = false
            var snapshots = 0
            var pkg: String? = null
            var currentOp: String? = null
            val total = LinkedHashMap<String, Long>()
            val background = HashMap<String, Long>()
            for (raw in text.lineSequence()) {
                val line = raw.trim()
                if (line.isEmpty()) continue
                val header = HISTORY_HEADER.find(line)
                if (header != null) {
                    headerSeen = true
                    mode = header.groupValues[1].ifEmpty { null }
                    continue
                }
                when {
                    line == "snapshot:" -> {
                        snapshots++
                        pkg = null
                        currentOp = null
                    }
                    UID_LINE.matches(line) -> {
                        pkg = null
                        currentOp = null
                    }
                    PACKAGE_LINE.matches(line) -> {
                        pkg = PACKAGE_LINE.matchEntire(line)!!.groupValues[1]
                        currentOp = null
                    }
                    HISTORY_OP_LINE.matches(line) -> currentOp = HISTORY_OP_LINE.matchEntire(line)!!.groupValues[1]
                    else -> {
                        val entry = ENTRY_LINE.matchEntire(line) ?: continue
                        val p = pkg ?: continue
                        if (currentOp != op) continue
                        val n = ACCESS.find(entry.groupValues[3])?.groupValues?.get(1)?.toLongOrNull() ?: continue
                        total[p] = (total[p] ?: 0L) + n
                        if (entry.groupValues[1] in BACKGROUND_STATES) background[p] = (background[p] ?: 0L) + n
                    }
                }
            }
            if (!headerSeen) return HistoryResult.Failed(OpsFailure.NO_HISTORY, firstLine(text))
            // PASSIVE: the service does not count accesses itself (`incrementOpAccessedCount` only acts in ACTIVE mode).
            if (mode?.contains("DISABLED") == true || mode?.contains("PASSIVE") == true) return HistoryResult.Failed(OpsFailure.HISTORY_DISABLED, mode)
            // The service always prints the in-memory snapshot first: none at all means another layout.
            if (snapshots == 0) return HistoryResult.Failed(OpsFailure.UNRECOGNIZED, "History: sans snapshot")
            return HistoryResult.Ok(total.mapValues { (p, t) -> OpCounts(t, background[p] ?: 0L) }, snapshots, mode)
        } catch (e: Exception) {
            return HistoryResult.Failed(OpsFailure.UNRECOGNIZED, e.toString())
        }
    }

    /** Failure that can be told from the whole text (denied, unknown option, empty), else null. */
    private fun failureOf(text: String): HistoryResult.Failed? {
        if (text.isBlank()) return HistoryResult.Failed(OpsFailure.EMPTY_OUTPUT)
        val head = text.lineSequence().firstOrNull { it.isNotBlank() }?.trim().orEmpty()
        return when {
            text.contains("Permission Denial") -> HistoryResult.Failed(OpsFailure.PERMISSION_DENIED, firstLine(text))
            ERROR_PREFIXES.any { head.startsWith(it) } -> HistoryResult.Failed(OpsFailure.UNKNOWN_OPTION, head)
            else -> null
        }
    }

    private fun firstLine(text: String) = text.lineSequence().firstOrNull { it.isNotBlank() }?.trim()?.take(200)

    /**
     * Last access time (epoch ms) per package for [op] in the output of `--op`, from the `Access:` lines
     * (the most recent over every uid state). The relative duration in parentheses is preferred to the
     * absolute date (no time zone involved); the date is the fallback. Never throws.
     */
    fun parseLastAccess(text: String, op: String, nowMs: Long, zone: TimeZone = TimeZone.getDefault()): Map<String, Long> {
        val result = LinkedHashMap<String, Long>()
        try {
            var pkg: String? = null
            var inOp = false
            for (raw in text.lineSequence()) {
                val line = raw.trim()
                if (line.isEmpty()) continue
                when {
                    UID_LINE.matches(line) -> {
                        pkg = null
                        inOp = false
                    }
                    PACKAGE_LINE.matches(line) -> {
                        pkg = PACKAGE_LINE.matchEntire(line)!!.groupValues[1]
                        inOp = false
                    }
                    STATE_OP_LINE.matches(line) -> inOp = STATE_OP_LINE.matchEntire(line)!!.groupValues[1] == op
                    inOp && pkg != null && line.startsWith("Access:") -> {
                        val m = ACCESS_LINE.find(line) ?: continue
                        val at = m.groupValues[4].takeIf { it.isNotEmpty() }?.let(::parseDuration)?.let { nowMs + it }
                            ?: m.groupValues[3].takeIf { it.isNotEmpty() }?.let { parseDate(it, zone) }
                            ?: continue
                        if (at <= nowMs + FUTURE_SLACK_MS) result.merge(pkg, at) { a, b -> maxOf(a, b) }
                    }
                }
            }
        } catch (_: Exception) {
            // Best effort: whatever was read.
        }
        return result
    }

    private const val FUTURE_SLACK_MS = 60_000L

    /** `TimeUtils.formatDuration`: `-5m3s123ms`, `+1d2h03m04s005ms`, `0`, `-100ms` → signed milliseconds; null if not one. */
    fun parseDuration(text: String): Long? {
        val s = text.trim()
        if (s == "0" || s == "+0" || s == "-0") return 0L
        val sign = when (s.firstOrNull()) {
            '-' -> -1L
            '+' -> 1L
            else -> return null
        }
        val body = s.substring(1)
        var rest = body
        var ms = 0L
        var any = false
        while (rest.isNotEmpty()) {
            val m = DURATION_TOKEN.find(rest)?.takeIf { it.range.first == 0 } ?: return null
            val n = m.groupValues[1].toLongOrNull() ?: return null
            ms += n * when (m.groupValues[2]) {
                "d" -> 86_400_000L
                "h" -> 3_600_000L
                "m" -> 60_000L
                "s" -> 1_000L
                else -> 1L
            }
            any = true
            rest = rest.substring(m.range.last + 1)
        }
        return if (any) sign * ms else null
    }

    private fun parseDate(text: String, zone: TimeZone): Long? = try {
        SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS", Locale.US).apply { timeZone = zone; isLenient = false }.parse(text)?.time
    } catch (_: Exception) {
        null
    }
}
