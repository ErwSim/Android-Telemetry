package io.github.erwsim.watchpost.policy.logs

import io.github.erwsim.watchpost.core.event.Rfc3339
import io.github.erwsim.watchpost.core.event.eventData
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/** Filtering of the chatty tags. */
data class SecurityLogFilter(
    /** `app_process_start` (one entry per process start: hundreds per hour). */
    val appProcessStart: Boolean = true,
    /** Merge identical `app_process_start` (same process, uid and APK hash) per window. */
    val aggregateAppProcess: Boolean = true,
    val windowMs: Long = 60 * 60_000L,
    /** `wifi_connection`/`wifi_disconnection`/`bluetooth_connection`/`bluetooth_disconnection`. */
    val radio: Boolean = true,
)

/** [tsMs]: time of the (first) log entry, the event's `ts` (contract §2 "Précisions"). */
data class SecurityOutput(val sev: Int, val data: JsonObject, val tsMs: Long)

/** Batch → `security.log` data (contract §2). Pure (tested on the JVM). */
object SecurityLogProcessor {
    const val TYPE = "security.log"
    private val RADIO_TAGS = setOf("wifi_connection", "wifi_disconnection", "bluetooth_connection", "bluetooth_disconnection")

    /**
     * @param afterNanos only entries strictly newer than this (pre-reboot logs overlap with what was
     *   already retrieved before the reboot).
     * @param preReboot marks entries from `retrievePreRebootSecurityLogs` (`pre_reboot: true`).
     */
    fun process(raw: List<RawSecurityEvent>, filter: SecurityLogFilter, afterNanos: Long = Long.MIN_VALUE, preReboot: Boolean = false): List<SecurityOutput> {
        val translated = raw.asSequence()
            .filter { it.timeNanos > afterNanos }
            .sortedBy { it.timeNanos }
            .map(SecurityLogTranslator::translate)
            .filter { filter.radio || it.tag !in RADIO_TAGS }
            .filter { filter.appProcessStart || it.tag != APP_PROCESS_START }
            .toList()
        val window = if (filter.aggregateAppProcess) filter.windowMs else 0L
        val (processes, others) = translated.partition { it.tag == APP_PROCESS_START }
        val outputs = ArrayList<SecurityOutput>()
        others.forEach { outputs += output(it, 1, it.timeMs, it.timeMs, preReboot) }
        aggregateByWindow(processes, window, { it.timeMs }) { t ->
            listOf(str(t, "process"), str(t, "uid"), str(t, "apk_sha256"))
        }.forEach { g -> outputs += output(g.first, g.count, g.firstMs, g.lastMs, preReboot) }
        return outputs.sortedBy { it.tsMs }
    }

    private fun str(t: TranslatedSecurityEvent, key: String): String? = (t.fields[key] as? JsonPrimitive)?.content

    private fun output(t: TranslatedSecurityEvent, count: Int, firstMs: Long, lastMs: Long, preReboot: Boolean) = SecurityOutput(
        t.sev,
        eventData {
            put("tag", t.tag)
            put("level", t.level)
            put("log_id", t.logId)
            put("fields", t.fields)
            if (count > 1) {
                put("count", count)
                put("last_event_ts", Rfc3339.format(lastMs))
            }
            if (preReboot) put("pre_reboot", true)
        },
        firstMs,
    )

    /** CA tags trigger an immediate user CA check (security.ca_cert). */
    fun touchesCertificates(outputs: List<SecurityOutput>): Boolean = outputs.any {
        val tag = (it.data["tag"] as? JsonPrimitive)?.content
        tag == "cert_authority_installed" || tag == "cert_authority_removed"
    }

    private const val APP_PROCESS_START = "app_process_start"
}
