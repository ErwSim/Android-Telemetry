package io.github.erwsim.vigie.collectors.risk

import io.github.erwsim.vigie.collectors.apps.AppInventoryLogic
import io.github.erwsim.vigie.core.event.Severity
import io.github.erwsim.vigie.core.event.eventData
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import kotlinx.serialization.json.int

/** What is remembered of the last `app.risk` emitted for an app (persisted state). */
data class RiskEntry(val versionCode: Long, val score: Int, val reasons: List<String>)

/** Pure logic of the `app_risk` collector: when to emit, what to emit, persistence. */
object RiskLogic {
    enum class Trigger {
        /** `PACKAGE_ADDED` / `PACKAGE_REPLACED`: always reported. */
        INSTALL_OR_UPDATE,

        /** Daily scan: reported only when something changed. */
        DAILY,
    }

    fun entryOf(f: AppFacts, a: RiskAssessment) = RiskEntry(f.versionCode, a.score, a.reasonCodes)

    /**
     * Daily rule: emit if the app was never reported, if its version changed (an update missed while the
     * agent was not running) or if its score or its reasons changed. An install or an update is always
     * reported.
     */
    fun shouldEmit(previous: RiskEntry?, now: RiskEntry, trigger: Trigger): Boolean =
        trigger == Trigger.INSTALL_OR_UPDATE || previous == null || previous.versionCode != now.versionCode ||
            previous.score != now.score || previous.reasons != now.reasons

    fun severity(level: RiskLevel): Int = when (level) {
        RiskLevel.LOW -> Severity.INFO
        RiskLevel.MEDIUM -> Severity.NOTABLE
        RiskLevel.HIGH -> Severity.WARNING
    }

    /** `app.risk` data (contract §11.2). */
    fun data(f: AppFacts, a: RiskAssessment) = eventData {
        put("package", f.pkg)
        put("label", f.label)
        if (f.versionCode > 0) put("version_code", f.versionCode)
        put("installer", f.installer)
        put("from_store", f.installer != null && f.installer in AppInventoryLogic.STORES)
        put("score", a.score)
        put("level", a.level.wire)
        putStrings("reasons", a.reasonCodes)
    }

    fun encode(state: Map<String, RiskEntry>): String = JsonObject(
        state.toSortedMap().mapValues { (_, e) ->
            JsonObject(
                mapOf(
                    "vc" to JsonPrimitive(e.versionCode),
                    "s" to JsonPrimitive(e.score),
                    "r" to JsonArray(e.reasons.map(::JsonPrimitive)),
                ),
            )
        },
    ).toString()

    /** Null if absent or unreadable (the next scan then reports every app again, once). */
    fun decode(text: String?): Map<String, RiskEntry>? {
        if (text.isNullOrEmpty()) return null
        return try {
            Json.parseToJsonElement(text).jsonObject.mapValues { (_, v) ->
                val o = v.jsonObject
                RiskEntry(
                    versionCode = o.getValue("vc").jsonPrimitive.long,
                    score = o.getValue("s").jsonPrimitive.int,
                    reasons = o.getValue("r").jsonArray.map { it.jsonPrimitive.content },
                )
            }
        } catch (_: Exception) {
            null
        }
    }
}
