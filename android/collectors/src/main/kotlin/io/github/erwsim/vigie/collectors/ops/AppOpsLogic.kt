package io.github.erwsim.vigie.collectors.ops

import io.github.erwsim.vigie.collectors.apps.AppInventoryLogic
import io.github.erwsim.vigie.core.event.Rfc3339
import io.github.erwsim.vigie.core.event.eventData
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long

/** An operation of the contract: its `app.ops.op` value and its name in the system's dump. */
data class OpSpec(val wire: String, val dumpName: String)

/** One element of `app.ops.apps`. */
data class OpUsage(val pkg: String, val op: String, val count: Long, val backgroundCount: Long, val lastTs: Long?, val rejectedCount: Long = 0)

/** What is remembered between two readings: the sums per op and the time of the reading that gave them. */
data class OpsState(val sums: Map<String, Map<String, OpCounts>>, val atMs: Map<String, Long>)

/** Pure logic of the `app_ops` collector. */
object AppOpsLogic {
    /** The ten operations of contract §11.2, in the order they are read. */
    val OPS = listOf(
        OpSpec("send_sms", "SEND_SMS"),
        OpSpec("read_sms", "READ_SMS"),
        OpSpec("receive_sms", "RECEIVE_SMS"),
        OpSpec("call_phone", "CALL_PHONE"),
        OpSpec("read_contacts", "READ_CONTACTS"),
        OpSpec("read_call_log", "READ_CALL_LOG"),
        OpSpec("record_audio", "RECORD_AUDIO"),
        OpSpec("camera", "CAMERA"),
        OpSpec("fine_location", "FINE_LOCATION"),
        OpSpec("get_accounts", "GET_ACCOUNTS"),
    )

    /** A reading older than this is only a new baseline (the gap would not be an hour any more). */
    const val MAX_WINDOW_MS = 24 * 3_600_000L

    /** Items per event are cut by size (the 32 KiB event limit) and in number (one hour is not a database). */
    const val PART_BYTES = 12 * 1024
    const val MAX_ITEMS = 300

    /**
     * Usage between two readings of one op: the increase of each package's sums. A sum that went down (old
     * snapshots expired from the system's history) counts as 0, never as a negative or a reset: the result is
     * a lower bound. A package seen for the first time counts in full (it did something since the baseline).
     * Background is bounded by the total.
     */
    fun deltas(op: OpSpec, previous: Map<String, OpCounts>, now: Map<String, OpCounts>, lastAccess: Map<String, Long>): List<OpUsage> =
        now.mapNotNull { (pkg, c) ->
            val p = previous[pkg]
            val count = c.total - (p?.total ?: 0L)
            val rejected = c.rejected - (p?.rejected ?: 0L)
            // An op only refused (no access) is reported too: a refused attempt is as telling as a successful one.
            if (count <= 0 && rejected <= 0) return@mapNotNull null
            val newCount = maxOf(count, 0L)
            val bg = (c.background - (p?.background ?: 0L)).coerceIn(0L, newCount)
            OpUsage(pkg, op.wire, newCount, bg, lastAccess[pkg], maxOf(rejected, 0L))
        }

    /** Largest usage (accesses + refusals) first (ties: package, op), cut to [MAX_ITEMS]. */
    fun sorted(items: List<OpUsage>): List<OpUsage> =
        items.sortedWith(compareByDescending<OpUsage> { it.count + it.rejectedCount }.thenBy { it.pkg }.thenBy { it.op }).take(MAX_ITEMS)

    fun item(u: OpUsage): JsonObject = eventData {
        put("package", u.pkg)
        put("op", u.op)
        put("count", u.count)
        put("background_count", u.backgroundCount)
        put("rejected_count", u.rejectedCount)
        put("last_ts", u.lastTs?.let(Rfc3339::format))
    }

    /** The `app.ops` events of one window: same `from`/`to`, items cut into parts of at most [PART_BYTES]. */
    fun events(fromMs: Long, toMs: Long, items: List<OpUsage>): List<JsonObject> {
        if (items.isEmpty()) return emptyList()
        val parts = AppInventoryLogic.chunkBySize(sorted(items).map(::item), PART_BYTES)
        return parts.map { part ->
            eventData {
                put("from", Rfc3339.format(fromMs))
                put("to", Rfc3339.format(toMs))
                put("apps", JsonArray(part))
            }
        }
    }

    fun encode(s: OpsState): String = JsonObject(
        mapOf(
            "t" to JsonObject(s.atMs.mapValues { JsonPrimitive(it.value) }),
            "c" to JsonObject(
                s.sums.mapValues { (_, byPkg) ->
                    JsonObject(byPkg.toSortedMap().mapValues { JsonArray(listOf(JsonPrimitive(it.value.total), JsonPrimitive(it.value.background), JsonPrimitive(it.value.rejected))) })
                },
            ),
        ),
    ).toString()

    /** Null if absent or unreadable: the next reading is then only a baseline. */
    fun decode(text: String?): OpsState? {
        if (text.isNullOrEmpty()) return null
        return try {
            val o = Json.parseToJsonElement(text).jsonObject
            OpsState(
                sums = o.getValue("c").jsonObject.mapValues { (_, byPkg) ->
                    byPkg.jsonObject.mapValues { (_, v) -> OpCounts(v.jsonArray[0].jsonPrimitive.long, v.jsonArray[1].jsonPrimitive.long, v.jsonArray.getOrNull(2)?.jsonPrimitive?.long ?: 0L) }
                },
                atMs = o.getValue("t").jsonObject.mapValues { it.value.jsonPrimitive.long },
            )
        } catch (_: Exception) {
            null
        }
    }
}
