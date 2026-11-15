package io.github.erwsim.vigie.policy.logs

import io.github.erwsim.vigie.core.event.Rfc3339
import io.github.erwsim.vigie.core.event.eventData
import kotlinx.serialization.json.JsonObject

/** One Device Owner network log entry reduced to plain values (from `DnsEvent`/`ConnectEvent`). */
sealed class NetRecord {
    /** `NetworkEvent.getPackageName()`: a package, `<sharedUserId>:<uid>` for a shared uid, or null. */
    abstract val rawPackage: String?
    abstract val timeMs: Long

    data class Dns(
        override val rawPackage: String?,
        override val timeMs: Long,
        val hostname: String,
        val addresses: List<String>,
        val addressCount: Int,
    ) : NetRecord()

    data class Connect(
        override val rawPackage: String?,
        override val timeMs: Long,
        val ip: String,
        val port: Int,
    ) : NetRecord()
}

/** Who made the request. */
data class Owner(val pkg: String?, val uid: Int?)

/**
 * Resolves the app behind a network log entry. The platform gives a package name, or for a shared
 * uid `PackageManager.getNameForUid()` = `<sharedUserId>:<uid>` (e.g. `android.uid.system:1000`).
 * For a shared uid with a single package that package is reported, otherwise the shared user id.
 * Lookups are memoized for one batch.
 */
class OwnerResolver(
    private val uidOf: (String) -> Int?,
    private val packagesForUid: (Int) -> List<String>,
) {
    private val cache = HashMap<String, Owner>()

    fun resolve(raw: String?): Owner {
        if (raw.isNullOrEmpty()) return Owner(null, null)
        return cache.getOrPut(raw) {
            val colon = raw.lastIndexOf(':')
            val uidPart = if (colon > 0) raw.substring(colon + 1).toIntOrNull() else null
            if (uidPart != null) {
                val packages = runCatching { packagesForUid(uidPart) }.getOrDefault(emptyList())
                Owner(packages.singleOrNull() ?: raw.substring(0, colon), uidPart)
            } else {
                Owner(raw, runCatching { uidOf(raw) }.getOrNull())
            }
        }
    }
}

data class NetOutput(val type: String, val data: JsonObject)

/**
 * Turns a retrieved batch into `net.dns` / `net.connect` data (contract §2), optionally aggregated:
 * identical requests (same app and host, or same app, IP and port) in the same window become one
 * event with `count` and `last_event_ts`. `event_ts` is the time of the (first) request: the event's
 * own `ts` is the retrieval time, up to 1 h 30 later.
 */
object NetworkLogProcessor {
    const val MAX_ADDRESSES = 16

    fun process(
        records: List<NetRecord>,
        resolver: OwnerResolver,
        windowMs: Long,
        includeConnect: Boolean,
    ): List<NetOutput> {
        val kept = if (includeConnect) records else records.filterIsInstance<NetRecord.Dns>()
        val groups = aggregateByWindow(kept, windowMs, { it.timeMs }) { r ->
            val owner = resolver.resolve(r.rawPackage)
            when (r) {
                is NetRecord.Dns -> listOf("dns", owner.pkg, owner.uid, r.hostname.lowercase())
                is NetRecord.Connect -> listOf("connect", owner.pkg, owner.uid, r.ip, r.port)
            }
        }
        return groups.map { g -> toOutput(g, resolver.resolve(g.first.rawPackage)) }
    }

    private fun toOutput(g: Aggregated<NetRecord>, owner: Owner): NetOutput = when (val r = g.first) {
        is NetRecord.Dns -> {
            val addresses = g.members.flatMap { (it as NetRecord.Dns).addresses }.distinct().take(MAX_ADDRESSES)
            val total = g.members.maxOf { (it as NetRecord.Dns).addressCount }
            NetOutput(
                "net.dns",
                eventData {
                    put("package", owner.pkg)
                    put("uid", owner.uid)
                    put("hostname", r.hostname)
                    putStrings("addresses", addresses)
                    put("address_count", maxOf(total, addresses.size))
                    timing(g)
                },
            )
        }
        is NetRecord.Connect -> NetOutput(
            "net.connect",
            eventData {
                put("package", owner.pkg)
                put("uid", owner.uid)
                put("ip", r.ip)
                put("port", r.port)
                timing(g)
            },
        )
    }

    private fun io.github.erwsim.vigie.core.event.EventDataBuilder.timing(g: Aggregated<NetRecord>) {
        put("event_ts", Rfc3339.format(g.firstMs))
        if (g.count > 1) {
            put("count", g.count)
            put("last_event_ts", Rfc3339.format(g.lastMs))
        }
    }

    /** Batch tokens are consecutive: a gap means batches were dropped by the system before retrieval. */
    fun lostBatches(lastProcessed: Long, token: Long): Long = if (lastProcessed <= 0 || token <= lastProcessed) 0 else token - lastProcessed - 1
}
