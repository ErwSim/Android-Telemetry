package io.github.erwsim.vigie.policy

import io.github.erwsim.vigie.core.event.Rfc3339
import io.github.erwsim.vigie.core.testing.Contract
import io.github.erwsim.vigie.policy.logs.NetRecord
import io.github.erwsim.vigie.policy.logs.NetworkLogProcessor
import io.github.erwsim.vigie.policy.logs.OwnerResolver
import io.github.erwsim.vigie.policy.logs.aggregateByWindow
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class NetworkLogTest {
    private val t0 = 1_763_242_800_000L // aligned on 10 minutes
    private var lookups = 0
    private fun resolver() = OwnerResolver(
        uidOf = { pkg ->
            lookups++
            mapOf("com.google.android.gms" to 10150, "com.whatsapp" to 10201)[pkg]
        },
        packagesForUid = { uid -> mapOf(1000 to listOf("android", "com.android.settings"), 10500 to listOf("com.only.one"))[uid].orEmpty() },
    )

    private fun JsonObject.s(k: String) = this[k]?.jsonPrimitive?.content

    @Test
    fun `owner resolution - package, shared uid, single-package shared uid, unknown`() {
        val r = resolver()
        assertEquals("com.google.android.gms" to 10150, r.resolve("com.google.android.gms").let { it.pkg to it.uid })
        assertEquals("android.uid.system" to 1000, r.resolve("android.uid.system:1000").let { it.pkg to it.uid })
        assertEquals("com.only.one" to 10500, r.resolve("shared.one:10500").let { it.pkg to it.uid })
        assertEquals("com.unknown" to null, r.resolve("com.unknown").let { it.pkg to it.uid })
        assertEquals(null to null, r.resolve(null).let { it.pkg to it.uid })
        // Memoized per batch.
        r.resolve("com.google.android.gms")
        assertEquals(2, lookups)
    }

    @Test
    fun `dns and connect events follow the contract, with event time`() {
        val records = listOf(
            NetRecord.Dns("com.google.android.gms", t0 + 1_000, "app-measurement.com", listOf("142.250.1.1"), 1),
            NetRecord.Connect("android.uid.system:1000", t0 + 2_000, "142.250.1.1", 443),
        )
        val out = NetworkLogProcessor.process(records, resolver(), windowMs = 0, includeConnect = true)
        assertEquals(listOf("net.dns", "net.connect"), out.map { it.type })
        val dns = out[0].data
        assertEquals("com.google.android.gms", dns.s("package"))
        assertEquals("10150", dns.s("uid"))
        assertEquals("app-measurement.com", dns.s("hostname"))
        assertEquals(listOf("142.250.1.1"), dns["addresses"]!!.jsonArray.map { it.jsonPrimitive.content })
        assertEquals("1", dns.s("address_count"))
        // ts = time of the request (origin), no event_ts field.
        assertEquals(t0 + 1_000, out[0].tsMs)
        assertEquals(t0 + 2_000, out[1].tsMs)
        assertNull(dns["event_ts"])
        assertNull(dns["count"])
        out.forEach { Contract.check(it.type, it.data) }
        val connect = out[1].data
        assertEquals("android.uid.system", connect.s("package"))
        assertEquals("1000", connect.s("uid"))
        assertEquals("142.250.1.1", connect.s("ip"))
        assertEquals("443", connect.s("port"))
    }

    @Test
    fun `aggregation counts identical requests per window and keeps distinct ones`() {
        val minute = 60_000L
        val records = buildList {
            repeat(30) { add(NetRecord.Dns("com.whatsapp", t0 + it * 10_000L, "g.whatsapp.net", listOf("157.240.0.${it % 3}"), 3)) }
            add(NetRecord.Dns("com.whatsapp", t0 + 2 * minute, "mmg.whatsapp.net", emptyList(), 0))
            // Same host, other app: separate.
            add(NetRecord.Dns("com.google.android.gms", t0 + 3 * minute, "g.whatsapp.net", emptyList(), 0))
            // Next window: separate.
            add(NetRecord.Dns("com.whatsapp", t0 + 11 * minute, "g.whatsapp.net", emptyList(), 0))
            repeat(4) { add(NetRecord.Connect("com.whatsapp", t0 + it * 1_000L, "157.240.0.1", 443)) }
            add(NetRecord.Connect("com.whatsapp", t0 + 5_000, "157.240.0.1", 5222))
        }
        val out = NetworkLogProcessor.process(records, resolver(), windowMs = 10 * minute, includeConnect = true)
        val dns = out.filter { it.type == "net.dns" }
        assertEquals(4, dns.size)
        val main = dns.first()
        assertEquals("30", main.data.s("count"))
        assertEquals(t0, main.tsMs)
        assertEquals(Rfc3339.format(t0 + 290_000L), main.data.s("last_event_ts"))
        assertEquals(3, main.data["addresses"]!!.jsonArray.size)
        out.forEach { Contract.check(it.type, it.data) }
        val connects = out.filter { it.type == "net.connect" }
        assertEquals(listOf("4", null), connects.map { it.data.s("count") })
        // Without aggregation every entry is emitted; DNS only when connect is off.
        assertEquals(records.size, NetworkLogProcessor.process(records, resolver(), 0, true).size)
        assertEquals(33, NetworkLogProcessor.process(records, resolver(), 0, false).size)
    }

    @Test
    fun `window aggregation helper`() {
        val groups = aggregateByWindow(listOf(5L, 7L, 12L, 15L), 10L, { it }) { "k" }
        assertEquals(listOf(2, 2), groups.map { it.count })
        assertEquals(listOf(5L to 7L, 12L to 15L), groups.map { it.firstMs to it.lastMs })
    }

    @Test
    fun `lost batches are detected from token gaps, resets are not losses`() {
        assertEquals(0L, NetworkLogProcessor.lostBatches(0, 5)) // first batch ever
        assertEquals(0L, NetworkLogProcessor.lostBatches(4, 5))
        assertEquals(2L, NetworkLogProcessor.lostBatches(4, 7))
        assertEquals(0L, NetworkLogProcessor.lostBatches(9, 1)) // logging restarted (reboot, re-enable)
    }

    @Test
    fun `batches finalized while paused are fetched, those beyond the 5-batch window are lost`() {
        assertEquals(NetworkLogProcessor.FetchPlan(listOf(5L), 0), NetworkLogProcessor.tokensToFetch(0, 5))
        assertEquals(NetworkLogProcessor.FetchPlan(listOf(5L), 0), NetworkLogProcessor.tokensToFetch(4, 5))
        assertEquals(NetworkLogProcessor.FetchPlan(listOf(5L, 6L, 7L), 0), NetworkLogProcessor.tokensToFetch(4, 7))
        assertEquals(NetworkLogProcessor.FetchPlan(listOf(16L, 17L, 18L, 19L, 20L), 11), NetworkLogProcessor.tokensToFetch(4, 20))
        assertEquals(NetworkLogProcessor.FetchPlan(listOf(1L), 0), NetworkLogProcessor.tokensToFetch(9, 1))
    }
}
