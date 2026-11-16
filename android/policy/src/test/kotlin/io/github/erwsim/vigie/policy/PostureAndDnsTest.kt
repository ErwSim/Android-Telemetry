package io.github.erwsim.vigie.policy

import io.github.erwsim.vigie.core.event.Severity
import io.github.erwsim.vigie.policy.dns.DnsGuardDecision
import io.github.erwsim.vigie.policy.dns.DnsGuardInput
import io.github.erwsim.vigie.policy.dns.DnsGuardLogic
import io.github.erwsim.vigie.policy.dns.DnsMessage
import io.github.erwsim.vigie.policy.engine.AppliedRecord
import io.github.erwsim.vigie.policy.engine.ItemKind
import io.github.erwsim.vigie.policy.posture.CaCert
import io.github.erwsim.vigie.policy.posture.CaCertDiff
import io.github.erwsim.vigie.policy.posture.PostureDiff
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class PostureAndDnsTest {
    private val base = linkedMapOf<String, Any?>(
        "security_patch" to "2026-10-01", "patch_age_days" to 45, "encrypted" to true, "lock_secure" to true,
        "adb_enabled" to false, "private_dns_mode" to "hostname", "private_dns_host" to "dns.exemple.fr",
        "device_owner" to true, "user_ca_certs" to emptyList<String>(), "play_protect" to null,
    )

    @Test
    fun `posture strings follow the contract and null fields are absent`() {
        val s = PostureDiff.asStrings(base)
        assertEquals("true", s["encrypted"])
        assertEquals("", s["user_ca_certs"])
        assertEquals("45", s["patch_age_days"])
        assertTrue("play_protect" !in s)
        assertEquals("a,b", PostureDiff.asString(listOf("a", "b")))
    }

    @Test
    fun `one change per modified field, patch age excluded, unreadable fields ignored`() {
        val prev = PostureDiff.asStrings(base)
        val now = LinkedHashMap(base).apply {
            this["patch_age_days"] = 46
            this["adb_enabled"] = true
            this["private_dns_mode"] = "opportunistic"
            this["private_dns_host"] = ""
            this["user_ca_certs"] = listOf("ab".repeat(32))
            this["lock_secure"] = null // became unreadable: not a change
            this["play_protect"] = true // became readable: not a change
        }
        val changes = PostureDiff.diff(prev, PostureDiff.asStrings(now))
        assertEquals(listOf("adb_enabled", "private_dns_host", "private_dns_mode", "user_ca_certs"), changes.map { it.field })
        val byField = changes.associateBy { it.field }
        assertEquals("false" to "true", byField.getValue("adb_enabled").let { it.old to it.new })
        assertEquals(Severity.WARNING, byField.getValue("adb_enabled").sev)
        assertEquals(Severity.WARNING, byField.getValue("private_dns_mode").sev)
        assertEquals(Severity.WARNING, byField.getValue("user_ca_certs").sev)
        assertTrue(PostureDiff.diff(null, PostureDiff.asStrings(now)).isEmpty()) // first run: baseline
        assertTrue(PostureDiff.diff(prev, prev).isEmpty())
    }

    @Test
    fun `severities match the server rules`() {
        assertEquals(Severity.CRITICAL, PostureDiff.severity("device_owner", "false"))
        assertEquals(Severity.INFO, PostureDiff.severity("device_owner", "true"))
        assertEquals(Severity.CRITICAL, PostureDiff.severity("verified_boot_state", "orange"))
        assertEquals(Severity.WARNING, PostureDiff.severity("play_protect", "false"))
        assertEquals(Severity.INFO, PostureDiff.severity("adb_enabled", "false"))
        assertEquals(Severity.INFO, PostureDiff.severity("user_ca_certs", ""))
    }

    @Test
    fun `patch age in days`() {
        val now = java.time.Instant.parse("2026-11-15T21:43:03Z").toEpochMilli()
        assertEquals(45, PostureDiff.patchAgeDays("2026-10-01", now))
        assertNull(PostureDiff.patchAgeDays("n/a", now))
        assertNull(PostureDiff.patchAgeDays(null, now))
    }

    @Test
    fun `user CA additions and removals`() {
        val a = CaCert("aa".repeat(32), "CN=A")
        val b = CaCert("bb".repeat(32), "CN=B")
        assertTrue(CaCertDiff.diff(null, listOf(a)).isEmpty())
        val changes = CaCertDiff.diff(mapOf(a.sha256 to a.subject), listOf(b))
        assertEquals(listOf("added" to b, "removed" to a), changes.map { it.event to it.cert })
    }

    @Test
    fun `DoT query and response checks`() {
        val q = DnsMessage.query(0x1234, "dns.exemple.fr")
        assertEquals(0x12, q[0].toInt())
        assertEquals(0x34, q[1].toInt())
        // Header (12) + 3dns 7exemple 2fr 0 (16) + type + class (4).
        assertEquals(12 + 16 + 4, q.size)
        val framed = DnsMessage.frame(q)
        assertEquals(q.size, (framed[0].toInt() shl 8) or framed[1].toInt())
        fun response(id: Int, flags2: Int) = byteArrayOf((id shr 8).toByte(), id.toByte(), 0x81.toByte(), flags2.toByte()) + ByteArray(8)
        assertNull(DnsMessage.checkResponse(response(0x1234, 0x80), 0x1234))
        assertNull(DnsMessage.checkResponse(response(0x1234, 0x83), 0x1234)) // NXDOMAIN still proves the server resolves
        assertTrue(DnsMessage.checkResponse(response(0x1234, 0x85), 0x1234)!!.startsWith("REFUSED"))
        assertTrue(DnsMessage.checkResponse(response(0x9999, 0x80), 0x1234)!!.contains("identifiant"))
        assertTrue(DnsMessage.checkResponse(ByteArray(4), 0x1234)!!.contains("tronquée"))
    }

    private val record = AppliedRecord(id = "dns", kind = ItemKind.PRIVATE_DNS, target = "dns.exemple.fr", dnsAddresses = listOf("203.0.113.5"))

    private fun input(
        record: AppliedRecord? = this.record, network: Boolean = true, validated: Boolean = false, probe: Boolean? = false,
        since: Long? = null, now: Long = 1_000_000, fallback: Boolean = true, restore: Boolean = true,
    ) = DnsGuardInput(record, network, validated, probe, since, now, fallback, 15 * 60_000L, restore)

    @Test
    fun `DNS guard - fallback only after a continuous failure, never on a validated or absent network`() {
        assertEquals(DnsGuardDecision.Healthy, DnsGuardLogic.decide(input(record = null)))
        assertEquals(DnsGuardDecision.Healthy, DnsGuardLogic.decide(input(validated = true, probe = null)))
        assertEquals(DnsGuardDecision.Unknown, DnsGuardLogic.decide(input(network = false)))
        // Network not validated but our check reaches the host: not the DNS server's fault.
        assertEquals(DnsGuardDecision.Healthy, DnsGuardLogic.decide(input(probe = true)))
        val first = DnsGuardLogic.decide(input())
        assertEquals(DnsGuardDecision.Failing(1_000_000, 1_000_000 + 15 * 60_000L), first)
        assertEquals(DnsGuardDecision.Failing(1_000_000, 1_000_000 + 15 * 60_000L), DnsGuardLogic.decide(input(since = 1_000_000, now = 1_000_000 + 60_000)))
        assertEquals(DnsGuardDecision.Fallback(1_000_000), DnsGuardLogic.decide(input(since = 1_000_000, now = 1_000_000 + 15 * 60_000L)))
        // Fallback disabled: protection wins, it keeps failing.
        assertTrue(DnsGuardLogic.decide(input(since = 0, now = 10 * 3_600_000L, fallback = false)) is DnsGuardDecision.Failing)
    }

    @Test
    fun `DNS guard - a failure start left in the future by a clock that moved back does not delay the fallback for ever`() {
        val now = 1_000_000L
        // Recorded one year "ahead": the wait starts again from now instead of lasting a year.
        val decision = DnsGuardLogic.decide(input(since = now + 365L * 86_400_000, now = now))
        assertEquals(DnsGuardDecision.Failing(now, now + 15 * 60_000L), decision)
    }

    @Test
    fun `self-granted permissions are granted once, foreground location first`() {
        val declared = listOf("android.permission.ACCESS_BACKGROUND_LOCATION", "android.permission.ACCESS_FINE_LOCATION", "android.permission.BLUETOOTH_SCAN")
        assertEquals(
            listOf("android.permission.ACCESS_FINE_LOCATION", "android.permission.BLUETOOTH_SCAN", "android.permission.ACCESS_BACKGROUND_LOCATION"),
            DeviceOwnerManager.pendingSelfGrants(declared, { false }, emptySet()),
        )
        // Revoked by the owner after the first automatic grant: not granted again behind his back.
        assertEquals(
            listOf("android.permission.BLUETOOTH_SCAN"),
            DeviceOwnerManager.pendingSelfGrants(declared, { false }, setOf("android.permission.ACCESS_FINE_LOCATION", "android.permission.ACCESS_BACKGROUND_LOCATION")),
        )
        assertEquals(emptyList<String>(), DeviceOwnerManager.pendingSelfGrants(declared, { true }, emptySet()))
    }

    @Test
    fun `DNS guard - re-imposes after a fallback only when the host answers and auto-restore is on`() {
        val fallen = record.copy(dnsFallback = true)
        assertEquals(DnsGuardDecision.Reapply, DnsGuardLogic.decide(input(record = fallen, probe = true)))
        assertEquals(DnsGuardDecision.Unknown, DnsGuardLogic.decide(input(record = fallen, probe = false)))
        assertEquals(DnsGuardDecision.Unknown, DnsGuardLogic.decide(input(record = fallen, probe = true, restore = false)))
    }
}
