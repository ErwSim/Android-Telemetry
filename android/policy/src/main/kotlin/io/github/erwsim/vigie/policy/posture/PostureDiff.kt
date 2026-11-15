package io.github.erwsim.vigie.policy.posture

import io.github.erwsim.vigie.core.event.Severity
import java.time.LocalDate
import java.time.ZoneOffset
import java.time.temporal.ChronoUnit

/** One `security.posture_change`: values converted to strings (contract §2, "Précisions"). */
data class PostureChange(val field: String, val old: String, val new: String, val sev: Int)

/** Pure posture logic (tested on the JVM). */
object PostureDiff {
    /** Derived from the date, not a change of the device (contract: no posture_change). */
    private val EXCLUDED = setOf("patch_age_days")

    /** Contract string form: booleans `true`/`false`, lists joined with `,`. */
    fun asString(value: Any?): String = when (value) {
        null -> ""
        is Collection<*> -> value.joinToString(",") { asString(it) }
        else -> value.toString()
    }

    fun asStrings(posture: Map<String, Any?>): Map<String, String> =
        posture.filterValues { it != null }.mapValues { asString(it.value) }

    /**
     * Fields present in both snapshots whose value changed. A field that becomes unreadable (absent)
     * or readable again is not a change of the device and produces nothing.
     */
    fun diff(previous: Map<String, String>?, current: Map<String, String>): List<PostureChange> {
        if (previous == null) return emptyList()
        return current.keys.sorted()
            .filter { it !in EXCLUDED && it in previous && previous[it] != current[it] }
            .map { PostureChange(it, previous.getValue(it), current.getValue(it), severity(it, current.getValue(it))) }
    }

    /** Same thresholds as the server's simulator and Wazuh rules. */
    fun severity(field: String, value: String): Int = when (field) {
        "device_owner", "encrypted", "lock_secure" -> if (value == "false") Severity.CRITICAL else Severity.INFO
        "verified_boot_state" -> if (value != "green") Severity.CRITICAL else Severity.INFO
        "adb_enabled", "adb_wifi_enabled", "dev_options", "unknown_sources" -> if (value == "true") Severity.WARNING else Severity.INFO
        "play_protect", "usb_data_signaling" -> if (value == "false") Severity.WARNING else Severity.INFO
        "private_dns_mode", "private_dns_host", "always_on_vpn" -> Severity.WARNING
        "user_ca_certs" -> if (value.isNotEmpty()) Severity.WARNING else Severity.INFO
        else -> Severity.INFO
    }

    /** Days since the security patch date (`YYYY-MM-DD`), null if unparsable. */
    fun patchAgeDays(patch: String?, nowMs: Long): Int? = try {
        val date = LocalDate.parse(patch ?: return null)
        val today = java.time.Instant.ofEpochMilli(nowMs).atZone(ZoneOffset.UTC).toLocalDate()
        ChronoUnit.DAYS.between(date, today).toInt()
    } catch (_: Exception) {
        null
    }

    /** `private_dns_mode` setting / DPM mode → contract value (`off`, `opportunistic`, `hostname`). */
    fun dnsModeFromSetting(raw: String?): String? = when (raw) {
        null, "" -> null
        "off" -> "off"
        "opportunistic" -> "opportunistic"
        "hostname" -> "hostname"
        else -> raw
    }
}

/** A user-installed CA: SHA-256 of its DER encoding and its subject. */
data class CaCert(val sha256: String, val subject: String)

data class CaChange(val event: String, val cert: CaCert)

object CaCertDiff {
    /** Changes between two snapshots (null previous: first run, baseline only). */
    fun diff(previous: Map<String, String>?, current: List<CaCert>): List<CaChange> {
        if (previous == null) return emptyList()
        val now = current.associateBy { it.sha256 }
        val added = current.filter { it.sha256 !in previous }.map { CaChange("added", it) }
        val removed = previous.filterKeys { it !in now }.map { (sha, subject) -> CaChange("removed", CaCert(sha, subject)) }
        return added + removed
    }
}
