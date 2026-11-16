package io.github.erwsim.watchpost.collectors.cell

import android.telephony.TelephonyManager
import io.github.erwsim.watchpost.core.event.EventDataBuilder
import io.github.erwsim.watchpost.core.event.eventData
import kotlinx.serialization.json.JsonObject

/** Pure cellular logic: technology names, serving-cell snapshot, change filter, 2G downgrade. */
object CellLogic {
    /** `TelephonyManager.NETWORK_TYPE_*` → `net.cell.tech` word (lowercase constant name). */
    @Suppress("DEPRECATION") // CDMA/EVDO/iDEN constants: legacy networks, still possible in roaming.
    fun techName(networkType: Int): String? = when (networkType) {
        TelephonyManager.NETWORK_TYPE_GPRS -> "gprs"
        TelephonyManager.NETWORK_TYPE_EDGE -> "edge"
        TelephonyManager.NETWORK_TYPE_GSM -> "gsm"
        TelephonyManager.NETWORK_TYPE_CDMA -> "cdma"
        TelephonyManager.NETWORK_TYPE_1xRTT -> "1xrtt"
        TelephonyManager.NETWORK_TYPE_IDEN -> "iden"
        TelephonyManager.NETWORK_TYPE_UMTS -> "umts"
        TelephonyManager.NETWORK_TYPE_EVDO_0 -> "evdo_0"
        TelephonyManager.NETWORK_TYPE_EVDO_A -> "evdo_a"
        TelephonyManager.NETWORK_TYPE_EVDO_B -> "evdo_b"
        TelephonyManager.NETWORK_TYPE_HSDPA -> "hsdpa"
        TelephonyManager.NETWORK_TYPE_HSUPA -> "hsupa"
        TelephonyManager.NETWORK_TYPE_HSPA -> "hspa"
        TelephonyManager.NETWORK_TYPE_HSPAP -> "hspap"
        TelephonyManager.NETWORK_TYPE_EHRPD -> "ehrpd"
        TelephonyManager.NETWORK_TYPE_TD_SCDMA -> "td_scdma"
        TelephonyManager.NETWORK_TYPE_LTE -> "lte"
        TelephonyManager.NETWORK_TYPE_NR -> "nr"
        TelephonyManager.NETWORK_TYPE_IWLAN -> "iwlan"
        else -> null
    }

    /** 2G radio access technologies (GSM/GPRS/EDGE, CDMA 1x, iDEN): no mutual authentication. */
    val TECH_2G = setOf("gsm", "gprs", "edge", "cdma", "1xrtt", "iden")

    fun is2g(tech: String?): Boolean = tech != null && tech in TECH_2G

    /** One registered WWAN registration (ServiceState.getNetworkRegistrationInfoList). */
    data class Registration(val packetSwitched: Boolean, val circuitSwitched: Boolean, val tech: String?, val roaming: Boolean)

    /** The registered (serving) cell from getAllCellInfo / onCellInfoChanged. */
    data class ServingCell(
        val tech: String,
        val mcc: String? = null,
        val mnc: String? = null,
        val tac: Int? = null,
        val ci: Long? = null,
        val pci: Int? = null,
        val band: Int? = null,
        val signalDbm: Int? = null,
        val operator: String? = null,
    )

    /** What `net.cell` reports. Equality ignores the signal (an event per change, not per dBm). */
    data class Snapshot(
        val tech: String,
        val mcc: String?,
        val mnc: String?,
        val tac: Int?,
        val ci: Long?,
        val pci: Int?,
        val band: Int?,
        val roaming: Boolean?,
        val operator: String?,
    ) {
        fun writeTo(b: EventDataBuilder, signalDbm: Int?) {
            b.put("tech", tech)
            b.put("mcc", mcc)
            b.put("mnc", mnc)
            b.put("tac", tac)
            b.put("ci", ci)
            b.put("pci", pci)
            b.put("band", band)
            b.put("signal_dbm", signalDbm)
            b.put("roaming", roaming)
            b.put("operator", operator)
        }
    }

    /**
     * Technology used for data if registered, else for voice. [registrations] is null while the
     * service state is unknown: the serving cell's technology is used instead.
     */
    fun currentTech(registrations: List<Registration>?, cell: ServingCell?): String? {
        if (registrations == null) return cell?.tech
        return registrations.firstOrNull { it.packetSwitched && it.tech != null && it.tech != "iwlan" }?.tech
            ?: registrations.firstOrNull { it.circuitSwitched && it.tech != null && it.tech != "iwlan" }?.tech
    }

    /**
     * The 2G technology used by a registered radio (data or voice), if any. The serving cell is
     * only used while the registration state is unknown (null): cell lists can lag behind.
     */
    fun tech2g(registrations: List<Registration>?, cell: ServingCell?): String? =
        if (registrations == null) cell?.tech?.takeIf(::is2g) else registrations.firstOrNull { is2g(it.tech) }?.tech

    /**
     * Builds the snapshot; `tech = "none"` when registered nowhere (out of service, airplane
     * mode, no SIM). Cell identity fields come from the serving cell (they need precise location).
     */
    fun snapshot(registrations: List<Registration>?, cell: ServingCell?, roaming: Boolean?, operatorName: String?, operatorNumeric: String?): Snapshot {
        val tech = currentTech(registrations, cell) ?: return Snapshot("none", null, null, null, null, null, null, null, null)
        val sameCell = cell?.takeIf { it.tech == tech || generation(it.tech) == generation(tech) }
        return Snapshot(
            tech = tech,
            mcc = sameCell?.mcc ?: operatorNumeric?.takeIf { it.length >= 5 }?.substring(0, 3),
            mnc = sameCell?.mnc ?: operatorNumeric?.takeIf { it.length >= 5 }?.substring(3),
            tac = sameCell?.tac,
            ci = sameCell?.ci,
            pci = sameCell?.pci,
            band = sameCell?.band,
            roaming = roaming ?: registrations?.takeIf { it.isNotEmpty() }?.any { it.roaming },
            operator = sameCell?.operator?.takeIf { it.isNotBlank() } ?: operatorName?.takeIf { it.isNotBlank() },
        )
    }

    /** `net.cell_security` data for a 2G downgrade. */
    fun downgradeData(transition: String, s: Snapshot): JsonObject = eventData {
        put("kind", "downgrade_2g")
        put(
            "detail",
            buildString {
                append(transition)
                s.mcc?.let { append(", plmn ").append(it).append('-').append(s.mnc ?: "?") }
                s.tac?.let { append(", tac ").append(it) }
                s.ci?.let { append(", ci ").append(it) }
            },
        )
    }

    fun generation(tech: String?): Int = when (tech) {
        null -> 0
        in TECH_2G -> 2
        "lte" -> 4
        "nr" -> 5
        "iwlan" -> 0
        else -> 3
    }

    /** CellIdentity values: CellInfo.UNAVAILABLE (Int.MAX_VALUE) and negatives become null. */
    fun valid(v: Int): Int? = v.takeIf { it in 0 until Int.MAX_VALUE }

    fun valid(v: Long): Long? = v.takeIf { it in 0 until Long.MAX_VALUE }

    fun dbm(v: Int): Int? = v.takeIf { it in -160..-20 }

    /**
     * Change filter: a snapshot is emitted when it differs from the last emitted one, at most once
     * per [minIntervalMs] unless the technology, the network (MCC/MNC) or roaming changes (those are
     * always reported). A suppressed change is reported by the next callback after the interval.
     */
    class ChangeFilter(private val minIntervalMs: Long = 20_000) {
        var last: Snapshot? = null
            private set
        private var lastEmitMs = Long.MIN_VALUE / 2

        fun offer(s: Snapshot, nowMs: Long): Boolean {
            val prev = last
            if (s == prev) return false
            val major = prev == null || prev.tech != s.tech || prev.mcc != s.mcc || prev.mnc != s.mnc || prev.roaming != s.roaming
            if (!major && nowMs - lastEmitMs < minIntervalMs) return false
            last = s
            lastEmitMs = nowMs
            return true
        }

        fun reset() {
            last = null
            lastEmitMs = Long.MIN_VALUE / 2
        }
    }

    /**
     * 2G downgrade detector: alerts when the device moves from a non-2G technology (or from an
     * unknown state, e.g. at start) to 2G, at most once per [cooldownMs]. "No service" does not
     * reset the previous technology, so LTE → no service → GSM is a downgrade.
     */
    class DowngradeDetector(private val cooldownMs: Long = 30 * 60_000L) {
        /** Last technology with service (persisted by the collector across restarts). */
        var lastTech: String? = null
        var lastAlertMs: Long = Long.MIN_VALUE / 2

        /**
         * [tech] is the current technology ("none" without service), [tech2g] the 2G technology in
         * use for data or voice, if any. Returns the alert detail, or null. [nowMs] is wall time.
         */
        fun onState(tech: String?, tech2g: String?, nowMs: Long): String? {
            if (tech2g == null && (tech == null || tech == "none")) return null
            val previous = lastTech
            lastTech = tech2g ?: tech
            if (tech2g == null) return null
            if (previous != null && is2g(previous)) return null
            if (nowMs - lastAlertMs in 0 until cooldownMs) return null
            lastAlertMs = nowMs
            return "${previous ?: "unknown"} → $tech2g"
        }
    }
}
