package io.github.erwsim.vigie.collectors.location

/**
 * Location modes (contract §10), pure logic (unit-tested):
 * - `gps` (default): `GPS_PROVIDER` only (+ the passive provider if enabled). Nothing goes to Google
 *   through Vigie (the GNSS assistance — XTRA, SUPL — is configured by the system, not by Vigie);
 * - `gps_network`: GPS plus `NETWORK_PROVIDER`. On a phone with Google Play services, the network
 *   provider is Google's: the Wi-Fi access points and cell towers around are sent to Google;
 * - `fused`: `FUSED_PROVIDER` only (GPS, Wi-Fi, cells and sensors combined by Google Play services on a
 *   GMS phone, same transmission to Google). Indoors, a position within seconds; less GNSS time.
 *
 * Fallback: a provider of the mode that is absent or switched off is skipped; if nothing remains, GPS
 * alone (and if GPS is off too, no request until a provider comes back: `location.provider` says so).
 */
object LocationModes {
    const val GPS = "gps"
    const val GPS_NETWORK = "gps_network"
    const val FUSED = "fused"
    val ALL = listOf(GPS, GPS_NETWORK, FUSED)

    // Same values as LocationManager.*_PROVIDER (kept here so the logic stays pure).
    const val P_GPS = "gps"
    const val P_NETWORK = "network"
    const val P_FUSED = "fused"
    const val P_PASSIVE = "passive"

    /** Providers wanted by [mode], most precise first. */
    fun wanted(mode: String): List<String> = when (mode) {
        GPS_NETWORK -> listOf(P_GPS, P_NETWORK)
        FUSED -> listOf(P_FUSED)
        else -> listOf(P_GPS)
    }

    /** The providers actually requested, and whether this is a fallback from what the mode wants. */
    data class Plan(val providers: List<String>, val fallback: Boolean)

    /**
     * [exists]: the provider is known to `LocationManager`; [enabled]: switched on. Absent or disabled
     * providers are skipped; with nothing left, GPS if it is usable, otherwise nothing.
     */
    fun plan(mode: String, exists: (String) -> Boolean, enabled: (String) -> Boolean): Plan {
        val wanted = wanted(mode)
        val usable = wanted.filter { exists(it) && enabled(it) }
        if (usable.isNotEmpty()) return Plan(usable, usable != wanted)
        val gps = if (exists(P_GPS) && enabled(P_GPS)) listOf(P_GPS) else emptyList()
        return Plan(gps, true)
    }

    /** Request quality per provider (`LocationRequest.QUALITY_*` values, mirrored). */
    fun quality(provider: String): Int = if (provider == P_NETWORK) QUALITY_BALANCED else QUALITY_HIGH

    const val QUALITY_HIGH = 100
    const val QUALITY_BALANCED = 102

    /**
     * In `gps_network`, both providers answer at each interval: a network fix is dropped when a GPS fix
     * was emitted less than half an interval ago (the GPS one is more precise). Other providers: always kept.
     */
    fun keepFix(provider: String?, nowElapsedMs: Long, lastGpsEmitElapsedMs: Long?, intervalMs: Long): Boolean {
        if (provider != P_NETWORK || lastGpsEmitElapsedMs == null) return true
        return nowElapsedMs - lastGpsEmitElapsedMs >= intervalMs / 2
    }

    /** For `locate`: done when the most precise provider of the plan answered, or every provider did. */
    fun locateDone(plan: List<String>, answered: Set<String>): Boolean =
        plan.isNotEmpty() && (plan.first() in answered || answered.containsAll(plan))
}
