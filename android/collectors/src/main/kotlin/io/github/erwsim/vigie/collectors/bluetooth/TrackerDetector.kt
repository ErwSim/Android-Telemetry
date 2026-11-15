package io.github.erwsim.vigie.collectors.bluetooth

import io.github.erwsim.vigie.collectors.location.MotionTracker

/**
 * Pure "is this tracker following me?" logic. A tracker is reported when it has been seen
 * - at least [minSightings] times (one sighting per address per [sightingGapMs] at most),
 * - over at least [minDurationMs] between first and last sighting,
 * - while the phone moved at least [minDistanceM] (distance between the positions known at the
 *   sightings, from the passive location cache),
 * and it is forgotten when unseen for [forgetAfterMs]. Without any known position, nothing is
 * reported (a tracker that stays with a static phone is a neighbour's, not a follower).
 * A reported address is reported again at most every [realertMs].
 *
 * Limit: trackers rotate their address (AirTag separated from its owner: about every 24 h,
 * others more often); a rotation restarts the count.
 */
class TrackerDetector(
    val minSightings: Int = 4,
    val minDurationMs: Long = 30 * 60_000L,
    val minDistanceM: Double = 500.0,
    val sightingGapMs: Long = 60_000L,
    val forgetAfterMs: Long = 60 * 60_000L,
    val realertMs: Long = 6 * 3_600_000L,
    val maxTracked: Int = 256,
) {
    data class Position(val lat: Double, val lon: Double)

    data class Alert(val address: String, val kind: String, val rssi: Int?, val firstSeenWallMs: Long, val sightings: Int)

    private class Entry(
        val kind: String,
        val firstSeenWallMs: Long,
        val firstElapsedMs: Long,
        var lastElapsedMs: Long,
        var sightings: Int,
        var rssi: Int?,
        var origin: Position?,
        var maxDistanceM: Double = 0.0,
        var alertedElapsedMs: Long? = null,
    )

    private val entries = LinkedHashMap<String, Entry>()

    val trackedCount: Int get() = entries.size

    /** Records an advertisement; returns an alert when the tracker qualifies as following. */
    fun onSighting(address: String, kind: String, rssi: Int?, wallMs: Long, elapsedMs: Long, position: Position?): Alert? {
        prune(elapsedMs)
        val e = entries[address]
        if (e == null) {
            if (entries.size >= maxTracked) entries.remove(entries.keys.first())
            entries[address] = Entry(kind, wallMs, elapsedMs, elapsedMs, 1, rssi, position)
            return null
        }
        e.rssi = rssi ?: e.rssi
        if (position != null) {
            val origin = e.origin
            if (origin == null) {
                e.origin = position
            } else {
                e.maxDistanceM = maxOf(e.maxDistanceM, MotionTracker.distanceM(origin.lat, origin.lon, position.lat, position.lon))
            }
        }
        if (elapsedMs - e.lastElapsedMs < sightingGapMs) return null
        e.lastElapsedMs = elapsedMs
        e.sightings += 1
        val qualifies = e.sightings >= minSightings &&
            elapsedMs - e.firstElapsedMs >= minDurationMs &&
            e.origin != null && e.maxDistanceM >= minDistanceM
        if (!qualifies) return null
        val alerted = e.alertedElapsedMs
        if (alerted != null && elapsedMs - alerted < realertMs) return null
        e.alertedElapsedMs = elapsedMs
        return Alert(address, e.kind, e.rssi, e.firstSeenWallMs, e.sightings)
    }

    /** Forgets trackers unseen for [forgetAfterMs]. */
    fun prune(elapsedMs: Long) {
        entries.values.removeAll { elapsedMs - it.lastElapsedMs > forgetAfterMs }
    }

    fun clear() = entries.clear()
}
