package io.github.erwsim.watchpost.collectors.location

import kotlin.math.asin
import kotlin.math.cos
import kotlin.math.max
import kotlin.math.sin
import kotlin.math.sqrt

/**
 * Decides between "moving" and "stationary" from successive fixes (pure logic, unit-tested).
 *
 * Moving: reported speed ≥ [movingSpeedMps], or the fix left the anchor circle (radius
 * [radiusM], widened by the fix accuracy). Stationary: no exit from the circle for [stationaryAfterMs].
 * A significant-motion trigger switches back to moving immediately.
 *
 * No fix at all (indoors, underground) also ends in stationary after [stationaryAfterMs] without
 * any fix ([onNoFix]): otherwise the fast cadence would keep the GNSS receiver searching for hours
 * (it searches for up to a minute per attempt), which is the most expensive thing this agent can do.
 */
class MotionTracker(
    private val stationaryAfterMs: Long = 5 * 60_000L,
    private val movingSpeedMps: Float = 1.0f,
    private val radiusM: Float = 50f,
    /** `elapsedRealtime` when the tracking started (the wait for a first fix starts there). */
    startedAtElapsedMs: Long = 0L,
) {
    enum class Mode { MOVING, STATIONARY }

    var mode: Mode = Mode.MOVING
        private set

    private var anchorLat = Double.NaN
    private var anchorLon = Double.NaN
    private var anchorElapsedMs = 0L

    /** Last fix, or last moment the fast cadence was (re)started: what [onNoFix] measures from. */
    private var lastSignalElapsedMs = startedAtElapsedMs

    fun onFix(lat: Double, lon: Double, accuracyM: Float?, speedMps: Float?, elapsedMs: Long): Mode {
        lastSignalElapsedMs = elapsedMs
        if (anchorLat.isNaN()) {
            setAnchor(lat, lon, elapsedMs)
            return mode
        }
        val distance = distanceM(anchorLat, anchorLon, lat, lon)
        val radius = max(radiusM, (accuracyM ?: 0f) * 1.5f)
        val moved = (speedMps != null && speedMps >= movingSpeedMps) || distance > radius
        if (moved) {
            mode = Mode.MOVING
            setAnchor(lat, lon, elapsedMs)
        } else if (elapsedMs - anchorElapsedMs >= stationaryAfterMs) {
            mode = Mode.STATIONARY
        }
        return mode
    }

    fun onSignificantMotion(elapsedMs: Long): Mode {
        mode = Mode.MOVING
        anchorElapsedMs = elapsedMs
        lastSignalElapsedMs = elapsedMs
        return mode
    }

    /**
     * To call from time to time while waiting for fixes: without any fix for [stationaryAfterMs]
     * in moving mode, falls back to the slow cadence (a fix that shows a move, or a
     * significant-motion trigger, brings the fast one back).
     */
    fun onNoFix(elapsedMs: Long): Mode {
        if (mode == Mode.MOVING && elapsedMs - lastSignalElapsedMs >= stationaryAfterMs) mode = Mode.STATIONARY
        return mode
    }

    private fun setAnchor(lat: Double, lon: Double, elapsedMs: Long) {
        anchorLat = lat
        anchorLon = lon
        anchorElapsedMs = elapsedMs
    }

    companion object {
        /** Haversine distance in metres. */
        fun distanceM(lat1: Double, lon1: Double, lat2: Double, lon2: Double): Double {
            val r = 6_371_008.8
            val dLat = Math.toRadians(lat2 - lat1)
            val dLon = Math.toRadians(lon2 - lon1)
            val a = sin(dLat / 2) * sin(dLat / 2) +
                cos(Math.toRadians(lat1)) * cos(Math.toRadians(lat2)) * sin(dLon / 2) * sin(dLon / 2)
            return 2 * r * asin(sqrt(a.coerceIn(0.0, 1.0)))
        }
    }
}
