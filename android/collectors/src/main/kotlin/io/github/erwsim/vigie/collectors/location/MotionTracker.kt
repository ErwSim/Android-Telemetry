package io.github.erwsim.vigie.collectors.location

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
 */
class MotionTracker(
    private val stationaryAfterMs: Long = 5 * 60_000L,
    private val movingSpeedMps: Float = 1.0f,
    private val radiusM: Float = 50f,
) {
    enum class Mode { MOVING, STATIONARY }

    var mode: Mode = Mode.MOVING
        private set

    private var anchorLat = Double.NaN
    private var anchorLon = Double.NaN
    private var anchorElapsedMs = 0L

    fun onFix(lat: Double, lon: Double, accuracyM: Float?, speedMps: Float?, elapsedMs: Long): Mode {
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
