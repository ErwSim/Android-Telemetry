package io.github.erwsim.watchpost.collectors

import io.github.erwsim.watchpost.collectors.location.LocationCollector
import io.github.erwsim.watchpost.collectors.location.LocationModes
import io.github.erwsim.watchpost.collectors.location.LocationModes.P_FUSED
import io.github.erwsim.watchpost.collectors.location.LocationModes.P_GPS
import io.github.erwsim.watchpost.collectors.location.LocationModes.P_NETWORK
import io.github.erwsim.watchpost.core.settings.AgentSettings
import io.github.erwsim.watchpost.core.settings.SettingSpec
import io.github.erwsim.watchpost.core.testing.Contract
import io.github.erwsim.watchpost.core.testing.MemoryPrefs
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** Contract §10: location modes, provider plan and fallbacks. */
class LocationModesTest {
    private fun plan(mode: String, present: Set<String>, on: Set<String> = present) =
        LocationModes.plan(mode, exists = { it in present }, enabled = { it in on })

    @Test
    fun eachModeRequestsItsProviders() {
        val all = setOf(P_GPS, P_NETWORK, P_FUSED)
        assertEquals(LocationModes.Plan(listOf(P_GPS), false), plan(LocationModes.GPS, all))
        assertEquals(LocationModes.Plan(listOf(P_GPS, P_NETWORK), false), plan(LocationModes.GPS_NETWORK, all))
        assertEquals(LocationModes.Plan(listOf(P_FUSED), false), plan(LocationModes.FUSED, all))
        // GPS mode never asks the network or fused providers, whatever is available.
        assertFalse(plan(LocationModes.GPS, all).providers.any { it == P_NETWORK || it == P_FUSED })
    }

    @Test
    fun missingOrDisabledProvidersFallBackCleanly() {
        // Fused absent (no Play services) or switched off ("Google location accuracy" off): GPS alone.
        assertEquals(LocationModes.Plan(listOf(P_GPS), true), plan(LocationModes.FUSED, setOf(P_GPS, P_NETWORK)))
        assertEquals(LocationModes.Plan(listOf(P_GPS), true), plan(LocationModes.FUSED, setOf(P_GPS, P_FUSED), on = setOf(P_GPS)))
        // Network off: GPS kept, marked as a fallback.
        assertEquals(LocationModes.Plan(listOf(P_GPS), true), plan(LocationModes.GPS_NETWORK, setOf(P_GPS, P_NETWORK), on = setOf(P_GPS)))
        // GPS off in gps_network: the network provider alone.
        assertEquals(LocationModes.Plan(listOf(P_NETWORK), true), plan(LocationModes.GPS_NETWORK, setOf(P_GPS, P_NETWORK), on = setOf(P_NETWORK)))
        // Everything off: nothing requested (location.provider reports it), never a crash.
        assertEquals(LocationModes.Plan(emptyList(), true), plan(LocationModes.FUSED, setOf(P_GPS, P_FUSED), on = emptySet()))
        assertEquals(LocationModes.Plan(emptyList(), true), plan(LocationModes.GPS, emptySet()))
        // An unknown stored mode behaves like the default.
        assertEquals(listOf(P_GPS), plan("galileo", setOf(P_GPS, P_FUSED)).providers)
    }

    @Test
    fun networkFixesDoNotDuplicateARecentGpsFix() {
        val interval = 60_000L
        assertTrue(LocationModes.keepFix(P_NETWORK, 100_000, null, interval))
        assertFalse(LocationModes.keepFix(P_NETWORK, 100_000, 80_000, interval))
        assertTrue(LocationModes.keepFix(P_NETWORK, 100_000, 70_000, interval))
        assertTrue(LocationModes.keepFix(P_GPS, 100_000, 99_000, interval))
        assertTrue(LocationModes.keepFix(P_FUSED, 100_000, 99_000, interval))
    }

    @Test
    fun locateWaitsForTheMostPreciseProvider() {
        assertFalse(LocationModes.locateDone(listOf(P_GPS, P_NETWORK), setOf(P_NETWORK)))
        assertTrue(LocationModes.locateDone(listOf(P_GPS, P_NETWORK), setOf(P_GPS)))
        assertTrue(LocationModes.locateDone(listOf(P_GPS, P_NETWORK), setOf(P_GPS, P_NETWORK)))
        assertTrue(LocationModes.locateDone(listOf(P_FUSED), setOf(P_FUSED)))
        assertFalse(LocationModes.locateDone(emptyList(), emptySet()))
    }

    @Test
    fun qualityPerProvider() {
        assertEquals(android.location.LocationRequest.QUALITY_HIGH_ACCURACY, LocationModes.quality(P_GPS))
        assertEquals(android.location.LocationRequest.QUALITY_HIGH_ACCURACY, LocationModes.quality(P_FUSED))
        assertEquals(android.location.LocationRequest.QUALITY_BALANCED_POWER_ACCURACY, LocationModes.quality(P_NETWORK))
        assertEquals(android.location.LocationManager.GPS_PROVIDER, P_GPS)
        assertEquals(android.location.LocationManager.NETWORK_PROVIDER, P_NETWORK)
        assertEquals(android.location.LocationManager.FUSED_PROVIDER, P_FUSED)
    }

    @Test
    fun theModeSettingIsAClosedListDefaultingToGps() {
        val settings = AgentSettings(MemoryPrefs())
        assertEquals(LocationModes.GPS, settings[LocationCollector.MODE])
        settings.set(LocationCollector.MODE, "fused")
        assertEquals(LocationModes.FUSED, settings[LocationCollector.MODE])
        settings.set(LocationCollector.MODE, "google_everything")
        assertEquals("an unknown value is ignored", LocationModes.FUSED, settings[LocationCollector.MODE])
        val spec = LocationCollector().settings.filterIsInstance<SettingSpec.ChoiceSpec>().single()
        assertEquals(LocationModes.ALL, spec.options.map { it.value })
        assertTrue("every mode explains what goes to Google", spec.options.all { it.descriptionRes != null })
    }

    @Test
    fun theFixProviderIsTheRealOne() {
        for (provider in listOf(P_GPS, P_NETWORK, P_FUSED, "passive")) {
            val data = LocationCollector.fixData(48.85, 2.35, 12f, null, null, null, provider, mock = false, fixTimeMs = 1_763_242_983_974L)
            Contract.check("location.fix", data)
            assertEquals(provider, data["provider"].toString().trim('"'))
        }
    }
}
