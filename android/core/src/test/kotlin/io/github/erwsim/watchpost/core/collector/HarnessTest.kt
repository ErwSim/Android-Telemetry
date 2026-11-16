package io.github.erwsim.watchpost.core.collector

import io.github.erwsim.watchpost.core.testing.CollectorHarness
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** The shared harness itself: no race with `ctx.io`, a requirement check never breaks the reconciliation. */
class HarnessTest {
    private open class Simple(override val id: String) : Collector {
        override val titleRes = 0
        override val descriptionRes = 0
        override val eventTypes = listOf("device.screen")
    }

    /** Hops to ctx.io (twice, with a pause in the blocking part) before emitting. */
    private class IoHopper : Simple("io_hopper") {
        override suspend fun start(ctx: CollectorContext) {
            ctx.scope.launch(ctx.io) {
                Thread.sleep(50)
                val state = withContext(ctx.io) {
                    Thread.sleep(50)
                    "on"
                }
                ctx.emit("device.screen") { put("state", state) }
            }
        }

        override suspend fun collectOnce(ctx: CollectorContext, reason: CollectReason) {
            val state = withContext(ctx.io) {
                Thread.sleep(30)
                "off"
            }
            ctx.emit("device.screen") { put("state", state) }
        }
    }

    @Test
    fun settleWaitsForWorkOnTheIoDispatcher() {
        repeat(20) {
            CollectorHarness(IoHopper()).use { h ->
                h.startAll()
                assertEquals(listOf("\"on\""), h.eventsOf("device.screen").map { it.data["state"].toString() })
                h.collectOnce("io_hopper")
                assertEquals(2, h.eventsOf("device.screen").size)
            }
        }
    }

    @Test
    fun delayedWorkIsAwaitedExplicitly() {
        val delayed = object : Simple("delayed") {
            override suspend fun start(ctx: CollectorContext) {
                ctx.scope.launch {
                    delay(100)
                    ctx.emit("device.screen") { put("state", "on") }
                }
            }
        }
        CollectorHarness(delayed).use { h ->
            h.startAll()
            assertEquals(1, h.awaitEvents("device.screen").size)
        }
    }

    @Test
    fun systemFeatureRequirementsAndFailingChecksNeverStopTheOtherCollectors() {
        val nfc = object : Simple("nfc_like") {
            override val requirements = listOf(Requirement.SystemFeature("android.hardware.nfc"))
        }
        val broken = object : Simple("broken_check") {
            override fun checkAvailability(ctx: CollectorContext): Availability = throw IllegalStateException("boom")
        }
        val plain = Simple("plain")
        CollectorHarness(nfc, broken, plain).use { h ->
            h.startAll()
            assertEquals(CollectorRunState.UNAVAILABLE, h.status("nfc_like").state)
            assertTrue(h.status("nfc_like").reason!!.contains("android.hardware.nfc"))
            assertEquals(CollectorRunState.UNAVAILABLE, h.status("broken_check").state)
            assertEquals(CollectorRunState.RUNNING, h.status("plain").state)
        }
        CollectorHarness(nfc).use { h ->
            h.features += "android.hardware.nfc"
            h.startAll()
            assertEquals(CollectorRunState.RUNNING, h.status("nfc_like").state)
        }
    }
}
