package io.github.erwsim.watchpost.collectors.notifications

import io.github.erwsim.watchpost.notifier.protocol.NoiseFilter
import io.github.erwsim.watchpost.notifier.protocol.NoiseFilter.Verdict
import io.github.erwsim.watchpost.notifier.protocol.NotifierProtocol
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class NoiseFilterTest {
    private fun seen(key: String, pkg: String = "com.chat", text: String? = "a", category: String? = "msg", ongoing: Boolean = false, summary: Boolean = false) =
        NoiseFilter.Seen(
            key = key,
            packageName = pkg,
            groupSummary = summary,
            persistent = NoiseFilter.isPersistent(ongoing, foregroundService = false, category = category),
            fingerprint = NoiseFilter.fingerprint(category, "ch", "high", ongoing, "t", text),
        )

    @Test
    fun selfIgnoredAndGroupSummaries() {
        val f = NoiseFilter()
        assertEquals(Verdict.SELF, f.onPosted(seen("k", NotifierProtocol.AGENT_PACKAGE), emptySet(), 0))
        assertEquals(Verdict.SELF, f.onPosted(seen("k", NotifierProtocol.NOTIFIER_PACKAGE), emptySet(), 0))
        assertEquals(Verdict.IGNORED, f.onPosted(seen("k", "com.noisy"), setOf("com.noisy"), 0))
        assertEquals(Verdict.GROUP_SUMMARY, f.onPosted(seen("sum", summary = true), emptySet(), 0))
        assertEquals(Verdict.GROUP_SUMMARY, f.onRemoved("sum", "com.chat", groupSummary = true, ignored = emptySet()))
        // Children of the group are reported normally.
        assertEquals(Verdict.EMIT, f.onPosted(seen("child1"), emptySet(), 0))
        assertEquals(Verdict.EMIT, f.onPosted(seen("child2"), emptySet(), 0))
    }

    @Test
    fun repeatedUpdatesAreDeduplicated() {
        val f = NoiseFilter(minUpdateIntervalMs = 30_000)
        assertEquals(Verdict.EMIT, f.onPosted(seen("k", text = "1 message"), emptySet(), 0))
        assertEquals(Verdict.DUPLICATE, f.onPosted(seen("k", text = "1 message"), emptySet(), 1_000))
        assertEquals(Verdict.DUPLICATE, f.onPosted(seen("k", text = "1 message"), emptySet(), 3_600_000))
        // A new message in the same notification: reported, but not more than once per 30 s.
        assertEquals(Verdict.TOO_FREQUENT, f.onPosted(seen("k", text = "2 messages"), emptySet(), 10_000))
        assertEquals(Verdict.EMIT, f.onPosted(seen("k", text = "2 messages"), emptySet(), 3_600_000))
        assertEquals(Verdict.EMIT, f.onRemoved("k", "com.chat", false, emptySet()))
        assertEquals(Verdict.NOT_REPORTED, f.onRemoved("k", "com.chat", false, emptySet()))
    }

    @Test
    fun persistentNotificationsFirstPostAndRemovalOnly() {
        val f = NoiseFilter()
        // Media playback updating every track / second.
        assertEquals(Verdict.EMIT, f.onPosted(seen("media", category = "transport", text = "Titre 1"), emptySet(), 0))
        for (i in 2..50) assertEquals(Verdict.ONGOING_UPDATE, f.onPosted(seen("media", category = "transport", text = "Titre $i"), emptySet(), i * 60_000L))
        assertEquals(Verdict.EMIT, f.onRemoved("media", "com.chat", false, emptySet()))
        // Ongoing download, then "Download complete" (not ongoing any more): reported once.
        assertEquals(Verdict.EMIT, f.onPosted(seen("dl", category = "progress", ongoing = true, text = "1 %"), emptySet(), 0))
        assertEquals(Verdict.ONGOING_UPDATE, f.onPosted(seen("dl", category = "progress", ongoing = true, text = "50 %"), emptySet(), 1_000))
        assertEquals(Verdict.EMIT, f.onPosted(seen("dl", category = null, text = "Finished"), emptySet(), 2_000))
        assertEquals(Verdict.DUPLICATE, f.onPosted(seen("dl", category = null, text = "Finished"), emptySet(), 3_000))
        assertTrue(NoiseFilter.isPersistent(ongoing = false, foregroundService = true, category = null))
        assertTrue(NoiseFilter.isPersistent(ongoing = false, foregroundService = false, category = "stopwatch"))
    }

    @Test
    fun ratePerApp() {
        val f = NoiseFilter(maxPerApp = 20, appWindowMs = 600_000)
        repeat(20) { assertEquals(Verdict.EMIT, f.onPosted(seen("k$it", "com.spam"), emptySet(), it.toLong())) }
        assertEquals(Verdict.RATE_LIMITED, f.onPosted(seen("k20", "com.spam"), emptySet(), 100))
        // Other apps are not affected; removals of reported notifications still go through.
        assertEquals(Verdict.EMIT, f.onPosted(seen("other", "com.calm"), emptySet(), 100))
        assertEquals(Verdict.EMIT, f.onRemoved("k0", "com.spam", false, emptySet()))
        // Window slides.
        assertEquals(Verdict.EMIT, f.onPosted(seen("k21", "com.spam"), emptySet(), 600_001))
    }

    @Test
    fun seededNotificationsAndDeliveryFailures() {
        val f = NoiseFilter()
        f.seed(seen("old", text = "x"), 0)
        assertEquals(Verdict.DUPLICATE, f.onPosted(seen("old", text = "x"), emptySet(), 1))
        assertEquals(Verdict.NOT_REPORTED, f.onRemoved("old", "com.chat", false, emptySet()))
        f.seed(seen("old2", text = "x"), 0)
        assertEquals(Verdict.EMIT, f.onPosted(seen("old2", text = "y"), emptySet(), 1))
        // Not delivered: forgotten, so the same notification is reported when it shows up again.
        f.deliveryFailed("old2")
        assertEquals(Verdict.EMIT, f.onPosted(seen("old2", text = "y"), emptySet(), 2))
    }

    @Test
    fun memoryIsBounded() {
        val f = NoiseFilter(maxPerApp = Int.MAX_VALUE, maxTracked = 100)
        repeat(10_000) { f.onPosted(seen("k$it", "com.app$it"), emptySet(), it.toLong()) }
        assertEquals(100, f.trackedCount())
    }
}
