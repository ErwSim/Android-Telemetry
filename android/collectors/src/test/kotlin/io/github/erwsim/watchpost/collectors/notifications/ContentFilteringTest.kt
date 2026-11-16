package io.github.erwsim.watchpost.collectors.notifications

import io.github.erwsim.watchpost.notifier.protocol.CodeRedactor.MASK
import io.github.erwsim.watchpost.notifier.protocol.ContentPolicy
import io.github.erwsim.watchpost.notifier.protocol.Limits
import io.github.erwsim.watchpost.notifier.protocol.NotifierConfig
import io.github.erwsim.watchpost.notifier.protocol.PackageLists
import io.github.erwsim.watchpost.notifier.protocol.TextBounds
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

/** Content rule, truncation and package lists (applied by the companion before the channel). */
class ContentFilteringTest {
    private val on = NotifierConfig(
        accepting = true, contentEnabled = true, redactCodes = true,
        contentExcluded = setOf("com.bank.app"), ignored = setOf("com.noisy.app"),
    )

    @Test
    fun contentOffByDefaultMeansNoTitleNorText() {
        assertSame(ContentPolicy.NONE, ContentPolicy.apply("com.chat", "Alice", "Salut", on.copy(contentEnabled = false)))
        assertSame(ContentPolicy.NONE, ContentPolicy.apply("com.chat", "Alice", "Salut", NotifierConfig.CLOSED))
        assertTrue(!NotifierConfig.CLOSED.contentEnabled && NotifierConfig.CLOSED.redactCodes && !NotifierConfig.CLOSED.accepting)
    }

    @Test
    fun excludedAppsNeverGetContent() {
        assertSame(ContentPolicy.NONE, ContentPolicy.apply("com.bank.app", "Virement", "Code 482913", on))
        val c = ContentPolicy.apply("com.chat", "Alice", "Ton code : 482913", on)
        assertEquals("Alice", c.title)
        assertEquals("Ton code : $MASK", c.text)
        assertEquals(true, c.redacted)
    }

    @Test
    fun redactedFlag() {
        assertEquals(false, ContentPolicy.apply("com.chat", "Alice", "Salut", on).redacted)
        // Masking disabled: no flag at all (nothing was checked).
        val off = ContentPolicy.apply("com.chat", "Alice", "Code 482913", on.copy(redactCodes = false))
        assertEquals("Code 482913", off.text)
        assertNull(off.redacted)
        // Already masked by the companion, masking switched off since: the flag stays.
        assertEquals(true, ContentPolicy.apply("com.chat", "A", "Code $MASK", on.copy(redactCodes = false), alreadyRedacted = true).redacted)
        // Blank content: no field.
        assertSame(ContentPolicy.NONE, ContentPolicy.apply("com.chat", "  ", "\u0000", on))
    }

    @Test
    fun truncationTo512CodePointsAfterMasking() {
        val long = "a".repeat(600)
        assertEquals(512, ContentPolicy.apply("com.chat", long, null, on).title!!.length)
        // Code points, not UTF-16 units: an emoji counts as one and is never split.
        val emoji = "😀".repeat(600)
        val t = ContentPolicy.apply("com.chat", emoji, null, on).title!!
        assertEquals(512, TextBounds.codePoints(t))
        assertEquals(1024, t.length)
        // A code straddling the 512th character is masked before the cut: no half code leaks.
        val straddling = "x".repeat(508) + " 48291367 fin"
        val s = ContentPolicy.apply("com.chat", null, straddling, on).text!!
        assertTrue(s, !s.contains("4829"))
        assertTrue(TextBounds.codePoints(s) <= Limits.MAX_CONTENT_CODE_POINTS)
        // Huge texts are cut before any work.
        assertEquals(Limits.MAX_RAW_CHARS, TextBounds.precut("b".repeat(1_000_000))!!.length)
        assertEquals(9, TextBounds.precut("aaaaaaaaa😀", 10)!!.length) // no half surrogate pair
    }

    @Test
    fun controlCharactersAreRemoved() {
        val c = ContentPolicy.apply("com.chat", "A\u0007B", "ligne 1\nligne 2\u001b[31m", on)
        assertEquals("A B", c.title)
        assertEquals("ligne 1\nligne 2 [31m", c.text)
    }

    @Test
    fun packageLists() {
        val p = PackageLists.parseText("com.a.b\n# commentaire\ncom.c.d, com.a.b ; pas-un-paquet\n\n  org.x.y  # fin\nsansPoint")
        assertEquals(listOf("com.a.b", "com.c.d", "org.x.y"), p.packages)
        assertEquals(listOf("pas-un-paquet", "sansPoint"), p.rejected)
        // Bounded size.
        val many = PackageLists.parse((1..2_000).map { "com.app.n$it" })
        assertEquals(Limits.MAX_LIST_ENTRIES, many.packages.size)
        assertTrue(many.rejected.size <= 20)
        assertTrue(PackageLists.parse(listOf("com." + "a".repeat(300))).packages.isEmpty())
        // Defaults are valid package names; the ignored list is empty by default.
        assertEquals(PackageLists.DEFAULT_CONTENT_EXCLUDED, PackageLists.parse(PackageLists.DEFAULT_CONTENT_EXCLUDED).packages)
        assertTrue(PackageLists.DEFAULT_IGNORED.isEmpty())
        // SMS and dialers are excluded from content by default (principle 4: no SMS, no call log).
        assertTrue(PackageLists.DEFAULT_CONTENT_EXCLUDED.containsAll(listOf("com.samsung.android.messaging", "com.google.android.apps.messaging", "com.samsung.android.dialer")))
        // Storage round trip, and "stored empty" differs from "absent" (default).
        assertEquals(p.packages, PackageLists.splitStored(PackageLists.joinForStorage(p.packages)))
        assertTrue(PackageLists.splitStored("").isEmpty())
    }

    @Test
    fun configVersionChangesWithEverySetting() {
        val versions = setOf(
            on.version, on.copy(accepting = false).version, on.copy(contentEnabled = false).version,
            on.copy(redactCodes = false).version, on.copy(contentExcluded = emptySet()).version, on.copy(ignored = emptySet()).version,
        )
        assertEquals(6, versions.size)
        assertEquals(on.version, on.copy(contentExcluded = setOf("com.bank.app")).version)
    }
}
