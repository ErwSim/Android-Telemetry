package io.github.erwsim.watchpost

import io.github.erwsim.watchpost.ui.safeLabel
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** An application's name is hostile input: shown on one bounded line, next to its package name. */
class SafeLabelTest {
    @Test
    fun `a name cannot push the package name away, hide behind control characters or run for ever`() {
        assertEquals("Messages", safeLabel("Messages"))
        assertEquals("Mise à jour du système", safeLabel("  Mise à jour\n\n\n\tdu   système \u0000"))
        // Right-to-left override and zero-width characters (format characters) are dropped.
        assertEquals("Samsung Messages", safeLabel("\u202ESamsung\u200B Messages\u2066"))
        assertEquals("a b", safeLabel("a\u2028\u2029b"))
        assertEquals(60, safeLabel("x".repeat(5_000)).length)
        assertTrue(safeLabel("\n\n\u202E").isEmpty())
    }
}
