package io.github.erwsim.watchpost.core.command

import io.github.erwsim.watchpost.core.testing.CommandVector
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** Floor on the command passphrase: what an offline search of a relayed signature finds in days is refused. */
class CommandCodeTest {
    @Test
    fun codesWithoutLettersOrWithFewDistinctCharactersAreRefused() {
        for (weak in listOf(
            "123456789012", // 12 digits: 10^12 codes
            "0612345678 06", // phone number
            "12/03/1985 12/03", // dates
            "aaaaaaaaaaaa",
            "abababababab",
            "aaaabbbbcccc1111", // 4 distinct characters
            "!@#\$%^&*()_+", // no letter, no digit
            "1234 5678 9012 3456", // 16 digits
        )) {
            assertTrue(weak, CommandCrypto.isTooWeak(weak))
        }
    }

    @Test
    fun passphrasesAndLongRandomDigitsAreAccepted() {
        for (ok in listOf(
            CommandVector.CODE,
            "A long and unusual passphrase 2026",
            "pässwörd-código-密码-🔑🔑",
            "kX9#mQ2\$vL7@pR4!",
            "4729 1853 6027 3391 8840", // 20 random digits ≈ 66 bits
            "abcdefghijkl",
        )) {
            assertFalse(ok, CommandCrypto.isTooWeak(ok))
        }
    }
}
