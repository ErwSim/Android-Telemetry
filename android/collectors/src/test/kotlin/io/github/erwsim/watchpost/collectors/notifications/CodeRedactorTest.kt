package io.github.erwsim.watchpost.collectors.notifications

import io.github.erwsim.watchpost.notifier.protocol.CodeRedactor
import io.github.erwsim.watchpost.notifier.protocol.CodeRedactor.MASK
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Masking of 4-to-8-digit codes. The "false positive" and "miss" cases document the limits of the
 * rule (see [CodeRedactor]); they are asserted so that a change of behaviour is noticed.
 */
class CodeRedactorTest {
    private fun r(s: String) = CodeRedactor.redact(s).text

    @Test
    fun masksCodesSurroundedByText() {
        assertEquals("Votre code est $MASK.", r("Votre code est 482913."))
        assertEquals("$MASK est votre code de vérification", r("4829 est votre code de vérification"))
        assertEquals("Code:$MASK", r("Code:48291367"))
        assertEquals("G-$MASK is your Google verification code", r("G-482913 is your Google verification code"))
        assertEquals("code$MASK", r("code482913")) // letters glued to the digits do not protect them
        assertEquals("<#> $MASK est votre code. FA+9qCX9VSu", r("<#> 482913 est votre code. FA+9qCX9VSu"))
        assertEquals("Code : $MASK, valable 10 min", r("Code : 482913, valable 10 min"))
    }

    @Test
    fun masksGroupedCodesAsAWhole() {
        assertEquals("Code $MASK", r("Code 482 913"))
        assertEquals("Code $MASK", r("Code 482-913"))
        assertEquals("Code $MASK", r("Code 482 913"))
        assertEquals("Code $MASK", r("Code 4 8 2 9 1 3"))
        // Two codes in one text, and a non-Latin script.
        assertEquals("$MASK puis $MASK", r("1234 puis 87654321"))
        assertEquals("رمز التحقق $MASK", r("رمز التحقق ٤٨٢٩١٣"))
        assertEquals("Code $MASK", r("Code １２３４５６")) // full-width digits
    }

    @Test
    fun boundaries() {
        assertEquals("123", r("123"))
        assertEquals(MASK, r("1234"))
        assertEquals(MASK, r("12345678"))
        assertEquals("123456789", r("123456789")) // 9 digits: not a code by this rule (miss if it is one)
        assertFalse(CodeRedactor.redact("rien à masquer").redacted)
        assertTrue(CodeRedactor.redact("1234").redacted)
        // Idempotent: the mask contains no digit.
        assertEquals(r("Code 482913"), r(r("Code 482913")))
    }

    @Test
    fun amountsDatesAndPhoneNumbersThatAreKept() {
        assertEquals("Paiement de 1234,56 €", r("Paiement de 1234,56 €"))
        assertEquals("Paiement de 1 234,56 €", r("Paiement de 1 234,56 €"))
        assertEquals("Solde : 12.5000 BTC", r("Solde : 12.5000 BTC"))
        assertEquals("RDV le 16/11/2026 à 14:30", r("RDV le 16/11/2026 à 14:30"))
        assertEquals("RDV le 16.11.2026", r("RDV le 16.11.2026"))
        assertEquals("Appelez le 06 12 34 56 78", r("Appelez le 06 12 34 56 78"))
        assertEquals("Appelez le 0612345678", r("Appelez le 0612345678"))
        assertEquals("Appelez le +33 6 12 34 56 78", r("Appelez le +33 6 12 34 56 78"))
        assertEquals("Il est 12:30", r("Il est 12:30"))
    }

    @Test
    fun falsePositivesMaskedAlthoughNotCodes() {
        assertEquals("Paiement de $MASK €", r("Paiement de 1500 €"))
        assertEquals("Paiement de $MASK €", r("Paiement de 1 500 €"))
        assertEquals("Le 16 novembre $MASK", r("Le 16 novembre 2026"))
        assertEquals("Le $MASK", r("Le 2026-11-16"))
        assertEquals("$MASK Paris", r("75011 Paris"))
        assertEquals("Call +44 20 $MASK $MASK", r("Call +44 20 7946 0958")) // 4-digit blocks of a long number
        assertEquals("FR76 $MASK $MASK", r("FR76 3000 6000")) // IBAN blocks
    }

    @Test
    fun missesLeftVisible() {
        assertEquals("Code 123.456", r("Code 123.456")) // dotted
        assertEquals("Code 1234.5678", r("Code 1234.5678")) // looks like a decimal number
        assertEquals("Code A1B2C3", r("Code A1B2C3")) // alphanumeric
        assertEquals("Code 482", r("Code 482")) // 3 digits
        assertEquals("Code 123 456 $MASK", r("Code 123 456 2026")) // glued to another number: 10 digits
        assertEquals("Code quatre huit deux neuf", r("Code quatre huit deux neuf"))
    }
}
