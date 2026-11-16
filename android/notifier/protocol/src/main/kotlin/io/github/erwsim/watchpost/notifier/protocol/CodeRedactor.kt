package io.github.erwsim.watchpost.notifier.protocol

/**
 * Masks numeric codes of 4 to 8 digits (verification codes received by SMS or by an app), so that
 * they never reach the server. Applied by the companion before the channel, and again by the agent.
 *
 * Rule (deliberately broad: masking too much is preferred to leaking a code):
 * 1. A "run" is a maximal sequence of decimal digits (any script: `\p{Nd}`) whose groups may be
 *    separated by ONE space, no-break space, narrow no-break space or hyphen: `123456`, `123 456`,
 *    `123-456`, `1 2 3 4`. Letters around it do not matter (`G-123456`, `code123456` are masked).
 * 2. A run that is the integer or decimal part of a decimal number (`1234,56`, `12.5000`) or a part
 *    of a date written with slashes (`16/11/2026`) is left as is.
 * 3. A run of 4 to 8 digits in total is replaced as a whole by [MASK].
 * 4. A longer run (phone number, IBAN, card number…) is kept, except its groups of 4 to 8 digits,
 *    which are masked one by one (`+44 20 7946 0958` → `+44 20 •••• ••••`; `06 12 34 56 78` is kept).
 *
 * Known false positives (masked although not a code): years (`2026`), amounts without decimals
 * (`1500 €`, `1 500 €`), ISO dates (`2026-11-16`), 4-digit blocks of phone numbers, postal codes
 * (`75011`), order or tracking numbers of 4 to 8 digits.
 * Known misses (codes left visible): codes of 3 digits or of 9 digits or more, alphanumeric codes
 * (`A1B2C3`), codes written with dots (`123.456`) or with a comma, a slash or two separators between
 * groups, a code split into small groups glued by a single space to another number (`123 456 2026`:
 * 10 digits, only `2026` is masked), codes spelled out in words. Android 15+ also hides the content
 * of the notifications it recognises as one-time codes from listeners that are not trusted, such as
 * the companion: this rule is a second layer, not the only one.
 */
object CodeRedactor {
    const val MASK = "••••"
    const val MIN_DIGITS = 4
    const val MAX_DIGITS = 8

    data class Result(val text: String, val redacted: Boolean)

    private val RUN = Regex("\\p{Nd}+(?:[ \\u00A0\\u202F\\-]\\p{Nd}+)*")
    private val GROUP = Regex("\\p{Nd}+")

    fun redact(input: String): Result {
        var redacted = false
        val out = StringBuilder(input.length)
        var last = 0
        for (m in RUN.findAll(input)) {
            val start = m.range.first
            val end = m.range.last + 1
            if (isPartOfDecimalOrDate(input, start, end)) continue
            val run = m.value
            val digits = run.count { Character.isDigit(it) }
            val replacement = when {
                digits in MIN_DIGITS..MAX_DIGITS -> MASK
                digits > MAX_DIGITS -> GROUP.replace(run) { g -> if (g.value.length in MIN_DIGITS..MAX_DIGITS) MASK else g.value }
                else -> continue
            }
            if (replacement == run) continue
            out.append(input, last, start).append(replacement)
            last = end
            redacted = true
        }
        if (!redacted) return Result(input, false)
        out.append(input, last, input.length)
        return Result(out.toString(), true)
    }

    private fun isPartOfDecimalOrDate(s: String, start: Int, end: Int): Boolean {
        fun digitAt(i: Int) = i in s.indices && Character.isDigit(s[i])
        val before = if (start >= 1) s[start - 1] else null
        val after = if (end < s.length) s[end] else null
        if ((before == '.' || before == ',' || before == '/') && digitAt(start - 2)) return true
        if ((after == '.' || after == ',' || after == '/') && digitAt(end + 1)) return true
        return false
    }
}
