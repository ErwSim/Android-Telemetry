package io.github.erwsim.watchpost.notifier.protocol

/** Text normalisation shared by both sides of the channel (pure functions). */
object TextBounds {
    /**
     * First [maxChars] UTF-16 units of [cs] as a String, without allocating the whole text and
     * without leaving half of a surrogate pair at the end.
     */
    fun precut(cs: CharSequence?, maxChars: Int = Limits.MAX_RAW_CHARS): String? {
        if (cs == null) return null
        if (cs.length <= maxChars) return cs.toString()
        var end = maxChars
        if (end > 0 && Character.isHighSurrogate(cs[end - 1])) end--
        return cs.subSequence(0, end).toString()
    }

    /** At most [maxCodePoints] Unicode code points (a surrogate pair is never split). */
    fun truncateCodePoints(s: String, maxCodePoints: Int): String {
        if (s.length <= maxCodePoints) return s // each code point takes at least one char
        if (s.codePointCount(0, s.length) <= maxCodePoints) return s
        return s.substring(0, s.offsetByCodePoints(0, maxCodePoints))
    }

    /**
     * Control characters (Unicode category Cc, except line feed and tab) become spaces, the text is
     * trimmed and truncated to [maxCodePoints]; blank → null (field absent).
     */
    fun clean(s: String?, maxCodePoints: Int): String? {
        if (s == null) return null
        val sb = StringBuilder(minOf(s.length, maxCodePoints * 2))
        for (ch in s) {
            sb.append(if (Character.getType(ch) == Character.CONTROL.toInt() && ch != '\n' && ch != '\t') ' ' else ch)
        }
        val trimmed = sb.toString().trim()
        if (trimmed.isEmpty()) return null
        return truncateCodePoints(trimmed, maxCodePoints)
    }

    fun codePoints(s: String): Int = s.codePointCount(0, s.length)
}
