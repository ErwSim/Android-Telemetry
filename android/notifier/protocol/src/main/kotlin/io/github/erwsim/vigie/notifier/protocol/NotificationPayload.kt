package io.github.erwsim.vigie.notifier.protocol

import io.github.erwsim.vigie.notifier.protocol.NotifierProtocol as P

/**
 * One `app.notification` event as it crosses the channel (contract §10). [title], [text] and
 * [redacted] are present only when the settings allow content for that app; the companion decides
 * it before sending and the agent applies the same rule again on reception.
 */
data class NotificationPayload(
    val packageName: String,
    /** [NotifierProtocol.EVENT_POSTED] or [NotifierProtocol.EVENT_REMOVED]. */
    val event: String,
    val category: String? = null,
    val channel: String? = null,
    val ongoing: Boolean = false,
    /** One of [Importance.VALUES], absent if unknown. */
    val importance: String? = null,
    val title: String? = null,
    val text: String? = null,
    val redacted: Boolean? = null,
) {
    fun toValues(): Map<String, Any?> = mapOf(
        P.KEY_PROTOCOL to P.VERSION,
        P.KEY_PACKAGE to packageName,
        P.KEY_EVENT to event,
        P.KEY_CATEGORY to category,
        P.KEY_CHANNEL to channel,
        P.KEY_ONGOING to ongoing,
        P.KEY_IMPORTANCE to importance,
        P.KEY_TITLE to title,
        P.KEY_TEXT to text,
        P.KEY_REDACTED to redacted,
    )

    /** Never prints third-party content (title, text), even by accident in a log or a test failure. */
    override fun toString(): String =
        "NotificationPayload($packageName, $event, category=$category, channel=$channel, ongoing=$ongoing, " +
            "importance=$importance, title=${if (title != null) "<${title.length}>" else "-"}, " +
            "text=${if (text != null) "<${text.length}>" else "-"}, redacted=$redacted)"

    /** Result of [decode]: a valid payload, or the reason it was refused (no content in the reason). */
    sealed class Decoded {
        data class Valid(val payload: NotificationPayload) : Decoded()
        data class Invalid(val reason: String) : Decoded()
    }

    companion object {
        /**
         * Agent-side validation of what the companion sent. Refuses (rather than repairs) anything the
         * companion would never send: too many keys, invalid or own package name, unknown event or
         * importance, a field over its bound. Within the bounds, text is cleaned again.
         */
        fun decode(r: ValueReader): Decoded {
            if (r.keyCount() > Limits.MAX_KEYS) return Decoded.Invalid("too_many_keys")
            val pkg = r.string(P.KEY_PACKAGE) ?: return Decoded.Invalid("package_missing")
            if (!PackageLists.isValidPackage(pkg)) return Decoded.Invalid("package_invalid")
            if (pkg in P.SELF_PACKAGES) return Decoded.Invalid("package_self")
            val event = r.string(P.KEY_EVENT)
            if (event != P.EVENT_POSTED && event != P.EVENT_REMOVED) return Decoded.Invalid("event_invalid")
            val importance = r.string(P.KEY_IMPORTANCE)
            if (importance != null && importance !in Importance.VALUES) return Decoded.Invalid("importance_invalid")

            val category = bounded(r.string(P.KEY_CATEGORY), Limits.MAX_CATEGORY_CODE_POINTS) ?: return Decoded.Invalid("category_too_long")
            val channel = bounded(r.string(P.KEY_CHANNEL), Limits.MAX_CHANNEL_CODE_POINTS) ?: return Decoded.Invalid("channel_too_long")
            val title = bounded(r.string(P.KEY_TITLE), Limits.MAX_CONTENT_CODE_POINTS) ?: return Decoded.Invalid("title_too_long")
            val text = bounded(r.string(P.KEY_TEXT), Limits.MAX_CONTENT_CODE_POINTS) ?: return Decoded.Invalid("text_too_long")
            val removed = event == P.EVENT_REMOVED
            val t = if (removed) null else TextBounds.clean(title.value, Limits.MAX_CONTENT_CODE_POINTS)
            val x = if (removed) null else TextBounds.clean(text.value, Limits.MAX_CONTENT_CODE_POINTS)
            return Decoded.Valid(
                NotificationPayload(
                    packageName = pkg,
                    event = event,
                    category = TextBounds.clean(category.value, Limits.MAX_CATEGORY_CODE_POINTS),
                    channel = TextBounds.clean(channel.value, Limits.MAX_CHANNEL_CODE_POINTS),
                    ongoing = r.bool(P.KEY_ONGOING) == true,
                    importance = importance,
                    title = t,
                    text = x,
                    redacted = if (t == null && x == null) null else r.bool(P.KEY_REDACTED),
                ),
            )
        }

        private class Box(val value: String?)

        /** null = over the bound (refused); Box(null) = absent. */
        private fun bounded(s: String?, maxCodePoints: Int): Box? = when {
            s == null -> Box(null)
            s.length > maxCodePoints * 2 -> null
            TextBounds.codePoints(s) > maxCodePoints -> null
            else -> Box(s)
        }
    }
}

/** `NotificationManager.IMPORTANCE_*` as lowercase names (like `net.cell.tech`); unspecified → absent. */
object Importance {
    val VALUES = setOf("none", "min", "low", "default", "high", "max")

    fun name(importance: Int): String? = when (importance) {
        0 -> "none"
        1 -> "min"
        2 -> "low"
        3 -> "default"
        4 -> "high"
        5 -> "max"
        else -> null
    }
}

/** What the settings let through of a notification's title and text (applied on both sides). */
object ContentPolicy {
    data class Content(val title: String?, val text: String?, val redacted: Boolean?) {
        override fun toString() = "Content(title=${title?.length}, text=${text?.length}, redacted=$redacted)"
    }

    val NONE = Content(null, null, null)

    /**
     * Content off, or app excluded from content: [NONE] (title and text are dropped here, before the
     * channel). Otherwise: control characters removed, codes masked if enabled (BEFORE truncation,
     * so that a code is never cut in half and half-leaked), then 512 code points at most.
     * `redacted` is present when content is present and masking is enabled (true if something was
     * masked, here or earlier by the companion: [alreadyRedacted]).
     */
    fun apply(packageName: String, rawTitle: String?, rawText: String?, config: NotifierConfig, alreadyRedacted: Boolean = false): Content {
        if (!config.allowsContent(packageName)) return NONE
        var masked = false
        fun process(raw: String?): String? {
            val cleaned = TextBounds.clean(TextBounds.precut(raw), Limits.MAX_RAW_CHARS) ?: return null
            val r = if (config.redactCodes) CodeRedactor.redact(cleaned) else CodeRedactor.Result(cleaned, false)
            if (r.redacted) masked = true
            return TextBounds.clean(r.text, Limits.MAX_CONTENT_CODE_POINTS)
        }
        val title = process(rawTitle)
        val text = process(rawText)
        if (title == null && text == null) return NONE
        val redacted = when {
            config.redactCodes -> masked || alreadyRedacted
            alreadyRedacted -> true
            else -> null
        }
        return Content(title, text, redacted)
    }
}
