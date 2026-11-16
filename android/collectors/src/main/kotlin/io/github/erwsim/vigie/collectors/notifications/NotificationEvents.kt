package io.github.erwsim.vigie.collectors.notifications

import io.github.erwsim.vigie.core.event.EventDataBuilder
import io.github.erwsim.vigie.core.event.eventData
import io.github.erwsim.vigie.notifier.protocol.NotificationPayload
import kotlinx.serialization.json.JsonObject

/** `data` of `app.notification` (contract §2 and §10); public so that the contract tests can build samples. */
object NotificationEvents {
    const val TYPE = "app.notification"

    fun data(p: NotificationPayload): JsonObject = eventData { fill(p) }

    fun EventDataBuilder.fill(p: NotificationPayload) {
        put("package", p.packageName)
        put("event", p.event)
        put("category", p.category)
        put("channel", p.channel)
        put("ongoing", p.ongoing)
        put("importance", p.importance)
        put("title", p.title)
        put("text", p.text)
        put("redacted", p.redacted)
    }
}
