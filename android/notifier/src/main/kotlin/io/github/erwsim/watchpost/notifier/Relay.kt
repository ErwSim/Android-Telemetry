package io.github.erwsim.watchpost.notifier

import android.annotation.SuppressLint
import android.content.Context
import android.os.SystemClock
import io.github.erwsim.watchpost.notifier.protocol.ContentPolicy
import io.github.erwsim.watchpost.notifier.protocol.NoiseFilter
import io.github.erwsim.watchpost.notifier.protocol.NotificationPayload
import io.github.erwsim.watchpost.notifier.protocol.NotifierConfig
import io.github.erwsim.watchpost.notifier.protocol.NotifierProtocol as P
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit

/** One listener callback, as read on the main thread. [title]/[text] never leave this process unless the settings allow it. */
class RawNotification(
    val key: String,
    val packageName: String,
    val category: String?,
    val channel: String?,
    val ongoing: Boolean,
    val foregroundService: Boolean,
    val groupSummary: Boolean,
    val importance: String?,
    val title: String?,
    val text: String?,
) {
    fun seen() = NoiseFilter.Seen(
        key = key,
        packageName = packageName,
        groupSummary = groupSummary,
        persistent = NoiseFilter.isPersistent(ongoing, foregroundService, category),
        fingerprint = NoiseFilter.fingerprint(category, channel, importance, ongoing, title, text),
    )

    override fun toString() = "RawNotification($packageName)"
}

/**
 * The companion's pipeline, on ONE worker thread with a bounded queue (the listener's callbacks
 * run on the main thread and must return at once; a call to the agent can block while its process
 * starts): settings read from the agent → noise reduction → content rule (content off or app
 * excluded: title and text dropped HERE) → channel.
 *
 * Settings: read from the agent, kept in memory at most [CONFIG_TTL_MS], read again at once when
 * the agent broadcasts [P.ACTION_CONFIG_CHANGED] or answers with another settings version. Until
 * they could be read, nothing is relayed. After a failure to reach the agent, nothing is tried for
 * [RETRY_AFTER_FAILURE_MS] (notifications of that period are dropped and counted, never kept).
 */
@SuppressLint("StaticFieldLeak") // Application context only.
object Relay {
    private const val QUEUE_SIZE = 256
    const val CONFIG_TTL_MS = 60_000L
    private const val RETRY_AFTER_FAILURE_MS = 10_000L

    private class Snapshot(val config: NotifierConfig, val agentVersion: Long?, val atMs: Long)

    @Volatile
    private var context: Context? = null

    @Volatile
    private var snapshot: Snapshot? = null

    @Volatile
    private var invalidated = false

    @Volatile
    private var lastFailureMs = Long.MIN_VALUE / 2

    // Worker thread only.
    private val noise = NoiseFilter()

    private val worker = ThreadPoolExecutor(
        1, 1, 0L, TimeUnit.MILLISECONDS, ArrayBlockingQueue(QUEUE_SIZE),
        { r -> Thread(r, "watchpost-notifier").apply { isDaemon = true } },
        { _, _ -> NotifierState.overflow.incrementAndGet() },
    )

    fun init(context: Context) {
        if (this.context == null) this.context = context.applicationContext
    }

    private fun channel(): AgentChannel? = context?.let(::AgentChannel)

    private fun submit(block: () -> Unit) {
        worker.execute {
            try {
                block()
            } catch (_: Exception) {
                // Never crash the listener's process; nothing is logged (payloads hold third-party content).
            }
        }
    }

    fun onConnected(active: List<RawNotification>) {
        NotifierState.listenerConnected = true
        submit {
            val now = SystemClock.elapsedRealtime()
            noise.reset()
            active.forEach { noise.seed(it.seen(), now) }
            invalidated = true
            channel()?.call(P.METHOD_STATUS, mapOf(P.KEY_LISTENER_CONNECTED to true))
        }
    }

    fun onDisconnected() {
        NotifierState.listenerConnected = false
        submit {
            noise.reset()
            channel()?.call(P.METHOD_STATUS, mapOf(P.KEY_LISTENER_CONNECTED to false))
        }
    }

    fun onPosted(raw: RawNotification) = submit { posted(raw) }

    fun onRemoved(raw: RawNotification) = submit { removed(raw) }

    /** The agent's settings changed: read them again before the next report. */
    fun invalidateConfig() {
        invalidated = true
        lastFailureMs = Long.MIN_VALUE / 2
    }

    private fun posted(raw: RawNotification) {
        val config = currentConfig() ?: return dropUndelivered()
        if (!config.accepting) return dropUndelivered()
        val verdict = noise.onPosted(raw.seen(), config.ignored, SystemClock.elapsedRealtime())
        if (!verdict.emit) {
            NotifierState.filtered.incrementAndGet()
            return
        }
        val content = ContentPolicy.apply(raw.packageName, raw.title, raw.text, config)
        deliver(raw, payload(raw, P.EVENT_POSTED, content))
    }

    private fun removed(raw: RawNotification) {
        val config = currentConfig() ?: return dropUndelivered()
        if (!config.accepting) return dropUndelivered()
        val verdict = noise.onRemoved(raw.key, raw.packageName, raw.groupSummary, config.ignored)
        if (!verdict.emit) {
            NotifierState.filtered.incrementAndGet()
            return
        }
        deliver(raw, payload(raw, P.EVENT_REMOVED, ContentPolicy.NONE))
    }

    private fun payload(raw: RawNotification, event: String, content: ContentPolicy.Content) = NotificationPayload(
        packageName = raw.packageName,
        event = event,
        category = raw.category,
        channel = raw.channel,
        ongoing = raw.ongoing,
        importance = raw.importance,
        title = content.title,
        text = content.text,
        redacted = content.redacted,
    )

    private fun deliver(raw: RawNotification, p: NotificationPayload) {
        val reply = channel()?.call(P.METHOD_POST, p.toValues()) ?: AgentChannel.Reply.Failed
        if (reply is AgentChannel.Reply.Ok) {
            NotifierState.relayed.incrementAndGet()
            NotifierState.lastRelayMs = System.currentTimeMillis()
            NotifierState.lastRelayPackage = p.packageName
            val version = reply.values.long(P.KEY_CONFIG_VERSION)
            if (version != null && version != snapshot?.agentVersion) invalidated = true
            return
        }
        noise.deliveryFailed(raw.key)
        NotifierState.notDelivered.incrementAndGet()
        noteFailure(reply)
    }

    private fun dropUndelivered() {
        NotifierState.notDelivered.incrementAndGet()
    }

    /** Settings to apply now, or null (agent unreachable, incompatible, refused): then nothing is relayed. */
    private fun currentConfig(): NotifierConfig? {
        val now = SystemClock.elapsedRealtime()
        val s = snapshot
        if (s != null && !invalidated && now - s.atMs < CONFIG_TTL_MS) return s.config
        if (now - lastFailureMs < RETRY_AFTER_FAILURE_MS) return null
        return fetchConfig()
    }

    /** Reads the agent's settings now (also used by the screen, from a background thread). */
    fun fetchConfig(): NotifierConfig? {
        val ch = channel() ?: return null
        invalidated = false
        val reply = ch.call(P.METHOD_CONFIG)
        val config = (reply as? AgentChannel.Reply.Ok)?.let { NotifierConfig.fromValues(it.values) }
        if (reply is AgentChannel.Reply.Ok && config != null) {
            snapshot = Snapshot(config, reply.values.long(P.KEY_CONFIG_VERSION), SystemClock.elapsedRealtime())
            NotifierState.config = config
            NotifierState.agent = NotifierState.Agent.OK
            return config
        }
        snapshot = null
        NotifierState.config = null
        if (reply is AgentChannel.Reply.Ok) NotifierState.agent = NotifierState.Agent.INCOMPATIBLE else noteFailure(reply)
        return null
    }

    private fun noteFailure(reply: AgentChannel.Reply) {
        NotifierState.agent = when (reply) {
            is AgentChannel.Reply.Ok -> return
            is AgentChannel.Reply.Refused -> when (reply.status) {
                P.STATUS_NOT_ACCEPTING -> {
                    invalidated = true // read the settings again: "accepting" changed
                    return
                }
                P.STATUS_RATE_LIMITED, P.STATUS_INVALID -> return
                P.STATUS_STARTING -> NotifierState.Agent.STARTING
                P.STATUS_DENIED -> NotifierState.Agent.DENIED
                else -> NotifierState.Agent.INCOMPATIBLE
            }
            AgentChannel.Reply.AgentAbsent -> NotifierState.Agent.ABSENT
            AgentChannel.Reply.Denied -> NotifierState.Agent.DENIED
            AgentChannel.Reply.Failed -> NotifierState.Agent.UNREACHABLE
        }
        snapshot = null
        lastFailureMs = SystemClock.elapsedRealtime()
    }
}
