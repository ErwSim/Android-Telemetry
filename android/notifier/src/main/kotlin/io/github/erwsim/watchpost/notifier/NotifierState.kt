package io.github.erwsim.watchpost.notifier

import io.github.erwsim.watchpost.notifier.protocol.NotifierConfig
import java.util.concurrent.atomic.AtomicLong

/**
 * What the screen shows, in memory only: nothing is written to disk by the companion (no
 * notification content, no history). Lost when the process ends.
 */
object NotifierState {
    enum class Agent { UNKNOWN, OK, ABSENT, DENIED, STARTING, INCOMPATIBLE, UNREACHABLE }

    @Volatile
    var listenerConnected: Boolean = false

    @Volatile
    var agent: Agent = Agent.UNKNOWN

    /** Last settings read from the agent (null: never read, or the last read failed). */
    @Volatile
    var config: NotifierConfig? = null

    /** Wall-clock time and app of the last notification event the agent accepted (0: none). */
    @Volatile
    var lastRelayMs: Long = 0L

    @Volatile
    var lastRelayPackage: String? = null

    val relayed = AtomicLong()

    /** Not reported on purpose: updates, persistent notifications, group summaries, ignored apps, rate limit. */
    val filtered = AtomicLong()

    /** Dropped because the agent was absent, stopped, not accepting or refused it. */
    val notDelivered = AtomicLong()

    /** Dropped because too many notifications were waiting (agent too slow to answer). */
    val overflow = AtomicLong()
}
