package io.github.erwsim.watchpost.core.command

import io.github.erwsim.watchpost.core.collector.CollectorHost
import io.github.erwsim.watchpost.core.collector.CollectorRunState

/**
 * Implemented by the `location` collector (`:collectors`): one precise fix right now, emitted as an
 * ordinary `location.fix` through the collector's own path (same provider choice, same `mock`
 * detection). The command layer never talks to `LocationManager` itself.
 */
interface OnDemandLocator {
    /** Collector id (to check that it is running). */
    val id: String

    /** Acquires and emits fixes for at most [timeoutMs]; never throws for a missing fix. */
    suspend fun locateNow(timeoutMs: Long): LocateOutcome
}

sealed class LocateOutcome {
    /** At least one fix emitted; [provider] and [accuracyM] of the best one. */
    data class Fixed(val provider: String, val accuracyM: Float?) : LocateOutcome()
    data object NoFix : LocateOutcome()
    data class Unavailable(val reason: String) : LocateOutcome()
}

/**
 * `locate` (contract §8): precise fix (acquisition up to 60 s) through the running `location` collector,
 * then the buffer is sent at once ([RemoteCommands] forces an upload once `command.result` is emitted,
 * so that the fix and the result leave together). If the user switched the collector off (or its
 * permission is missing), the command fails (`location_unavailable`): a command never overrides a local choice.
 */
class LocateExecutor(
    private val host: () -> CollectorHost?,
    private val timeoutMs: Long = ACQUISITION_MS,
) : CommandExecutor {
    override suspend fun execute(command: AcceptedCommand): ExecutionResult {
        val h = host() ?: return ExecutionResult.failed("location_unavailable")
        val locator = h.collectors.filterIsInstance<OnDemandLocator>().firstOrNull()
            ?: return ExecutionResult.failed("location_unavailable")
        if (h.statuses.value[locator.id]?.state != CollectorRunState.RUNNING) return ExecutionResult.failed("location_unavailable")
        return when (val outcome = locator.locateNow(timeoutMs)) {
            is LocateOutcome.Fixed -> ExecutionResult.executed(
                "fix_${outcome.provider}" + (outcome.accuracyM?.let { "_${it.toInt()}m" } ?: ""),
            )
            LocateOutcome.NoFix -> ExecutionResult.failed("no_fix")
            is LocateOutcome.Unavailable -> ExecutionResult.failed(outcome.reason)
        }
    }

    companion object {
        const val ACQUISITION_MS = 60_000L
    }
}
