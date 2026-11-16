package io.github.erwsim.watchpost.core.collector

import androidx.annotation.StringRes
import io.github.erwsim.watchpost.core.settings.SettingSpec

/**
 * A source of events. Implementations live in `:collectors` (no Device Owner privilege) or
 * `:policy` (Device Owner), one class per file, and are listed in that module's entry point
 * (`CollectorsModule.all()` / `PolicyModule.collectors()`). See `android/ARCHITECTURE-CODE.md`.
 *
 * Lifecycle (driven by [CollectorHost], never by the collector itself):
 * - [start] when the agent runs, the collector is enabled and every required [Requirement] is met;
 * - [stop] when it is disabled, loses a requirement, one of its [settings] changes (stop + start),
 *   or the agent stops;
 * - [collectOnce] for [periodic] work (WorkManager), whether or not the agent service runs.
 *
 * Threading: [start], [stop] and [collectOnce] are called on the collectors' thread
 * ([CollectorContext.looper]); they may suspend but must not block. Blocking work goes to
 * `ctx.scope.launch(Dispatchers.IO)`. Callbacks must be registered with [CollectorContext.handler]
 * (or through the ctx helpers) so they run on the same thread and errors are isolated.
 */
interface Collector {
    /** Stable id, `[a-z0-9_]+`: used in settings keys and in `agent.heartbeat.collectors`. */
    val id: String

    /** Short English title (string resource of the collector's module). */
    @get:StringRes
    val titleRes: Int

    /** English description of what is collected, shown in the app (transparency). */
    @get:StringRes
    val descriptionRes: Int

    /** Event types this collector may emit (shown in the app and documented in the contract). */
    val eventTypes: List<String>

    val defaultEnabled: Boolean get() = true

    /** Permissions/capabilities checked by the host before [start]. */
    val requirements: List<Requirement> get() = emptyList()

    /** User-tunable settings, rendered generically in the settings screen. */
    val settings: List<SettingSpec> get() = emptyList()

    /** Periodic one-shot collection scheduled with WorkManager (null: none). */
    val periodic: PeriodicSpec? get() = null

    /** Extra availability check (hardware, OS feature…) after [requirements]. */
    fun checkAvailability(ctx: CollectorContext): Availability = Availability.Available

    suspend fun start(ctx: CollectorContext) {}

    suspend fun stop(ctx: CollectorContext) {}

    suspend fun collectOnce(ctx: CollectorContext, reason: CollectReason) {}
}

/** Periodic collection through WorkManager (minimum 15 minutes, inexact under Doze). */
data class PeriodicSpec(
    val intervalMinutes: Long,
    /** Also call [Collector.collectOnce] right after [Collector.start]. */
    val runAtStart: Boolean = true,
)

enum class CollectReason { START, PERIODIC, MANUAL }

sealed class Requirement {
    /** A runtime or install-time permission; [optional] ones only degrade the collector. */
    data class Permission(val name: String, val optional: Boolean = false) : Requirement()

    /** Only meaningful when the app is Device Owner. */
    data object DeviceOwner : Requirement()

    /** `PackageManager.hasSystemFeature`. */
    data class SystemFeature(val name: String) : Requirement()
}

sealed class Availability {
    data object Available : Availability()

    /** [reason] is an English sentence shown to the user. */
    data class Unavailable(val reason: String) : Availability()
}

/** Contract values for `agent.heartbeat.collectors`. */
enum class CollectorRunState(val wire: String) {
    RUNNING("running"),
    DISABLED("disabled"),
    UNAVAILABLE("unavailable"),
}

data class CollectorStatus(
    val state: CollectorRunState,
    /** English reason when unavailable, or the last error. */
    val reason: String? = null,
    val lastError: String? = null,
    val missingPermissions: List<String> = emptyList(),
)
