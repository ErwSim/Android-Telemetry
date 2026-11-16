package io.github.erwsim.vigie.policy.remote

import io.github.erwsim.vigie.core.command.AcceptedCommand
import io.github.erwsim.vigie.core.command.CommandExecutor
import io.github.erwsim.vigie.core.command.CommandParams
import io.github.erwsim.vigie.core.command.CommandTypes
import io.github.erwsim.vigie.core.command.ExecutionResult
import io.github.erwsim.vigie.core.command.Refusal
import io.github.erwsim.vigie.core.command.WipeGate

/**
 * Device Owner calls of the remote commands `lock` and `clear_lock_message` (contract §8), behind an
 * interface so that the executors are tested on the JVM. Android implementation: [AndroidLockScreenGateway].
 */
interface LockScreenGateway {
    fun isDeviceOwner(): Boolean

    /** `DevicePolicyManager.lockNow()` (needs `<force-lock/>` in `device_admin.xml`). */
    fun lockNow()

    /** `DevicePolicyManager.setDeviceOwnerLockScreenInfo(admin, info)`; null clears it. */
    fun setLockScreenInfo(info: String?)
    fun lockScreenInfo(): String?
}

/**
 * The factory reset. **The only implementation that does anything is [AndroidFactoryReset]**, built in
 * exactly one place (`PolicyModule.registerCommandExecutors`) and handed only to [WipeExecutor]
 * (`WipeIsolationTest` checks the sources). Tests use a recording fake: no test can wipe anything.
 */
fun interface FactoryReset {
    fun wipe()
}

/** `lock`: optional message on the lock screen first, then immediate lock. */
class LockExecutor(private val gateway: LockScreenGateway) : CommandExecutor {
    override suspend fun execute(command: AcceptedCommand): ExecutionResult {
        if (command.type != CommandTypes.LOCK) return ExecutionResult.refused(Refusal.UNKNOWN_TYPE)
        if (!gateway.isDeviceOwner()) return ExecutionResult.refused(Refusal.NOT_DEVICE_OWNER)
        val message = (command.params as? CommandParams.Lock)?.message
        var detail = "ok"
        if (message != null) {
            detail = try {
                gateway.setLockScreenInfo(message)
                "ok_message"
            } catch (e: Exception) {
                // Locking matters more than the message: lock anyway, say the message failed.
                "ok_message_failed"
            }
        }
        return try {
            gateway.lockNow()
            ExecutionResult.executed(detail)
        } catch (e: SecurityException) {
            ExecutionResult.failed("lock_refused")
        } catch (e: Exception) {
            ExecutionResult.failed("lock_error_${e.javaClass.simpleName}".take(80))
        }
    }
}

/** `clear_lock_message`: removes the Device Owner lock-screen message (the owner's own info shows again). */
class ClearLockMessageExecutor(private val gateway: LockScreenGateway) : CommandExecutor {
    override suspend fun execute(command: AcceptedCommand): ExecutionResult {
        if (command.type != CommandTypes.CLEAR_LOCK_MESSAGE) return ExecutionResult.refused(Refusal.UNKNOWN_TYPE)
        if (!gateway.isDeviceOwner()) return ExecutionResult.refused(Refusal.NOT_DEVICE_OWNER)
        return try {
            gateway.setLockScreenInfo(null)
            ExecutionResult.executed()
        } catch (e: Exception) {
            ExecutionResult.failed("clear_error_${e.javaClass.simpleName}".take(80))
        }
    }
}

/**
 * `wipe`: the only irreversible action of the app. Runs the reset only if [WipeGate.allows] holds for
 * the verified command **and** the live state read now (channel on, command code set, "Autoriser
 * l'effacement à distance" on, not expired), and the app is still Device Owner. Anything else is refused
 * and [reset] is not called.
 */
class WipeExecutor(
    private val live: () -> WipeGate.Live,
    private val isDeviceOwner: () -> Boolean,
    private val reset: FactoryReset,
) : CommandExecutor {
    override suspend fun execute(command: AcceptedCommand): ExecutionResult {
        if (command.type != CommandTypes.WIPE) return ExecutionResult.refused(Refusal.UNKNOWN_TYPE)
        if (!WipeGate.allows(command, live())) return ExecutionResult.refused(Refusal.DISABLED)
        if (!isDeviceOwner()) return ExecutionResult.refused(Refusal.NOT_DEVICE_OWNER)
        return try {
            reset.wipe()
            // On a real device the process is killed during the reset; reaching this line is normal only in tests.
            ExecutionResult.executed()
        } catch (e: Exception) {
            ExecutionResult.failed("wipe_error_${e.javaClass.simpleName}".take(80))
        }
    }
}
