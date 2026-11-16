package io.github.erwsim.vigie.core.command

import io.github.erwsim.vigie.core.event.AgentClock
import io.github.erwsim.vigie.core.event.EventTypes
import io.github.erwsim.vigie.core.settings.AgentSettings
import io.github.erwsim.vigie.core.settings.SettingKey
import io.github.erwsim.vigie.core.sink.EventSink
import io.github.erwsim.vigie.core.sink.emit
import java.util.concurrent.ConcurrentHashMap

/** Local settings of the command channel (changed only in the app; each change emits `agent.config_changed`). */
object CommandSettings {
    /** Off by default: the owner switches the channel on in the app. */
    val ENABLED = SettingKey.BoolKey("commands.enabled", false)
    val MODE = SettingKey.ChoiceKey("commands.mode", ChannelMode.STREAM.wire, ChannelMode.entries.map { it.wire })
    val POLL_INTERVAL_MIN = SettingKey.IntKey("commands.poll_interval_min", 5, 1, 15)

    /** "Autoriser l'effacement à distance": off by default, switched on only after an explicit confirmation. */
    val ALLOW_WIPE = SettingKey.BoolKey("commands.allow_wipe", false)

    val KEYS = setOf(ENABLED.name, MODE.name, POLL_INTERVAL_MIN.name, ALLOW_WIPE.name)
}

/**
 * Everything of the remote commands that lives in `:core`: settings, command key, verification,
 * processing, channel. Executors are registered by the modules that own the platform calls
 * ([register]): ring/vibrate by `:app`, lock/wipe by `:policy`, locate here.
 */
class RemoteCommands(
    private val settings: AgentSettings,
    private val clock: AgentClock,
    private val sink: EventSink,
    val keys: CommandKeyStore,
    val state: CommandStateStore,
    private val deviceId: () -> String?,
    private val isDeviceOwner: () -> Boolean,
    private val hooks: CommandProcessor.Hooks,
    /** Builds the channel once [processor] and [state] exist (called from the constructor). */
    channelFactory: (RemoteCommands) -> CommandChannel,
) {
    private val executors = ConcurrentHashMap<String, CommandExecutor>()

    val verifier = CommandVerifier(clock, state, keys)
    val processor = CommandProcessor(
        clock = clock,
        verifier = verifier,
        state = state,
        sink = sink,
        environment = ::environment,
        executors = { executors },
        hooks = hooks,
    )
    val channel: CommandChannel = channelFactory(this)

    fun register(type: String, executor: CommandExecutor) {
        require(type in CommandTypes.ALL) { "not a contract §8 command: $type" }
        executors[type] = executor
    }

    fun environment() = CommandVerifier.Environment(
        channelEnabled = settings[CommandSettings.ENABLED],
        deviceId = deviceId(),
        wipeAllowed = settings[CommandSettings.ALLOW_WIPE],
        isDeviceOwner = isDeviceOwner,
    )

    /** Live conditions of [WipeGate], read again by the wipe executor right before the reset. */
    fun wipeLive() = WipeGate.Live(
        channelEnabled = settings[CommandSettings.ENABLED],
        codeConfigured = keys.isConfigured(deviceId()),
        wipeAllowed = settings[CommandSettings.ALLOW_WIPE],
        nowMs = clock.nowMillis(),
    )

    fun channelConfig() = ChannelConfig(
        enabled = settings[CommandSettings.ENABLED],
        mode = ChannelMode.fromWire(settings[CommandSettings.MODE]),
        pollIntervalMin = settings[CommandSettings.POLL_INTERVAL_MIN],
    )

    fun isCodeConfigured(): Boolean = keys.isConfigured(deviceId())

    sealed class CodeResult {
        data object Saved : CodeResult()
        data object TooShort : CodeResult()
        data object Mismatch : CodeResult()
        data object NotEnrolled : CodeResult()
    }

    /**
     * Derives `K` from [code] for the enrolled device id and stores it sealed; the code is not kept.
     * Slow (PBKDF2, 600 000 iterations): call from a background thread. Emits `agent.config_changed`
     * (`commands.code`, `unset`/`set`/`changed`): never the code.
     */
    fun setCode(code: String, confirmation: String): CodeResult {
        if (code != confirmation) return CodeResult.Mismatch
        if (CommandCrypto.codeLength(code) < CommandCrypto.MIN_CODE_CODE_POINTS) return CodeResult.TooShort
        val id = deviceId() ?: return CodeResult.NotEnrolled
        val before = if (keys.isConfigured(id)) "set" else "unset"
        keys.save(id, CommandCrypto.deriveKey(code, id), clock.nowMillis())
        sink.emit(EventTypes.AGENT_CONFIG_CHANGED) {
            put("key", "commands.code")
            put("old", before)
            put("new", if (before == "set") "changed" else "set")
        }
        return CodeResult.Saved
    }

    fun clearCode() {
        val before = if (keys.configuredFor.value != null) "set" else "unset"
        keys.clear()
        if (before == "set") {
            sink.emit(EventTypes.AGENT_CONFIG_CHANGED) {
                put("key", "commands.code")
                put("old", "set")
                put("new", "unset")
            }
        }
        // Without a code, remote wipe cannot happen anyway; the switch goes back to its safe default.
        settings.set(CommandSettings.ALLOW_WIPE, false)
    }
}
