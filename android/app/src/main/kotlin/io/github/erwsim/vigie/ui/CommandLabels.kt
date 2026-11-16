package io.github.erwsim.vigie.ui

import android.content.Context
import androidx.annotation.StringRes
import io.github.erwsim.vigie.R
import io.github.erwsim.vigie.core.command.ChannelPhase
import io.github.erwsim.vigie.core.command.CommandTypes
import io.github.erwsim.vigie.core.command.Refusal

/** French labels of the remote commands (types, outcomes, refusal reasons, channel states). */
object CommandLabels {
    @StringRes
    fun type(type: String): Int = when (type) {
        CommandTypes.RING -> R.string.cmd_type_ring
        CommandTypes.VIBRATE -> R.string.cmd_type_vibrate
        CommandTypes.STOP_RING -> R.string.cmd_type_stop_ring
        CommandTypes.LOCATE -> R.string.cmd_type_locate
        CommandTypes.LOCK -> R.string.cmd_type_lock
        CommandTypes.CLEAR_LOCK_MESSAGE -> R.string.cmd_type_clear_lock_message
        CommandTypes.WIPE -> R.string.cmd_type_wipe
        else -> R.string.cmd_type_unknown
    }

    @StringRes
    fun status(status: String): Int = when (status) {
        "executed" -> R.string.cmd_status_executed
        "failed" -> R.string.cmd_status_failed
        else -> R.string.cmd_status_refused
    }

    /** Explanation of a refusal or failure; null for a plain success. */
    fun detail(context: Context, status: String, detail: String): String? {
        val res = when (detail) {
            Refusal.DISABLED -> R.string.cmd_refusal_disabled
            Refusal.MALFORMED -> R.string.cmd_refusal_malformed
            Refusal.WRONG_DEVICE -> R.string.cmd_refusal_wrong_device
            Refusal.UNKNOWN_TYPE -> R.string.cmd_refusal_unknown_type
            Refusal.NO_CODE_CONFIGURED -> R.string.cmd_refusal_no_code
            Refusal.BAD_SIGNATURE -> R.string.cmd_refusal_bad_signature
            Refusal.EXPIRED -> R.string.cmd_refusal_expired
            Refusal.REPLAY -> R.string.cmd_refusal_replay
            Refusal.BAD_PARAMS -> R.string.cmd_refusal_bad_params
            Refusal.NOT_DEVICE_OWNER -> R.string.cmd_refusal_not_device_owner
            Refusal.LOCKED_OUT -> R.string.cmd_refusal_locked_out
            "dnd_alarms_muted" -> R.string.cmd_detail_dnd
            "no_fix" -> R.string.cmd_detail_no_fix
            "location_unavailable" -> R.string.cmd_detail_location_unavailable
            "ok", "stopped" -> return null
            else -> return if (status == "executed" && detail.startsWith("ok")) null else detail
        }
        return context.getString(res)
    }

    @StringRes
    fun phase(phase: ChannelPhase): Int = when (phase) {
        ChannelPhase.OFF -> R.string.cmd_phase_off
        ChannelPhase.NOT_ENROLLED -> R.string.cmd_phase_not_enrolled
        ChannelPhase.WAITING_NETWORK -> R.string.cmd_phase_waiting_network
        ChannelPhase.CONNECTING -> R.string.cmd_phase_connecting
        ChannelPhase.CONNECTED -> R.string.cmd_phase_connected
        ChannelPhase.POLL_IDLE -> R.string.cmd_phase_poll_idle
        ChannelPhase.BACKOFF -> R.string.cmd_phase_backoff
        ChannelPhase.REFUSED -> R.string.cmd_phase_refused
        ChannelPhase.UNSUPPORTED -> R.string.cmd_phase_unsupported
    }
}
