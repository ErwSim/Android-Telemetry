package io.github.erwsim.watchpost.notifier

import android.content.Context
import io.github.erwsim.watchpost.notifier.protocol.BundleValues
import io.github.erwsim.watchpost.notifier.protocol.NotifierProtocol as P
import io.github.erwsim.watchpost.notifier.protocol.ValueReader
import io.github.erwsim.watchpost.notifier.protocol.bundleOf

/**
 * Companion side of the local channel: `ContentResolver.call` on the agent's provider (see
 * [P]). Blocking (binder call, and a cold start of the agent's process if it is not running):
 * never on the main thread. Never throws.
 */
class AgentChannel(private val context: Context) {
    sealed class Reply {
        /** The agent answered `ok`. */
        data class Ok(val values: ValueReader) : Reply()

        /** The agent answered with another status ([P.STATUS_NOT_ACCEPTING], [P.STATUS_DENIED]…). */
        data class Refused(val status: String) : Reply()

        /** No provider: the agent is not installed (or not visible). */
        data object AgentAbsent : Reply()

        /** The system refused the provider: the permission is not granted (APKs signed by different keys). */
        data object Denied : Reply()

        /** The agent's process died during the call (update, kill) or another failure. */
        data object Failed : Reply()
    }

    fun call(method: String, values: Map<String, Any?> = emptyMap()): Reply {
        val result = try {
            context.contentResolver.call(P.AUTHORITY, method, null, bundleOf(values + (P.KEY_PROTOCOL to P.VERSION)))
        } catch (_: SecurityException) {
            return Reply.Denied
        } catch (_: IllegalArgumentException) {
            return Reply.AgentAbsent // "Unknown authority"
        } catch (_: Exception) {
            return Reply.Failed
        } ?: return Reply.Failed
        val r = BundleValues(result)
        return when (val status = r.string(P.KEY_STATUS)) {
            null -> Reply.Failed
            P.STATUS_OK -> Reply.Ok(r)
            else -> Reply.Refused(status)
        }
    }
}
