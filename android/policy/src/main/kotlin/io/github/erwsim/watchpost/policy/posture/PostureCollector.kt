package io.github.erwsim.watchpost.policy.posture

import android.app.admin.DevicePolicyManager
import android.content.IntentFilter
import android.database.ContentObserver
import android.net.Uri
import android.provider.Settings
import android.security.KeyChain
import androidx.core.content.edit
import io.github.erwsim.watchpost.core.collector.CollectReason
import io.github.erwsim.watchpost.core.collector.Collector
import io.github.erwsim.watchpost.core.collector.CollectorContext
import io.github.erwsim.watchpost.core.collector.PeriodicSpec
import io.github.erwsim.watchpost.core.event.Severity
import io.github.erwsim.watchpost.core.event.WatchpostJson
import io.github.erwsim.watchpost.core.event.eventData
import io.github.erwsim.watchpost.policy.R
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.serialization.builtins.MapSerializer
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.builtins.serializer

/**
 * `security.posture` at start, daily and on change, plus one `security.posture_change` per changed
 * field; `security.ca_cert` when a user CA appears or disappears; `security.keyguard` (unlock
 * failures/successes reported to the device admin). Change triggers: settings observers (ADB,
 * developer options, private DNS), trust store and Device Owner broadcasts, password
 * changes and CA entries of the security log. No polling.
 *
 * Works without Device Owner (fewer fields: those that need it are left out).
 */
class PostureCollector : Collector {
    override val id = ID
    override val titleRes = R.string.collector_posture_title
    override val descriptionRes = R.string.collector_posture_desc
    override val eventTypes = listOf("security.posture", "security.posture_change", "security.ca_cert", "security.keyguard")
    override val periodic = PeriodicSpec(intervalMinutes = 24 * 60, runAtStart = true)

    @Volatile
    private var ctx: CollectorContext? = null
    private var reader: PostureReader? = null
    private val mutex = Mutex()
    @Volatile
    private var pending: Job? = null

    override suspend fun start(ctx: CollectorContext) {
        this.ctx = ctx
        pending = null
        val observer = object : ContentObserver(ctx.handler) {
            override fun onChange(selfChange: Boolean, uri: Uri?) = requestCheck()
        }
        val resolver = ctx.appContext.contentResolver
        for (key in WATCHED_GLOBAL) {
            ctx.guard("observe $key") { resolver.registerContentObserver(Settings.Global.getUriFor(key), false, observer) }
        }
        ctx.onStop { resolver.unregisterContentObserver(observer) }
        // The two KeyChain actions are sent by the KeyChain app (its own uid, not the system server):
        // exported receiver needed. All three are protected broadcasts, and the only effect is a re-read.
        ctx.registerReceiver(
            IntentFilter().apply {
                addAction(KeyChain.ACTION_TRUST_STORE_CHANGED)
                addAction(KeyChain.ACTION_KEYCHAIN_CHANGED)
                addAction(DevicePolicyManager.ACTION_DEVICE_OWNER_CHANGED)
            },
            exported = true,
        ) { requestCheck() }
    }

    override suspend fun stop(ctx: CollectorContext) {
        this.ctx = null
        pending?.cancel()
    }

    override suspend fun collectOnce(ctx: CollectorContext, reason: CollectReason) {
        collect(ctx, always = true)
    }

    /** Debounced re-check after a change signal (several settings often change together). */
    fun requestCheck() {
        val c = ctx ?: return
        pending?.cancel()
        pending = c.scope.launch {
            delay(DEBOUNCE_MS)
            collect(c, always = false)
        }
    }

    /** From the device admin receiver: `security.keyguard`. */
    fun onKeyguard(succeeded: Boolean, failedAttempts: Int?) {
        val c = ctx ?: return
        val sev = when {
            succeeded -> Severity.INFO
            (failedAttempts ?: 0) >= 3 -> Severity.WARNING
            else -> Severity.NOTABLE
        }
        c.sink.emit("security.keyguard", sev, keyguardData(succeeded, failedAttempts))
    }

    private suspend fun collect(ctx: CollectorContext, always: Boolean) = mutex.withLock {
        val reader = reader ?: PostureReader(ctx.appContext).also { reader = it }
        val (posture, cas) = withContext(ctx.io) {
            val cas = reader.userCaCerts()
            reader.read(ctx.clock.nowMillis(), cas) to cas
        }
        // CA additions/removals.
        val previousCas = ctx.prefs.getString(K_CAS, null)?.let { decode(it) }
        for (change in CaCertDiff.diff(previousCas, cas)) {
            ctx.sink.emit("security.ca_cert", Severity.WARNING, caCertData(change))
        }
        ctx.prefs.edit { putString(K_CAS, encode(cas.associate { it.sha256 to it.subject })) }

        val current = PostureDiff.asStrings(posture)
        val previous = ctx.prefs.getString(K_POSTURE, null)?.let { decode(it) }
        val changes = PostureDiff.diff(previous, current)
        if (!always && changes.isEmpty()) {
            // Same posture; still remember newly readable fields.
            ctx.prefs.edit { putString(K_POSTURE, encode(current)) }
            return@withLock
        }
        val sev = changes.maxOfOrNull { it.sev } ?: Severity.INFO
        ctx.sink.emit("security.posture", sev, postureData(posture))
        for (c in changes) {
            ctx.sink.emit("security.posture_change", c.sev, changeData(c))
        }
        ctx.prefs.edit { putString(K_POSTURE, encode(current)) }
    }

    private fun encode(map: Map<String, String>) = WatchpostJson.encodeToString(MAP, map)

    private fun decode(text: String): Map<String, String>? = try {
        WatchpostJson.decodeFromString(MAP, text)
    } catch (_: Exception) {
        null
    }

    companion object {
        const val ID = "posture"

        /** `security.posture` data from [PostureReader.read] (null: unreadable, absent). */
        fun postureData(p: Map<String, Any?>): JsonObject = eventData {
            for ((k, v) in p) {
                when (v) {
                    null -> Unit
                    is Boolean -> put(k, v)
                    is Number -> put(k, v)
                    is Collection<*> -> putStrings(k, v.map { it.toString() })
                    else -> put(k, v.toString())
                }
            }
        }

        fun changeData(c: PostureChange): JsonObject = eventData {
            put("field", c.field)
            put("old", c.old)
            put("new", c.new)
        }

        fun caCertData(change: CaChange): JsonObject = eventData {
            put("event", change.event)
            put("sha256", change.cert.sha256)
            put("subject", change.cert.subject)
        }

        fun keyguardData(succeeded: Boolean, failedAttempts: Int?): JsonObject = eventData {
            put("event", if (succeeded) "unlock_succeeded" else "unlock_failed")
            put("failed_attempts", failedAttempts)
        }

        private const val K_POSTURE = "last_posture"
        private const val K_CAS = "user_cas"
        private const val DEBOUNCE_MS = 3_000L
        private val MAP = MapSerializer(String.serializer(), String.serializer())
        private val WATCHED_GLOBAL = listOf(
            Settings.Global.ADB_ENABLED,
            Settings.Global.DEVELOPMENT_SETTINGS_ENABLED,
            PostureReader.KEY_ADB_WIFI,
            PostureReader.KEY_DNS_MODE,
            PostureReader.KEY_DNS_SPECIFIER,
        )
    }
}
