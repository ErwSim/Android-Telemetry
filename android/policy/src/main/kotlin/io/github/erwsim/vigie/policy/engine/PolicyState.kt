package io.github.erwsim.vigie.policy.engine

import android.annotation.SuppressLint
import android.content.SharedPreferences
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject

/** Kind of an applied policy item. */
@Serializable
enum class ItemKind {
    @SerialName("package") PACKAGE,
    @SerialName("permission") PERMISSION,
    @SerialName("restriction") RESTRICTION,
    @SerialName("setting") SETTING,
    @SerialName("private_dns") PRIVATE_DNS,
    @SerialName("backup") BACKUP,
    @SerialName("vpn") VPN,
}

@Serializable
enum class RecordStatus {
    /** Written BEFORE the device is changed (write-ahead): a crash in between leaves something to undo. */
    @SerialName("pending") PENDING,
    @SerialName("applied") APPLIED,
}

/** Previous state of one runtime permission, to restore it exactly. */
@Serializable
data class PermissionPrev(
    val permission: String,
    /** `PERMISSION_GRANT_STATE_*` before Vigie denied it. */
    @SerialName("prev_state") val prevState: Int,
    /** Whether it was granted before (matters when [prevState] is DEFAULT: user-controlled). */
    @SerialName("prev_granted") val prevGranted: Boolean,
    val applied: Boolean = false,
)

/**
 * One change Vigie made to the device, with everything needed to undo it exactly. Flat on
 * purpose (nullable fields per kind): unknown fields are ignored on read, so an older or newer
 * app version can still undo what an other version applied.
 */
@Serializable
data class AppliedRecord(
    /** Catalog id (`pkg:…`, `perm:…`, `restr:…`, `set:…`) or `dns`, `backup`, `vpn`. */
    val id: String,
    val kind: ItemKind,
    /** Package, restriction key, setting key or DNS host. */
    val target: String,
    /** `equilibre`/`strict`, absent for a manual action. */
    val profile: String? = null,
    val status: RecordStatus = RecordStatus.PENDING,
    @SerialName("applied_at_ms") val appliedAtMs: Long = 0,
    val method: PackageMethod? = null,
    val permissions: List<PermissionPrev> = emptyList(),
    val namespace: String? = null,
    @SerialName("prev_value") val prevValue: String? = null,
    @SerialName("new_value") val newValue: String? = null,
    @SerialName("prev_dns_mode") val prevDnsMode: Int? = null,
    @SerialName("prev_dns_host") val prevDnsHost: String? = null,
    @SerialName("dns_locked_by_us") val dnsLockedByUs: Boolean = false,
    /** Last known addresses of the DoT host (to probe it while the strict private DNS fails). */
    @SerialName("dns_addresses") val dnsAddresses: List<String> = emptyList(),
    @SerialName("dns_fallback") val dnsFallback: Boolean = false,
    @SerialName("prev_bool") val prevBool: Boolean? = null,
    @SerialName("prev_vpn_package") val prevVpnPackage: String? = null,
    @SerialName("prev_vpn_lockdown") val prevVpnLockdown: Boolean? = null,
    @SerialName("vpn_lockdown") val vpnLockdown: Boolean? = null,
    @SerialName("last_error") val lastError: String? = null,
)

@Serializable
data class AppliedState(
    val version: Int = 1,
    val records: List<AppliedRecord> = emptyList(),
)

/** What the owner chose on the screen (persisted; nothing is applied until "Appliquer"). */
@Serializable
data class PolicySelection(
    val profile: Profile = Profile.BALANCED,
    /** Item id → selected, overriding the catalog default. Also `dns`, `dns_lock`, `backup`. */
    val overrides: Map<String, Boolean> = emptyMap(),
) {
    fun isSelected(item: CatalogItem): Boolean = profile.includes(item.profile) && (overrides[item.id] ?: item.default)

    val privateDns: Boolean get() = overrides[ID_DNS] ?: true

    /**
     * Off unless asked for: the lock (`disallow_config_private_dns`) removes the owner's own way out
     * through the Settings if the DNS host stops answering. First impose the DNS without it, watch
     * it work, then lock.
     */
    val privateDnsLock: Boolean get() = overrides[ID_DNS_LOCK] ?: false

    /** Backup re-enabling is part of the balanced profile only (keeps Google features working). */
    val restoreBackup: Boolean get() = profile == Profile.BALANCED && (overrides[ID_BACKUP] ?: true)

    /** Same profile with every item of [items] switched on or off (one section of the screen). */
    fun withItems(items: List<CatalogItem>, selected: Boolean): PolicySelection =
        copy(overrides = overrides + items.associate { it.id to selected })

    /**
     * Nothing selected at all: every catalog item, the private DNS, its lock and the backup switched
     * off. Starting point to apply one thing only (e.g. just the private DNS). Applying it as is
     * undoes whatever was applied.
     */
    fun withNothingSelected(catalog: PolicyCatalog): PolicySelection =
        copy(overrides = catalog.items.associate { it.id to false } + mapOf(ID_DNS to false, ID_DNS_LOCK to false, ID_BACKUP to false))

    companion object {
        const val ID_DNS = "dns"
        const val ID_DNS_LOCK = "dns_lock"
        const val ID_BACKUP = "backup"
        const val ID_VPN = "vpn"
    }
}

/** One line of the local action journal (shown on the screen; the same facts go out as `security.policy`). */
@Serializable
data class JournalEntry(
    @SerialName("ts_ms") val tsMs: Long,
    val action: String,
    val target: String,
    val profile: String? = null,
    val ok: Boolean,
    val error: String? = null,
)

/**
 * Persistence of the applied state, the journal and the selection in SharedPreferences, written
 * with `commit()` (synchronous) so that the write-ahead record is on disk before the device is
 * changed. SharedPreferences survive app updates and reboots.
 */
@SuppressLint("ApplySharedPref", "UseKtx") // commit() is deliberate: the write-ahead record must be on disk first.
class PolicyStore(private val prefs: SharedPreferences) {
    private val json = Json { ignoreUnknownKeys = true; encodeDefaults = false; explicitNulls = false }

    /**
     * The applied state. A text that cannot be read as a whole is read record by record (a record
     * written by another version with a kind or a method this one does not know must not make
     * every other record disappear); what is unreadable is kept aside under [K_STATE_CORRUPT] and
     * reported by [stateWasUnreadable], so that "Tout rétablir" falls back on a catalog sweep
     * ([PolicyEngine.sweepCatalog]) instead of silently forgetting what was applied.
     */
    fun state(): AppliedState {
        val text = prefs.getString(K_STATE, null) ?: return AppliedState()
        try {
            return json.decodeFromString(AppliedState.serializer(), text)
        } catch (_: Exception) {
            // Fall through: salvage what can be read.
        }
        if (prefs.getString(K_STATE_CORRUPT, null) != text) prefs.edit().putString(K_STATE_CORRUPT, text).commit()
        val records = try {
            (json.parseToJsonElement(text) as? JsonObject)?.get("records").let { it as? JsonArray }.orEmpty().mapNotNull { element ->
                try {
                    json.decodeFromJsonElement(AppliedRecord.serializer(), element)
                } catch (_: Exception) {
                    null
                }
            }
        } catch (_: Exception) {
            emptyList()
        }
        return AppliedState(records = records)
    }

    /** True once a persisted state could not be read entirely, until [clearUnreadableMarker]. */
    fun stateWasUnreadable(): Boolean = prefs.contains(K_STATE_CORRUPT)

    fun clearUnreadableMarker() {
        prefs.edit().remove(K_STATE_CORRUPT).commit()
    }

    fun saveState(state: AppliedState) {
        check(prefs.edit().putString(K_STATE, json.encodeToString(AppliedState.serializer(), state)).commit()) {
            "policy state not persisted"
        }
    }

    fun selection(): PolicySelection = prefs.getString(K_SELECTION, null)?.let {
        try {
            json.decodeFromString(PolicySelection.serializer(), it)
        } catch (_: Exception) {
            null
        }
    } ?: PolicySelection()

    fun saveSelection(selection: PolicySelection) {
        prefs.edit().putString(K_SELECTION, json.encodeToString(PolicySelection.serializer(), selection)).commit()
    }

    fun journal(): List<JournalEntry> = prefs.getString(K_JOURNAL, null)?.let {
        try {
            json.decodeFromString(JOURNAL_SERIALIZER, it)
        } catch (_: Exception) {
            null
        }
    } ?: emptyList()

    fun appendJournal(entry: JournalEntry) {
        val list = (journal() + entry).takeLast(MAX_JOURNAL)
        prefs.edit().putString(K_JOURNAL, json.encodeToString(JOURNAL_SERIALIZER, list)).commit()
    }

    private companion object {
        const val K_STATE = "applied_state"
        const val K_STATE_CORRUPT = "applied_state_corrupt"
        const val K_SELECTION = "selection"
        const val K_JOURNAL = "journal"
        const val MAX_JOURNAL = 200
        val JOURNAL_SERIALIZER = kotlinx.serialization.builtins.ListSerializer(JournalEntry.serializer())
    }
}
