package io.github.erwsim.vigie.collectors.apps

import io.github.erwsim.vigie.core.event.Rfc3339
import io.github.erwsim.vigie.core.event.Severity
import io.github.erwsim.vigie.core.event.eventData
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.longOrNull

/** What is remembered of each app between two inventories (persisted state, compact JSON). */
data class AppRecord(
    val pkg: String,
    val versionName: String?,
    val versionCode: Long,
    val signer: String?,
    /** Granted runtime ("dangerous") permissions. */
    val granted: Set<String>,
    val installer: String? = null,
    val system: Boolean = false,
)

/** Inventory-only details (labels are loaded only for the daily inventory). */
data class AppDetails(
    val pkg: String,
    val label: String?,
    val enabled: Boolean,
    val suspended: Boolean,
    val hidden: Boolean,
    val targetSdk: Int,
    val firstInstall: Long?,
    val lastUpdate: Long?,
)

data class PermissionChange(val pkg: String, val permission: String, val granted: Boolean)

data class AppDiff(
    val installed: List<AppRecord>,
    val updated: List<AppRecord>,
    val removed: List<AppRecord>,
    val permissionChanges: List<PermissionChange>,
) {
    val isEmpty: Boolean get() = installed.isEmpty() && updated.isEmpty() && removed.isEmpty() && permissionChanges.isEmpty()
}

/** Pure logic of the apps collector: differences between inventories, persistence, splitting. */
object AppInventoryLogic {
    /**
     * Differences from [old] to [new]. "Updated" = other version code or other signer (a signer
     * change is the strongest signal of a replaced app). Permission changes are reported for apps
     * present in both (an installation reports its permissions in the inventory).
     */
    fun diff(old: Map<String, AppRecord>, new: Map<String, AppRecord>): AppDiff {
        val installed = new.values.filter { it.pkg !in old }.sortedBy { it.pkg }
        val removed = old.values.filter { it.pkg !in new }.sortedBy { it.pkg }
        val updated = ArrayList<AppRecord>()
        val changes = ArrayList<PermissionChange>()
        for (n in new.values.sortedBy { it.pkg }) {
            val o = old[n.pkg] ?: continue
            if (o.versionCode != n.versionCode || o.signer != n.signer) updated += n
            permissionChanges(o, n, changes)
        }
        return AppDiff(installed, updated, removed, changes)
    }

    fun permissionChanges(o: AppRecord, n: AppRecord, into: MutableList<PermissionChange> = ArrayList()): List<PermissionChange> {
        (n.granted - o.granted).sorted().forEach { into += PermissionChange(n.pkg, it, true) }
        (o.granted - n.granted).sorted().forEach { into += PermissionChange(n.pkg, it, false) }
        return into
    }

    /** The installer is not re-read at every scan: keep the known one while the version is the same. */
    fun carryInstallers(old: Map<String, AppRecord>, new: Map<String, AppRecord>): Map<String, AppRecord> =
        new.mapValues { (pkg, n) ->
            val o = old[pkg]
            if (n.installer == null && o != null && o.versionCode == n.versionCode) n.copy(installer = o.installer) else n
        }

    fun encode(records: Map<String, AppRecord>): String = JsonObject(
        records.toSortedMap().mapValues { (_, r) ->
            JsonObject(
                buildMap {
                    r.versionName?.let { put("vn", JsonPrimitive(it)) }
                    put("vc", JsonPrimitive(r.versionCode))
                    r.signer?.let { put("sg", JsonPrimitive(it)) }
                    r.installer?.let { put("in", JsonPrimitive(it)) }
                    if (r.system) put("sy", JsonPrimitive(true))
                    put("gr", JsonArray(r.granted.sorted().map(::JsonPrimitive)))
                },
            )
        },
    ).toString()

    /** Null if absent or unreadable (then the next scan only sets a new baseline). */
    fun decode(text: String?): Map<String, AppRecord>? {
        if (text.isNullOrEmpty()) return null
        return try {
            Json.parseToJsonElement(text).jsonObject.mapValues { (pkg, v) ->
                val o = v.jsonObject
                AppRecord(
                    pkg = pkg,
                    versionName = o["vn"]?.jsonPrimitive?.content,
                    versionCode = o["vc"]?.jsonPrimitive?.longOrNull ?: 0,
                    signer = o["sg"]?.jsonPrimitive?.content,
                    granted = o["gr"]?.jsonArray?.map { it.jsonPrimitive.content }?.toSet().orEmpty(),
                    installer = o["in"]?.jsonPrimitive?.content,
                    system = o["sy"]?.jsonPrimitive?.booleanOrNull ?: false,
                )
            }
        } catch (_: Exception) {
            null
        }
    }

    /**
     * Splits [items] into parts whose serialized size stays under [maxBytes] (UTF-8), keeping the
     * order. A single item larger than the budget gets a part of its own.
     */
    fun chunkBySize(items: List<JsonElement>, maxBytes: Int): List<List<JsonElement>> {
        val parts = ArrayList<List<JsonElement>>()
        var current = ArrayList<JsonElement>()
        var size = 2 // "[]"
        for (item in items) {
            val itemSize = item.toString().toByteArray(Charsets.UTF_8).size + 1 // + comma
            if (current.isNotEmpty() && size + itemSize > maxBytes) {
                parts += current
                current = ArrayList()
                size = 2
            }
            current += item
            size += itemSize
        }
        if (current.isNotEmpty()) parts += current
        return parts
    }

    /** `app.installed` / `app.updated` / `app.removed` data. */
    fun changeData(r: AppRecord): JsonObject = eventData {
        put("package", r.pkg)
        put("version_name", r.versionName)
        if (r.versionCode > 0) put("version_code", r.versionCode)
        put("installer", r.installer)
        put("signer_sha256", r.signer)
    }

    /**
     * Sideloaded (non-store) installation of a user app, or update signed by another key: 2.
     * Other installations and removals: 1. Ordinary updates: 0.
     */
    fun changeSeverity(type: String, r: AppRecord, signerChanged: Boolean): Int = when {
        type == "app.installed" && !r.system && isSideload(r.installer) -> Severity.WARNING
        type == "app.updated" && signerChanged -> Severity.WARNING
        type == "app.updated" -> Severity.INFO
        else -> Severity.NOTABLE
    }

    fun permissionData(c: PermissionChange): JsonObject = eventData {
        put("package", c.pkg)
        put("permission", c.permission)
        put("granted", c.granted)
    }

    /** One entry of `app.inventory.apps`. */
    fun inventoryItem(d: AppDetails, r: AppRecord?): JsonObject = eventData {
        put("package", d.pkg)
        put("label", d.label)
        put("version_name", r?.versionName)
        put("version_code", r?.versionCode)
        put("installer", r?.installer)
        put("system", r?.system)
        put("enabled", d.enabled)
        put("suspended", d.suspended)
        put("hidden", d.hidden)
        put("target_sdk", d.targetSdk)
        put("first_install", d.firstInstall?.let(Rfc3339::format))
        put("last_update", d.lastUpdate?.let(Rfc3339::format))
        put("signer_sha256", r?.signer)
        putStrings("granted_dangerous", r?.granted?.sorted())
    }

    /** The `app.inventory` events: parts numbered from 1, all with the same [inventoryId]. */
    fun inventoryParts(items: List<JsonElement>, inventoryId: String, maxBytes: Int): List<JsonObject> {
        val parts = chunkBySize(items, maxBytes)
        return parts.mapIndexed { i, part ->
            eventData {
                put("inventory_id", inventoryId)
                put("part", i + 1)
                put("parts", parts.size)
                put("apps", JsonArray(part))
            }
        }
    }

    /** Installers considered as stores (anything else, or none, is a sideload). */
    val STORES = setOf(
        "com.android.vending",
        "com.sec.android.app.samsungapps",
        "com.google.android.feedback",
        "org.fdroid.fdroid",
    )

    fun isSideload(installer: String?): Boolean = installer == null || installer !in STORES
}
