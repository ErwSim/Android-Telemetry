package io.github.erwsim.watchpost.policy.engine

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

/** Policy profiles. [wire] is the `profile` value of `security.policy` events. */
@Serializable
enum class Profile(val wire: String) {
    @SerialName("balanced")
    BALANCED("equilibre"),

    @SerialName("strict")
    STRICT("strict"),
    ;

    /** Strict contains everything of balanced. */
    fun includes(other: Profile): Boolean = this == STRICT || other == BALANCED
}

@Serializable
enum class Risk {
    @SerialName("low") LOW,
    @SerialName("medium") MEDIUM,
    @SerialName("high") HIGH,
    @SerialName("critical") CRITICAL,
}

/** How a package is disabled (docs/research/android-platform.md §3.6). */
@Serializable
enum class PackageMethod {
    /** `setApplicationHidden`: the app disappears, its processes and components stop. */
    @SerialName("hide") HIDE,

    /** `setPackagesSuspended`: greyed icon, activities blocked; background services may still run. */
    @SerialName("suspend") SUSPEND,
}

/** Common view of a catalog entry, for previews and the screen. */
sealed interface CatalogItem {
    /** Stable id: `pkg:<package>`, `perm:<package>:<n>`, `restr:<key>`, `set:<ns>:<key>`. */
    val id: String
    val profile: Profile
    val default: Boolean
    val risk: Risk
}

@Serializable
data class PackageEntry(
    @SerialName("package") val pkg: String,
    val publisher: String,
    val label: String,
    val role: String,
    override val risk: Risk,
    val effect: String,
    override val profile: Profile,
    val method: PackageMethod,
    override val default: Boolean = true,
    val uad: String? = null,
) : CatalogItem {
    override val id: String get() = "pkg:$pkg"
}

@Serializable
data class PermissionEntry(
    @SerialName("package") val pkg: String,
    val label: String,
    val permissions: List<String>,
    override val risk: Risk,
    val effect: String,
    override val profile: Profile,
    override val default: Boolean = true,
) : CatalogItem {
    /** Set by [PolicyCatalog.parse]: several entries may target the same package. */
    @kotlinx.serialization.Transient
    var index: Int = 0

    override val id: String get() = "perm:$pkg:$index"
}

@Serializable
data class RestrictionEntry(
    val key: String,
    val title: String,
    val description: String,
    val breaks: String,
    override val risk: Risk,
    override val profile: Profile,
    override val default: Boolean = true,
) : CatalogItem {
    override val id: String get() = "restr:$key"
}

/** A `Settings.Global`/`Settings.Secure` key written with WRITE_SECURE_SETTINGS (granted by ADB). */
@Serializable
data class SettingEntry(
    val namespace: String,
    val key: String,
    val value: String,
    val title: String,
    val description: String,
    val breaks: String,
    override val risk: Risk,
    override val profile: Profile,
    override val default: Boolean = true,
) : CatalogItem {
    override val id: String get() = "set:$namespace:$key"
}

/**
 * Versioned, human-readable policy data (`res/raw/policy_catalog.json`). The hard-coded
 * [PackageDenyList] and [RestrictionGuard] always win over this file.
 */
@Serializable
data class PolicyCatalog(
    val version: Int,
    val updated: String,
    val source: String,
    val notes: String = "",
    val packages: List<PackageEntry> = emptyList(),
    val permissions: List<PermissionEntry> = emptyList(),
    val restrictions: List<RestrictionEntry> = emptyList(),
    val settings: List<SettingEntry> = emptyList(),
) {
    val items: List<CatalogItem> get() = packages + permissions + restrictions + settings

    fun item(id: String): CatalogItem? = items.firstOrNull { it.id == id }

    companion object {
        private val json = Json { ignoreUnknownKeys = true }

        fun parse(text: String): PolicyCatalog {
            val catalog = json.decodeFromString(serializer(), text)
            catalog.permissions.groupBy { it.pkg }.values.forEach { list -> list.forEachIndexed { i, e -> e.index = i } }
            val ids = catalog.items.map { it.id }
            require(ids.size == ids.toSet().size) { "duplicate catalog ids: ${ids.groupBy { it }.filterValues { it.size > 1 }.keys}" }
            catalog.settings.forEach { require(it.namespace == "global" || it.namespace == "secure") { "bad namespace ${it.namespace}" } }
            return catalog
        }
    }
}
