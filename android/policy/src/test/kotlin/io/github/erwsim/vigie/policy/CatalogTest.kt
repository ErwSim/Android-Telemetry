package io.github.erwsim.vigie.policy

import android.os.UserManager
import io.github.erwsim.vigie.policy.engine.PackageDenyList
import io.github.erwsim.vigie.policy.engine.PolicyCatalog
import io.github.erwsim.vigie.policy.engine.Profile
import io.github.erwsim.vigie.policy.engine.RestrictionGuard
import io.github.erwsim.vigie.policy.engine.Risk
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/** Checks of the real data file shipped in the APK (res/raw/policy_catalog.json). */
class CatalogTest {
    private val catalog = PolicyCatalog.parse(File("src/main/res/raw/policy_catalog.json").readText())

    @Test
    fun `no catalog entry is in the hard-coded deny list`() {
        val denied = catalog.packages.map { it.pkg }.filter { PackageDenyList.isDenied(it) } +
            catalog.permissions.map { it.pkg }.filter { PackageDenyList.isDenied(it) }
        assertEquals(emptyList<String>(), denied)
        val forbidden = catalog.restrictions.map { it.key }.filter(RestrictionGuard::isForbidden)
        assertEquals(emptyList<String>(), forbidden)
    }

    @Test
    fun `deny list covers the research's never-touch list`() {
        listOf(
            "com.samsung.android.kgclient", "com.samsung.android.sm.policy", "com.sec.android.soagent", "com.wssyncmldm",
            "com.samsung.android.cidmanager", "com.samsung.android.gru", "com.samsung.android.honeyboard",
            "com.samsung.android.wifi.softap.resources", "com.google.android.rkpdapp", "com.google.android.ext.services",
            "com.google.android.networkstack", "com.google.android.permissioncontroller", "com.google.android.configupdater",
            "com.google.android.webview", "com.samsung.android.app.routines", "com.sec.android.app.launcher",
            "com.android.systemui", "com.android.phone", "com.android.settings", "com.sec.android.diagmonagent",
            "com.samsung.android.securitylogagent", "com.samsung.android.knox.attestation", "com.android.shell",
            "com.google.android.packageinstaller", "io.github.erwsim.vigie",
        ).forEach { assertTrue(it, PackageDenyList.isDenied(it)) }
        assertTrue(RestrictionGuard.isForbidden(UserManager.DISALLOW_DEBUGGING_FEATURES))
        assertTrue(RestrictionGuard.isForbidden(UserManager.DISALLOW_SHARE_LOCATION))
        assertTrue(RestrictionGuard.isForbidden(UserManager.DISALLOW_CONFIG_PRIVATE_DNS))
    }

    @Test
    fun `restriction keys exist in the SDK`() {
        val sdkKeys = UserManager::class.java.fields.filter { it.name.startsWith("DISALLOW_") }.map { it.get(null) as String }.toSet()
        catalog.restrictions.forEach { assertTrue(it.key, it.key in sdkKeys) }
    }

    @Test
    fun `balanced profile keeps Google services, the store and payment working`() {
        val balanced = catalog.packages.filter { it.profile == Profile.BALANCED }.map { it.pkg }.toSet()
        listOf(
            "com.google.android.gms", "com.android.vending", "com.google.android.gsf", "com.osp.app.signin",
            "com.samsung.android.fmm", "com.samsung.android.spay", "com.sec.spp.push",
        ).forEach { assertFalse(it, it in balanced) }
        // Critical items are never pre-selected.
        catalog.items.filter { it.risk == Risk.CRITICAL || it.risk == Risk.HIGH }.forEach {
            if (it.profile == Profile.BALANCED) assertFalse(it.id, it.default)
        }
        assertTrue(catalog.packages.filter { it.risk == Risk.CRITICAL }.none { it.default })
        assertTrue(catalog.packages.size > 30)
    }
}
