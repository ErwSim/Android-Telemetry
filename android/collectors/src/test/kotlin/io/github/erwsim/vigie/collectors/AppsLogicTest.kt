package io.github.erwsim.vigie.collectors

import io.github.erwsim.vigie.collectors.apps.AppDetails
import io.github.erwsim.vigie.collectors.apps.AppInventoryLogic
import io.github.erwsim.vigie.collectors.apps.AppRecord
import io.github.erwsim.vigie.collectors.apps.AppsCollector
import io.github.erwsim.vigie.collectors.apps.ForegroundAppCollector
import io.github.erwsim.vigie.collectors.apps.ForegroundTracker
import io.github.erwsim.vigie.collectors.apps.ForegroundTracker.Kind
import io.github.erwsim.vigie.collectors.apps.PermissionChange
import io.github.erwsim.vigie.collectors.apps.SpecialAccessSnapshot
import io.github.erwsim.vigie.core.event.Severity
import io.github.erwsim.vigie.core.event.VigieJson
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class AppsLogicTest {
    private val signer = "a".repeat(64)
    private fun app(pkg: String, vc: Long = 1, signer: String? = this.signer, granted: Set<String> = emptySet(), installer: String? = null) =
        AppRecord(pkg, "1.$vc", vc, signer, granted, installer)

    @Test
    fun diffFindsInstallsUpdatesRemovalsAndPermissionChanges() {
        val old = listOf(
            app("org.kept"),
            app("org.updated", vc = 1),
            app("org.removed"),
            app("org.perm", granted = setOf("android.permission.CAMERA", "android.permission.READ_CONTACTS")),
            app("org.resigned"),
        ).associateBy { it.pkg }
        val new = listOf(
            app("org.kept"),
            app("org.updated", vc = 2),
            app("org.new"),
            app("org.perm", granted = setOf("android.permission.CAMERA", "android.permission.RECORD_AUDIO")),
            app("org.resigned", signer = "b".repeat(64)),
        ).associateBy { it.pkg }
        val d = AppInventoryLogic.diff(old, new)
        assertEquals(listOf("org.new"), d.installed.map { it.pkg })
        assertEquals(listOf("org.resigned", "org.updated"), d.updated.map { it.pkg })
        assertEquals(listOf("org.removed"), d.removed.map { it.pkg })
        assertEquals(
            listOf(
                PermissionChange("org.perm", "android.permission.RECORD_AUDIO", true),
                PermissionChange("org.perm", "android.permission.READ_CONTACTS", false),
            ),
            d.permissionChanges,
        )
        assertTrue(AppInventoryLogic.diff(new, new).isEmpty)
    }

    @Test
    fun persistedStateRoundTrips() {
        val state = listOf(
            app("org.a", granted = setOf("android.permission.CAMERA"), installer = "com.android.vending"),
            AppRecord("org.b", null, 7, null, emptySet(), null, system = true),
        ).associateBy { it.pkg }
        assertEquals(state, AppInventoryLogic.decode(AppInventoryLogic.encode(state)))
        assertNull(AppInventoryLogic.decode(null))
        assertNull(AppInventoryLogic.decode("{not json"))
    }

    @Test
    fun installerIsCarriedWhileTheVersionIsTheSame() {
        val old = mapOf("org.a" to app("org.a", installer = "com.android.vending"), "org.b" to app("org.b", installer = "x"))
        val new = mapOf("org.a" to app("org.a"), "org.b" to app("org.b", vc = 2))
        val carried = AppInventoryLogic.carryInstallers(old, new)
        assertEquals("com.android.vending", carried.getValue("org.a").installer)
        assertNull(carried.getValue("org.b").installer) // Updated: re-read.
    }

    @Test
    fun changeEventsAndSeverities() {
        val sideloaded = app("org.side", installer = "com.google.android.packageinstaller")
        val data = AppInventoryLogic.changeData(sideloaded)
        listOf("app.installed", "app.updated", "app.removed").forEach { Contract.check(it, data) }
        assertEquals(Severity.WARNING, AppInventoryLogic.changeSeverity("app.installed", sideloaded, false))
        assertEquals(Severity.NOTABLE, AppInventoryLogic.changeSeverity("app.installed", app("org.store", installer = "com.android.vending"), false))
        assertEquals(Severity.INFO, AppInventoryLogic.changeSeverity("app.updated", sideloaded, false))
        assertEquals(Severity.WARNING, AppInventoryLogic.changeSeverity("app.updated", sideloaded, true))
        // Removal of an unknown package: only the package name, no fake values.
        assertEquals(setOf("package"), AppInventoryLogic.changeData(AppRecord("org.gone", null, 0, null, emptySet())).keys)
        Contract.check("app.permission_changed", AppInventoryLogic.permissionData(PermissionChange("org.a", "android.permission.CAMERA", true)))
    }

    private fun details(pkg: String) = AppDetails(pkg, "Application $pkg", true, false, false, 36, 1_700_000_000_000, 1_760_000_000_000)

    @Test
    fun inventoryIsSplitIntoPartsWellBelow32KiB() {
        val perms = setOf(
            "android.permission.ACCESS_FINE_LOCATION", "android.permission.ACCESS_BACKGROUND_LOCATION",
            "android.permission.CAMERA", "android.permission.RECORD_AUDIO", "android.permission.READ_CONTACTS",
            "android.permission.POST_NOTIFICATIONS", "android.permission.BLUETOOTH_CONNECT",
        )
        val records = (1..450).associate { i ->
            val pkg = "com.example.vendor.application.number$i"
            pkg to app(pkg, vc = i.toLong(), granted = perms, installer = "com.android.vending")
        }
        val items = records.keys.sorted().map { AppInventoryLogic.inventoryItem(details(it), records[it]) }
        val parts = AppInventoryLogic.inventoryParts(items, "01JCQ8Z3K4M5N6P7Q8R9S0T1V2", AppsCollector.PART_BYTES)
        assertTrue(parts.size > 1)
        var total = 0
        parts.forEachIndexed { i, part ->
            Contract.check("app.inventory", part)
            assertEquals("01JCQ8Z3K4M5N6P7Q8R9S0T1V2", part["inventory_id"]!!.jsonPrimitive.content)
            assertEquals(i + 1, part["part"]!!.jsonPrimitive.int)
            assertEquals(parts.size, part["parts"]!!.jsonPrimitive.int)
            // Whole event (envelope ≈ 200 bytes) far below the 32 KiB limit.
            val size = VigieJson.encodeToString(JsonObject.serializer(), part).toByteArray().size
            assertTrue("part $i is $size bytes", size < 20 * 1024)
            total += (part["apps"] as JsonArray).size
        }
        assertEquals(450, total)
        val first = ((parts[0]["apps"] as JsonArray)[0] as JsonObject)
        assertEquals(14, first.size) // Every contract field present for a complete app.
    }

    @Test
    fun chunkingKeepsOrderAndIsolatesOversizedItems() {
        val items = listOf(10, 10, 5000, 10).map { n -> kotlinx.serialization.json.JsonPrimitive("x".repeat(n)) }
        val parts = AppInventoryLogic.chunkBySize(items, 100)
        assertEquals(listOf(2, 1, 1), parts.map { it.size })
        assertTrue(AppInventoryLogic.chunkBySize(emptyList(), 100).isEmpty())
    }

    @Test
    fun foregroundReportsAppSwitchesOnly() {
        val t = ForegroundTracker()
        assertEquals(listOf(ForegroundTracker.Change("resumed", "org.mail", "org.mail.Inbox")), t.onEvent(Kind.RESUMED, "org.mail", "org.mail.Inbox"))
        // Activity change inside the same app, and its pause: nothing.
        assertTrue(t.onEvent(Kind.PAUSED, "org.mail", "org.mail.Inbox").isEmpty())
        assertTrue(t.onEvent(Kind.RESUMED, "org.mail", "org.mail.Compose").isEmpty())
        // Switch to another app.
        assertEquals(
            listOf(ForegroundTracker.Change("paused", "org.mail", "org.mail.Compose"), ForegroundTracker.Change("resumed", "org.maps", null)),
            t.onEvent(Kind.RESUMED, "org.maps", null),
        )
        // Screen off: the app leaves the foreground; back on: resumed again.
        assertEquals(listOf(ForegroundTracker.Change("paused", "org.maps", null)), t.onEvent(Kind.SCREEN_OFF, null, null))
        assertTrue(t.onEvent(Kind.SCREEN_OFF, null, null).isEmpty())
        assertEquals("resumed", t.onEvent(Kind.RESUMED, "org.maps", "org.maps.Main").single().event)
        val data = ForegroundAppCollector.data(ForegroundTracker.Change("resumed", "org.maps", "org.maps.Main"))
        Contract.check("app.foreground", data)
        assertEquals(3, data.size)
        assertEquals(Kind.SCREEN_OFF, ForegroundAppCollector.kindOf(17)) // KEYGUARD_SHOWN.
    }

    @Test
    fun specialAccessSnapshot() {
        val s = SpecialAccessSnapshot(
            accessibilityServices = listOf("com.bank/.A11y"),
            notificationListeners = null, // Not readable: absent.
            deviceAdmins = listOf("io.github.erwsim.vigie/.policy.VigieAdminReceiver"),
            overlayApps = emptyList(),
            unknownSourcesApps = listOf("org.fdroid.fdroid"),
            usageAccessApps = listOf("io.github.erwsim.vigie"),
            vpnApps = listOf("com.wireguard.android"),
            defaultApps = mapOf("browser" to "org.mozilla.firefox", "sms" to "com.google.android.apps.messaging"),
        )
        val data = io.github.erwsim.vigie.core.event.eventData { s.writeTo(this) }
        Contract.check("app.special_access", data)
        assertFalse(data.containsKey("notification_listeners"))
        assertEquals(0, (data["overlay_apps"] as JsonArray).size) // Readable and empty: [].
        assertEquals(s, SpecialAccessSnapshot.decode(s.encode()))

        assertFalse(s.gainedCritical(s))
        assertTrue(s.copy(accessibilityServices = listOf("com.bank/.A11y", "com.evil/.Spy")).gainedCritical(s))
        assertFalse(s.copy(accessibilityServices = emptyList()).gainedCritical(s)) // Removal is not critical.
        assertFalse(s.copy(notificationListeners = listOf("x/.Y")).gainedCritical(s)) // Unknown before.

        assertEquals(
            listOf("com.app/.Listener", "org.other/com.vendor.Service"),
            SpecialAccessSnapshot.splitComponents("org.other/com.vendor.Service:com.app/com.app.Listener"),
        )
        assertTrue(SpecialAccessSnapshot.splitComponents(null).isEmpty())
    }
}
