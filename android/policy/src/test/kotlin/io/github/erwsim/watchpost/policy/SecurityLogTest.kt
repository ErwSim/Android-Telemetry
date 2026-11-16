package io.github.erwsim.watchpost.policy

import android.app.admin.SecurityLog
import io.github.erwsim.watchpost.core.event.Severity
import io.github.erwsim.watchpost.core.testing.Contract
import io.github.erwsim.watchpost.policy.logs.RawSecurityEvent
import io.github.erwsim.watchpost.policy.logs.SecurityLogFilter
import io.github.erwsim.watchpost.policy.logs.SecurityLogProcessor
import io.github.erwsim.watchpost.policy.logs.SecurityLogTranslator
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class SecurityLogTest {
    private fun raw(tag: Int, data: Any?, level: Int = SecurityLog.LEVEL_INFO, nanos: Long = 1_763_000_000_000_000_000L, id: Long = 7) =
        RawSecurityEvent(tag, level, id, nanos, data)

    private fun fields(tag: Int, data: Any?): JsonObject = SecurityLogTranslator.translate(raw(tag, data)).fields

    private fun JsonObject.s(k: String) = this[k]?.jsonPrimitive?.content

    /** Every tag of the contract table, with a payload shaped like the platform's. */
    @Test
    fun `contract table - field names for every listed tag`() {
        val cases: List<Triple<Int, Any?, Map<String, String>>> = listOf(
            Triple(SecurityLog.TAG_ADB_SHELL_INTERACTIVE, null, emptyMap()),
            Triple(SecurityLog.TAG_ADB_SHELL_CMD, "pm list packages", mapOf("command" to "pm list packages")),
            Triple(SecurityLog.TAG_SYNC_RECV_FILE, "/sdcard/a.pdf", mapOf("path" to "/sdcard/a.pdf")),
            Triple(SecurityLog.TAG_SYNC_SEND_FILE, "/sdcard/b.pdf", mapOf("path" to "/sdcard/b.pdf")),
            Triple(
                SecurityLog.TAG_APP_PROCESS_START,
                arrayOf<Any>("com.whatsapp", 1_763_000_000_123L, 10201, 8841, "default:targetSdkVersion=35", "ab12"),
                mapOf("process" to "com.whatsapp", "start_time" to "1763000000123", "uid" to "10201", "pid" to "8841", "seinfo" to "default:targetSdkVersion=35", "apk_sha256" to "ab12"),
            ),
            Triple(SecurityLog.TAG_KEYGUARD_DISMISSED, null, emptyMap()),
            Triple(SecurityLog.TAG_KEYGUARD_SECURED, null, emptyMap()),
            Triple(SecurityLog.TAG_KEYGUARD_DISMISS_AUTH_ATTEMPT, arrayOf<Any>(0, 1), mapOf("success" to "false", "strength" to "1")),
            Triple(SecurityLog.TAG_OS_STARTUP, arrayOf<Any>("green", "enforcing"), mapOf("verified_boot_state" to "green", "dm_verity_mode" to "enforcing")),
            Triple(SecurityLog.TAG_OS_SHUTDOWN, null, emptyMap()),
            Triple(SecurityLog.TAG_LOGGING_STARTED, null, emptyMap()),
            Triple(SecurityLog.TAG_LOGGING_STOPPED, null, emptyMap()),
            Triple(SecurityLog.TAG_LOG_BUFFER_SIZE_CRITICAL, null, emptyMap()),
            Triple(SecurityLog.TAG_MEDIA_MOUNT, arrayOf<Any>("/storage/4A21-0000", "SanDisk"), mapOf("mount_point" to "/storage/4A21-0000", "label" to "SanDisk")),
            Triple(SecurityLog.TAG_MEDIA_UNMOUNT, arrayOf<Any>("/storage/4A21-0000", "SanDisk"), mapOf("mount_point" to "/storage/4A21-0000", "label" to "SanDisk")),
            Triple(SecurityLog.TAG_CRYPTO_SELF_TEST_COMPLETED, 1, mapOf("success" to "true")),
            Triple(SecurityLog.TAG_KEY_GENERATED, arrayOf<Any>(1, "watchpost_key", 10301), mapOf("success" to "true", "alias" to "watchpost_key", "uid" to "10301")),
            Triple(SecurityLog.TAG_KEY_IMPORT, arrayOf<Any>(1, "k", 10301), mapOf("success" to "true", "alias" to "k", "uid" to "10301")),
            Triple(SecurityLog.TAG_KEY_DESTRUCTION, arrayOf<Any>(0, "k", 10301), mapOf("success" to "false", "alias" to "k", "uid" to "10301")),
            Triple(SecurityLog.TAG_KEY_INTEGRITY_VIOLATION, arrayOf<Any>("k", 10301), mapOf("alias" to "k", "uid" to "10301")),
            Triple(SecurityLog.TAG_CERT_AUTHORITY_INSTALLED, arrayOf<Any>(1, "CN=Proxy CA", 0), mapOf("success" to "true", "subject" to "CN=Proxy CA", "user_id" to "0")),
            Triple(SecurityLog.TAG_CERT_AUTHORITY_REMOVED, arrayOf<Any>(1, "CN=Proxy CA", 0), mapOf("success" to "true", "subject" to "CN=Proxy CA", "user_id" to "0")),
            Triple(SecurityLog.TAG_CERT_VALIDATION_FAILURE, "expired", mapOf("reason" to "expired")),
            Triple(SecurityLog.TAG_USER_RESTRICTION_ADDED, arrayOf<Any>("io.github.erwsim.watchpost", 0, "no_add_user"), mapOf("admin_package" to "io.github.erwsim.watchpost", "user_id" to "0", "restriction" to "no_add_user")),
            Triple(SecurityLog.TAG_USER_RESTRICTION_REMOVED, arrayOf<Any>("io.github.erwsim.watchpost", 0, "no_add_user"), mapOf("admin_package" to "io.github.erwsim.watchpost", "user_id" to "0", "restriction" to "no_add_user")),
            Triple(SecurityLog.TAG_PASSWORD_CHANGED, arrayOf<Any>(196608, 0), mapOf("complexity" to "196608", "user_id" to "0")),
            Triple(SecurityLog.TAG_WIFI_CONNECTION, arrayOf<Any>("AA:BB:CC:DD:EE:FF", "connect", ""), mapOf("bssid" to "aa:bb:cc:dd:ee:ff", "event_type" to "connect", "reason" to "")),
            Triple(SecurityLog.TAG_WIFI_DISCONNECTION, arrayOf<Any>("AA:BB:CC:DD:EE:FF", "local"), mapOf("bssid" to "aa:bb:cc:dd:ee:ff", "reason" to "local")),
            Triple(SecurityLog.TAG_BLUETOOTH_CONNECTION, arrayOf<Any>("8C:79:F5:1E:42:A7", 1, ""), mapOf("address" to "8c:79:f5:1e:42:a7", "success" to "true", "reason" to "")),
            Triple(SecurityLog.TAG_BLUETOOTH_DISCONNECTION, arrayOf<Any>("8C:79:F5:1E:42:A7", "remote"), mapOf("address" to "8c:79:f5:1e:42:a7", "reason" to "remote")),
            Triple(SecurityLog.TAG_PACKAGE_INSTALLED, arrayOf<Any>("com.example.shop", 254400L, 0), mapOf("package" to "com.example.shop", "version_code" to "254400", "user_id" to "0")),
            Triple(SecurityLog.TAG_PACKAGE_UPDATED, arrayOf<Any>("com.example.shop", 254401L, 0), mapOf("package" to "com.example.shop", "version_code" to "254401", "user_id" to "0")),
            Triple(SecurityLog.TAG_PACKAGE_UNINSTALLED, arrayOf<Any>("com.example.shop", 254401L, 0), mapOf("package" to "com.example.shop", "version_code" to "254401", "user_id" to "0")),
            // Tags without names in the contract: argN.
            Triple(SecurityLog.TAG_WIPE_FAILURE, null, emptyMap()),
            Triple(SecurityLog.TAG_REMOTE_LOCK, arrayOf<Any>("com.admin", 0, 0), mapOf("arg0" to "com.admin", "arg1" to "0", "arg2" to "0")),
            Triple(SecurityLog.TAG_BACKUP_SERVICE_TOGGLED, arrayOf<Any>("io.github.erwsim.watchpost", 0, 1), mapOf("arg0" to "io.github.erwsim.watchpost", "arg1" to "0", "arg2" to "1")),
            Triple(SecurityLog.TAG_CAMERA_POLICY_SET, arrayOf<Any>("com.admin", 0, 0, 1), mapOf("arg0" to "com.admin", "arg1" to "0", "arg2" to "0", "arg3" to "1")),
        )
        // The table covers every tag named by the contract (shared reference of the contract).
        val contractTags = Contract.SECURITY_LOG_FIELDS.keys
        Contract.SECURITY_LOG_FIELDS.forEach { (tag, names) -> assertEquals(tag, names, SecurityLogTranslator.FIELD_TABLE.getValue(tag).toSet()) }
        assertEquals(contractTags, SecurityLogTranslator.FIELD_TABLE.keys)
        assertTrue(cases.map { SecurityLogTranslator.tagName(it.first) }.toSet().containsAll(contractTags + setOf("wipe_failure", "remote_lock", "backup_service_toggled")))
        for ((tag, data, expected) in cases) {
            val f = fields(tag, data)
            assertEquals(SecurityLogTranslator.tagName(tag), expected, f.mapValues { it.value.jsonPrimitive.content })
        }
        // Success flags are JSON booleans, numbers stay numbers.
        val auth = fields(SecurityLog.TAG_KEYGUARD_DISMISS_AUTH_ATTEMPT, arrayOf<Any>(1, 0))
        assertEquals(true, auth["success"]!!.jsonPrimitive.booleanOrNull)
        assertFalse(auth["strength"]!!.jsonPrimitive.isString)
    }

    @Test
    fun `every SDK tag constant has a contract name`() {
        val all = SecurityLog::class.java.fields.filter { it.name.startsWith("TAG_") }.map { it.getInt(null) }
        assertTrue(all.isNotEmpty())
        for (value in all) assertFalse("unnamed tag $value", SecurityLogTranslator.tagName(value).startsWith("tag_"))
        assertEquals("tag_999999", SecurityLogTranslator.tagName(999_999))
    }

    @Test
    fun `level, log id, event time and severity`() {
        val t = SecurityLogTranslator.translate(raw(SecurityLog.TAG_ADB_SHELL_CMD, "id", SecurityLog.LEVEL_WARNING, nanos = 1_763_242_983_974_000_000L, id = 42))
        assertEquals("adb_shell_cmd", t.tag)
        assertEquals("warning", t.level)
        assertEquals(42L, t.logId)
        assertEquals(1_763_242_983_974L, t.timeMs)
        assertEquals(Severity.NOTABLE, t.sev)
        assertEquals("error", SecurityLogTranslator.levelName(SecurityLog.LEVEL_ERROR))
        assertEquals(Severity.WARNING, SecurityLogTranslator.translate(raw(SecurityLog.TAG_OS_STARTUP, arrayOf<Any>("orange", "enforcing"))).sev)
        assertEquals(Severity.INFO, SecurityLogTranslator.translate(raw(SecurityLog.TAG_OS_STARTUP, arrayOf<Any>("green", "enforcing"))).sev)
        assertEquals(Severity.WARNING, SecurityLogTranslator.translate(raw(SecurityLog.TAG_KEY_INTEGRITY_VIOLATION, arrayOf<Any>("k", 1))).sev)
        assertEquals(Severity.NOTABLE, SecurityLogTranslator.translate(raw(SecurityLog.TAG_KEYGUARD_DISMISS_AUTH_ATTEMPT, arrayOf<Any>(0, 1))).sev)
    }

    @Test
    fun `processor aggregates app process starts and filters chatty tags`() {
        val base = 1_763_000_000_000L * 1_000_000
        val minute = 60_000_000_000L
        val starts = (0 until 5).map { i ->
            raw(SecurityLog.TAG_APP_PROCESS_START, arrayOf<Any>("com.whatsapp", 1L, 10201, 100 + i, "default", "ab"), nanos = base + i * minute, id = i.toLong())
        }
        val other = raw(SecurityLog.TAG_APP_PROCESS_START, arrayOf<Any>("com.signal", 1L, 10202, 300, "default", "cd"), nanos = base + 2 * minute)
        val wifi = raw(SecurityLog.TAG_WIFI_CONNECTION, arrayOf<Any>("AA:BB:CC:DD:EE:FF", "connect", ""), nanos = base + minute)
        val adb = raw(SecurityLog.TAG_ADB_SHELL_INTERACTIVE, null, nanos = base + 3 * minute)

        val out = SecurityLogProcessor.process(starts + other + wifi + adb, SecurityLogFilter())
        val byTag = out.groupBy { it.data["tag"]!!.jsonPrimitive.content }
        assertEquals(2, byTag.getValue("app_process_start").size)
        val whatsapp = byTag.getValue("app_process_start").single { it.data["fields"]!!.jsonObject.s("process") == "com.whatsapp" }
        assertEquals("5", whatsapp.data.s("count"))
        assertEquals(io.github.erwsim.watchpost.core.event.Rfc3339.format(1_763_000_000_000L + 4 * 60_000L), whatsapp.data.s("last_event_ts"))
        assertNull(byTag.getValue("app_process_start").single { it.data["fields"]!!.jsonObject.s("process") == "com.signal" }.data["count"])
        assertEquals(1, byTag.getValue("wifi_connection").size)
        assertEquals(Severity.NOTABLE, byTag.getValue("adb_shell_interactive").single().sev)
        // Output is in time order; ts = first occurrence, no event_ts field.
        val times = out.map { it.tsMs }
        assertEquals(times.sorted(), times)
        assertEquals(1_763_000_000_000L, whatsapp.tsMs)
        assertTrue(out.none { it.data.containsKey("event_ts") })
        out.forEach { Contract.check(SecurityLogProcessor.TYPE, it.data) }

        val quiet = SecurityLogProcessor.process(starts + wifi + adb, SecurityLogFilter(appProcessStart = false, radio = false))
        assertEquals(listOf("adb_shell_interactive"), quiet.map { it.data.s("tag") })
        val all = SecurityLogProcessor.process(starts, SecurityLogFilter(aggregateAppProcess = false))
        assertEquals(5, all.size)
    }

    @Test
    fun `pre-reboot logs keep only entries newer than the last one sent, marked pre_reboot`() {
        val old = raw(SecurityLog.TAG_OS_SHUTDOWN, null, nanos = 1_000)
        val new = raw(SecurityLog.TAG_LOGGING_STOPPED, null, nanos = 2_000)
        val out = SecurityLogProcessor.process(listOf(old, new), SecurityLogFilter(), afterNanos = 1_500, preReboot = true)
        assertEquals(listOf("logging_stopped"), out.map { it.data.s("tag") })
        assertEquals(JsonPrimitive(true), out.single().data["pre_reboot"])
        assertTrue(SecurityLogProcessor.touchesCertificates(SecurityLogProcessor.process(listOf(raw(SecurityLog.TAG_CERT_AUTHORITY_INSTALLED, arrayOf<Any>(1, "CN=x", 0))), SecurityLogFilter())))
    }
}
