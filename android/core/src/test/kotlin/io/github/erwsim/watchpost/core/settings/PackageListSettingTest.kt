package io.github.erwsim.watchpost.core.settings

import io.github.erwsim.watchpost.core.testing.MemoryPrefs
import io.github.erwsim.watchpost.core.testing.RecordingSink
import kotlinx.serialization.json.JsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class PackageListSettingTest {
    private val key = SettingKey.PackageListKey("policy.guard.sms.allowed", setOf("com.samsung.android.messaging"), maxSize = 3)

    @Test
    fun `a list reads its default until saved, then exactly what was saved`() {
        val settings = AgentSettings(MemoryPrefs())
        assertEquals(setOf("com.samsung.android.messaging"), settings[key])
        assertFalse(settings.isSet(key))
        assertTrue(settings.set(key, setOf("org.example.b", "org.example.a")))
        assertEquals(listOf("org.example.a", "org.example.b"), settings[key].toList())
        assertTrue(settings.isSet(key))
        // An empty list is a real value (not the default).
        assertTrue(settings.set(key, emptySet()))
        assertEquals(emptySet<String>(), settings[key])
    }

    @Test
    fun `invalid names and oversized lists are refused, nothing is written`() {
        val settings = AgentSettings(MemoryPrefs())
        assertFalse(settings.set(key, setOf("org.example.a", "not a package")))
        assertFalse(settings.set(key, setOf("org.example.a", "a")))
        assertFalse(settings.set(key, setOf("org.example.a\ncom.evil.b")))
        assertFalse(settings.set(key, setOf("a.b", "c.d", "e.f", "g.h")))
        assertFalse(settings.isSet(key))
        assertTrue(PackageNames.isValid("io.github.erwsim.watchpost"))
        assertFalse(PackageNames.isValid("io..watchpost"))
        assertFalse(PackageNames.isValid("1io.watchpost"))
    }

    @Test
    fun `a change emits agent config_changed with the sorted lists, an identical save does not`() {
        val settings = AgentSettings(MemoryPrefs())
        val sink = RecordingSink()
        settings.sink = sink
        settings.set(key, setOf("org.example.b", "org.example.a"))
        val e = sink.of("agent.config_changed").single().data
        assertEquals(JsonPrimitive("policy.guard.sms.allowed"), e["key"])
        assertEquals(JsonPrimitive("com.samsung.android.messaging"), e["old"])
        assertEquals(JsonPrimitive("org.example.a,org.example.b"), e["new"])
        settings.set(key, setOf("org.example.a", "org.example.b"))
        assertEquals(1, sink.of("agent.config_changed").size)
    }

    @Test
    fun `a stored text edited by hand is read leniently`() {
        val prefs = MemoryPrefs()
        prefs.edit().putString(key.name, "org.example.a\n\n  bad entry \norg.example.b,org.example.c").commit()
        assertEquals(setOf("org.example.a", "org.example.b", "org.example.c"), AgentSettings(prefs)[key])
    }
}
