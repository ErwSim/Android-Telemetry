package io.github.erwsim.vigie.core.testing

import android.content.Context
import android.content.ContextWrapper
import android.content.SharedPreferences
import androidx.room.Room
import androidx.room.RoomDatabase
import androidx.sqlite.driver.bundled.BundledSQLiteDriver
import io.github.erwsim.vigie.core.event.AgentClock
import io.github.erwsim.vigie.core.outbox.OutboxDatabase
import kotlinx.coroutines.Dispatchers
import java.io.File

/** Controllable clock. */
class FakeClock(var now: Long = 1_763_242_983_974L, var elapsed: Long = 86_400_123L) : AgentClock {
    override fun nowMillis(): Long = now
    override fun elapsedRealtime(): Long = elapsed

    fun advance(ms: Long) {
        now += ms
        elapsed += ms
    }
}

/**
 * Minimal Context for JVM tests: database path, in-memory SharedPreferences. Everything else is
 * an Android stub returning default values (null system services, etc.).
 */
class TestContext(private val dir: File) : ContextWrapper(null) {
    private val prefs = HashMap<String, MemoryPrefs>()
    override fun getDatabasePath(name: String): File = File(dir, name)
    override fun getApplicationContext(): Context = this
    override fun getPackageName(): String = "io.github.erwsim.vigie"
    override fun getSharedPreferences(name: String, mode: Int): SharedPreferences =
        synchronized(prefs) { prefs.getOrPut(name) { MemoryPrefs() } }
}

/** Opens the real outbox schema on the JVM with the bundled SQLite driver (file-backed). */
fun openTestDatabase(dir: File, name: String = "outbox-test.db"): OutboxDatabase =
    Room.databaseBuilder(TestContext(dir), OutboxDatabase::class.java, name)
        .setDriver(BundledSQLiteDriver())
        .setQueryCoroutineContext(Dispatchers.IO)
        .setJournalMode(RoomDatabase.JournalMode.WRITE_AHEAD_LOGGING)
        // There is no main Looper on the JVM: skip the main-thread assertion (tests never block a UI thread).
        .allowMainThreadQueries()
        .build()

/** In-memory SharedPreferences (enough for the agent's usage). */
class MemoryPrefs : SharedPreferences {
    private val map = HashMap<String, Any?>()

    override fun getAll(): MutableMap<String, *> = HashMap(map)
    override fun getString(key: String, defValue: String?): String? = map[key] as String? ?: defValue
    @Suppress("UNCHECKED_CAST")
    override fun getStringSet(key: String, defValues: MutableSet<String>?): MutableSet<String>? =
        (map[key] as Set<String>?)?.toMutableSet() ?: defValues
    override fun getInt(key: String, defValue: Int): Int = map[key] as Int? ?: defValue
    override fun getLong(key: String, defValue: Long): Long = map[key] as Long? ?: defValue
    override fun getFloat(key: String, defValue: Float): Float = map[key] as Float? ?: defValue
    override fun getBoolean(key: String, defValue: Boolean): Boolean = map[key] as Boolean? ?: defValue
    override fun contains(key: String): Boolean = map.containsKey(key)
    override fun registerOnSharedPreferenceChangeListener(listener: SharedPreferences.OnSharedPreferenceChangeListener?) = Unit
    override fun unregisterOnSharedPreferenceChangeListener(listener: SharedPreferences.OnSharedPreferenceChangeListener?) = Unit

    override fun edit(): SharedPreferences.Editor = object : SharedPreferences.Editor {
        private val pending = HashMap<String, Any?>()
        private val removed = HashSet<String>()
        private var clear = false
        override fun putString(key: String, value: String?) = apply { pending[key] = value }
        override fun putStringSet(key: String, values: MutableSet<String>?) = apply { pending[key] = values?.toSet() }
        override fun putInt(key: String, value: Int) = apply { pending[key] = value }
        override fun putLong(key: String, value: Long) = apply { pending[key] = value }
        override fun putFloat(key: String, value: Float) = apply { pending[key] = value }
        override fun putBoolean(key: String, value: Boolean) = apply { pending[key] = value }
        override fun remove(key: String) = apply { removed += key }
        override fun clear() = apply { clear = true }
        override fun commit(): Boolean {
            if (clear) map.clear()
            removed.forEach(map::remove)
            pending.forEach { (k, v) -> if (v == null) map.remove(k) else map[k] = v }
            return true
        }
        override fun apply() {
            commit()
        }
    }
}
