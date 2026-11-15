package io.github.erwsim.vigie.core.capability

import java.util.concurrent.TimeUnit

/**
 * Reads system properties through `/system/bin/getprop` (public binary, no hidden API).
 * Some properties are hidden from apps by SELinux: the result is then null.
 * Blocking (spawns a process): call it from `Dispatchers.IO`, rarely.
 */
object SystemProps {
    fun get(name: String): String? {
        require(Regex("^[a-zA-Z0-9._-]+$").matches(name)) { "bad property name" }
        return try {
            val process = ProcessBuilder("/system/bin/getprop", name).redirectErrorStream(true).start()
            val out = process.inputStream.bufferedReader().use { it.readText() }
            if (!process.waitFor(2, TimeUnit.SECONDS)) {
                process.destroy()
                return null
            }
            out.trim().takeIf { it.isNotEmpty() }
        } catch (_: Exception) {
            null
        }
    }

    /** `ro.build.version.oneui` (e.g. `90000`) → `9.0`; null when absent (non-Samsung). */
    fun oneUiVersion(raw: String? = get("ro.build.version.oneui")): String? {
        val v = raw?.toIntOrNull() ?: return raw
        return "${v / 10000}.${(v % 10000) / 100}"
    }
}
