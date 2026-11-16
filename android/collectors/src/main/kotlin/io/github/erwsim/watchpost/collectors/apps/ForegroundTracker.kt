package io.github.erwsim.watchpost.collectors.apps

/**
 * Pure reduction of the UsageStats event stream to app switches: `resumed` when another app comes
 * to the foreground, `paused` for the app that leaves it (or when the screen turns off / the
 * keyguard shows). Activity changes inside the same app are not reported.
 */
class ForegroundTracker(var currentPackage: String? = null, var currentClass: String? = null) {
    data class Change(val event: String, val pkg: String, val cls: String?)

    enum class Kind { RESUMED, PAUSED, SCREEN_OFF, OTHER }

    fun onEvent(kind: Kind, pkg: String?, cls: String?): List<Change> = when (kind) {
        Kind.RESUMED -> {
            if (pkg == null || pkg == currentPackage) {
                if (pkg != null) currentClass = cls ?: currentClass
                emptyList()
            } else {
                val out = ArrayList<Change>(2)
                currentPackage?.let { out += Change("paused", it, currentClass) }
                currentPackage = pkg
                currentClass = cls
                out += Change("resumed", pkg, cls)
                out
            }
        }
        Kind.SCREEN_OFF -> leave()
        // A pause is usually followed by the next app's resume; it is only final at screen off.
        Kind.PAUSED, Kind.OTHER -> emptyList()
    }

    private fun leave(): List<Change> {
        val pkg = currentPackage ?: return emptyList()
        val out = listOf(Change("paused", pkg, currentClass))
        currentPackage = null
        currentClass = null
        return out
    }
}
