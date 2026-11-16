package io.github.erwsim.watchpost.notifier.protocol

/**
 * Package lists of the notification settings: apps whose title and text are never relayed
 * ("exclues du contenu") and apps ignored altogether. Lists of package names: an app is matched
 * only if its exact package name is listed, so the default list is necessarily incomplete (another
 * bank, a regional variant, a renamed app is not covered).
 */
object PackageLists {
    private val PACKAGE_RE = Regex("^[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z][A-Za-z0-9_]*)+$")

    fun isValidPackage(s: String): Boolean = s.length <= Limits.MAX_PACKAGE_CHARS && PACKAGE_RE.matches(s)

    data class Parsed(val packages: List<String>, val rejected: List<String>)

    /**
     * Entries separated by line breaks, commas, semicolons or spaces; `#` starts a comment. Valid
     * package names are kept (deduplicated, sorted, at most [Limits.MAX_LIST_ENTRIES]); the others
     * are returned in [Parsed.rejected] (at most 20, each cut to 80 characters).
     */
    fun parseText(text: String): Parsed =
        parse(text.lineSequence().map { it.substringBefore('#') }.flatMap { it.split(',', ';', ' ', '\t').asSequence() }.asIterable())

    fun parse(entries: Iterable<String>): Parsed {
        val ok = sortedSetOf<String>()
        val rejected = ArrayList<String>()
        var seen = 0
        for (raw in entries) {
            if (++seen > Limits.MAX_LIST_ENTRIES * 4) break // hostile input: stop reading
            val e = raw.trim()
            if (e.isEmpty()) continue
            if (isValidPackage(e) && (ok.size < Limits.MAX_LIST_ENTRIES || e in ok)) ok += e else if (rejected.size < 20) rejected += e.take(80)
        }
        return Parsed(ok.toList(), rejected)
    }

    /**
     * Default "content excluded" list: banks and payment apps common in France, authenticators,
     * password managers, SMS apps (principle 4: no SMS content) and dialers (no call log: caller name
     * and number). Package names believed correct but not checked one by one on a device.
     */
    val DEFAULT_CONTENT_EXCLUDED: List<String> = listOf(
        // Banks and payment
        "com.boursorama.android.clients",
        "fr.creditagricole.androidapp",
        "net.bnpparibas.mescomptes",
        "mobi.societegenerale.mobile.lappli",
        "fr.lcl.android.customerarea",
        "fr.banquepopulaire.cyberplus",
        "com.caisseepargne.android.mobilebanking",
        "com.fullsix.android.labanquepostale.accountaccess",
        "com.cm_prod.bad",
        "com.cic_prod.bad",
        "com.revolut.revolut",
        "de.number26.android",
        "com.transferwise.android",
        "com.paypal.android.p2pmobile",
        "com.google.android.apps.walletnfcrel",
        "com.samsung.android.spay",
        // Authenticators and identity
        "com.google.android.apps.authenticator2",
        "com.azure.authenticator",
        "com.authy.authy",
        "com.beemdevelopment.aegis",
        "org.fedorahosted.freeotp",
        "com.yubico.yubioath",
        "com.duosecurity.duomobile",
        "com.okta.android.auth",
        "com.lastpass.authenticator",
        "com.bitwarden.authenticator",
        "fr.laposte.idn",
        // Password managers
        "com.x8bit.bitwarden",
        "com.agilebits.onepassword",
        "com.lastpass.lpandroid",
        "com.dashlane",
        "keepass2android.keepass2android",
        "com.kunzisoft.keepass.free",
        "com.kunzisoft.keepass.libre",
        "com.callpod.android_apps.keeper",
        "proton.android.pass",
        "com.samsung.android.samsungpass",
        // SMS (principle 4) and calls (no call log)
        "com.samsung.android.messaging",
        "com.google.android.apps.messaging",
        "com.android.messaging",
        "com.samsung.android.dialer",
        "com.samsung.android.incallui",
        "com.google.android.dialer",
        "com.android.server.telecom",
        "com.android.phone",
    ).sorted()

    /** Default "ignored" list: empty (every app is reported by name unless the owner adds it). */
    val DEFAULT_IGNORED: List<String> = emptyList()

    fun joinForStorage(packages: List<String>): String = packages.joinToString("\n")

    fun splitStored(stored: String): List<String> = parse(stored.lines()).packages
}
