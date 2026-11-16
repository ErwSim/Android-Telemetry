package io.github.erwsim.vigie.collectors.risk

/**
 * Realistic profiles used to measure the false positives and the false negatives of [RiskScorer].
 *
 * They are NOT extracted from real APKs: each one is built from the features and the permissions such an app
 * usually has (manifest as commonly documented), with brand-free names. They show how the weighting behaves on
 * the families that matter, not how it behaves on one given application.
 */
object RiskCorpus {
    enum class Kind { LEGIT, MALICIOUS }

    /**
     * [ideal]: the level a human reviewer would want. [expected]: the level the scorer gives today (the test
     * fails when they drift, which forces the README table and the report to be updated knowingly).
     */
    data class Profile(val id: String, val kind: Kind, val ideal: RiskLevel, val expected: RiskLevel, val note: String, val facts: AppFacts)

    private const val P = "android.permission."
    const val PLAY = "com.android.vending"
    const val FDROID = "org.fdroid.fdroid"
    const val INSTALLER = "com.google.android.packageinstaller"

    private fun perms(vararg names: String) = names.map { if ('.' in it) it else P + it }.toSet()

    private fun app(
        id: String,
        installer: String? = PLAY,
        requestedOnly: Set<String> = emptySet(),
        granted: Set<String> = emptySet(),
        system: Boolean = false,
        self: Boolean = false,
        accessibility: Boolean = false,
        listener: Boolean = false,
        admin: Boolean = false,
        vpn: Boolean = false,
        boot: Boolean = false,
        launcher: Boolean = true,
        defaultSms: Boolean = false,
        target: Int = 36,
        debuggable: Boolean = false,
    ) = AppFacts(
        pkg = "test.$id", label = id, versionCode = 1, installer = installer, system = system, isSelf = self,
        requested = granted + requestedOnly, granted = granted,
        accessibilityService = accessibility, notificationListener = listener, deviceAdminReceiver = admin, vpnService = vpn,
        bootReceiver = boot, launcherActivity = launcher, defaultSmsApp = defaultSms, targetSdk = target, debuggable = debuggable,
    )

    private val BOOT = perms("RECEIVE_BOOT_COMPLETED")
    private val SMS_ALL = perms("SEND_SMS", "READ_SMS", "RECEIVE_SMS", "RECEIVE_MMS", "RECEIVE_WAP_PUSH")

    val ALL: List<Profile> = listOf(
        // ---- Legitimate apps (installed by the owner from a store, unless stated) ----
        legit(
            "messagerie_chiffree", RiskLevel.LOW, RiskLevel.LOW, "Appels, micro/caméra en appel, démarrage au boot.",
            app(
                "messagerie_chiffree", granted = perms("CAMERA", "RECORD_AUDIO", "READ_CONTACTS", "READ_CALL_LOG", "ANSWER_PHONE_CALLS", "READ_PHONE_STATE", "ACCESS_FINE_LOCATION"),
                requestedOnly = BOOT + perms("FOREGROUND_SERVICE", "FOREGROUND_SERVICE_MICROPHONE", "FOREGROUND_SERVICE_CAMERA"), boot = true,
            ),
        ),
        legit("banque", RiskLevel.LOW, RiskLevel.LOW, "Caméra (chèque, identité), position, état du téléphone.", app("banque", granted = perms("CAMERA", "ACCESS_FINE_LOCATION", "READ_PHONE_STATE"))),
        legit("clavier_tiers", RiskLevel.LOW, RiskLevel.LOW, "Un clavier n'est pas noté pour son service de saisie.", app("clavier_tiers", granted = perms("READ_CONTACTS", "RECORD_AUDIO"), requestedOnly = BOOT, boot = true)),
        legit("navigateur", RiskLevel.LOW, RiskLevel.LOW, "Caméra, micro, position.", app("navigateur", granted = perms("CAMERA", "RECORD_AUDIO", "ACCESS_FINE_LOCATION"))),
        legit(
            "lanceur", RiskLevel.LOW, RiskLevel.LOW, "Écouteur de notifications pour les pastilles.",
            app("lanceur", granted = perms("READ_CONTACTS"), requestedOnly = BOOT, listener = true, boot = true),
        ),
        legit(
            "lanceur_verrouillage", RiskLevel.LOW, RiskLevel.MEDIUM, "Lanceur dont la fonction « double toucher pour verrouiller » passe par l'accessibilité.",
            app("lanceur_verrouillage", granted = perms("READ_CONTACTS"), requestedOnly = BOOT, listener = true, accessibility = true, boot = true),
        ),
        legit(
            "gestionnaire_mots_de_passe", RiskLevel.LOW, RiskLevel.MEDIUM, "Remplissage par accessibilité et affichage par-dessus les apps : indiscernable d'un trojan sur ces deux critères.",
            app("gestionnaire_mots_de_passe", granted = perms("CAMERA"), requestedOnly = perms("SYSTEM_ALERT_WINDOW"), accessibility = true),
        ),
        legit(
            "controle_parental", RiskLevel.MEDIUM, RiskLevel.HIGH, "Mêmes pouvoirs qu'un logiciel espion, par construction : ne se distingue pas sans savoir qui l'a installé.",
            app(
                "controle_parental", granted = perms("ACCESS_FINE_LOCATION", "ACCESS_BACKGROUND_LOCATION", "READ_SMS", "READ_CALL_LOG", "READ_CONTACTS"),
                requestedOnly = BOOT + perms("SYSTEM_ALERT_WINDOW", "PACKAGE_USAGE_STATS"), accessibility = true, admin = true, vpn = true, listener = true, boot = true,
            ),
        ),
        legit("vpn", RiskLevel.LOW, RiskLevel.LOW, "Service VPN et démarrage au boot.", app("vpn", requestedOnly = BOOT, vpn = true, boot = true)),
        legit(
            "sms_tiers_par_defaut", RiskLevel.LOW, RiskLevel.MEDIUM, "Appli SMS tierce choisie par défaut : elle doit avoir tous les droits SMS.",
            app("sms_tiers_par_defaut", granted = SMS_ALL + perms("READ_CONTACTS"), requestedOnly = BOOT, boot = true, defaultSms = true),
        ),
        legit(
            "antivirus", RiskLevel.MEDIUM, RiskLevel.HIGH, "Une suite de sécurité demande accessibilité, superposition, notifications, SMS, VPN et administration.",
            app(
                "antivirus", granted = perms("READ_SMS", "RECEIVE_SMS", "READ_CONTACTS"), requestedOnly = BOOT + perms("SYSTEM_ALERT_WINDOW"),
                accessibility = true, listener = true, admin = true, vpn = true, boot = true,
            ),
        ),
        legit(
            "automatisation", RiskLevel.MEDIUM, RiskLevel.HIGH, "Une app d'automatisation (type Tasker) a tous les pouvoirs : accessibilité, SMS, appels, superposition.",
            app(
                "automatisation", granted = SMS_ALL + perms("CALL_PHONE", "READ_CONTACTS"), requestedOnly = BOOT + perms("SYSTEM_ALERT_WINDOW"),
                accessibility = true, listener = true, boot = true,
            ),
        ),
        legit("gestionnaire_fichiers", RiskLevel.LOW, RiskLevel.LOW, "Demande à installer des paquets (APK) ; boutique F-Droid.", app("gestionnaire_fichiers", installer = FDROID, requestedOnly = perms("REQUEST_INSTALL_PACKAGES"))),
        legit("navigation_hors_ligne", RiskLevel.LOW, RiskLevel.LOW, "Position en arrière-plan pour le suivi de trajet.", app("navigation_hors_ligne", installer = FDROID, granted = perms("ACCESS_FINE_LOCATION", "ACCESS_BACKGROUND_LOCATION"), requestedOnly = BOOT, boot = true)),
        legit(
            "identification_appelant", RiskLevel.LOW, RiskLevel.HIGH, "Identification d'appelant avec droits SMS (paiement) : envoi de SMS + démarrage au boot sans être l'appli SMS.",
            app(
                "identification_appelant", granted = SMS_ALL + perms("READ_CALL_LOG", "CALL_PHONE", "READ_CONTACTS"), requestedOnly = BOOT + perms("SYSTEM_ALERT_WINDOW"), boot = true,
            ),
        ),
        legit("composeur_tiers", RiskLevel.LOW, RiskLevel.LOW, "Composeur tiers par défaut.", app("composeur_tiers", granted = perms("CALL_PHONE", "READ_CALL_LOG", "READ_CONTACTS", "ANSWER_PHONE_CALLS"), requestedOnly = BOOT, boot = true)),
        legit("authentificateur", RiskLevel.LOW, RiskLevel.LOW, "Caméra pour les QR codes.", app("authentificateur", installer = FDROID, granted = perms("CAMERA"))),
        legit(
            "remappage_boutons", RiskLevel.LOW, RiskLevel.MEDIUM, "Remappage de boutons : accessibilité + superposition.",
            app("remappage_boutons", requestedOnly = perms("SYSTEM_ALERT_WINDOW"), accessibility = true, boot = false),
        ),
        legit("banque_ancienne", RiskLevel.LOW, RiskLevel.LOW, "Appli bancaire abandonnée, cible Android 9.", app("banque_ancienne", granted = perms("CAMERA", "READ_PHONE_STATE"), target = 28)),
        legit(
            "composeur_systeme", RiskLevel.LOW, RiskLevel.LOW, "Appli système (appels, SMS, notifications) : plafonnée à « faible ».",
            app(
                "composeur_systeme", installer = null, system = true, granted = SMS_ALL + perms("CALL_PHONE", "READ_CALL_LOG", "READ_CONTACTS"),
                requestedOnly = BOOT + perms("SYSTEM_ALERT_WINDOW"), listener = true, accessibility = true, boot = true, launcher = false,
            ),
        ),
        legit(
            "vigie", RiskLevel.LOW, RiskLevel.LOW, "L'agent lui-même : position en arrière-plan, démarrage au boot, accès à l'utilisation.",
            app("vigie", installer = null, self = true, granted = perms("ACCESS_FINE_LOCATION", "ACCESS_BACKGROUND_LOCATION", "READ_PHONE_STATE"), requestedOnly = BOOT, boot = true),
        ),

        // ---- Malicious profiles ----
        bad(
            "troyen_bancaire", RiskLevel.HIGH, RiskLevel.HIGH, "Faux lecteur PDF : accessibilité + superposition + SMS + notifications + installation, hors boutique.",
            app(
                "troyen_bancaire", installer = INSTALLER, granted = perms("READ_SMS", "RECEIVE_SMS"), requestedOnly = BOOT + perms("SYSTEM_ALERT_WINDOW", "REQUEST_INSTALL_PACKAGES"),
                accessibility = true, listener = true, boot = true, target = 31,
            ),
        ),
        bad(
            "fraude_sms", RiskLevel.HIGH, RiskLevel.HIGH, "Le cas du propriétaire : envoi massif de SMS en tâche de fond, faux fonds d'écran.",
            app("fraude_sms", installer = null, granted = perms("SEND_SMS", "READ_CONTACTS"), requestedOnly = BOOT, boot = true),
        ),
        bad(
            "fraude_sms_sans_boot", RiskLevel.HIGH, RiskLevel.MEDIUM, "Même envoi, déclenché par une notification push : pas de démarrage au boot, donc pas de combinaison.",
            app("fraude_sms_sans_boot", installer = INSTALLER, granted = perms("SEND_SMS")),
        ),
        bad(
            "fraude_sms_boutique", RiskLevel.HIGH, RiskLevel.MEDIUM, "Même profil distribué par la boutique : la boutique n'efface pas le risque, mais n'ajoute pas de points non plus.",
            app("fraude_sms_boutique", granted = perms("SEND_SMS"), requestedOnly = BOOT, boot = true),
        ),
        bad(
            "espion_sans_icone", RiskLevel.HIGH, RiskLevel.HIGH, "Logiciel espion complet, installé par ADB, sans icône.",
            app(
                "espion_sans_icone", installer = null, granted = perms("ACCESS_FINE_LOCATION", "ACCESS_BACKGROUND_LOCATION", "RECORD_AUDIO", "READ_SMS", "READ_CALL_LOG", "READ_CONTACTS"),
                requestedOnly = BOOT + perms("FOREGROUND_SERVICE_MICROPHONE"), accessibility = true, listener = true, admin = true, boot = true, launcher = false,
            ),
        ),
        bad(
            "espion_minimal", RiskLevel.HIGH, RiskLevel.HIGH, "Suivi de position seul : sans icône, position, démarrage au boot.",
            app("espion_minimal", installer = null, granted = perms("ACCESS_FINE_LOCATION"), requestedOnly = BOOT, boot = true, launcher = false),
        ),
        bad(
            "espion_discret_mais_avec_icone", RiskLevel.HIGH, RiskLevel.LOW, "Espion qui garde une icône anodine (« Notes ») : aucune des trois combinaisons ne le voit, seul « hors boutique » reste.",
            app("espion_discret_mais_avec_icone", installer = INSTALLER, granted = perms("ACCESS_FINE_LOCATION", "RECORD_AUDIO", "READ_CONTACTS"), requestedOnly = BOOT, boot = true),
        ),
        bad(
            "installateur_charge_utile", RiskLevel.HIGH, RiskLevel.MEDIUM, "Dropper hors boutique : demande à installer des paquets, rien d'autre. Moyen, pas élevé.",
            app("installateur_charge_utile", installer = INSTALLER, requestedOnly = perms("REQUEST_INSTALL_PACKAGES", "QUERY_ALL_PACKAGES", "FOREGROUND_SERVICE")),
        ),
        bad(
            "installateur_charge_utile_boutique", RiskLevel.HIGH, RiskLevel.LOW, "Dropper publié sur la boutique : seule la demande d'installation le trahit, ce qui ne suffit pas.",
            app("installateur_charge_utile_boutique", requestedOnly = perms("REQUEST_INSTALL_PACKAGES", "QUERY_ALL_PACKAGES", "FOREGROUND_SERVICE")),
        ),
        bad(
            "rat_depose_par_messagerie", RiskLevel.HIGH, RiskLevel.HIGH, "Outil d'accès à distance déposé par une app de messagerie : accessibilité, notifications, superposition, SMS.",
            app(
                "rat_depose_par_messagerie", installer = "org.telegram.messenger", granted = perms("READ_SMS", "RECEIVE_SMS"),
                requestedOnly = perms("SYSTEM_ALERT_WINDOW"), accessibility = true, listener = true, target = 30,
            ),
        ),
        bad(
            "adware_accessibilite", RiskLevel.MEDIUM, RiskLevel.MEDIUM, "Publicité forcée par accessibilité et superposition, hors boutique.",
            app("adware_accessibilite", installer = INSTALLER, requestedOnly = perms("SYSTEM_ALERT_WINDOW"), accessibility = true),
        ),
        bad(
            "verrouilleur", RiskLevel.HIGH, RiskLevel.MEDIUM, "Écran de rançon : administrateur + superposition + démarrage au boot, hors boutique.",
            app("verrouilleur", installer = INSTALLER, requestedOnly = BOOT + perms("SYSTEM_ALERT_WINDOW"), admin = true, boot = true),
        ),
    )

    private fun legit(id: String, ideal: RiskLevel, expected: RiskLevel, note: String, facts: AppFacts) = Profile(id, Kind.LEGIT, ideal, expected, note, facts)

    private fun bad(id: String, ideal: RiskLevel, expected: RiskLevel, note: String, facts: AppFacts) = Profile(id, Kind.MALICIOUS, ideal, expected, note, facts)
}
