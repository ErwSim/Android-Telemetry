# Vigie Agent (Android)

Agent de télémétrie de sécurité installé par le propriétaire sur **son propre** téléphone (cible : Galaxy S25+,
Android 16/17, One UI 8/9, non rooté), promu **Device Owner** par ADB. Il collecte des événements, les garde
dans un tampon hors-ligne et les envoie par lots (HTTPS + certificat client) au collecteur Vigie enrôlé.

Principes (voir `../docs/ARCHITECTURE.md`) : notification permanente et icône visible, aucun envoi ailleurs que
vers l'adresse enrôlée, le serveur ne peut rien commander, aucune dépendance Google (ni Play Services, ni
Firebase, ni ML Kit), pas de contenu privé de tiers, chaque collecteur désactivable, tout réversible.

Développeurs (ajout de collecteurs, module Device Owner) : lire **`ARCHITECTURE-CODE.md`**.

## Contenu de cette version

| Élément | État |
|---|---|
| Tampon Room (`seq` transactionnel, plafond 200 Mio / 30 j, purge « plus anciens de plus faible sévérité » + `agent.buffer_overflow`) | fait, testé (JVM) |
| Envoi : lots ≤ 500 événements et ≤ 1 Mio gzip, suppression après accusé, 401/413/429/5xx, `Retry-After`, backoff avec gigue, « gros volumes en Wi-Fi seulement », reprise au retour du réseau | fait, testé (MockWebServer) |
| Enrôlement `.vigie` : clé dans l'Android Keystore, jeton chiffré, mTLS, épinglage de l'AC serveur, test `GET /api/v1/ping`, désenrôlement | fait ; analyse et mTLS testés sur JVM, Keystore Android **non testé** |
| Service de premier plan (`specialUse` + `location`), démarrage au boot et après mise à jour, redémarrage (sticky + maintenance 15 min), `agent.started/stopped/heartbeat/collector_error/config_changed` | fait, non testé sur appareil |
| Collecteurs `location` (GPS + passif, cadence adaptative, `mock`), `device` (écran, batterie, économie d'énergie, boot/arrêt, inventaire, stockage, heure/fuseau, mode avion, thermique), `heartbeat` | faits ; logique testée sur JVM |
| Device Owner minimal : récepteur d'administration, auto-attribution des permissions, protection contre l'arrêt forcé, `agent.tamper` | fait, non testé sur appareil |
| Interface Material 3 (Accueil, Collecteurs, Journal local, Réglages, Enrôlement, emplacement « Politique ») | faite, non testée sur appareil |
| Moteur de politique (DNS privé, paquets, restrictions), journaux réseau/sécurité, autres collecteurs | **pas dans ce lot** |

## Versions et outillage

| Élément | Version | Remarque |
|---|---|---|
| Gradle (wrapper) | 9.9.1 | `gradle/wrapper/` versionné |
| Android Gradle Plugin | 9.5.1 | Kotlin intégré à AGP (pas de plugin `kotlin-android` appliqué) |
| Kotlin | 2.4.21 | KSP 2.3.14 (Room) |
| `compileSdk` / `targetSdk` / `minSdk` | 37 / 37 / 36 | plateforme SDK `android-37.0`, build-tools 36.0.0 |
| JDK | 17 minimum (vérifié avec 21) | |
| Bibliothèques | Room 2.8.5, WorkManager 2.12.0, OkHttp 5.5.1, kotlinx-serialization 1.13.0, coroutines 1.11.0, Compose BOM 2026.09.00 (Material 3) | AndroidX uniquement côté Google |

## Construire

Prérequis : JDK 17+, SDK Android (`ANDROID_HOME`, ou `sdk.dir=` dans `android/local.properties`) avec
`platforms;android-37.0` et `build-tools;36.0.0` (AGP les télécharge si les licences sont acceptées).

```bash
cd android
./gradlew assembleDebug                 # Windows : .\gradlew.bat assembleDebug
./gradlew lint test                     # vérifications (lint Android + tests JVM)
```

### Signature de la version release (une seule fois, puis à conserver)

```bash
./scripts/generate-keystore.sh          # Windows : .\scripts\generate-keystore.ps1
./gradlew assembleRelease               # → app/build/outputs/apk/release/app-release.apk
```

Le script crée `android/keystore/vigie-release.jks` et `android/keystore.properties` (tous deux ignorés par
git). On peut aussi fournir `VIGIE_KEYSTORE_FILE`, `VIGIE_KEYSTORE_PASSWORD`, `VIGIE_KEY_ALIAS`,
`VIGIE_KEY_PASSWORD` dans l'environnement. Sans clé, `assembleRelease` produit un APK **non signé**.

> **Sauvegardez la clé (chiffrée, hors de l'ordinateur).** Android n'accepte une mise à jour que signée par
> la même clé. Pour un Device Owner, il n'y a pas de contournement : sans la clé d'origine, il faut retirer le
> Device Owner (ou réinitialiser le téléphone) avant d'installer une version signée autrement. L'APK est
> signé en schéma v3 (suffisant pour Android 9+, et permet une rotation de clé future).

### Paramètres de construction

| Paramètre | Défaut | Rôle |
|---|---|---|
| `-Pvigie.testOnly=true\|false` | `true` | `android:testOnly`. `true` permet de retirer le Device Owner par `adb shell dpm remove-active-admin` et impose `adb install -t` (les scripts le font). `false` : seul l'app pourra retirer le rôle. |
| `-Pvigie.versionCode=N` | `1` | À **augmenter** à chaque mise à jour. |
| `-Pvigie.versionName=x.y.z` | `0.1.0` | Version affichée et envoyée (`agent_version`). |

## Installer et activer

Tous les scripts sont dans `android/scripts/`, en double : `*.sh` (Linux/macOS) et `*.ps1` (Windows
PowerShell). Ils exigent `adb` (Android SDK Platform-Tools) dans le `PATH` et un téléphone en débogage USB.
Avec plusieurs appareils connectés : `export ANDROID_SERIAL=…` / `$env:ANDROID_SERIAL = '…'`.

1. **Préparer le téléphone** : Options de développement › Débogage USB ; désactiver temporairement le
   « Blocage automatique » (Auto Blocker) de Samsung, qui bloque les commandes USB.
2. **Installer** : `./scripts/install-apk.sh [app.apk]` (`adb install -r -t`).
3. **Activer le Device Owner** : `./scripts/enable-device-owner.sh`. Le script vérifie qu'aucun autre
   propriétaire n'existe, qu'il n'y a qu'un utilisateur (pas de Dossier sécurisé, Dual Messenger, espace
   privé, profil pro, invité) et **aucun compte** : Android refuse sinon. Retirez temporairement les comptes
   (Google, Samsung, messageries…), activez, puis rajoutez-les : le Device Owner ne l'interdit pas.
   Effets connus du mode Device Owner : sauvegarde Android coupée (réactivable), Dossier sécurisé, Dual
   Messenger et espace privé indisponibles, mention « appareil géré ».
4. **Ouvrir Vigie** : en Device Owner, l'app s'accorde ses permissions (localisation, notifications…) et
   active la protection contre l'arrêt forcé. Sans Device Owner (mode dégradé), accorder les permissions
   depuis l'onglet Collecteurs, ou `./scripts/grant-adb-permissions.sh`.
5. **Batterie** : `./scripts/battery-exemptions.sh`, puis à la main sur Samsung : Paramètres › Batterie ›
   Limites d'utilisation en arrière-plan › Applications jamais en veille › Vigie.
6. **Réactiver** le Blocage automatique si souhaité (son interaction avec un Device Owner tiers n'est pas
   vérifiée, voir la recherche plateforme).

## Enrôler

1. Sur le serveur : `vigie-collector enroll --name s25 --out s25.vigie`.
2. Copier par câble : `./scripts/push-enrollment.sh s25.vigie` (→ `Téléchargements`).
3. Dans l'app : Réglages › Enrôlement › « Importer un fichier .vigie », vérifier le résumé, « Enrôler ».
   La clé privée est importée dans l'Android Keystore (non exportable) puis oubliée ; le jeton est chiffré
   par une clé AES du Keystore ; un test `GET /api/v1/ping` est lancé ; l'app tente de supprimer le fichier.
4. Supprimer toutes les copies du fichier : `./scripts/push-enrollment.sh --remove s25.vigie` et sur le PC.

Si `server_ca_pem` est présent, seule cette AC est acceptée pour le serveur. Sinon, seules les AC du système
(jamais celles ajoutées par l'utilisateur). Les redirections HTTP sont refusées. Avant l'enrôlement, les
événements restent sur le téléphone (dans la limite du tampon). « Désenrôler » efface clé, jeton et
événements en attente ; la collecte locale continue.

## Mettre à jour

```bash
./gradlew assembleRelease -Pvigie.versionCode=2 -Pvigie.versionName=0.2.0
./scripts/install-apk.sh
```

Même clé de signature obligatoire, `versionCode` strictement croissant. L'agent redémarre seul après la mise
à jour (`MY_PACKAGE_REPLACED`). Les données (tampon, enrôlement, réglages) sont conservées.

## Retirer le Device Owner et désinstaller

1. (Lots suivants) défaire la politique depuis l'écran « Politique » de l'app.
2. `./scripts/remove-device-owner.sh [--uninstall]` (`-Uninstall` en PowerShell) : `dpm remove-active-admin`,
   possible **uniquement** avec un APK `testOnly`. Avec un APK non testOnly, seule l'app pourra retirer le
   rôle (fonction prévue avec le moteur de politique) ou une réinitialisation.
3. La sauvegarde Android peut ensuite être réactivée dans les Paramètres.

## Fonctionnement (résumé)

- **Service de premier plan** permanent, types `specialUse` (+ `location` si la permission est accordée) ;
  notification « Vigie collecte… » avec le nombre d'événements en attente et l'heure du dernier envoi.
- **WorkManager** : envoi périodique (15 min par défaut) et au retour du réseau, collectes périodiques
  (heartbeat 15 min, inventaire quotidien), maintenance toutes les 15 min (âge du tampon, intégrité,
  redémarrage du service si besoin).
- **Envoi déclenché** aussi par tout événement `sev >= 2` et par un tampon de plus de 500 événements.
- **Écritures groupées** : jusqu'à 3 s en mémoire avant une transaction unique (immédiat si `sev >= 2`). Un
  arrêt brutal peut perdre ces quelques secondes, jamais créer de trou ni de doublon de `seq`.
- **Direct Boot** non utilisé : rien n'est collecté entre un redémarrage et le premier déverrouillage (le
  tampon et l'enrôlement sont dans le stockage chiffré par les identifiants). `device.boot` est émis après
  le déverrouillage.
- **Certificate Transparency** (imposée par défaut avec `targetSdk 37`) est désactivée dans
  `network_security_config.xml` : une AC serveur privée n'a pas de SCT. L'app ne contacte que l'hôte enrôlé
  et, en mode AC privée, l'épinglage est plus strict que la CT.
- **`agent.tamper`** : demande ou désactivation de l'administrateur, permission retirée, arrêt forcé détecté
  (`ApplicationExitInfo`), perte du rôle Device Owner.

## Collecteurs

Chaque collecteur est désactivable dans l'onglet Collecteurs ; s'il lui manque une capacité, il s'affiche
« indisponible » avec la raison. Permissions « ADB » : `./scripts/grant-adb-permissions.sh`. Noms de types et
de champs : `docs/contrat/contrat.md` §2 (vérifiés par les tests JVM de `:collectors`).

| Collecteur (id) | Émet | Capacité requise | Coût |
|---|---|---|---|
| Battement de cœur (`heartbeat`) | `agent.heartbeat` | — | WorkManager 15 min |
| Appareil (`device`) | `device.inventory`, `boot`, `shutdown`, `screen`, `battery`, `power_save`, `storage`, `thermal`, `time_changed`, `timezone_changed`, `airplane_mode` | — | diffusions + relevé quotidien |
| USB (`usb`) | `device.usb` (câble, fonctions dont `adb`, appareil ou accessoire branché) | — | diffusions, ≤ 60/h |
| Localisation (`location`) | `location.fix`, `location.provider` | localisation précise (+ arrière-plan) | GPS adaptatif + passif |
| Connectivité (`connectivity`) | `net.connectivity` | — (ACCESS_NETWORK_STATE) | rappel système, ≤ 60/h |
| Wi-Fi (`wifi`) | `net.wifi` connecté/déconnecté | localisation précise pour SSID/BSSID (sinon omis) | rappel système, aucun balayage |
| Réseaux Wi-Fi voisins (`wifi_scan`, **désactivé par défaut**) | `net.wifi_scan` (≤ 60 points d'accès) | localisation précise | passif (balayages des autres) ; actif optionnel ≥ 30 min ; ≤ 1 événement / 15 min |
| Point d'accès mobile (`hotspot`) | `net.hotspot` | — | diffusion système |
| NFC (`nfc`) | `net.nfc` | matériel NFC | diffusion système |
| Réseau mobile (`cell`) | `net.cell`, `net.cell_security` (`downgrade_2g`, sév. 2) | téléphonie ; localisation précise pour les identifiants de cellule et « Téléphone » (READ_PHONE_STATE) pour le suivi cellule par cellule et le signal (optionnelles) | TelephonyCallback, ≤ 1 événement / 20 s hors changement de techno |
| Bluetooth (`bluetooth`) | `net.bluetooth` (état, connexions) | « Appareils à proximité » pour les connexions (optionnelle) | diffusions, ≤ 120/h |
| Traceurs (`ble_tracker`) | `net.ble_tracker` (sév. 2) | BLUETOOTH_SCAN + localisation précise | balayage BLE basse consommation filtré matériellement, résultats groupés 60 s, Bluetooth allumé |
| Volumes réseau (`net_usage`) | `net.usage` horaire par app et transport | accès à l'utilisation (ADB) **ou** Device Owner | WorkManager 1 h, 2 requêtes |
| Applications (`apps`) | `app.inventory` (parties < 16 Kio, `inventory_id`), `app.installed/updated/removed`, `app.permission_changed` | — (QUERY_ALL_PACKAGES) | diffusions + parcours des paquets toutes les heures, libellés une fois par jour |
| Accès spéciaux (`special_access`) | `app.special_access` | — | au changement (paquets, réglages, extinction d'écran ≤ 1/15 min) + quotidien |
| App au premier plan (`foreground`) | `app.foreground` (changements d'app seulement) | accès à l'utilisation (ADB ou Paramètres) | relevé 60 s écran allumé uniquement + WorkManager 15 min ; 100 à 400/jour |
| Caméra (`camera`) | `sensor.camera` (+ `screen_on`, `locked`) | — | rappel système, ≤ 120/h |
| Microphone (`microphone`) | `sensor.microphone` (+ `screen_on`, `locked`) | — | rappel système, ≤ 120/h |

Détails et limites :

- **Champs absents** plutôt que valeurs factices : `<unknown ssid>`, `02:00:00:00:00:00`, `CellInfo.UNAVAILABLE`,
  RSSI −127 ne sont jamais émis.
- **`net.cell`** : `tech` = nom de `NETWORK_TYPE_*` en minuscules (`gsm`, `edge`, `umts`, `lte`, `nr`…) et
  `none` hors service. **`net.cell_security`** : seule la rétrogradation vers la 2G (données ou voix) est
  détectable sans privilège ; chiffrement nul et demande d'identifiant sont des API système. Mesure efficace :
  `DISALLOW_CELLULAR_2G` (module `:policy`).
- **`net.ble_tracker`** : AirTag/Find My « séparé du propriétaire », SmartTag (0xFD5A), Tile (0xFEED/0xFEEC),
  Localiser de Google en mode anti-pistage (0xFEAA, trame 0x41). Alerte si vu ≥ 4 fois (une fois par minute au
  plus), sur ≥ 30 min, pendant un déplacement ≥ 500 m (réglables), positions tirées du cache passif ; rien
  sans position connue. Un changement d'adresse du traceur (rotation) remet le compte à zéro.
- **`net.usage`** : le système compte par tranches d'environ 2 h et répartit au prorata : valeurs horaires
  estimées, fenêtre terminée depuis au moins 30 min, rattrapage ≤ 24 h, 100 apps au plus par événement.
- **`app.special_access`** : services d'accessibilité et administrateurs (API publiques) ; écouteurs de
  notifications (réglage sécurisé `enabled_notification_listeners`, omis si illisible) ; superposition,
  installation d'apps inconnues, accès à l'utilisation (app-op de chaque app qui demande la permission) ;
  `vpn_apps` = apps qui **déclarent** un VpnService (le propriétaire du VPN actif n'est pas visible) ;
  `default_apps` : navigateur, accueil, téléphone, SMS, clavier, assistant et saisie automatique si lisibles.
- **`app.foreground`** : l'horodatage est celui du relevé (≤ 60 s de retard), le contrat n'ayant pas de champ
  pour l'heure d'origine.
- **Attribution expérimentale** (réglage « Attribution expérimentale (DUMP) » des collecteurs Caméra et
  Microphone, désactivé par défaut) : avec `DUMP` accordée par ADB, `Debug.dumpService("appops", --op …)` est
  analysé pour remplir `package` quand une seule app utilise la caméra ou le micro. Format texte non garanti,
  refus SELinux possible : sans certitude, `package` reste absent. Pas d'attribution de la localisation (aucun
  type au contrat).
- **Non écrits** (choix) : écoute des notifications, accessibilité, SMS/appels (principe 4) ; tout ce qui exige
  le Device Owner (journaux réseau et sécurité, posture, politique : module `:policy`).

## Politique Device Owner

Module `:policy`, écran **Réglages › Device Owner › Politique**. **Rien n'est appliqué automatiquement** : en
dehors du socle (auto-attribution des permissions de Vigie, protection contre l'arrêt forcé) et des journaux
ci-dessous, c'est le propriétaire qui choisit un profil, ajuste les éléments, lit l'aperçu (« Ce qui va
changer ») et applique. Chaque action émet `security.policy` (`action`, `target`, `profile` = `equilibre`/
`strict`, `ok`, `error`) et une ligne du journal local de l'écran. L'état appliqué (avec l'état antérieur de
chaque élément) est écrit **avant** chaque changement (SharedPreferences `vigie_policy`, `commit()`), puis
confirmé après relecture de l'effet : il survit aux mises à jour de l'app et aux redémarrages, et « Rétablir »
remet exactement l'état d'avant. Un échec (exception, refus Samsung, effet non constaté) donne `ok=false` avec
l'erreur et n'empêche pas les autres éléments. Aucune politique ne vient du serveur.

### Journaux et posture (collecteurs, onglet Collecteurs)

| Collecteur (id) | Émet | Remarques |
|---|---|---|
| Journal de sécurité (`security_log`) | `security.log` | lots livrés par le système (≤ 2 h) ; `fields` selon la table du contrat (`argN` sinon) ; `app_process_start` agrégé par heure (désactivable) ; connexions Wi-Fi/Bluetooth désactivables ; journaux d'avant redémarrage lus une fois par démarrage si l'appareil les fournit (`pre_reboot: true`) |
| Journal réseau (`network_log`) | `net.dns`, `net.connect` | lots ≤ 1200 entrées (≤ 1 h 30) ; paquet et uid (uid partagés : `android.uid.system`…) ; agrégation des requêtes identiques par fenêtre (10 min, réglable : `count`, `last_event_ts`) ; émission par paquets de 100 ; lot notifié pendant l'arrêt de l'agent récupéré au démarrage suivant ; lots perdus signalés en `agent.collector_error` |
| Posture (`posture`) | `security.posture`, `security.posture_change`, `security.ca_cert`, `security.keyguard` | au démarrage, chaque jour et à chaque changement (observateurs de réglages, magasin de certificats, Device Owner, changement de code) ; un champ illisible est omis ; fonctionne partiellement sans Device Owner |

Ces trois collecteurs sont actifs par défaut (comme tout collecteur). Couper `network_log` ou `security_log`
dans l'onglet Collecteurs coupe aussi la journalisation du système (`security.policy` `network_logging` /
`security_logging`). Le journal réseau fait afficher par Android la mention « réseau surveillé ». `event_ts`
porte l'heure d'origine d'une entrée de journal (le `ts` de l'événement est l'heure de récupération).

### Profils

| | Équilibré (par défaut) | Strict (= équilibré + …) |
|---|---|---|
| Paquets | 35 (28 cochés) : Customization Service, Knox Analytics, DSMS, Device Quality Agent, diagnostics réseau et journaux Samsung, Device ID Service (OAID), AdServices / On-Device Personalization / Federated Compute de Google, Market Feedback, Partner Setup, apps Meta préinstallées… ; optionnels : Bixby, Samsung Free, Android System Intelligence, Gemini | 22 (8 cochés) : compte Samsung, Samsung Cloud, Experience Service, Samsung Push, Update Center, OMC Agent, KLMS, Appli Google ; optionnels : Find My Mobile, Samsung Wallet/Pay/Pass, Galaxy Store, Entretien de l'appareil, Services Google Play, GSF, Play Store |
| Permissions refusées | localisation de l'Appli Google (+ optionnel : Samsung Internet, Météo) | micro/caméra/contacts de l'Appli Google, Bixby ; optionnel : localisation d'arrière-plan et appareils à proximité des Services Google Play, capteurs de Samsung Health |
| Restrictions | pas d'ajout d'utilisateur, pas de 2G, pas de sources inconnues, pas de capture ni de suggestions de contenu | + pas d'ajout de certificats, pas de mode sans échec, pas de contenu envoyé à l'assistant, UWB, Thread, partage Bluetooth, nouveaux administrateurs ; optionnel : eSIM, transfert USB, NFC |
| Réglages | recherche Bluetooth permanente coupée (`ble_scan_always_enabled=0`, si WRITE_SECURE_SETTINGS) ; sauvegarde Android réactivée | sauvegarde laissée coupée |
| DNS privé | imposé vers l'hôte de l'enrôlement (`private_dns_host`), verrouillé | idem |

**Ce que le strict casse** (cochés par défaut) : compte Samsung, Galaxy Store, Samsung Cloud, Find My Mobile
(via le compte), notifications Samsung, Appli Google / Assistant / Entourer pour chercher, recherche vocale,
mode sans échec, ajout de certificats (Wi-Fi d'entreprise). Les éléments à risque élevé ou critique (Services
Google Play, Play Store, paiement, antivol, NFC) ne sont **jamais cochés par défaut**.

Données : `policy/src/main/res/raw/policy_catalog.json` (versionné, lisible : paquet, éditeur, rôle, risque,
effet connu, méthode, profil), tiré de `docs/research/android-plateforme.md` §7. Un paquet absent est ignoré.
Méthode : **masquer** (`setApplicationHidden`, services arrêtés) pour les agents d'arrière-plan, **suspendre**
(`setPackagesSuspended`, icône grisée) pour les apps visibles.

### Garde-fous (codés en dur, plus forts que le catalogue)

- **Liste de refus** des paquets (`PackageDenyList`) : `kgclient` et `sm.policy` (verrouillage jusqu'à
  réinitialisation), paquets OTA (`soagent`, `wssyncmldm`…), attestation (`rkpdapp`, `knox.attestation`),
  modules système (permissions, réseau, WebView, `ext.services`, `configupdater`), `diagmonagent` (boucle de
  relance), `securitylogagent`, Routines, clavier Samsung, lanceur, téléphone, SMS, alertes d'urgence,
  installeurs, Paramètres, SystemUI, `com.android.shell` (ADB), fournisseurs de contenu, Vigie ; plus, lus à
  l'exécution : lanceur(s), composeur, app SMS, claviers activés, installeurs, administrateurs actifs, VPN
  permanent. Vérifiée à l'aperçu **et** au moment d'appliquer.
- **Restrictions jamais posées** : `no_debugging_features` (couperait ADB), `no_share_location`,
  `no_factory_reset`, comptes, installation d'apps, réseau mobile, Wi-Fi, VPN… ; le signal de données USB
  n'est jamais coupé (aucun appel à `setUsbDataSignalingEnabled(false)`).
- Un élément déjà en place sans Vigie (paquet déjà masqué, restriction déjà posée, permission déjà refusée)
  n'est ni touché ni enregistré : « Tout rétablir » ne le défait donc pas.

### DNS privé imposé

1. Vigie vérifie d'abord, depuis le téléphone, que l'hôte répond : poignée de main TLS sur le port 853
   (AC système, vérification du nom) **et** une requête DNS dans la session. Sinon rien n'est changé
   (`private_dns_set` `ok=false`, « vérification préalable »).
2. `setGlobalPrivateDnsModeSpecifiedHost` (hors fil principal) ; codes `HOST_NOT_SERVING` /
   `FAILURE_SETTING` rapportés ; relecture du mode.
3. Verrou optionnel `disallow_config_private_dns`.
4. **Repli** (Réglages › Device Owner) : si le réseau n'est plus validé **et** que le contrôle DoT de l'hôte
   (par ses dernières adresses connues) échoue sans interruption pendant 15 min (5 à 240), le DNS repasse en
   mode automatique pour garder Internet ; `security.policy` sév. 2 (alerte Wazuh). Dès que l'hôte répond de
   nouveau, il est réimposé (réglable). Compromis : un attaquant qui bloque le port 853 obtient ce repli, mais
   jamais en silence ; désactiver le repli fait primer la protection (plus d'Internet tant que le serveur ne
   répond pas : « Tout rétablir » ou l'issue de secours ADB le défait).
5. Rétablir remet le mode d'avant (`off` par `setGlobalSetting(private_dns_mode)`, automatique ou hôte
   précédent).

Recherche Wi-Fi permanente, diagnostics Samsung et identifiant publicitaire Google n'ont pas de clé de
réglage dont l'effet soit établi (stockés hors des Paramètres depuis Android 11, ou propres à Samsung/GMS) :
non gérés, à couper à la main (Paramètres › Localisation › Services de localisation ; Paramètres › Google ›
Annonces). VPN permanent : choisir une app VPN installée (option « bloquer sans VPN » à n'utiliser qu'avec
un VPN fiable).

### Tout défaire

- **Tout rétablir** (écran Politique, confirmation) : défait tout ce que Vigie a appliqué, du plus récent au
  plus ancien ; un élément qui résiste reste listé avec son erreur (réessayer). Les journaux restent actifs.
- **Retirer le Device Owner** (confirmation + case « J'ai compris ») : tout rétablir, couper journaux réseau
  et sécurité, retirer la protection contre l'arrêt forcé, `device_owner_cleared`, puis
  `clearDeviceOwnerApp`. S'arrête avant le retrait si quelque chose n'a pas pu être rétabli (« Retirer quand
  même » possible). Fonctionne aussi avec un APK non testOnly. `agent.tamper` `device_owner_lost` suit
  (attendu).

### Issue de secours sans interface (ADB)

```bash
./scripts/rescue-revert.sh                  # « Tout rétablir »   (PowerShell : .\scripts\rescue-revert.ps1)
./scripts/rescue-revert.sh --remove-owner   # + retirer le Device Owner (-RemoveOwner)
```

Le script envoie une diffusion explicite à `…policy.rescue.RescueReceiver`. Ce récepteur exige que
l'expéditeur détienne `android.permission.FORCE_STOP_PACKAGES`, de niveau `signature|privileged` sans
drapeau `development` ni `appop` (vérifié dans le manifeste du framework android-37) : aucune app tierce ne
peut l'obtenir, même par `pm grant` ; seuls le shell ADB (qui la détient pour `am force-stop`) et le système
peuvent déclencher l'ordre. Le récepteur ne peut que **défaire**. Résultat rendu à `am broadcast` : 1 tout
rétabli, 2 partiel (détail), 3 Vigie n'est plus Device Owner (le script propose alors `pm unhide` /
`pm unsuspend` pour les paquets qu'elle avait désactivés), 4 délai dépassé (l'opération continue).
Dernier recours si l'app ne démarre plus du tout : `adb shell pm unhide <paquet>` pour chaque paquet de
l'écran (liste dans le catalogue), puis `remove-device-owner.sh` (APK testOnly).

### À vérifier sur le téléphone avant d'appliquer un profil

1. `dpm set-device-owner`, puis l'écran Politique : « Mode Device Owner : Oui », journaux actifs.
2. `./scripts/rescue-revert.sh` à vide (réponse « Tout est rétabli (reverted=0…) ») : l'issue de secours
   fonctionne **avant** d'en avoir besoin.
3. DNS privé seul (décocher le reste) : application, navigation, puis coupure du serveur pour voir le repli.
4. Un seul paquet à faible risque (ex. Astuces), « Rétablir », puis le profil équilibré ; redémarrer ; tester
   push, Play Store, banque, paiement ; « Tout rétablir » et comparer.
5. Seulement ensuite, le profil strict, élément par élément.

## Ce qui est vérifié, ce qui ne l'est pas

Vérifié dans l'environnement de développement (Linux, sans émulateur ni appareil) :
`./gradlew lint test assembleDebug assembleRelease` réussit ; 73 tests JVM (tampon Room sur SQLite JVM :
séquence après redémarrage, transaction interrompue, purge par sévérité/âge ; envoi contre MockWebServer :
tous les codes du contrat, gzip, lots, 1 Mio, Wi-Fi, reprise ; sérialisation exacte du §1 ; analyse des
fichiers `.vigie` et mTLS avec épinglage ; isolation des pannes des collecteurs) ; APK release signé (schéma v3, vérifié par `apksigner`)
et manifeste fusionné inspectés (aucun service d'écoute des notifications, d'accessibilité, SMS, journal
d'appels ni superposition).

**Non vérifié** (aucun appareil) : tout le comportement sur téléphone — activation Device Owner sur S25+,
auto-attribution des permissions, `setUserControlDisabledPackages`, démarrage au boot et survie du service
24 h, import réel dans l'Android Keystore et handshake TLS avec une clé Keystore (Conscrypt), réception des
diffusions, GPS et capteur de mouvement significatif, consommation batterie, rendu de l'interface,
désactivation de la CT par `network_security_config`, scripts ADB (relus, non exécutés ; les scripts
PowerShell n'ont pas été exécutés du tout). Robolectric n'a pas pu être utilisé (ses jars Android sont servis
par un miroir inaccessible depuis l'environnement de développement) : les classes Android sont remplacées par
des stubs dans les tests.
