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
