# Vigie Agent (Android)

Agent de télémétrie de sécurité installé par le propriétaire sur **son propre** téléphone (cible : Galaxy S25+,
Android 16/17, One UI 8/9, non rooté), promu **Device Owner** par ADB. Il collecte des événements, les garde
dans un tampon hors-ligne et les envoie par lots (HTTPS + certificat client) au collecteur Vigie enrôlé.

Principes (voir `../docs/ARCHITECTURE.md`) : notification permanente et icône visible, aucun envoi ailleurs que
vers l'adresse enrôlée, le serveur ne peut rien commander, aucune dépendance Google (ni Play Services, ni
Firebase, ni ML Kit), pas de contenu privé de tiers, chaque collecteur désactivable, tout réversible.

Développeurs (ajout de collecteurs, module Device Owner) : lire **`ARCHITECTURE-CODE.md`**.

## Contenu de cette version

« Testé » signifie ici : tests JVM dans l'environnement de développement. **Rien n'a été exécuté sur un
téléphone ni sur un émulateur** (voir la dernière section).

| Élément | État |
|---|---|
| Tampon Room (`seq` transactionnel, plafond 200 Mio / 30 j, purge « plus anciens de plus faible sévérité » + `agent.buffer_overflow`) ; purge par âge protégée contre un saut de l'horloge murale (`AgeHorizon`) | fait, testé (JVM) |
| Horodatage d'origine des événements relevés après coup (`app.foreground`, `net.dns`, `net.connect`, `security.log`) | fait, testé |
| Envoi : lots ≤ 500 événements et ≤ 1 Mio gzip, suppression après accusé, 400 (lot empoisonné : bissection) / 401 / 413 / 429 / 5xx, `Retry-After`, backoff avec gigue, « gros volumes en Wi-Fi seulement », reprise au retour du réseau | fait, testé (MockWebServer) ; **jamais exercé sur appareil ni contre un vrai serveur en 400** |
| Enrôlement `.vigie` : clé dans l'Android Keystore, jeton chiffré, mTLS, épinglage de l'AC serveur, test `GET /api/v1/ping`, désenrôlement | fait ; analyse et mTLS testés, Keystore Android **non testé** |
| Service de premier plan (`specialUse` + `location`), démarrage au boot et après mise à jour, redémarrage (sticky + maintenance 15 min), `agent.started/stopped/heartbeat/collector_error/config_changed` | fait, non testé sur appareil |
| 21 collecteurs : 18 sans privilège (`:collectors`) et 3 Device Owner (`:policy`), voir « Collecteurs » | faits ; logique et conformité au contrat testées, comportement réel non testé |
| Device Owner : récepteur d'administration, auto-attribution des permissions et protection contre l'arrêt forcé (avec `security.policy`), `agent.tamper`, retrait volontaire sans fausse alerte | fait ; logique testée, non testé sur appareil |
| Politique Device Owner : profils, DNS privé imposé et repli, paquets, permissions, restrictions, réglages, VPN permanent, « Tout rétablir », retrait du Device Owner, issue de secours ADB | fait ; moteur testé contre une passerelle factice, non testé sur appareil |
| Interface Material 3 (Accueil, Collecteurs avec réglages par collecteur, Journal local, Réglages, Enrôlement, Politique) | faite, non testée sur appareil |

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
| `-Pvigie.testOnly=true\|false` | `true` | `android:testOnly`. Impose `adb install -t` (les scripts le font). `true` garde un dernier recours si l'app ne démarre plus : `adb shell dpm remove-active-admin` (voir « Retirer le Device Owner »). `false` : seul Vigie (écran Politique ou issue de secours ADB) pourra retirer le rôle, ou une réinitialisation. |
| `-Pvigie.versionCode=N` | `1` | À **augmenter** à chaque mise à jour. |
| `-Pvigie.versionName=x.y.z` | `0.1.0` | Version affichée et envoyée (`agent_version`). |

## Installer et activer

Tous les scripts sont dans `android/scripts/`, en double : `*.sh` (Linux/macOS) et `*.ps1` (Windows
PowerShell). Les `.ps1` ne sont pas signés : Windows les refuse avec sa politique d'exécution par défaut.
Lancez-les ainsi, sans rien changer à la configuration de la machine (la dérogation ne vaut que pour ce
processus) : `powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\install-apk.ps1 [options]`.
Un chemin de fichier passé à un script (`install-apk`, `push-enrollment`) est relatif au dossier d'où vous
le lancez. Ils exigent `adb` (Android SDK Platform-Tools) dans le `PATH` et un téléphone en débogage USB.
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
4. **Ouvrir Vigie** : en Device Owner, l'app s'accorde ses permissions d'exécution (localisation,
   notifications, Bluetooth, téléphone…) et active la protection contre l'arrêt forcé (chaque action émet
   `security.policy`). Chaque permission n'est auto-accordée qu'**une fois** par activation du Device Owner :
   si vous en retirez une ensuite dans les Paramètres, Vigie ne la reprend pas d'elle-même (le collecteur
   passe « indisponible », `agent.tamper` `permission_revoked` est émis, l'onglet Collecteurs propose de la
   redonner). Sans Device Owner (mode dégradé), accorder les permissions depuis l'onglet
   Collecteurs. Dans les deux cas, `./scripts/grant-adb-permissions.sh` accorde aussi celles qui ne
   s'obtiennent que par ADB : accès à l'utilisation (`PACKAGE_USAGE_STATS` + app-op : `net_usage`,
   `foreground`), `WRITE_SECURE_SETTINGS` (réglage anti-pistage de la politique), `DUMP` (attribution
   expérimentale caméra/micro, désactivée par défaut). En mode dégradé il accorde aussi les permissions
   d'exécution (`BLUETOOTH_SCAN`, `BLUETOOTH_CONNECT`, `READ_PHONE_STATE`, localisation…).
5. **Batterie** : `./scripts/battery-exemptions.sh`, puis à la main sur Samsung : Paramètres › Batterie ›
   Limites d'utilisation en arrière-plan › Applications jamais en veille › Vigie.
6. **Réactiver** le Blocage automatique si souhaité (son interaction avec un Device Owner tiers n'est pas
   vérifiée, voir la recherche plateforme).

## Enrôler

1. Sur le serveur : `sudo ./enroll.sh s25` depuis `infra/` (installation Docker Compose, produit
   `./s25.vigie`) ; avec le collecteur lancé seul : `vigie-collector enroll --name s25 --out s25.vigie`.
2. Copier par câble : `./scripts/push-enrollment.sh chemin/vers/s25.vigie` (→ `Téléchargements` ; le chemin
   est relatif au dossier d'où vous lancez le script).
3. Dans l'app : Réglages › Enrôlement › « Importer un fichier .vigie », vérifier le résumé, « Enrôler ».
   La clé privée est importée dans l'Android Keystore (non exportable) puis oubliée ; le jeton est chiffré
   par une clé AES du Keystore ; un test `GET /api/v1/ping` est lancé ; l'app tente de supprimer le fichier.
4. Supprimer toutes les copies du fichier : `./scripts/push-enrollment.sh --remove s25.vigie` et sur le PC.

Si `server_ca_pem` est présent, seule cette AC est acceptée pour le serveur. Sinon, seules les AC du système
(jamais celles ajoutées par l'utilisateur). Les redirections HTTP sont refusées. Avant l'enrôlement, les
événements restent sur le téléphone (dans la limite du tampon). « Désenrôler » efface clé, jeton et
événements en attente ; la collecte locale continue.

**Renouveler sans désenrôler** (le certificat client expire au bout de 2 ans ; l'écran Enrôlement affiche
la date et la signale 30 jours avant) : produire un nouveau fichier `.vigie` sur le serveur, puis
Enrôlement › « Importer un nouveau fichier .vigie ». Avant de valider, l'écran dit ce que deviennent les
événements en attente :

| Nouveau fichier | Tampon |
|---|---|
| même adresse d'ingestion, même `device_id` (renouvellement) | conservé |
| même adresse, autre `device_id` | conservé, envoyé sous le nouvel identifiant (`agent.config_changed` `enrollment.device_id` le signale) |
| autre adresse d'ingestion | **effacé** : rien de ce qui a été collecté pour un serveur n'est envoyé à un autre |

Aujourd'hui `enroll` crée toujours un **nouvel** appareil (nouvel identifiant) : un renouvellement tombe donc
dans le deuxième cas, et l'historique côté serveur est réparti sur deux identifiants (révoquer l'ancien
ensuite : `sudo ./enroll.sh --revoke dev_…`). Une commande de renouvellement à identifiant constant
manque au collecteur. Le jeton (512 caractères ASCII visibles au plus) et l'identifiant sont validés à
l'import.

## Mettre à jour

```bash
./gradlew assembleRelease -Pvigie.versionCode=2 -Pvigie.versionName=0.2.0
./scripts/install-apk.sh
```

Même clé de signature obligatoire, `versionCode` strictement croissant. L'agent redémarre seul après la mise
à jour (`MY_PACKAGE_REPLACED`). Les données (tampon, enrôlement, réglages) sont conservées.

## Retirer le Device Owner et désinstaller

**Chemin recommandé** : dans l'app, écran **Politique › Retirer le Device Owner** (confirmation). Vigie défait
toute sa politique, coupe les journaux réseau et sécurité, retire la protection contre l'arrêt forcé, émet
`security.policy` `device_owner_cleared`, puis abandonne le rôle (`clearDeviceOwnerApp`). Le retrait étant
annoncé, il n'est **pas** signalé comme `agent.tamper`. Fonctionne avec tout APK, testOnly ou non. On peut
ensuite désinstaller Vigie normalement et réactiver la sauvegarde Android dans les Paramètres.

Replis, du plus au moins recommandé :

1. **Sans l'interface, par ADB** : `./scripts/remove-device-owner.sh [--uninstall]` (`-Uninstall` en
   PowerShell). Il envoie à Vigie le même ordre que l'écran, par l'issue de secours (voir « Issue de secours
   sans interface »), puis vérifie que le rôle a disparu. `rescue-revert.sh --remove-owner` y renvoie.
   Si un élément ne peut pas être défait, Vigie **garde le rôle** (elle seule peut réessayer) et le script
   demande s'il faut forcer le retrait.
2. **Si Vigie ne répond plus** (app qui ne démarre pas) et que l'APK est **testOnly** : le même script
   propose alors `adb shell dpm remove-active-admin`. Vigie ne défait rien elle-même dans ce cas. D'après le
   code AOSP (branche principale), Android lève lui-même les politiques de l'administrateur retiré, paquets
   masqués compris ; le script vérifie l'état réel de chaque paquet que Vigie avait masqué ou suspendu
   (`dumpsys package`) et ne tente `pm unhide` / `pm unsuspend` que pour ceux qui le sont encore. Ces deux
   commandes peuvent être refusées au shell ADB (`MANAGE_USERS` n'est pas dans le manifeste AOSP du shell ;
   un paquet suspendu par un administrateur ne l'est pas par le shell) : le recours est alors de redonner
   le rôle à Vigie (`enable-device-owner`) et de relancer `rescue-revert`, l'état appliqué étant conservé.
   Le retrait est signalé par `agent.tamper` (`admin_disabled`, `device_owner_lost`), ce qui est attendu.
3. APK non testOnly et app inutilisable : mettre à jour l'app (même clé de signature) pour la réparer, sinon
   réinitialisation du téléphone.

## Fonctionnement (résumé)

- **Service de premier plan** permanent, types `specialUse` (+ `location` si la permission est accordée) ;
  notification « Vigie collecte… » avec le nombre d'événements en attente et l'heure du dernier envoi.
- **WorkManager** : envoi périodique (15 min par défaut) et au retour du réseau, collectes périodiques
  (heartbeat 15 min, inventaire quotidien), maintenance toutes les 15 min (âge du tampon, intégrité,
  redémarrage du service si besoin).
- **Envoi déclenché** aussi par tout événement `sev >= 2` et par un tampon de plus de 500 événements.
- **Lot refusé en `400`** (contrat §3 : enveloppe illisible, déterministe) : au lieu de bloquer la file
  jusqu'à la purge par âge, l'agent coupe le lot en deux et renvoie chaque moitié (environ 2·log2(500) ≈ 18
  requêtes par événement fautif, au plus 60 refus `400`/`413` par passage, puis backoff `PROTOCOL` normal
  de 5 min à 6 h). Un événement qui reçoit encore `400` **seul** est supprimé, compté dans `dropped_total`
  et tracé par un `agent.collector_error` (`collector` = `upload`, type et id de l'événement, jamais son
  contenu ; 5 au plus par passage). Garde-fou : avant toute suppression, l'agent envoie un lot **sans
  événement** (même enveloppe) ; s'il reçoit aussi `400`, la faute est dans l'enveloppe ou le serveur, rien
  n'est supprimé (`last_error` = `http_400_envelope`, backoff). Un `5xx`, `429`, `401`/`403` ne coupe jamais
  un lot. Un arrêt brutal en cours de bissection ne perd rien : seul le tampon est durable, la bissection
  reprend sur ce qui reste.
- **Saut de l'horloge murale et purge par âge** : la purge utilise un « horizon » (`AgeHorizon`) qui avance au
  plus deux fois plus vite que l'horloge monotone (`elapsedRealtime`) et jamais au-delà de l'horloge murale.
  Un saut en avant de plus de 30 jours ne vide donc plus le tampon (une horloge qui reste fausse vieillit les
  événements au plus deux fois plus vite) ; un saut en arrière ne fait pas purger les événements écrits
  ensuite. Après un redémarrage, l'horizon ne peut avancer que de 2 jours au-delà de sa dernière valeur.
- **Écritures groupées** : jusqu'à 3 s en mémoire avant une transaction unique (immédiat si `sev >= 2`). Un
  arrêt brutal peut perdre ces quelques secondes, jamais créer de trou ni de doublon de `seq`.
- **Direct Boot** non utilisé : rien n'est collecté entre un redémarrage et le premier déverrouillage (le
  tampon et l'enrôlement sont dans le stockage chiffré par les identifiants). `device.boot` est émis après
  le déverrouillage.
- **Certificate Transparency** (imposée par défaut avec `targetSdk 37`) est désactivée dans
  `network_security_config.xml` : une AC serveur privée n'a pas de SCT. L'app ne contacte que l'hôte enrôlé
  et, en mode AC privée, l'épinglage est plus strict que la CT.
- **`agent.tamper`** : demande ou désactivation de l'administrateur, permission retirée, arrêt forcé détecté
  (`ApplicationExitInfo`), perte du rôle Device Owner. Un retrait volontaire par l'app (écran Politique ou
  issue de secours ADB) est annoncé au préalable : il produit `security.policy` `device_owner_cleared` et
  aucun `agent.tamper`.
- **Horodatage** : `ts` est l'heure de l'événement. Pour les événements que le système livre après coup
  (`app.foreground`, `net.dns`, `net.connect`, `security.log`), c'est l'heure d'origine donnée par le système
  (pour un regroupement, la première occurrence ; `count` et `last_event_ts` dans `data`), et `elapsed_ms`
  est estimé pour cet instant (0 si l'événement précède le démarrage en cours). `seq` reste l'ordre
  d'émission : `ts` n'est donc pas forcément croissant avec `seq`.

## Collecteurs

L'onglet Collecteurs liste les 21 collecteurs (18 de `:collectors` puis les 3 de `:policy`) : interrupteur,
état (actif, désactivé, activé mais agent arrêté, indisponible avec la raison), permissions manquantes,
types émis et **réglages propres** au collecteur. Y sont signalés « Désactivé par défaut » (`wifi_scan`),
« Device Owner requis » (journaux) et « Réglage expérimental » (attribution caméra/micro). Permissions « ADB » :
`./scripts/grant-adb-permissions.sh`. Noms de types, de champs et types des valeurs : `docs/contrat/contrat.md`
§2 et ses précisions, vérifiés par les tests JVM (référence unique `Contract` du banc de test partagé).

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
- **`app.foreground`** : `ts` est l'heure de l'événement d'usage donnée par le système, pas celle du relevé
  (qui peut avoir jusqu'à 60 s de retard).
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

**N'appliquer qu'une partie** : « Tout décocher » (carte Profil) éteint tous les interrupteurs, DNS privé,
verrou et sauvegarde compris ; cocher ensuite seulement ce qu'on veut essayer (par exemple le DNS privé
seul), « Aperçu », « Appliquer ». Chaque section (applications, permissions, restrictions) a aussi « Tout
décocher ici » et « Cocher les choix par défaut ». Ce qui est déjà appliqué et n'est plus coché est rétabli
à l'application suivante (l'aperçu le montre).

### Journaux et posture (collecteurs, onglet Collecteurs)

| Collecteur (id) | Émet | Remarques |
|---|---|---|
| Journal de sécurité (`security_log`) | `security.log` | lots livrés par le système (≤ 2 h) ; `fields` selon la table du contrat (`argN` sinon) ; `app_process_start` agrégé par heure (désactivable) ; connexions Wi-Fi/Bluetooth désactivables ; journaux d'avant redémarrage lus une fois par démarrage si l'appareil les fournit (`pre_reboot: true`) |
| Journal réseau (`network_log`) | `net.dns`, `net.connect` | lots ≤ 1200 entrées (≤ 1 h 30) ; paquet et uid (uid partagés : `android.uid.system`…) ; agrégation des requêtes identiques par fenêtre (10 min, réglable : `count`, `last_event_ts`) ; émission par paquets de 100 ; lot notifié pendant l'arrêt de l'agent récupéré au démarrage suivant ; lots perdus signalés en `agent.collector_error` |
| Posture (`posture`) | `security.posture`, `security.posture_change`, `security.ca_cert`, `security.keyguard` | au démarrage, chaque jour et à chaque changement (observateurs de réglages, magasin de certificats, Device Owner, changement de code) ; un champ illisible est omis ; fonctionne partiellement sans Device Owner |

Ces trois collecteurs sont actifs par défaut (comme tout collecteur). Couper `network_log` ou `security_log`
dans l'onglet Collecteurs coupe aussi la journalisation du système (`security.policy` `network_logging` /
`security_logging`). Le journal réseau fait afficher par Android la mention « réseau surveillé ». Le `ts` d'un
`net.dns`, `net.connect` ou `security.log` est l'heure d'origine de l'entrée (première occurrence s'il y a
regroupement), pas l'heure de récupération.

### Profils

| | Équilibré (par défaut) | Strict (= équilibré + …) |
|---|---|---|
| Paquets | 35 (28 cochés) : Customization Service, Knox Analytics, DSMS, Device Quality Agent, diagnostics réseau et journaux Samsung, Device ID Service (OAID), AdServices / On-Device Personalization / Federated Compute de Google, Market Feedback, Partner Setup, apps Meta préinstallées… ; optionnels : Bixby, Samsung Free, Android System Intelligence, Gemini | 22 (8 cochés) : compte Samsung, Samsung Cloud, Experience Service, Samsung Push, Update Center, OMC Agent, KLMS, Appli Google ; optionnels : Find My Mobile, Samsung Wallet/Pay/Pass, Galaxy Store, Entretien de l'appareil, Services Google Play, GSF, Play Store |
| Permissions refusées | localisation de l'Appli Google (+ optionnel : Samsung Internet, Météo) | micro/caméra/contacts de l'Appli Google, Bixby ; optionnel : localisation d'arrière-plan et appareils à proximité des Services Google Play, capteurs de Samsung Health |
| Restrictions | pas d'ajout d'utilisateur, pas de 2G, pas de sources inconnues, pas de capture ni de suggestions de contenu | + pas d'ajout de certificats, pas de mode sans échec, pas de contenu envoyé à l'assistant, UWB, Thread, partage Bluetooth ; optionnel : eSIM, transfert USB, NFC |
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
- **Restrictions** (`RestrictionGuard`) : seules les clés d'une **liste vérifiée** peuvent être posées (2G,
  sources inconnues, ajout d'utilisateur, capture de contenu, certificats, mode sans échec, eSIM, UWB,
  Thread, NFC, partage Bluetooth, transfert de fichiers USB, saisie automatique). Toute autre clé est
  refusée, même si un catalogue la liste ; sont en outre nommément interdites `no_debugging_features`
  (couperait ADB), `no_share_location`, `no_factory_reset`, comptes, installation d'apps, réseau mobile,
  Wi-Fi, VPN… Le signal de données USB n'est jamais coupé (aucun appel à
  `setUsbDataSignalingEnabled(false)`).
- **Réglages** (`SettingGuard`) : `WRITE_SECURE_SETTINGS` permet d'écrire n'importe quelle clé
  (`adb_enabled`, `user_setup_complete`, `private_dns_mode`…) ; seules `global:ble_scan_always_enabled` et
  `global:wifi_scan_always_enabled` sont admises.
- Un élément appliqué qu'une version plus récente des garde-fous refuse (ou un paquet devenu lanceur,
  clavier…) est **défait** à l'application suivante.
- Un élément déjà en place sans Vigie (paquet déjà masqué, restriction déjà posée, permission déjà refusée)
  n'est ni touché ni enregistré : « Tout rétablir » ne le défait donc pas.

### DNS privé imposé

1. Vigie vérifie d'abord, depuis le téléphone, que l'hôte répond : poignée de main TLS sur le port 853
   (AC système, vérification du nom) **et** une requête DNS dans la session. Sinon rien n'est changé
   (`private_dns_set` `ok=false`, « vérification préalable »).
2. `setGlobalPrivateDnsModeSpecifiedHost` (hors fil principal) ; codes `HOST_NOT_SERVING` /
   `FAILURE_SETTING` rapportés ; relecture du mode.
3. Verrou optionnel `disallow_config_private_dns`.
   Le verrou est **éteint par défaut** : imposer d'abord le DNS sans verrou, vérifier quelques jours
   qu'Internet fonctionne partout (Wi-Fi, mobile, portails captifs), puis verrouiller.
4. **Repli** (Réglages › Device Owner) : si le réseau n'est plus validé **et** que le contrôle DoT de l'hôte
   (par ses dernières adresses connues) échoue sans interruption pendant 15 min (5 à 240), le DNS repasse en
   mode automatique pour garder Internet ; `security.policy` sév. 2 (alerte Wazuh). Dès que l'hôte répond de
   nouveau, il est réimposé (réglable). Compromis : un attaquant qui bloque le port 853 obtient ce repli, mais
   jamais en silence ; désactiver le repli fait primer la protection (plus d'Internet tant que le serveur ne
   répond pas : « Tout rétablir » ou l'issue de secours ADB le défait).
5. Rétablir remet le mode d'avant (`off` par `setGlobalSetting(private_dns_mode)`, automatique ou hôte
   précédent).
6. Si un utilisateur non affilié existe (invité, utilisateur secondaire, mode maintenance Samsung), Android
   refuse les API DNS dédiées (`checkAllUsersAreAffiliatedWithDevice`) : le repli et le retour au mode
   automatique passent alors par `setGlobalSetting(private_dns_mode)`, qui n'a pas cette condition.

Le repli ne tourne que si le processus de Vigie vit (service de premier plan, ou passage de maintenance
toutes les 15 min, sans contrainte réseau). Pendant le délai de repli, le téléphone est **sans Internet**.

Recherche Wi-Fi permanente, diagnostics Samsung et identifiant publicitaire Google n'ont pas de clé de
réglage dont l'effet soit établi (stockés hors des Paramètres depuis Android 11, ou propres à Samsung/GMS) :
non gérés, à couper à la main (Paramètres › Localisation › Services de localisation ; Paramètres › Google ›
Annonces). VPN permanent : choisir une app VPN installée (option « bloquer sans VPN » à n'utiliser qu'avec
un VPN fiable).

### Tout défaire

- **Tout rétablir** (écran Politique, confirmation) : défait tout ce que Vigie a appliqué, du plus récent au
  plus ancien ; un élément qui résiste reste listé avec son erreur (réessayer). Les journaux restent actifs.
  Chaque élément est traité isolément : un échec (y compris l'impossibilité d'écrire l'état, stockage
  plein) n'arrête pas les suivants. Une permission refusée juste avant un plantage, donc jamais confirmée
  dans l'état, est rétablie aussi.
- **État illisible** : l'état appliqué est relu enregistrement par enregistrement (un enregistrement
  inconnu d'une autre version ne fait pas perdre les autres). S'il a été illisible, même en partie, « Tout
  rétablir » ajoute un **balayage du catalogue** : paquets du catalogue masqués ou suspendus réaffichés,
  restrictions du catalogue et verrou DNS levés, permissions du catalogue refusées rendues à l'utilisateur,
  DNS privé sorti de l'hôte enrôlé. Rien hors du catalogue n'est touché ; un réglage dont la valeur
  d'origine est inconnue est signalé, à rétablir à la main.
- **Retirer le Device Owner** (confirmation + case « J'ai compris ») : tout rétablir, couper journaux réseau
  et sécurité, retirer la protection contre l'arrêt forcé, `device_owner_cleared`, puis
  `clearDeviceOwnerApp`. S'arrête avant le retrait si quelque chose n'a pas pu être rétabli (« Retirer quand
  même » possible). Fonctionne aussi avec un APK non testOnly. Le retrait est annoncé à l'agent : pas
  d'`agent.tamper` (voir « Retirer le Device Owner et désinstaller »).

### Issue de secours sans interface (ADB)

```bash
./scripts/rescue-revert.sh          # « Tout rétablir », Vigie reste Device Owner (PowerShell : .\scripts\rescue-revert.ps1)
./scripts/rescue-revert.sh --sweep  # + balayage du catalogue, si l'état de Vigie est douteux (PowerShell : -Sweep)
./scripts/remove-device-owner.sh    # + retirer le Device Owner (= rescue-revert.sh --remove-owner)
```

Le script envoie une diffusion explicite à `…policy.rescue.RescueReceiver`. Ce récepteur exige que
l'expéditeur détienne `android.permission.FORCE_STOP_PACKAGES`, de niveau `signature|privileged` sans
drapeau `development` ni `appop` (vérifié dans le manifeste du framework android-37) : aucune app tierce ne
peut l'obtenir, même par `pm grant`. La détiennent : le shell ADB (`packages/Shell/AndroidManifest.xml`
d'AOSP, pour `am force-stop`), le système, et les apps signées par la clé de la plateforme ou privilégiées
et autorisées par le constructeur (donc des apps Samsung préinstallées, jamais une app installée par
l'utilisateur). Le récepteur ne peut que **défaire**. Résultat rendu à `am broadcast` : 1 tout rétabli,
2 partiel (détail), 3 Vigie n'est plus Device Owner (le script vérifie alors l'état des paquets qu'elle
avait désactivés), 4 délai dépassé (l'opération continue).
Codes de sortie de `rescue-revert` : ceux ci-dessus, et 5 si Vigie ne répond pas. Avec `remove_owner`, le rôle
n'est abandonné que si tout a été défait (`force` pour passer outre, proposé par le script).

Limites : l'app n'est pas « direct boot aware » (son état est en stockage chiffré par l'identifiant) : après
un redémarrage, l'issue de secours ne répond qu'**après le premier déverrouillage**. Elle a besoin que le
processus de l'app démarre : `VigieApplication` tolère pour cela un agent qui ne s'initialise pas (l'écran
affiche l'erreur, l'issue de secours reste utilisable). Si l'app ne démarre plus du tout,
`remove-device-owner.sh` propose le repli `dpm remove-active-admin` (APK testOnly uniquement).

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

- `./gradlew lint test assembleDebug assembleRelease` réussit (lint : 0 erreur, avertissements de style
  `UseKtx`/versions seulement).
- 180 tests JVM : `:core` 73 (tampon Room sur SQLite JVM : séquence après redémarrage, transaction
  interrompue, purge par sévérité/âge, horodatage d'origine non monotone ; envoi contre MockWebServer : tous
  les codes du contrat, gzip, lots, 1 Mio, Wi-Fi, reprise ; sérialisation exacte du §1 ; fichiers `.vigie` et
  mTLS avec épinglage ; isolation des pannes des collecteurs ; annonce du retrait du Device Owner ; banc de
  test), `:collectors` 57 (logique de chaque collecteur, conformité au contrat), `:policy` 46 (traduction du
  journal de sécurité, journaux réseau, posture, moteur de politique contre une passerelle factice,
  catalogue, DNS), `:app` 4 (conformité au contrat de bout en bout des 21 collecteurs, y compris
  `agent.heartbeat.collectors`).
- APK release : signé en schéma v3 (`apksigner verify`) ; après R8, classes du manifeste, base Room
  (`OutboxDatabase_Impl`), workers et sérialiseurs générés de toutes les classes `@Serializable` présents
  sous leur nom (`apkanalyzer dex packages`) ; catalogue `raw/policy_catalog` et `xml/device_admin` conservés
  par la réduction des ressources (`aapt2 dump resources`). Le code R8 lui-même n'a pas été exécuté.
- Manifeste fusionné (`aapt2 dump permissions`) : aucune permission ni service d'écoute des notifications,
  d'accessibilité, de SMS, de journal d'appels ou de superposition ; chaque permission déclarée est utilisée
  par un module (les trois accordables seulement par ADB : `PACKAGE_USAGE_STATS`, `WRITE_SECURE_SETTINGS`,
  `DUMP`).
- Scripts bash : syntaxe vérifiée (`bash -n`), relus contre le code (paquet, composants, action de l'issue de
  secours, option `-t`).

**Non vérifié** (aucun appareil) : tout le comportement sur téléphone — activation Device Owner sur S25+,
auto-attribution des permissions, `setUserControlDisabledPackages`, retrait du Device Owner et absence de
fausse alerte, démarrage au boot et survie du service 24 h, import réel dans l'Android Keystore et handshake
TLS avec une clé Keystore (Conscrypt), réception des diffusions, journaux réseau et sécurité réels, GPS et
capteur de mouvement significatif, consommation batterie, rendu de l'interface, désactivation de la CT par
`network_security_config`, politique (profils, DNS privé, repli), issue de secours ADB. Les scripts bash de
secours, d'installation et de copie ont été exécutés contre un `adb` factice (jamais contre un téléphone) ;
les scripts PowerShell ont été relus ligne à ligne contre les `.sh` mais ni exécutés ni analysés par
PowerShell (absent de l'environnement). Robolectric n'a pas pu être utilisé (ses jars Android sont servis par un miroir
inaccessible depuis l'environnement de développement) : les classes Android sont remplacées par des stubs
dans les tests ; les types produits uniquement depuis un rappel Android (écran, batterie, localisation…) sont
vérifiés par relecture, pas par test.
