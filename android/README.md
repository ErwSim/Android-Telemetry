# Vigie Agent (Android)

Agent de télémétrie de sécurité installé par le propriétaire sur **son propre** téléphone (cible : Galaxy S25+,
Android 16/17, One UI 8/9, non rooté), promu **Device Owner** par ADB. Il collecte des événements, les garde
dans un tampon hors-ligne et les envoie par lots (HTTPS + certificat client) au collecteur Vigie enrôlé.

Principes (voir `../docs/ARCHITECTURE.md`) : notification permanente et icône visible, aucun envoi ailleurs que
vers l'adresse enrôlée, le serveur ne peut transmettre que des commandes d'une liste fermée (sonner, vibrer,
localiser, verrouiller, effacer ; les sensibles signées par un code qu'il ne connaît pas, canal coupé par
défaut), aucune dépendance Google (ni Play Services, ni Firebase, ni ML Kit ; les modes de localisation
« réseau » et « fusionné » passent par les Services Google Play sur choix explicite), pas de contenu privé de
tiers, chaque collecteur désactivable, tout réversible.

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
| 25 collecteurs : 22 sans privilège (`:collectors`, dont `notifications` qui dépend de l'APK compagnon, et `app_risk`, `app_role`, `app_ops` du contrat §11.2) et 3 Device Owner (`:policy`), voir « Collecteurs » | faits ; logique et conformité au contrat testées, comportement réel non testé |
| Commandes à distance (contrat §8) : vérification complète (signature HMAC, anti-rejeu, expiration, verrouillage), canal SSE ou interrogation, sonner / vibrer / localiser / verrouiller + message / effacer, écran « Commandes à distance » | fait ; vérification, canal (MockWebServer) et garde-fous de l'effacement testés (JVM) ; **jamais exécuté sur appareil**, consommation **non mesurée** |
| Modes de localisation (contrat §10) : GPS seul (défaut), GPS + réseau, fusionné, avec repli | fait ; logique testée, fournisseurs réels non testés |
| Device Owner : récepteur d'administration, auto-attribution des permissions et protection contre l'arrêt forcé (avec `security.policy`), `agent.tamper`, retrait volontaire sans fausse alerte | fait ; logique testée, non testé sur appareil |
| Politique Device Owner : profils, DNS privé imposé et repli, paquets, permissions, restrictions, réglages, VPN permanent, « Tout rétablir », retrait du Device Owner, issue de secours ADB | fait ; moteur testé contre une passerelle factice, non testé sur appareil |
| Gardes de capacités (contrat §11.1) : SMS, appels, accessibilité, claviers, quarantaine des nouvelles applications, listes d'exceptions éditables (réglage « liste de paquets »), écran « Applications en quarantaine », notifications | fait ; testé contre la passerelle factice (dont plantage, état illisible, « Tout rétablir » après les 32 combinaisons) ; **jamais exécuté sur appareil** |
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

Pour renouveler le certificat d'un appareil (valable 2 ans) sans scinder son historique, le serveur émet un
fichier pour le **même** identifiant : `sudo ./enroll.sh --renew <nom|dev_…>` depuis `infra/` (ou
`vigie-collector renew <device_id> --out <fichier.vigie>`). L'ancien jeton et l'ancien certificat restent
acceptés jusqu'au premier envoi avec les nouveaux. `enroll` sans `--renew` crée un nouvel appareil (deuxième
cas du tableau). Le jeton (512 caractères ASCII visibles au plus) et l'identifiant sont validés à l'import.

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

L'onglet Collecteurs liste les 25 collecteurs (22 de `:collectors` puis les 3 de `:policy`) : interrupteur,
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
| Localisation (`location`) | `location.fix`, `location.provider` | localisation précise (+ arrière-plan) | GPS adaptatif + passif ; modes « GPS + réseau » et « fusionné » en option (voir ci-dessous) |
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
| Notifications (`notifications`) | `app.notification` (titre et texte seulement sur option) | APK compagnon « Vigie Notifications » installé, même clé, accès aux notifications (voir « Notifications ») | relayé par le compagnon ; ≤ 20 / app / 10 min, quelques dizaines par jour |
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
- **Modes de localisation** (réglage « Mode de localisation » du collecteur, contrat §10) :

  | Mode | Fournisseurs demandés | Ce qui part chez Google | Gain attendu |
  |---|---|---|---|
  | `gps` (défaut) | `GPS_PROVIDER` (+ passif si activé) | rien par Vigie (l'assistance GNSS XTRA/SUPL est réglée par le système) | — ; souvent aucune position en intérieur |
  | `gps_network` | GPS + `NETWORK_PROVIDER` | réseaux Wi-Fi et antennes alentour (fournisseur réseau = Services Google Play, actif seulement si « Précision de la localisation Google » est activée) | position approximative en intérieur en quelques secondes ; un peu plus de consommation |
  | `fused` | `FUSED_PROVIDER` seul | idem (fournisseur fusionné des Services Google Play) | position rapide, souvent précise en intérieur, moins de temps GNSS |

  `location.fix.provider` est le fournisseur réel de chaque position (`gps`, `network`, `fused`, `passive`). Un
  fournisseur absent ou désactivé est ignoré ; s'il ne reste rien, repli sur le GPS seul (réévalué à chaque
  changement de fournisseur et toutes les minutes tant qu'on est en repli). La cadence adaptative (mouvement /
  arrêt, mouvement significatif) et la détection `mock` s'appliquent dans les trois modes. En `gps_network`,
  une position réseau arrivée moins d'un demi-intervalle après une position GPS n'est pas émise.
  `location.provider` est émis pour le GPS et les fournisseurs du mode choisi.
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

## Profil de risque et usage

Trois collecteurs de `:collectors` répondent à une question : **quelle application est capable de, ou est en
train de, faire ce que faisait le logiciel malveillant de l'ancien téléphone** (2 000 SMS d'hameçonnage par jour
que l'appli SMS ne montrait pas), quel que soit le vecteur. Spécification : `docs/contrat/contrat.md` §11.2.
Rien n'a tourné sur un appareil : tout ce qui suit est testé sur la JVM (logique, banc partagé), pas sur le Galaxy S25+.

| Collecteur (id) | Émet | Capacité requise | Coût |
|---|---|---|---|
| Profil de risque (`app_risk`) | `app.risk` | — (QUERY_ALL_PACKAGES) | à chaque installation et mise à jour, puis quotidien (6 requêtes de composants + 1 parcours des paquets) ; une centaine d'événements au premier passage, ensuite seulement les changements |
| Apps par défaut (`app_role`) | `app.role` | — | au changement (paquets, réglages, extinction d'écran ≤ 1/15 min) + WorkManager 1 h ; quelques appels système |
| Usage des opérations (`app_ops`, **expérimental, désactivé par défaut**) | `app.ops` | `DUMP` **et** `PACKAGE_USAGE_STATS` accordées par ADB | WorkManager 1 h : 10 lectures bornées (8 s, 3 Mo chacune), 300 lignes au plus |

### `app.risk` : la note, ses raisons, sa pondération

La note est la fonction **pure** `RiskScorer.score(AppFacts)` (`collectors/…/risk/RiskModel.kt`) : elle ne lit que ce
que `PackageManager` expose (installateur, permissions demandées et accordées, composants déclarés, icône de
lanceur, `targetSdk`, drapeau débogable), jamais le contenu d'une app. Les points s'additionnent, la note est
bornée à 100. **Niveaux** : `low` 0 à 29, `medium` 30 à 59, `high` 60 à 100. Les apps du système (`FLAG_SYSTEM`) et
Vigie sont notées mais **plafonnées à 29** (`low`) ; leurs raisons restent listées, sauf celles qui n'ont pas de sens
pour une app préinstallée (installateur, icône, version cible, débogage). Chaque code a un libellé et une
explication en français (`collectors/src/main/res/values/strings_risk.xml`, clés `risk_reason_<code>` et
`risk_reason_<code>_desc`, accessibles par `RiskReason.fromCode(code)?.labelRes`). Un test vérifie que ce tableau
et le code disent la même chose.

| Code | Points | Condition (sur ce que le système expose) |
|---|---|---|
| `sideloaded` | 15 | app utilisateur dont l'installateur est absent, un installateur de paquets, un gestionnaire de fichiers ou le shell ADB (et non Play, Galaxy Store, F-Droid) |
| `unknown_installer` | 12 | app utilisateur installée par une autre app qui n'est pas une boutique (exclut `sideloaded`) |
| `no_launcher_icon` | 12 | app utilisateur sans activité `MAIN`/`LAUNCHER` activée (une icône désactivée compte comme absente) |
| `sms_send` | 20 | `SEND_SMS` accordée |
| `sms_read` | 12 | `READ_SMS`, `RECEIVE_SMS`, `RECEIVE_MMS` ou `RECEIVE_WAP_PUSH` accordée |
| `calls` | 10 | `CALL_PHONE`, `READ_CALL_LOG`, `WRITE_CALL_LOG`, `ANSWER_PHONE_CALLS` ou `PROCESS_OUTGOING_CALLS` accordée |
| `accessibility_service` | 25 | déclare un service d'accessibilité (protégé par `BIND_ACCESSIBILITY_SERVICE`), activé ou non |
| `notification_listener` | 15 | déclare un écouteur de notifications (`BIND_NOTIFICATION_LISTENER_SERVICE`) |
| `device_admin` | 15 | déclare un récepteur d'administration (`BIND_DEVICE_ADMIN`) |
| `overlay` | 12 | demande `SYSTEM_ALERT_WINDOW` (la demande compte : l'état « accordé » des accès spéciaux n'est pas fiable dans les drapeaux de paquet) |
| `install_packages` | 20 | demande `REQUEST_INSTALL_PACKAGES` ou `INSTALL_PACKAGES` |
| `vpn_service` | 10 | déclare un `VpnService` (`BIND_VPN_SERVICE`) |
| `boot_receiver` | 5 | déclare un récepteur de `BOOT_COMPLETED` **et** demande `RECEIVE_BOOT_COMPLETED` |
| `background_location` | 10 | `ACCESS_BACKGROUND_LOCATION` accordée |
| `mic_camera_background` | 8 | micro ou caméra accordés **et** permission de service de type micro/caméra demandée (ou, avant Android 14, service de premier plan) |
| `old_target_sdk` | 8 | app utilisateur dont `targetSdk` < 30 |
| `debuggable` | 10 | app utilisateur marquée `FLAG_DEBUGGABLE` |
| `combo_banking_trojan` | 30 | `accessibility_service` + `overlay` + (`sms_read` ou `notification_listener`) |
| `combo_sms_fraud` | 25 | `sms_send` + `boot_receiver`, sans être l'appli SMS par défaut |
| `combo_stalkerware` | 30 | `no_launcher_icon` + (position accordée, y compris approximative, ou micro) + `boot_receiver` |

Une combinaison s'ajoute aux points des raisons qu'elle combine : c'est ce qui sépare un trojan d'une app qui n'a
qu'un seul de ces pouvoirs. Une lecture qui échoue ne dégrade jamais une app (icône inconnue = présente,
composants inconnus = absents) ; une liste de paquets vide est une lecture ratée, pas « aucune app ».

**Émission.** À chaque `PACKAGE_ADDED` / `PACKAGE_REPLACED` (toujours), puis chaque jour pour les seules apps dont la
note, les raisons ou la version ont changé depuis la dernière émission (état persistant `risk_state`) ; le premier
passage les émet toutes une fois. Sévérité : `low` 0, `medium` 1, `high` 2. Champs : `package`, `label`,
`version_code`, `installer` (absent si inconnu), `from_store`, `score`, `level`, `reasons`.

**Ce que la note classe mal** (jeu de test `RiskCorpus` : 21 apps légitimes et 12 profils malveillants, bâtis
d'après les fonctions et permissions habituelles de chaque famille, **pas extraits d'APK réels**) :

- *Faux positifs « élevé »* (4 sur 21) : contrôle parental, suite antivirus, app d'automatisation (type Tasker) et
  identification d'appelant avec droits SMS. Leurs pouvoirs sont ceux d'un logiciel espion ou d'un trojan, par
  construction : aucune note fondée sur les capacités ne les sépare. Seul « qui l'a installé et pourquoi » le
  fait, et ni le système ni cet agent ne le savent.
- *Faux positifs « moyen »* (4) : gestionnaire de mots de passe et remappage de boutons (accessibilité +
  superposition), lanceur qui verrouille par l'accessibilité, appli SMS tierce choisie par défaut (elle doit
  avoir tous les droits SMS : seule la combinaison fraude au SMS lui est épargnée).
- *Aucune alerte* sur : messagerie, banque, clavier, navigateur, lanceur simple, VPN, composeur, authentificateur,
  gestionnaire de fichiers, navigation (tous sous 30).
- *Faux négatifs* : un dropper publié sur la boutique (seule la demande d'installation le trahit : 20, « faible »),
  un espion qui garde une icône anodine et n'a ni accessibilité ni notification (20 : seul « hors boutique »
  pèse). Sous-estimés mais « moyen » : fraude au SMS sans démarrage au boot (35, déclenchée par push, donc pas de
  combinaison) ou distribuée par la boutique (50), dropper hors boutique (35), verrouilleur de rançon (47),
  adware d'accessibilité (52).
- Limite de fond : la note juge des **capacités déclarées**, pas des actes. Une app qui obtient ses droits après
  l'installation (autorisation accordée plus tard, service d'accessibilité activé plus tard) est renotée au
  prochain passage quotidien (ou à sa mise à jour), pas à l'instant (de même pour une icône que l'app désactive
  après coup). `app.ops` mesure l'usage réel.

### `app.role` : les apps par défaut

Lu **sans privilège système**, d'après `android.jar` de l'API 37 : `RoleManager` ne donne à une app que
`isRoleAvailable`, `isRoleHeld` (pour elle-même) et `createRequestRoleIntent`. `getRoleHolders` est une API système
(`OBSERVE_ROLE_HOLDERS`, niveau signature) : un Device Owner n'a pas plus de droits ici. Sont donc suivis, par les
API publiques correspondantes (`DefaultApps`, une seule implémentation) :

| Rôle | Lecture | Fiabilité |
|---|---|---|
| `sms` | `Telephony.Sms.getDefaultSmsPackage` | fiable |
| `dialer` | `TelecomManager.getDefaultDialerPackage` | fiable |
| `browser`, `home` | app qui résout l'intention par défaut (`MATCH_DEFAULT_ONLY`) | fiable |
| `keyboard` | réglage sécurisé `default_input_method` (constante publique) | fiable |
| `assistant`, `autofill` | réglages sécurisés cachés `assistant`, `autofill_service` | **non garantie** : certains systèmes refusent la lecture ; une valeur absente veut dire « inconnue », jamais « retirée » |

**Non lisibles, donc omis** (jamais devinés) : `call_screening`, `call_redirection`, `emergency`, `notes`, `wallet`
(aucun accesseur public pour une autre app). `keyboard` et `autofill` ne sont pas des rôles Android mais des
réglages : ils sont ajoutés parce qu'un clavier ou un service de saisie malveillant lit tout ce qui est tapé ;
le contrat ne les nomme pas (à y ajouter).

**Articulation avec `app.special_access`** : les deux utilisent la même lecture. `special_access.default_apps` dit
l'**état courant** (quotidien et à chaque changement) ; `app.role` dit la **transition** datée (`old` → `new`, le
premier relevé n'étant qu'une référence, sans événement). Une valeur n'est donc jamais dite deux fois de façon
contradictoire ; seul l'instant de lecture peut différer de quelques secondes. Sévérité 2 pour `sms`, `dialer`,
`assistant`, `keyboard`, `autofill`, 1 pour `browser` et `home`. `old` est absent s'il n'y avait pas de valeur,
`new` absent si le rôle n'est plus attribué.

### `app.ops` : l'usage réel (expérimental)

Désactivé par défaut (carte « Usage des opérations sensibles (expérimental) »). Pour chacune des dix opérations du
contrat, il compte **combien d'accès le système a autorisés** à chaque app pendant la dernière heure, dont ceux en
arrière-plan (états `bg` et `cch` du système ; `fgsvc` compte comme premier plan). Un événement par heure, seulement
pour les apps qui ont utilisé une opération, 300 lignes au plus (coupées en parties de 12 Kio), `from`/`to` = les
deux relevés. **Le premier relevé n'est qu'une référence** (aucun événement).

- **Prérequis** : `DUMP` **et** `PACKAGE_USAGE_STATS`, par `scripts/grant-adb-permissions.sh`. Le code source du
  service (`AppOpsService.dump` → `DumpUtils.checkDumpAndUsageStatsPermission`) exige les deux : `DUMP` seule est
  refusée. Les attributions caméra/micro expérimentales (`AppOpsDump`) ont la même exigence.
- **Source** : `Debug.dumpService("appops", fd, ["--history", "--op", OP])`, soit le texte de
  `adb shell dumpsys appops --history --op SEND_SMS`. Seul l'**historique** donne des compteurs (`[bg-s] =
  access=37`) ; l'état courant ne donne que la date du dernier accès, lue (une lecture par opération utilisée)
  pour remplir `last_ts`. Un compteur est la **différence** entre deux relevés des sommes de l'historique
  (les dates des instantanés de l'historique ne sont pas fiables : relatives à un « début d'époque »). Une somme
  qui baisse (anciens instantanés expirés) vaut 0 : c'est une borne basse. Un relevé espacé de plus de 24 h est
  une nouvelle référence.
- **Ce qui est compté** : les accès autorisés (`access=`) : un envoi de SMS = une demande d'envoi, pas un nombre
  de parties ; en mode d'historique « passif » ou désactivé le système ne compte rien (le collecteur s'en déclare
  indisponible). Les refus (`reject=`, ce que produirait une garde `sms`
  du module `:policy`) ne le sont pas : le contrat n'a pas de champ pour eux. Les apps qui partagent un même
  UID apparaissent sous chacun de leurs paquets.
- **Échec propre** : permission refusée, option inconnue, sortie vide, historique absent (dont le magasin SQLite
  d'Android 16 derrière un indicateur, dont le dump n'imprime alors aucune section `History:`) ou désactivé, format non
  reconnu, sortie trop grosse, délai dépassé, `dumpService` refusé : si **aucune** des dix opérations n'est lisible,
  le collecteur devient « indisponible » avec la raison en français, émet **un seul** `agent.collector_error`
  (`<code>: <raison>`, un nouveau seulement si la raison change), ne réessaie qu'après 6 h. Si seules quelques
  opérations échouent, les autres continuent et l'opération en échec garde sa référence.
- **Sobriété** : 10 lectures par heure (8 s et 3 Mo au plus chacune, 60 s au total), plus une lecture d'état par
  opération utilisée (4 s). Le service tient ses verrous d'historique le temps d'écrire la sortie (effet non mesuré, sans doute de quelques millisecondes).
- **Format** : relevé dans les sources AOSP d'Android 14, 15 et 16 (`AppOpsService`, `HistoricalRegistry` et
  `LegacyHistoricalRegistry`, `AppOpsManager.keyToString`, `TimeUtils.formatDuration`), identique sur les trois ;
  **jamais observé sur le Samsung**. Les tests lisent des extraits écrits d'après ces sources, pas des
  captures.

**À vérifier sur le téléphone** : (1) `adb shell dumpsys appops --history --op SEND_SMS` produit bien des lignes
`[bg-s] = access=N` sur One UI (sinon `app.ops` se déclarera indisponible, sans dommage) ; (2) `Debug.dumpService`
n'est pas refusé par SELinux pour l'app (et la sortie arrive jusqu'à l'agent) ; (3) la taille d'une lecture
(un `--history --op` imprime les en-têtes de tous les paquets, quelques centaines de Kio) ; (4) qu'envoyer un SMS
depuis une app incrémente bien `SEND_SMS` pour *son* paquet ; (5) la liste de `RoleManager` : `app.special_access`
et `app.role` après un changement de navigateur, de clavier et d'appli SMS ; (6) quelques notes au hasard contre la
réalité, surtout les apps de contrôle parental ou d'automatisation si vous en avez.

## Notifications (APK compagnon)

Le collecteur `notifications` de l'agent dit **quelles apps affichent des notifications**. La lecture des
notifications n'est **pas** dans l'APK Device Owner : elle vit dans un APK séparé et optionnel, **Vigie
Notifications** (`io.github.erwsim.vigie.notifier`, module `:notifier`), qui contient le seul
`NotificationListenerService` du projet (principe 4 ; un DPC qui écoute aussi les notifications a déjà été
bloqué par Play Protect, voir `../docs/research/android-plateforme.md` §2.4 et §9 : si le compagnon l'est, l'agent
n'est pas touché). Le compagnon n'a **ni** la permission `INTERNET` **ni** aucune permission sensible, n'embarque
aucune bibliothèque (ni AndroidX, ni réseau, ni Google), a une icône et un écran qui expliquent ce qu'il fait,
son état et comment le retirer. Il ne garde rien : ni historique, ni contenu, ni fichier (état en mémoire).

### Ce qui est transmis (`app.notification`, contrat §10)

| Toujours | Seulement si « Contenu des notifications » est activé (désactivé par défaut) |
|---|---|
| `package`, `event` (`posted`/`removed`), `category`, `channel`, `ongoing`, `importance` (`none`, `min`, `low`, `default`, `high`, `max`) | `title`, `text` (512 caractères au plus, comptés en points de code), `redacted` (vrai si un code a été masqué ; absent si le masquage est désactivé) |

- **Contenu éteint** (défaut) : le titre et le texte ne quittent jamais le processus du compagnon (le filtrage
  se fait chez lui, avant le canal, d'après les réglages lus chez l'agent ; l'agent applique la même règle une
  seconde fois à la réception).
- **Masquage des codes** (activé par défaut) : toute suite de 4 à 8 chiffres est remplacée par `••••` avant la
  troncature (un code n'est jamais coupé en deux). Détail de la règle et de ses limites ci-dessous.
- **Apps exclues du contenu** (seul le nom de l'app part) : pré-remplie avec des banques et apps de paiement
  courantes en France, authentificateurs, gestionnaires de mots de passe, **SMS et téléphone** (pas de contenu
  de SMS ni de journal d'appels, principe 4). C'est une liste de **noms de paquet** : une app n'est reconnue que
  par son nom exact, la liste est donc forcément incomplète (autre banque, variante régionale, app renommée) ;
  noms non vérifiés un par un sur un appareil. Ajoutez vos apps sensibles.
- **Apps ignorées** (rien ne part) : vide par défaut.
- **Jamais transmis** : les notifications de Vigie et du compagnon ; les mises à jour d'une notification qui
  n'ont rien changé ; plus d'une mise à jour par notification toutes les 30 s ; les mises à jour des
  notifications **permanentes** (`ongoing`, service de premier plan, musique, téléchargement, minuteur, appel,
  navigation, entraînement : seuls le premier affichage et le retrait partent ; « Téléchargement terminé », qui
  n'est plus permanent, part une fois) ; les résumés de groupe (chaque notification du groupe part, pas le
  résumé) ; le retrait d'une notification qui n'a pas été transmise ; au-delà de **20 événements par app et par
  10 minutes** (les retraits de notifications transmises passent toujours). Les notifications déjà affichées
  quand le compagnon démarre ne sont pas transmises. Volume typique : quelques dizaines d'événements par jour.
- Android 15+ masque déjà le contenu des notifications qu'il reconnaît comme codes à usage unique aux écouteurs
  « non fiables » comme le compagnon : le masquage de Vigie est une seconde couche.

**Règle de masquage** (`notifier/protocol/…/CodeRedactor.kt`, testée par `CodeRedactorTest`) : une suite de chiffres
(toutes écritures) dont les groupes sont séparés par **une** espace, espace insécable ou un tiret (`123456`,
`123 456`, `123-456`, `G-123456`, `code123456`) est masquée en entier si elle compte 4 à 8 chiffres ; plus
longue (téléphone, IBAN, carte), seuls ses groupes de 4 à 8 chiffres le sont. Une partie de nombre décimal
(`1234,56`) ou de date à barres obliques (`16/11/2026`) est laissée.
- **Masqué à tort** : années (`2026`), montants sans décimales (`1500 €`, `1 500 €`), dates ISO (`2026-11-16`),
  codes postaux (`75011`), blocs de 4 chiffres de numéros de téléphone écrits par blocs de 4 (`+44 20 7946 0958`),
  blocs d'IBAN, numéros de commande ou de suivi de 4 à 8 chiffres.
- **Laissé passer** : codes de 3 chiffres ou de 9 et plus, codes alphanumériques (`A1B2C3`), codes écrits avec un
  point ou une virgule (`123.456`, `1234.5678`), avec deux séparateurs ou une barre oblique entre les groupes,
  code en petits groupes collé par une espace à un autre nombre (`123 456 2026` : seul `2026` est masqué),
  codes écrits en lettres. Les numéros de téléphone en blocs de 2 chiffres (`06 12 34 56 78`) ne sont pas masqués.

### Installer et activer

1. Construire avec **le même keystore** que l'agent (même construction) : `./gradlew :notifier:assembleRelease`
   → `notifier/build/outputs/apk/release/notifier-release.apk` (même configuration de signature que `:app`,
   lue dans `keystore.properties` ou les variables `VIGIE_*` ; `-Pvigie.testOnly`, `-Pvigie.versionCode`
   et `-Pvigie.versionName` s'appliquent aussi). Un compagnon signé par une autre clé est refusé à
   l'installation à côté de l'agent (`INSTALL_FAILED_DUPLICATE_PERMISSION`) et ne pourrait de toute façon
   rien lui remettre. Débogage avec débogage, release avec release.
2. `./scripts/install-notifier.sh [notifier.apk]` (`adb install -r -t`, compare ensuite les clés de signature
   de l'agent et du compagnon). L'ordre d'installation agent/compagnon est indifférent.
3. Accès aux notifications : `./scripts/notifier-access.sh` (`adb shell cmd notification allow_listener
   io.github.erwsim.vigie.notifier/io.github.erwsim.vigie.notifier.NotifierListenerService`, puis vérification
   dans `settings get secure enabled_notification_listeners`). Sans ADB : bouton « Réglage d'accès aux
   notifications » du compagnon, ou Paramètres › Notifications › … › Accès aux notifications (le chemin varie
   selon la version de One UI). Une app installée hors magasin d'apps peut y apparaître grisée
   (**« Paramètre restreint »**) : Paramètres › Applications › Vigie Notifications › ⋮ › « Autoriser les
   paramètres restreints », puis accorder l'accès ; la commande ADB n'est pas concernée par ce blocage.
4. Ouvrir « Vigie Notifications » : accès accordé, service d'écoute connecté, agent présent (même clé), collecte
   active, contenu activé ou non d'après l'agent, dernière notification relayée et compteurs.
5. Dans Vigie, onglet Collecteurs › Notifications : le collecteur passe de « indisponible » (compagnon absent,
   signé par une autre clé ou sans accès, raison affichée) à « actif » (au plus tard au prochain passage de
   maintenance, 15 min ; aussitôt si le compagnon signale son service d'écoute).

### Régler

- **Dans Vigie** (Collecteurs › Notifications) : l'interrupteur du collecteur (désactivé : le compagnon ne
  transmet plus rien), « Contenu des notifications » (désactivé par défaut), « Masquer les codes numériques »
  (activé par défaut). Chaque changement émet `agent.config_changed` et prévient le compagnon.
- **Dans le compagnon** : les deux listes d'apps (un nom de paquet par ligne, `#` pour un commentaire),
  « Enregistrer dans Vigie » ou « Rétablir les listes par défaut ». Elles sont **stockées dans l'agent** (clés
  `notifications.content_excluded_packages` et `notifications.ignored_packages` de ses réglages ; le cadre de
  réglages de l'agent n'a pas de type « liste » éditable), chaque changement émet `agent.config_changed`
  (`old`/`new` : noms séparés par des virgules, 1 000 caractères au plus). Entrées invalides refusées et
  affichées ; 500 apps au plus par liste.

### Canal local (sécurité)

- Le compagnon appelle un **fournisseur de contenu** de l'agent (`ContentResolver.call`, autorité
  `io.github.erwsim.vigie.notifications`) : appel synchrone, qui démarre le processus de l'agent s'il ne tourne
  pas (pas de démarrage de service en arrière-plan, donc pas de restriction Android 12+), sans liaison à gérer.
  Visibilité entre paquets : `<queries>` sur le paquet de l'agent côté compagnon ; l'agent voit tout
  (`QUERY_ALL_PACKAGES`).
- Protégé par la permission **`io.github.erwsim.vigie.permission.NOTIFICATION_RELAY`** de niveau `signature`,
  **déclarée par les deux APK** (même clé : pas de conflit, et l'ordre d'installation ou la désinstallation de
  l'un ne la fait pas disparaître). L'agent vérifie en plus, à chaque appel, que l'appelant détient la
  permission, que son uid et son paquet attribué sont ceux du compagnon et que sa clé de signature est la sienne.
- Dans l'autre sens, l'agent n'envoie qu'une diffusion vide « réglages modifiés » au récepteur du compagnon
  (protégé par la même permission) ; le compagnon relit alors les réglages. Il les relit aussi au plus toutes les
  minutes et dès que l'agent répond avec une autre version. Tant qu'il n'a pas pu les lire, il ne transmet rien.
- Tailles bornées des deux côtés : titre et texte 512 points de code, catégorie 64, canal 128, paquet 255
  caractères, 32 clés par appel ; au-delà, l'agent refuse l'appel (rien n'est enregistré). 300 appels par minute
  au plus côté agent ; file de 256 notifications au plus côté compagnon.
- Agent absent, arrêté, en cours de mise à jour ou collecteur désactivé : le compagnon **abandonne** les
  notifications de ce moment (il ne les garde pas pour plus tard) et le compte (« non remises ») ; après un échec
  il ne réessaie pas pendant 10 s. Si le processus de l'agent a été relancé par l'appel avant que son service ne
  redémarre les collecteurs, l'événement est écrit directement dans le tampon de l'agent.

### Retirer

- Couper la collecte en gardant le compagnon : désactiver le collecteur « Notifications » dans Vigie.
- Retirer l'accès : `./scripts/notifier-access.sh --revoke` (`cmd notification disallow_listener …`), ou le
  réglage d'accès aux notifications.
- Désinstaller : `./scripts/uninstall-notifier.sh` (retire l'accès puis `adb uninstall`), ou depuis les
  Paramètres. L'agent continue sans lui ; les listes restent dans les réglages de l'agent.

### Ce qui est vérifié, ce qui ne l'est pas

- **Vérifié dans l'environnement de développement** : compilation, lint (aucun avertissement sur le
  compagnon), APK debug et release (R8) ; le manifeste du compagnon ne demande que la permission du canal (pas
  d'`INTERNET`), son code release ne contient que le sien ; l'APK de l'agent ne contient aucun
  `NotificationListenerService`, déclare la permission de signature et l'exige sur son fournisseur ; tests JVM
  du masquage, des listes, de la troncature, de la réduction du bruit, de la validation côté agent (charges
  hostiles) et de la conformité de `app.notification` ; scripts bash essayés contre un faux `adb` (les `.ps1`
  n'ont pas été exécutés).
- **Rien n'a été exécuté sur un téléphone.** À vérifier sur le S25+, par ordre de risque :
  1. réaction de **Play Protect** à l'installation du compagnon (et éventuelle analyse de l'agent ensuite) ;
  2. accès accordé par `cmd notification allow_listener` sur One UI 8/9, et l'affichage « paramètre
     restreint » dans les Paramètres ;
  3. **survie du service d'écoute** (gestion de la batterie Samsung : au besoin, Vigie Notifications dans
     « Applications jamais en veille ») et reconnexion après redémarrage, mise à jour ou arrêt forcé ;
  4. canal quand l'agent est tué, en cours de mise à jour ou arrêté (« non remises » doit augmenter, aucune
     erreur) et démarrage de l'agent par l'appel du compagnon ;
  5. lecture de `enabled_notification_listeners` par l'agent (sinon le collecteur se fie à ce que dit le
     compagnon) ; diffusion « réglages modifiés » reçue par le compagnon ;
  6. contenu réel des notifications des apps courantes (messageries, codes reçus par SMS déjà masqués par
     Android 15+, notifications groupées) et volume quotidien.

## Commandes à distance

Décision du propriétaire du 16/11/2026 (principe 2 révisé, contrat §8) : le serveur peut transmettre au
téléphone des commandes d'une **liste fermée**, et rien d'autre. Aucune commande ne peut modifier un réglage,
la politique ou l'enrôlement : un type inconnu, un paramètre en trop ou hors bornes est **refusé**, jamais
interprété. Écran **Réglages › Commandes à distance** (ou carte « Commandes à distance » de l'accueil).

| Commande | Effet sur le téléphone | Exige | API Android |
|---|---|---|---|
| `ring` (`duration_s` 1–300, `vibrate`) | sonnerie d'alarme en boucle à plein volume (flux alarme, volume remis ensuite), vibration en option, notification « Vigie fait sonner ce téléphone » avec **Arrêter** | canal activé | `MediaPlayer` en `USAGE_ALARM`, `AudioManager.setStreamVolume(STREAM_ALARM)`, `VibrationAttributes.USAGE_ALARM` |
| `vibrate` (`duration_s` 1–60) | vibration seule | canal activé | `VibratorManager` |
| `stop_ring` | arrête sonnerie ou vibration | canal activé | — |
| `locate` | position immédiate par le collecteur `location` dans **son** mode (jusqu'à 60 s), puis envoi immédiat du tampon | canal activé, collecteur `location` actif | `LocationManager.getCurrentLocation` |
| `lock` (`message` ≤ 200 caractères, optionnel) | message sur l'écran de verrouillage puis verrouillage immédiat | **signée**, Device Owner | `setDeviceOwnerLockScreenInfo`, `lockNow` |
| `clear_lock_message` | retire le message | **signée**, Device Owner | `setDeviceOwnerLockScreenInfo(null)` |
| `wipe` | réinitialisation d'usine | **signée**, Device Owner, « Autoriser l'effacement à distance » | `DevicePolicyManager.wipeDevice(0)` |

Chaque commande traitée produit `command.result` (`command_id`, `type`, `status` = `executed`/`failed`/`refused`,
`detail`, `signed`), une ligne de l'historique local et **une notification sur le téléphone** (une commande ne
passe jamais inaperçue) ; le résultat est aussi envoyé au serveur (`POST /api/v1/commands/{id}/result`, gardé et
renvoyé tant qu'il n'est pas acquitté). La notification permanente et l'accueil disent quand le canal est actif.

### Mettre en service

1. Enrôler l'appareil (le code dépend de son identifiant).
2. **Commandes à distance** › « Recevoir les commandes à distance » (**désactivé par défaut**), mode
   « Connexion permanente » (défaut) ou « Interrogation périodique » (1 à 15 min).
3. **Code de commande** : 12 caractères au moins, saisi deux fois. Il n'est connu que du téléphone et de vous ;
   le serveur ne le reçoit pas et ne peut ni verrouiller ni effacer sans lui. **Cette promesse a deux
   limites** (l'écran les dit) : le serveur voit passer les commandes signées et peut donc essayer des codes
   hors ligne — de l'ordre de 15 000 essais par seconde et par carte graphique haut de gamme malgré les
   600 000 itérations (ordre de grandeur tiré des bancs publics de PBKDF2-HMAC-SHA256, non mesuré ici) :
   12 chiffres tombent en environ deux années-carte, soit quelques jours de matériel loué, un mot du
   dictionnaire suivi de chiffres en quelques heures, alors que cinq mots tirés au hasard ou 16 caractères
   aléatoires sont hors de portée ; et le code est saisi dans la console, que ce même serveur sert (un serveur
   compromis peut modifier la page et le lire). L'app refuse un code de moins de 6 caractères différents, ou
   sans lettre avec moins de 20 chiffres (`CommandCrypto.isTooWeak` : un plancher, pas une mesure de force).
   **Changer le code rend caduques toutes les commandes déjà signées**, y compris celles que le serveur
   détiendrait encore. Il est ressaisi dans la console à chaque commande sensible. Le téléphone n'en garde que la clé dérivée
   `K = PBKDF2-HMAC-SHA256(code, "vigie-cmd-v1:" + device_id, 600 000, 32 octets)`, chiffrée par une clé AES du
   Keystore ; le code lui-même n'est conservé nulle part (pas même dans l'écran). Après un réenrôlement sous un
   autre identifiant, l'app demande de le ressaisir. « Supprimer le code » remet aussi l'effacement à distance
   à « interdit ».
4. Optionnel : **Autoriser l'effacement à distance** (désactivé par défaut ; activation seulement avec un code
   défini et après avoir tapé EFFACER dans la confirmation). Chaque changement de ces réglages émet
   `agent.config_changed` (`commands.enabled`, `commands.mode`, `commands.allow_wipe`, `commands.code` avec
   `set`/`changed`/`unset`, jamais le code).
5. Si un message de verrouillage a été posé, l'écran propose « Effacer le message » (localement, sans commande).

### Vérifications (dans l'ordre du contrat)

canal activé (`disabled`) → `payload` analysable, `v` = 1, même `id` (`malformed`) → `device_id` (`wrong_device`)
→ type de la liste (`unknown_type`) → pour un type sensible : code défini (`no_code_configured`), pas de
verrouillage temporaire (`locked_out`), HMAC-SHA256 sur les **octets UTF-8 exacts** de `payload`, comparé en
temps constant (`bad_signature`) → `wipe` autorisé (`disabled` ; l'`id` d'un `wipe` signé et encore valide
refusé ici est **consommé** : le serveur garde la commande signée jusqu'à son expiration et pourrait sinon la
livrer de nouveau après l'activation de l'interrupteur) → non expirée, 5 min de tolérance (`expired`) →
jamais vue (`replay`) → paramètres dans les bornes (`bad_params`) → Device Owner pour `lock`,
`clear_lock_message`, `wipe` (`not_device_owner`). Avant la signature, seuls `v`, `id`, `device_id` et `type`
sont lus, pour refuser ; le reste (paramètres, dates) n'est analysé qu'après. Cinq `bad_signature` en une heure
bloquent les commandes sensibles une heure (persistant). Anti-rejeu persistant : 500 derniers `id` signés,
500 derniers `id` simples et 500 derniers `id` sensibles **consommés sans signature vérifiable** (trois fenêtres :
un serveur compromis qui enverrait des commandes en masse ne peut pas faire sortir un `id` signé vérifié de sa
fenêtre). Précisions de la revue de sécurité v1.1 (contrat §8) appliquées par l'agent : validité de `wipe`
limitée à **24 h** (`expired` au-delà, et un `wipe` à 7 jours refusé `disabled` n'est pas consommé : il serait
expiré de toute façon) ; une commande sensible refusée `disabled` (canal coupé) ou `no_code_configured` est
**consommée** (fenêtre « non vérifiée », si son `device_id` est le bon et ses dates encore valides) et ne
s'exécutera jamais, même après l'activation du canal ou la saisie du code ; U+2028 et U+2029 refusés dans le
message de `lock` ; plancher du code (6 caractères différents, 20 chiffres sans lettre). Précisions retenues là où le contrat se tait : clé inconnue
au premier niveau de `payload` ou `expires_at` antérieur à `issued_at` → `malformed` ; validité de plus de
30 jours (24 h pour `wipe`) ou `issued_at` à plus de 5 min dans le futur → `expired` ; `sig` sur une commande simple →
`malformed` ; `payload` avec une clé en double (même cachée derrière un échappement `\u`) → `malformed` ;
message de `lock` : 200 unités UTF-16 au plus, aucun caractère de contrôle sauf le saut de ligne
(`bad_params`, revérifié par l'agent : le serveur n'est pas de confiance). Le vecteur de test du §8 est reproduit à l'octet près
(`CommandVerifierTest`). Tout JSON venu du serveur (payload, événement du flux, réponse d'interrogation) est
refusé au-delà de quelques niveaux d'imbrication **avant** d'être analysé (`JsonNesting`) : l'analyseur est
récursif et un débordement de pile, qui n'est pas une `Exception`, arrêterait le canal.

Ce que la signature ne couvre pas, par construction : une commande signée reste exécutable jusqu'à son
`expires_at` (7 jours par défaut dans la console), quoi qu'affiche la console — un serveur compromis peut la
retenir puis la livrer plus tard, ou ignorer une annulation (l'annulation n'existe que côté serveur). Parade
locale : changer le code de commande, ou couper le canal ou l'effacement à distance.

### Effacement à distance : garde-fous

`wipe` est la seule action irréversible de l'app. Elle exige **toutes** ces conditions : canal activé, code
défini, signature valide, « Autoriser l'effacement à distance » activé, commande non expirée et jamais vue, et
Vigie Device Owner. L'agent émet d'abord `command.result` (`executed`, sév. 2), tente d'envoyer le tampon et le
résultat (10 s au plus), **revérifie toutes les conditions sur l'état courant** (un interrupteur coupé pendant
ces 10 s annule tout), puis appelle `wipeDevice(0)`. Choix d'API : `wipeData` lève `IllegalStateException` pour
une app ciblant l'API 34+ appelée sur l'utilisateur système (là où vit un Device Owner) ; `wipeDevice` (API 34)
est l'appel prévu pour réinitialiser l'appareil et exige la politique `<wipe-data/>` (déclarée dans
`policy/src/main/res/xml/device_admin.xml`, avec `<force-lock/>` pour `lockNow`). Drapeaux 0 : la protection
contre la réinitialisation (compte Google) et les eSIM sont **conservées** — un voleur ne peut pas réutiliser le
téléphone, vous gardez votre ligne. L'appel réel n'existe qu'à un endroit (`AndroidFactoryReset`), construit à
un seul endroit (`PolicyModule.registerCommandExecutors`) ; `RemoteCommandsPolicyTest` vérifie les 64
combinaisons des six conditions (une seule efface) et, dans les sources, qu'aucun autre chemin n'appelle
`wipeDevice`/`wipeData`.

### Limites réelles

- **« Ne pas déranger »** : la sonnerie utilise le flux alarme, qui n'est coupé ni par le mode silencieux ni
  par le mode vibreur. Si le mode « Ne pas déranger » du propriétaire coupe les alarmes (« Silence total », ou
  alarmes désactivées dans le mode), le son reste coupé : une app ciblant Android 15+ ne peut plus désactiver le
  « Ne pas déranger » de l'utilisateur (`setInterruptionFilter` ne pilote plus que sa propre règle), et être
  Device Owner ne donne aucun droit sur ce mode. Le résultat le dit (`detail` = `dnd_alarms_muted`) ; la
  vibration et la notification restent.
- **`lock` sans écran de verrouillage sécurisé** (pas de code, schéma ou empreinte) : `lockNow` éteint seulement
  l'écran. Le message s'affiche sur l'écran de verrouillage tant qu'il n'est pas retiré (commande ou app).
- **`locate` en mode GPS seul** : en intérieur, souvent aucune position en 60 s (`failed`, `no_fix`) ; les modes
  réseau/fusionné répondent mieux, au prix de ce qu'ils transmettent à Google. Collecteur `location` coupé ou
  sans permission : `failed`, `location_unavailable` (une commande ne passe jamais outre un choix local).
- **Politiques d'administration ajoutées** (`force-lock`, `wipe-data`) : elles sont lues à l'activation de
  l'administrateur. Sur un téléphone où Vigie était déjà Device Owner avec une version antérieure, vérifier que
  `lock` fonctionne après la mise à jour (sinon : `SecurityException` → `failed`, `lock_refused`).

### Canal et consommation (à mesurer sur le téléphone)

- **Connexion permanente** : `GET /api/v1/commands/stream` (Server-Sent Events) avec le même client TLS à
  certificat client que l'envoi. Aucun verrou de veille permanent : une lecture bloquante sur une connexion TCP
  au repos. Délai de lecture 300 s (2,5 × le maintien de 120 s du serveur : un maintien perdu est toléré). Les
  minuteries s'arrêtent quand le processeur dort : une alarme inexacte autorisée en veille profonde
  (`setAndAllowWhileIdle`, au plus une fois toutes les 15 min environ ; Android en espace l'effet d'au moins
  9 min en Doze) vérifie qu'un octet est arrivé depuis moins de 5 min, sinon la connexion est rouverte. Verrou
  de veille seulement pendant le traitement d'une commande (≤ 2 min), autour d'une interrogation (≤ 60 s) et
  après une alarme (≤ 30 s).
- **Coût attendu** : chaque maintien du serveur (toutes les 2 min) réveille le modem s'il est au repos — c'est
  la principale dépense, surtout en réseau mobile. Un service de premier plan garde normalement l'accès réseau
  en Doze (à vérifier sur One UI). Si la consommation est trop forte : mode « Interrogation périodique ».
- **Interrogation** : `GET /api/v1/commands` à l'intervalle choisi (alarme inexacte ; en veille profonde
  l'intervalle réel s'allonge), et à chaque envoi d'événements quand le flux n'est pas ouvert (au plus une fois
  par minute ; inutile quand le flux est ouvert, qui livre déjà les commandes en attente).
- **Pas de boucle** : sans réseau, rien n'est tenté jusqu'au retour du réseau (rappel système) ; échecs en
  backoff exponentiel avec gigue (5 s → 15 min ; `429` et `Retry-After` respectés ; `404` = serveur sans canal :
  6 h) ; un flux qui meurt aussitôt ouvert compte comme un échec ; un flux qui a vécu est rouvert après 2 à 10 s.
  **`401`/`403` arrête tout** et l'écran l'affiche (« refusé par le serveur ») jusqu'à un réenrôlement, un
  changement de réglage ou « Reconnecter ». Changement de réseau (Wi-Fi ↔ mobile) : le flux est rouvert aussitôt.
- **Renvoi** (contrat §8) : le serveur livre de nouveau une commande dont le résultat n'est pas arrivé (après
  5 min, 3 fois au plus), et le flux puis l'interrogation peuvent livrer la même. Une commande déjà traitée
  n'est **jamais réexécutée** (ni `wipe`, ni `lock`, ni `ring`) : l'agent renvoie son **résultat d'origine**,
  conservé avec l'`id` (1000 derniers), sans nouvel événement ni nouvelle ligne d'historique ; il ne répond
  `refused`/`replay` que pour un `id` encore dans la fenêtre anti-rejeu dont il n'a plus le résultat.

### Ce qui est vérifié, ce qui ne l'est pas

- **Vérifié (JVM)** : vecteur de test du §8 (et vecteurs PBKDF2 de la RFC 7914), **cas difficiles signés par
  le vrai code TypeScript de la console** (`ConsoleVectorsTest` rejoue
  `server/console/src/lib/fixtures/command-vectors.json` : accents, émojis, guillemets, sauts de ligne, texte
  bidirectionnel, codes non ASCII, décomposés ou bordés d'espaces), chaque motif de refus et
  l'ordre des vérifications, anti-rejeu après redémarrage, `wipe` refusé interrupteur coupé puis rejoué
  interrupteur activé (y compris après saturation de la mémoire des résultats par des commandes simples),
  JSON imbriqué à l'excès, plancher du code de commande, verrouillage après 5 signatures invalides, matrice
  des garde-fous de `wipe`, revérification avant l'effacement, client du canal contre MockWebServer (flux SSE,
  coupure, reconnexion, surveillance du flux, `401`, absence de réseau, bascule vers l'interrogation, résultat
  renvoyé après coupure, livraison en double, renvoi du résultat d'origine sans réexécution — `wipe`, `lock`,
  `ring`), conformité de `command.result` au contrat (`CommandResultContractTest`).
- **Essai croisé contre le vrai collecteur** (`CrossCommandsTest`, ignoré sans les variables `VIGIE_CROSS_*`,
  mode d'emploi en tête du fichier ; exécuté le 16/11/2026 contre `vigie-collector serve` en `http://` local) :
  commandes créées par l'API console avec un `payload` et une signature construits comme la console
  (`ring`, `lock` signé avec un message accentué sur deux lignes, `wipe` signé, `lock` signé avec un autre
  code), livrées par le vrai flux SSE puis par l'interrogation, vérifiées par le vrai client ; le serveur a
  enregistré `executed` pour les commandes légitimes et `refused`/`bad_signature` pour la fausse. Deux essais
  ajoutés par la revue de sécurité (16/11/2026, mêmes conditions) : les 13 cas difficiles **signés par le vrai
  code de la console** (`node server/console/scripts/command-vectors.ts <device_id>`) traversent le vrai
  collecteur et sont acceptés par le vrai vérificateur avec leur message exact ; et le **renvoi après 5 min par
  le vrai serveur** : `lock` et `wipe` (réinitialisation factice) dont le résultat n'était pas parvenu au
  serveur sont livrés de nouveau, ne sont pas réexécutés, et leur résultat d'origine est enregistré ; un
  `ring` dont le résultat ne pouvait pas partir est renvoyé entre-temps, n'est pas rejoué, et son résultat
  arrive à la reprise.
- **Rien n'a été exécuté sur un téléphone.** À vérifier sur le S25+, par ordre de risque :
  1. **`wipe`** : avec un téléphone de test ou une sauvegarde complète, vérifier que `wipeDevice(0)` réinitialise
     bien (et qu'il ne se passe rien tant que l'interrupteur est coupé) ;
  2. **`lock`** : `lockNow` et l'affichage du message par One UI sur l'écran de verrouillage
     (`setDeviceOwnerLockScreenInfo`), puis `clear_lock_message` et « Effacer le message » ;
  3. **consommation du canal permanent** sur 24 h en Wi-Fi puis en réseau mobile (Paramètres › Batterie,
     `adb shell dumpsys batterystats`), comparée au mode interrogation ; si elle est forte, essayer un maintien
     serveur plus long (`VIGIE_CMD_KEEPALIVE_S`, **240 s au plus** : le délai de lecture de l'agent est de
     300 s, et sans dépasser le délai de NAT de l'opérateur) ou le mode interrogation ;
  4. **réception en Doze** : écran éteint depuis plus d'une heure, envoyer `ring` ; noter le délai (la connexion
     doit rester ouverte grâce au service de premier plan) ; `adb shell dumpsys deviceidle force-idle` pour forcer ;
  5. **sonnerie** en mode silencieux, vibreur et « Ne pas déranger » (avec et sans alarmes autorisées), volume
     d'alarme remis ensuite, bouton « Arrêter » sur l'écran de verrouillage ;
  6. `locate` dans les trois modes de localisation, en intérieur et dehors ; reconnexion après passage Wi-Fi ↔
     mobile, mode avion, redémarrage du serveur ; comportement après révocation (`401` affiché, plus d'essais).

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

- **Tout rétablir** (écran Politique, confirmation) : éteint d'abord les gardes (section « Gardes de
  capacités »), puis défait tout ce que Vigie a appliqué, du plus récent au plus ancien ; un élément qui résiste reste listé avec son erreur (réessayer). Les journaux restent actifs.
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

## Gardes de capacités (contrat §11.1)

Écran **Politique › Gardes**. Une garde verrouille une capacité dont un logiciel malveillant a besoin, **quel que
soit le vecteur** par lequel il est arrivé (le cas vécu par le propriétaire : une appli qui envoyait 2 000 SMS de
hameçonnage par jour sans que l'appli SMS ne montre rien). Toutes sont **éteintes par défaut**, activées une par
une après un **aperçu** qui dit exactement quelle application perd quoi, et défaites par « Rétablir » (bouton
« Aperçu et désactivation »), « Tout rétablir », le retrait du Device Owner et l'issue de secours ADB. Chaque
action émet `security.policy` (`profile = "guard:<clé>"`, `action` ∈ `guard_enabled`, `guard_disabled`,
`permission_denied`, `permission_restored`/`permission_granted`, `quarantined`, `released` ; `target` = paquet
ou clé de la garde ; `permission` pour une permission).

| Clé | Ce qu'elle fait (API) | Option | Liste |
|---|---|---|---|
| `sms` | `setPermissionGrantState(DENIED)` sur `SEND_SMS` pour toute appli qui la demande | + `READ_SMS`, `RECEIVE_SMS`, `RECEIVE_MMS`, `RECEIVE_WAP_PUSH` | applis autorisées (pré-remplie : appli SMS par défaut) |
| `calls` | idem sur `CALL_PHONE` | + `ANSWER_PHONE_CALLS`, `READ_CALL_LOG`, `WRITE_CALL_LOG` | applis autorisées (pré-remplie : composeur par défaut) |
| `accessibility` | `setPermittedAccessibilityServices(liste)` | — | services approuvés |
| `input_methods` | `setPermittedInputMethods(liste)` | — | claviers approuvés |
| `quarantine` | `setPermissionGrantState(DENIED)` sur SMS, appels, journal d'appels, contacts (`READ/WRITE_CONTACTS`, `GET_ACCOUNTS`), micro, caméra, position en arrière-plan, appareils à proximité (`BLUETOOTH_SCAN/CONNECT/ADVERTISE`, `NEARBY_WIFI_DEVICES`, `UWB_RANGING`, `RANGING`) pour chaque appli **non système installée après l'activation** | — | — (« Libérer » appli par appli) |

### Sémantique réelle des API (sources : javadoc et code AOSP de `DevicePolicyManager`/`DevicePolicyManagerService`, branche principale, lus le 16/11/2026 ; SDK android-37 pour les signatures)

- **`setPermissionGrantState`** : `DENIED` refuse la permission et la **verrouille** dans les Paramètres (« contrôlé
  par l'administrateur ») ; une permission déjà accordée est **retirée** (Android arrête alors l'appli) ; la
  demande de l'appli échoue sans boîte de dialogue. La javadoc précise que l'utilisateur ne peut plus gérer
  **les autres permissions du même groupe** non plus (leur état actuel est conservé) : refuser `SEND_SMS`
  grise aussi le groupe SMS de l'appli. `DEFAULT` rend la main sans révoquer. Le système relit l'état et
  renvoie `false` s'il n'est pas atteint (Vigie relit aussi). Un Device Owner ciblant Q+ peut agir sur toutes les
  applis, système et privilégiées comprises (recherche §3.7) ; Vigie **s'interdit** les applis système. Les
  permissions marquées `SYSTEM_FIXED` sont probablement refusées (non vérifié, sans objet ici).
- **`setPermittedAccessibilityServices` / `setPermittedInputMethods`** : liste de **noms de paquets** ; `null` =
  aucune restriction ; liste vide = services du système seulement ; les services/claviers du système
  (`ApplicationInfo.isSystemApp()`) restent **toujours** permis et ne peuvent pas être restreints. Un service
  non système **déjà activé** doit figurer dans la liste, sinon l'appel renvoie `false` et **rien ne change**
  (`checkPackagesInPermittedListOrSystem`) : ces gardes **ne désactivent jamais** un service déjà actif, elles
  empêchent d'en activer un nouveau. Vigie ajoute donc d'office les services déjà activés à la liste et
  l'aperçu les nomme (« gardés, Android l'exige ») : pour en exclure un, le désactiver d'abord dans les
  Paramètres, puis réappliquer. Le clavier Samsung (`honeyboard`) et les services d'accessibilité Samsung
  préinstallés sont des applis système : toujours permis.

### Garde-fous (codés en dur)

- Jamais touchés, quelle que soit la liste : Vigie et son compagnon, **toute appli système** (`FLAG_SYSTEM` :
  SOS d'urgence, opérateur, Samsung), la liste de refus de la politique, et les **détenteurs actuels des rôles**
  appli SMS, composeur (par défaut et système), clavier en service, écran d'accueil par défaut. Seulement les
  détenteurs : ni toute appli capable d'être un lanceur (n'importe quelle appli peut déclarer une activité
  HOME), ni les administrateurs actifs (un logiciel malveillant peut le devenir).
- **Rôle qui change** (contrôlé à chaque diffusion de paquet, au changement de composeur, à l'ouverture de
  l'écran et toutes les 15 min) : le nouveau détenteur retrouve ses permissions, **entre dans la liste** de la
  garde (« la liste suit », `agent.config_changed`) et une notification le dit (« si ce n'est pas vous,
  vérifiez… »). Une appli en quarantaine choisie comme appli par défaut est libérée automatiquement (notifié).
- Un échec sur un paquet donne `permission_denied` `ok=false` et n'arrête pas les autres ; il n'est pas retenté à
  chaque passage (pas de rafale d'événements), mais à la prochaine « Aperçu et réapplication ».
- Deux éléments qui refusent la même permission (garde SMS et quarantaine, ou une permission du catalogue) la
  partagent : celui qui est défait en dernier la rétablit, dans son état d'origine.
- **Persistance** : le même état que le reste de la politique (`vigie_policy`, `commit()` avant chaque
  changement). Enregistrements `guard:<clé>` (la garde est active, son option, la liste en vigueur, la liste
  d'avant Vigie pour accessibilité/claviers, les applis libérées) et `guard:<clé>:<paquet>` (les permissions
  refusées et leur état d'avant). « Tout rétablir » **éteint d'abord toutes les gardes** (aucune ne peut
  refuser de nouveau ce qui vient d'être rendu si le processus meurt au milieu), puis défait le reste. État
  illisible : le balayage rend à l'utilisateur toute permission des gardes refusée sans enregistrement sur une
  appli non système (`DEFAULT` : elle n'est pas ré-accordée, l'appli la redemandera) et lève les listes
  d'accessibilité et de claviers.
- La liste choisie dans l'écran n'entre en vigueur qu'à « Aperçu et (ré)application » (l'écran signale une
  liste modifiée). Les listes sont des réglages « liste de paquets » (`policy.guard.<clé>.allowed`) : chaque
  modification émet `agent.config_changed`.

### Quand s'appliquent-elles

À l'activation (applis présentes, sauf quarantaine), puis à chaque `PACKAGE_ADDED`/`REPLACED`/`REMOVED` reçu par
un récepteur dynamique de `:policy` (indépendant du collecteur `apps`), au démarrage de l'agent, à l'ouverture de
l'écran et au passage de maintenance (15 min). Une mise à jour qui ajoute une permission gardée est donc refusée
dans la foulée. Quarantaine : une appli est « nouvelle » si son `firstInstallTime` (conservé par les mises à
jour, remis à zéro par une réinstallation) est postérieur à l'activation ; une appli libérée le reste tant
qu'elle n'est pas désinstallée.

### Ce que les gardes ne peuvent pas empêcher (franchement)

- **Fenêtre de course** : entre l'installation et le refus, quelques secondes si Vigie tourne, **jusqu'à 15 min**
  si son processus était arrêté. Une appli fraîchement installée ne peut pas s'exécuter avant d'être lancée
  (état « arrêté » d'Android), mais une appli qui en installe et lance une autre le peut.
- **Applis système** et **appli SMS / composeur par défaut** : jamais touchées. Un logiciel malveillant qui se
  fait choisir comme appli SMS par défaut (boîte de dialogue système) envoie des SMS : Vigie le **signale**
  (notification, `app.role` côté collecteurs) mais ne le bloque pas.
- **Autres voies** : SMS préparé par une appli et envoyé par l'appli SMS (il faut appuyer sur Envoyer… ou un
  service d'accessibilité le fait : d'où la garde Accessibilité) ; appel via le composeur ; VoIP, messageries
  par Internet ; exfiltration par le réseau (voir les détections du collecteur) ; superposition, écoute des
  notifications, administrateur de l'appareil (app-ops et accès spéciaux, hors de `setPermissionGrantState`).
- **Déjà acquis** : un service d'accessibilité ou un clavier déjà activé reste activé ; ce qui a été envoyé
  avant l'activation est parti. La quarantaine ne touche pas les applis déjà présentes.
- Une appli de la liste, ou libérée, qui serait compromise ensuite.
- Depuis Android 13, une appli installée hors magasin ne peut déjà pas activer l'accessibilité sans que
  l'utilisateur débloque les « paramètres restreints » : la garde Accessibilité couvre aussi les applis du
  magasin et le cas où l'utilisateur se fait manipuler.

### Ordre d'essai sur le téléphone (du moins au plus risqué) et contrôles

Rien de ceci n'a été exécuté sur un appareil. Avant tout : `rescue-revert` à vide (voir « Issue de secours »).

1. **Quarantaine** (aucun effet immédiat). Installer une petite appli de test (APK ou magasin) : notification
   « Nouvelle application en quarantaine », Paramètres › Applications › appli › Autorisations : SMS, contacts,
   micro… grisés « contrôlé par l'administrateur » ; « Libérer » : l'appli redemande. Mettre à jour l'appli
   libérée : pas de nouvelle quarantaine. Contrôler `quarantined`/`released` dans la console.
2. **Claviers** (liste vide) : l'aperçu doit lister le clavier tiers éventuellement activé comme « gardé ».
   Contrôler : saisie normale, y compris le code PIN après redémarrage (Direct Boot : clavier Samsung) ;
   Paramètres › Gestion globale › Clavier : un clavier non approuvé apparaît non activable.
3. **Accessibilité** (liste vide) : services déjà activés gardés ; TalkBack/Voice Assistant Samsung toujours
   activables ; un service tiers non activé ne l'est plus (« désactivé par l'administrateur »).
4. **Appels** sans option : aperçu (souvent vide) ; appeler depuis le composeur et depuis le carnet d'adresses
   Samsung ; appel d'urgence (ne pas composer réellement : vérifier seulement que le composeur s'ouvre).
5. **SMS** sans option : aperçu (applis tierces qui demandent `SEND_SMS`) ; envoyer un SMS depuis Samsung
   Messages ; SOS d'urgence intact (appli système) ; changer d'appli SMS par défaut et vérifier la notification
   « Appli par défaut changée » et la liste.
6. Seulement ensuite les **options** (lecture des SMS : la saisie automatique des codes reçus par SMS dans les
   applis tierces cesse ; journal d'appels).
7. Après chaque étape : « Tout rétablir », vérifier que l'état d'avant revient (Autorisations de l'appli,
   claviers, accessibilité) ; puis `rescue-revert` avec une garde active, et `remove-device-owner` en dernier.

## Ce qui est vérifié, ce qui ne l'est pas

Vérifié dans l'environnement de développement (Linux, sans émulateur ni appareil) :

- `./gradlew lint test assembleDebug assembleRelease` réussit (lint : 0 erreur, avertissements de style
  `UseKtx`/versions seulement).
- 299 tests JVM, dont 4 ignorés sans leurs variables d'environnement (les essais croisés contre le vrai
  collecteur : `CrossServerTest` et les trois de `CrossCommandsTest`, exécutés à part le 16/11/2026) —
  décompte du 16/11/2026 après la revue de sécurité de la v1.1 : `:core` 131 (dont les commandes à
  distance), `:collectors` 92, `:policy` 67, `:app` 9. Détail d'origine (v1) :
  `:core` 97 (tampon Room sur SQLite JVM : séquence après redémarrage, transaction
  interrompue, purge par sévérité/âge, horodatage d'origine non monotone ; envoi contre MockWebServer : tous
  les codes du contrat, gzip, lots, 1 Mio, Wi-Fi, reprise ; sérialisation exacte du §1 ; fichiers `.vigie` et
  mTLS avec épinglage ; isolation des pannes des collecteurs ; annonce du retrait du Device Owner ; banc de
  test), `:collectors` 59 (logique de chaque collecteur, conformité au contrat), `:policy` 60 (traduction du
  journal de sécurité, journaux réseau, posture, moteur de politique contre une passerelle factice,
  catalogue, DNS), `:app` 5 (conformité au contrat de bout en bout des 21 collecteurs, y compris
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
