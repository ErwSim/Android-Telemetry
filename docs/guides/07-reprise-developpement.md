# 07 — Reprendre le développement avec Claude Code

Ce guide permet de reprendre le projet sur votre PC avec Claude Code : cloner, construire, tester, lancer la pile serveur en
local avec le simulateur (sans téléphone), retrouver le contrat et le fichier d'état, et les pistes déjà identifiées pour une
version 2. Il suppose que vous avez lu le [README](../../README.md) racine.

> **Statut de vérification.** Les commandes de build et de test viennent des README des composants et ont été exécutées sous
> Linux dans l'environnement de développement cloud. **Aucune n'a été exécutée sous Windows.** Les adaptations PowerShell
> données ici sont des transcriptions non essayées.

## 1. Cloner et choisir la branche

```bash
git clone <adresse du dépôt> Android-Telemetry
cd Android-Telemetry
git branch -a                 # repérer la branche de travail
git log --oneline -5
```

Le travail de cette session de documentation a été fait sur la branche `ccr-c0082e88-fz8ojh` (nom donné par l'environnement
cloud) ; vérifiez avec `git branch -a` si elle a été fusionnée dans la branche principale, puis travaillez sur **votre** branche :

```bash
git switch -c ma-branche      # ou git checkout -b ma-branche
```

Lancez ensuite Claude Code **à la racine du dépôt** : il lit `CLAUDE.md` (français obligatoire pour la documentation, les messages de commit et
les textes d'interface ; identifiants de code en anglais ; principes non négociables). Les commits se font en français.

## 2. Où est quoi

| Fichier | Rôle |
|---|---|
| [`CLAUDE.md`](../../CLAUDE.md) | consignes du dépôt, ordre de lecture, règles |
| [`docs/ETAT.md`](../ETAT.md) | **fichier de reprise** : état d'avancement, ce qui est vérifié ou non. À lire en premier, **à mettre à jour à chaque fin de session** (son tableau classe encore les guides « en cours » : à corriger) |
| [`docs/ARCHITECTURE.md`](../ARCHITECTURE.md) | décisions, six principes non négociables, composants |
| [`docs/contrat/contrat.md`](../contrat/contrat.md) | **le contrat** : format des événements, API d'ingestion et de console, fichier `.vigie`, export Wazuh, variables du collecteur. Toute évolution commence **par ce fichier** |
| [`docs/research/`](../research/) | faits de plateforme vérifiés ou non (Android/Samsung ; SIEM, DNS, proxy), avec niveaux de confiance |
| [`android/ARCHITECTURE-CODE.md`](../../android/ARCHITECTURE-CODE.md) | modules Gradle, **recette pour ajouter un collecteur**, conventions de test |
| [`android/README.md`](../../android/README.md), [`infra/README.md`](../../infra/README.md), [`server/collector/README.md`](../../server/collector/README.md), [`server/console/README.md`](../../server/console/README.md) | référence de chaque composant |

Règles de `CLAUDE.md` à ne pas oublier : aucune furtivité ; le serveur n'envoie au téléphone que des commandes d'une liste fermée
(les sensibles signées par un code qu'il ne connaît pas), **jamais de configuration ni de politique** ; aucune dépendance Google
dans l'agent ; contenu privé de tiers réduit au minimum (la lecture des notifications vit dans l'APK compagnon, optionnel) ;
tout collecteur désactivable ; tout réversible. **Ne
jamais committer de secrets** (`.env`, clés, `.vigie`, `.p12`, keystore) ; dire clairement ce qui a été exécuté et ce qui ne
l'a pas été.

## 3. Prérequis par composant

| Composant | Outils | Remarque |
|---|---|---|
| Agent Android (`android/`) | JDK 17 ou plus (21 vérifié), SDK Android (`platforms;android-37.0`, `build-tools;36.0.0`, `platform-tools`) ; voir [guide 02](02-compiler-apk.md) | Gradle 9.9.1 et AGP 9.5.1 viennent du wrapper et du projet |
| Collecteur (`server/collector/`) | Go 1.24 | sans CGO ; `go test -race` exige un compilateur C (sous Windows, utilisez `go test ./...` sans `-race` si vous n'en avez pas) |
| Console (`server/console/`) | Node 22, npm | `npm run verify` exige Chromium via Playwright installé globalement |
| Infrastructure (`infra/`) | Docker Engine 26 ou plus, bash, openssl, curl | scripts **bash** : sous Windows, WSL2 avec Docker (non essayé) ; en pratique ils se testent sur le VPS ou un Linux |
| Règles Wazuh | la pile Docker en marche | `./wazuh/tests/run-tests.sh` passe par `docker compose exec` |

## 4. Construire et tester, composant par composant

**Agent Android et compagnon** (depuis `android/` ; modules `:core`, `:collectors`, `:policy`, `:app` et `:notifier`) :

```bash
./gradlew lint test assembleDebug assembleRelease        # Windows : .\gradlew.bat …
./gradlew :policy:test                                    # un seul module (:core, :collectors, :policy, :app)
```

C'est la vérification complète exigée avant de committer (`android/ARCHITECTURE-CODE.md`). Lint : 0 erreur (pas de baseline,
`abortOnError`). Les tests sont des **tests JVM purs** (392 au dernier décompte de `android/README.md`) : pas d'émulateur, pas de
Robolectric (ses jars Android étaient inaccessibles dans l'environnement de développement ; sur votre PC, c'est à réétudier).
Le banc de test partagé est dans les `testFixtures` de `:core` (`CollectorHarness`, référence `Contract`). Aucun test
n'est instrumenté : tout comportement sur appareil se vérifie avec le [guide 06](06-verifications-sur-appareil.md).

**Collecteur** (depuis `server/collector/`) :

```bash
go build -o bin/vigie-collector .
go vet ./... && go test -race ./...
```

Pour embarquer la console dans le binaire : `(cd ../console && npm ci && npm run build) && rm -rf web/dist && cp -r ../console/dist web/dist`
puis `go build`. Sans `web/dist/` (non versionné), c'est la page de `web/fallback/` qui est servie. Image Docker (contexte
`server/`, construit aussi la console) : `docker build -t vigie-collector:local server/`.

**Console** (depuis `server/console/`) :

```bash
npm ci
npm run typecheck && npm run lint && npm test
npm run build
npm run verify        # parcours Chromium contre le serveur factice servant dist/
```

**Règles Wazuh** (pile lancée, depuis `infra/`) : `./wazuh/tests/run-tests.sh` (121 cas ; `./wazuh/tests/run-tests.sh 015 100181`
filtre par sous-chaîne du nom de cas). Les cas se régénèrent avec `wazuh/tests/generer-cas.py`.

## 5. Travailler sans téléphone : le collecteur et le simulateur en local

Le simulateur (`vigie-collector sim`) envoie par l'API d'ingestion des événements réalistes de tous les types du catalogue
(journée type autour de Paris, y compris les événements rares : redémarrage, traceur BLE, 2G, `agent.tamper`, ADB…). Depuis les
versions 1.1 et 1.2 il peut aussi jouer un **agent de commandes** (qui se connecte au flux de commandes et exécute les ordres
signés par la console), un **faux AdGuard Home** et des **scénarios d'attaque** cohérents dans le temps : c'est le moyen de
travailler sans téléphone sur les commandes, le pistage et les détections.

**Collecteur + simulateur + console, sans Docker** (depuis `server/collector/`) :

```bash
export VIGIE_DATA_DIR=$PWD/.dev VIGIE_LISTEN=127.0.0.1:8080 VIGIE_COOKIE_SECURE=false \
       VIGIE_EXPORT_NDJSON=$PWD/.dev/export/events.ndjson VIGIE_PUBLIC_INGEST_URL=http://127.0.0.1:8080
# facultatif : VIGIE_CONSOLE_DIR=$PWD/../console/dist  (console servie depuis le disque)
go run . serve &
go run . enroll --name s25 --out .dev/s25.vigie
printf '%s\n' 'motdepasse-console' | go run . user set-password admin
go run . sim --enroll .dev/s25.vigie --backfill 48h --follow
```

Console : <http://127.0.0.1:8080/> (`admin` / `motdepasse-console`).

```powershell
cd server\collector
$env:VIGIE_DATA_DIR = "$PWD\.dev"; $env:VIGIE_LISTEN = '127.0.0.1:8080'; $env:VIGIE_COOKIE_SECURE = 'false'
$env:VIGIE_EXPORT_NDJSON = "$PWD\.dev\export\events.ndjson"; $env:VIGIE_PUBLIC_INGEST_URL = 'http://127.0.0.1:8080'
# terminal 1 :
go run . serve
# terminal 2 (mêmes variables d'environnement) :
go run . enroll --name s25 --out .dev\s25.vigie
'motdepasse-console' | go run . user set-password admin
go run . sim --enroll .dev\s25.vigie --backfill 48h --follow
```

(transcription non essayée). Le dossier `.dev/` est ignoré par git. En `http://` local, le simulateur pose lui-même
l'en-tête `X-Vigie-Client-Cert-Sha256` (accepté car `127.0.0.1` est un proxy de confiance par défaut).

**Scénarios d'attaque, commandes et faux AdGuard** (depuis `server/collector/`, détail dans son README) :

```bash
export VIGIE_DATA_DIR=$PWD/.dev VIGIE_LISTEN=127.0.0.1:8080 VIGIE_COOKIE_SECURE=false \
       VIGIE_EXPORT_NDJSON=$PWD/.dev/export/events.ndjson VIGIE_PUBLIC_INGEST_URL=http://127.0.0.1:8080 \
       VIGIE_ADGUARD_URL=http://127.0.0.1:3001 VIGIE_ADGUARD_USER=vigie VIGIE_ADGUARD_PASSWORD=adguard-demo \
       VIGIE_ADGUARD_LEVELS_FILE=$PWD/examples/adguard-levels.example.json VIGIE_ADGUARD_POLL_S=10 \
       VIGIE_DETECT_INTERVAL_S=15
go run . serve &
go run . enroll --name s25 --out .dev/s25.vigie
printf '%s\n' 'motdepasse-console' | go run . user set-password admin
go run . sim --enroll .dev/s25.vigie --backfill 72h --follow --scenario tout \
       --fake-adguard 127.0.0.1:3001 --fake-adguard-user vigie --fake-adguard-password adguard-demo \
       --command-code 'correct horse battery staple'
```

- `--scenario sain|fraude-sms|cheval-de-troie|proxy|spam|exfiltration|contournement-dns|espion|sms-discret|tout` (plusieurs
  séparés par des virgules) ; `sms-discret` reproduit l'attaque subie par le propriétaire (application de boutique, `SEND_SMS`
  accordée 25 à 30 h après l'installation) ; `--app-ops=false` simule l'absence du comptage expérimental (le scénario donne alors
  `detect.new_app_risky` et `detect.sms_permission`, jamais `detect.sms_abuse`).
- `--commands stream|poll|off`, `--poll-interval`, `--command-code`, `--allow-wipe`, `--clock-skew` : l'agent de commandes simulé
  (le code d'essai du contrat est `correct horse battery staple`, avec `device_id` `dev_0123456789abcdef` pour le vecteur de test).
- Les détections apparaissent au passage qui suit l'arrivée des données (`VIGIE_DETECT_INTERVAL_S`), celles qui dépendent
  du journal d'AdGuard après son relevé (`VIGIE_ADGUARD_POLL_S`). Ces commandes n'ont pas été relancées pour ce guide : elles sont
  celles du README du collecteur.

**Développer la console contre le vrai collecteur** (autre terminal, depuis `server/console/`) :

```bash
VIGIE_API_TARGET=http://127.0.0.1:8080 npm run dev        # http://localhost:5173
```

**Console seule, avec un serveur factice** : `npm run mock` (http://127.0.0.1:8787, `admin` / `vigie`) puis `npm run dev`. Le
serveur factice génère sept jours de télémétrie et accepte `POST /__mock/control` (pannes, session expirée, latence).

**Vérifier l'agent contre le vrai collecteur, sans téléphone.** Trois essais croisés du module `:app`, ignorés tant que leurs
variables ne sont pas définies (mode d'emploi dans l'en-tête de chaque fichier ; commandes non exécutées pour ce guide) :
`CrossServerTest` (le vrai tampon et le vrai envoi de l'agent, avec les événements types des collecteurs),
`CrossCommandsTest` (le canal de commandes : commandes créées par l'API console avec un `payload` et une signature construits comme
la console, livrées par le vrai flux SSE puis par l'interrogation, vérifiées par le vrai vérificateur ; variables
`VIGIE_CROSS_ENROLL`, `VIGIE_CROSS_URL`, `VIGIE_CROSS_CONSOLE_USER`, `VIGIE_CROSS_CONSOLE_PASSWORD`, et `VIGIE_CROSS_TS_*` /
`VIGIE_CROSS_REDELIVERY_*` pour les cas signés par le code de la console et le renvoi après 5 minutes) et `CrossDetectionsTest`
(le vrai code des collecteurs `app_risk`, `app_role`, `app_ops` raconte une fraude au SMS au vrai collecteur). Exemple pour le
premier, contre le collecteur lancé ci-dessus :

```bash
cd android
VIGIE_CROSS_ENROLL=$PWD/../server/collector/.dev/s25.vigie VIGIE_CROSS_URL=http://127.0.0.1:8080 \
  ./gradlew :app:testDebugUnitTest --tests '*CrossServerTest*' --rerun
```

**Pile Docker complète en local** (Caddy, Wazuh, AdGuard) : possible avec `sudo ./install.sh --domain vigie.lan --tls internal`
(AC interne de Caddy ; il faut alors faire confiance à `infra/data/caddy/server-root-ca.crt`, résoudre les noms vers la machine,
8 Go de RAM libres). C'est le mode des essais du 15/11/2026 (`infra/README.md` §11). Il n'y a **pas de pas-à-pas** documenté
pour y brancher le simulateur à travers Caddy en mTLS ; l'installation d'essai est décrite à `infra/README.md` §11.1 et §11.2
(simulateur dans un conteneur du réseau `vigie`), c'est un travail à mettre au propre si vous en avez besoin.

## 6. Boucle de travail avec les retours de l'appareil

1. Faites la première semaine d'essai avec le [guide 06](06-verifications-sur-appareil.md) et notez chaque écart (fiche de rapport).
2. Donnez à Claude Code la fiche (identifiant V…, texte exact, version, traces) et demandez-lui de reproduire le problème
   par un **test** quand c'est possible : le contrat (`Contract`) et le banc de test (`CollectorHarness`) servent à cela.
3. Une évolution du format d'un événement commence par `docs/contrat/contrat.md`, puis les règles Wazuh
   (`infra/wazuh/rules/` et leurs cas de test), puis le collecteur, puis la console, puis l'agent.
4. Mettez à jour `docs/ETAT.md` (ce qui est désormais vérifié sur appareil) et, pour la documentation utilisateur, le README
   racine (tableau d'état de vérification) et les guides concernés.

## 7. Écarts encore présents entre le code, les scripts et la documentation

Dernière vérification : état du dépôt au 16/11/2026, après les versions 1.1 et 1.2 et leurs revues. Les écarts relevés lors des
rédactions précédentes des guides et corrigés depuis ne sont plus listés (commande d'enrôlement citée dans l'application, écran
Politique sans « Tout décocher » et verrou DNS allumé par défaut, mot de passe de la console réécrit par `install.sh`,
configuration d'AdGuard écrasée, absence de notifications d'alerte, renouvellement du certificat client et des certificats Wazuh,
chemins relatifs des scripts bash, politique d'exécution PowerShell, `install-apk` retombant sur l'APK de débogage, texte de
`android/README.md` sur l'absence de commande de renouvellement).

- **`docs/ETAT.md`** : le tableau « Où on en est » donne encore 221 tests JVM pour l'agent (le dernier décompte de
  `android/README.md` est 392) et la console à 43 tests ; les lots de la v1.2 (« en cours », « à faire ») et « Alignement des
  guides… à faire » décrivent des travaux terminés ; la ligne « Guides utilisateur » ne cite pas le guide 08.
- **`server/collector/README.md`, lignes 320-321** (section du simulateur) : niveaux de risque `medium` 30-59 et `high` 60-100 ;
  le contrat §11.2/§11.4 et `android/README.md` donnent `medium` 30-69 et `high` 70-100.
- **`server/console/README.md`, ligne 252** : repli sur le score « < 35 faible, < 65 moyen » quand le niveau est absent ; ces seuils ne
  sont plus ceux du contrat (30 et 70), et le contrat dit que la console ne recalcule pas le niveau.
- **`infra/README.md`, §6.4** (« Limite constatée lors de l'essai… à corriger dans le collecteur ») : le collecteur lit désormais le
  journal d'AdGuard par pages sans `older_than` arbitraire (`server/collector/README.md`, « Lecture », `readLog`) ; le texte de
  l'infrastructure décrit encore l'ancienne lecture comme un défaut ouvert.
- **`infra/README.md` §7.4 et §7.2** : le tableau des détections ne cite pas `inventory_mismatch` (règle 100481, niveau 12,
  ajoutée dans `infra/wazuh/rules/vigie_rules.xml`) ; le texte compte 209 cas de règles, il y a 210 fichiers dans
  `infra/wazuh/tests/cases/`.
- **Désenrôler** efface toujours clé, jeton et événements en attente (voulu, annoncé par l'application) : seul « Importer un
  nouveau fichier .vigie » conserve le tampon.
- **Notifications des alertes** : optionnelles et désactivées par défaut ; SMTP avec TLS et authentification, et un vrai serveur
  ntfy, ne sont pas testés (`infra/README.md` §8.5). Les échéances des certificats d'appareils ne sont pas notifiées. Les alertes de
  niveau 8 (permission SMS accordée, nouvelle appli SMS par défaut) ne partent pas au seuil par défaut (10).
- **Non vérifiés sur appareil, par construction** : tout le canal de commandes (dont `wipe`), les gardes et la quarantaine, le
  comptage `app.ops` (format jamais observé sur le Samsung), le compagnon et Play Protect, `pm unhide`/`pm unsuspend` au shell ADB
  (probablement refusés), le repli du DNS privé avec un utilisateur non affilié, une réponse `400` réelle (bissection), voir le
  [guide 06](06-verifications-sur-appareil.md).

## 8. Pistes suivantes déjà identifiées

| Piste | Où elle est décrite |
|---|---|
| **VPN local par application** (type NetGuard/RethinkDNS) : attribution de **tous** les flux, UDP et IP en dur compris (`ConnectivityManager.getConnectionOwnerUid`). Un seul VPN actif sur Android, incompatible avec WireGuard | `docs/ARCHITECTURE.md` (« pas de VPN local en v1 »), recherche plateforme §3.5 et §8 |
| **Code de déverrouillage (ou authentification) avant d'affaiblir une garde** ou de libérer une quarantaine : aujourd'hui l'écran de Vigie ne le demande pas, et un service d'accessibilité déjà activé peut y appuyer | `android/README.md`, « Ce que les gardes ne peuvent pas empêcher » (« piste v1.3 ») |
| **Limite de débit des SMS imposée par le système** (plafonner l'envoi de SMS plutôt que de seulement le compter, puisque les SMS ne passent pas par le réseau IP) | idée du propriétaire, **non étudiée dans les documents du dépôt** ; le comptage actuel (`app.ops`) est expérimental |
| **Listes d'exclusion du compagnon de notifications éditables dans l'agent** (aujourd'hui éditées dans le compagnon et stockées dans les réglages de l'agent, qui n'a pas de type de réglage « liste » éditable dans son propre écran) | `android/README.md`, « Notifications (APK compagnon) › Régler » |
| **Knox SDK**, à réévaluer seulement si une clé de licence est obtenue (pare-feu par application, journal d'audit Knox) | recherche plateforme §8 |
| **Tuiles de carte auto-hébergées** (tileserver-gl, fichier PMTiles) | `infra/README.md` §10.2 |
| **Attribution caméra/micro par `DUMP`** : promouvoir le réglage expérimental si les essais le valident | `android/README.md` (collecteurs Caméra et Microphone), recherche §4 et §6 |
| **Politiques DPM supplémentaires** : `setMtePolicy`, `setSystemUpdatePolicy`, `setAppFunctionsPolicy`, `setNearbyAppStreamingPolicy`, `setContentProtectionPolicy` | recherche §3.10 |
| **Détection de brouillage ou d'usurpation GNSS** (`GnssStatus`, mesures brutes) et exposition dans l'interface de l'arbitrage XTRA/SUPL | recherche §5 |
| **Collecte avant le premier déverrouillage** (Direct Boot) | `android/README.md` (« Fonctionnement ») |
| **Vérification des développeurs** : enregistrer la clé de signature (compte « distribution limitée ») ou passer par des mises à jour silencieuses via le Device Owner | recherche §9 |
| **Alternative plus légère à Wazuh** (moins de 4 Go de RAM) | `docs/research/serveur-siem-dns.md` §9 |
| WireGuard (déjà présent comme option, non testé), mode ClientID (déjà présent, joker non testé) | `infra/README.md` §6.3 et §10.1 |

Pistes qui ne viennent pas des documents de conception mais ressortent de ce travail : tester les notifications d'alerte avec un vrai
serveur ntfy et un relais SMTP authentifié ; signer les commandes sensibles depuis une copie de la console gardée hors du serveur
(`server/console/README.md`, « Ce que la signature dans le navigateur garantit »).
