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

Règles de `CLAUDE.md` à ne pas oublier : aucune furtivité ; flux à sens unique (le serveur ne commande jamais le téléphone) ;
aucune dépendance Google dans l'agent ; pas de contenu privé de tiers ; tout collecteur désactivable ; tout réversible. **Ne
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

**Agent Android** (depuis `android/`) :

```bash
./gradlew lint test assembleDebug assembleRelease        # Windows : .\gradlew.bat …
./gradlew :policy:test                                    # un seul module (:core, :collectors, :policy, :app)
```

C'est la vérification complète exigée avant de committer (`android/ARCHITECTURE-CODE.md`). Lint : 0 erreur (pas de baseline,
`abortOnError`). Les tests sont des **tests JVM purs** (180 au dernier décompte de `android/README.md` ; la revue de l'application en a ajouté depuis) : pas d'émulateur, pas de
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
(journée type autour de Paris, y compris les événements rares : redémarrage, traceur BLE, 2G, `agent.tamper`, ADB…).

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

**Développer la console contre le vrai collecteur** (autre terminal, depuis `server/console/`) :

```bash
VIGIE_API_TARGET=http://127.0.0.1:8080 npm run dev        # http://localhost:5173
```

**Console seule, avec un serveur factice** : `npm run mock` (http://127.0.0.1:8787, `admin` / `vigie`) puis `npm run dev`. Le
serveur factice génère sept jours de télémétrie et accepte `POST /__mock/control` (pannes, session expirée, latence).

**Vérifier l'agent contre le vrai collecteur, sans téléphone.** Le test `CrossServerTest` (module `:app`) envoie les événements
types des 21 collecteurs, par le vrai tampon et le vrai envoi de l'agent, au collecteur lancé ci-dessus ; il est ignoré tant que
`VIGIE_CROSS_ENROLL` n'est pas défini (mode d'emploi dans l'en-tête du fichier du test ; commande non exécutée pour ce guide) :

```bash
cd android
VIGIE_CROSS_ENROLL=$PWD/../server/collector/.dev/s25.vigie VIGIE_CROSS_URL=http://127.0.0.1:8080 \
  ./gradlew :app:testDebugUnitTest --tests '*CrossServerTest*' --rerun
```

**Pile Docker complète en local** (Caddy, Wazuh, AdGuard) : possible avec `sudo ./install.sh --domain vigie.lan --tls internal`
(AC interne de Caddy ; il faut alors faire confiance à `infra/data/caddy/server-root-ca.crt`, résoudre les noms vers la machine,
8 Go de RAM libres). C'est le mode des essais du 15/11/2026 (`infra/README.md` §11). Il n'y a **pas de pas-à-pas** documenté
pour y brancher le simulateur à travers Caddy en mTLS ; c'est un travail à faire si vous en avez besoin.

## 6. Boucle de travail avec les retours de l'appareil

1. Faites la première semaine d'essai avec le [guide 06](06-verifications-sur-appareil.md) et notez chaque écart (fiche de rapport).
2. Donnez à Claude Code la fiche (identifiant V…, texte exact, version, traces) et demandez-lui de reproduire le problème
   par un **test** quand c'est possible : le contrat (`Contract`) et le banc de test (`CollectorHarness`) servent à cela.
3. Une évolution du format d'un événement commence par `docs/contrat/contrat.md`, puis les règles Wazuh
   (`infra/wazuh/rules/` et leurs cas de test), puis le collecteur, puis la console, puis l'agent.
4. Mettez à jour `docs/ETAT.md` (ce qui est désormais vérifié sur appareil) et, pour la documentation utilisateur, le README
   racine (tableau d'état de vérification) et les guides concernés.

## 7. Écarts constatés en rédigeant les guides (à traiter ou à décider)

- **Commande d'enrôlement.** `android/README.md` (section « Enrôler », étape 1) et le texte de l'écran d'enrôlement de l'application
  (`enroll_explanation`) citent `vigie-collector enroll --name s25 --out s25.vigie`. Avec l'installation Docker, la commande est
  `sudo ./enroll.sh s25` (`infra/enroll.sh`). Les deux produisent le même fichier ; le texte devrait citer `enroll.sh`.
- **Écran Politique** : aucun bouton « tout décocher » (37 interrupteurs à éteindre pour appliquer le DNS seul) ; « Verrouiller le
  réglage » du DNS est **allumé par défaut**, alors qu'il retire une porte de sortie lors du premier essai.
- **Réenrôlement** : tant qu'un enrôlement existe, l'écran n'offre que « Désenrôler » (qui **efface les événements en attente**) ; il n'y a
  pas de renouvellement du certificat client en place.
- **`install.sh` rejoue le mot de passe de la console** à partir de `.env` : un changement fait seulement par
  `user set-password` est annulé au passage suivant.
- **Aucune notification des alertes** (`email_notification` à `no`, aucune intégration) : l'absence de l'agent ou une alerte de niveau 12
  ne se voit que si vous ouvrez la console.
- **`install-apk`** prend `app-release.apk` puis, à défaut, l'APK de **débogage** (un build release non signé,
  `app-release-unsigned.apk`, n'est pas reconnu) ; une version récente du script demande confirmation pour un APK de
  débogage, mais ne propose pas de repli plus clair. En bash, un chemin relatif en argument est lu depuis
  `android/scripts/` (le script y change de dossier) : un chemin absolu est plus sûr.
- **Scripts PowerShell** : la politique d'exécution par défaut de Windows les bloque ; ni les scripts ni le README ne le
  mentionnent (documenté dans les guides).
- **`docs/ETAT.md`** : la ligne « Guides d'installation » est encore « en cours ».
- Le certificat client expire après 2 ans et les certificats internes de Wazuh après 5 ans, sans procédure de renouvellement
  automatisée.

## 8. Pistes v2 déjà identifiées dans les documents

| Piste | Où elle est décrite |
|---|---|
| **VPN local par application** (type NetGuard/RethinkDNS) : attribution de **tous** les flux, UDP et IP en dur compris (`ConnectivityManager.getConnectionOwnerUid`). Un seul VPN actif sur Android, incompatible avec WireGuard | `docs/ARCHITECTURE.md` (« pas de VPN local en v1 »), recherche plateforme §3.5 et §8 |
| **Module de notifications séparé** et optionnel (APK à part : `app.notification`), pour ne pas déclencher Play Protect | `docs/contrat/contrat.md` (note de `app.notification`), recherche §2.4 et §9 |
| **Knox SDK**, à réévaluer seulement si une clé de licence est obtenue (pare-feu par application, journal d'audit Knox) | recherche plateforme §8 |
| **Tuiles de carte auto-hébergées** (tileserver-gl, fichier PMTiles) | `infra/README.md` §10.2 |
| **Attribution caméra/micro par `DUMP`** : promouvoir le réglage expérimental si les essais le valident | `android/README.md` (collecteurs Caméra et Microphone), recherche §4 et §6 |
| **Politiques DPM supplémentaires** : `setMtePolicy`, `setSystemUpdatePolicy`, `setAppFunctionsPolicy`, `setNearbyAppStreamingPolicy`, `setContentProtectionPolicy` | recherche §3.10 |
| **Détection de brouillage ou d'usurpation GNSS** (`GnssStatus`, mesures brutes) et exposition dans l'interface de l'arbitrage XTRA/SUPL | recherche §5 |
| **Collecte avant le premier déverrouillage** (Direct Boot) | `android/README.md` (« Fonctionnement ») |
| **Vérification des développeurs** : enregistrer la clé de signature (compte « distribution limitée ») ou passer par des mises à jour silencieuses via le Device Owner | recherche §9 |
| **Alternative plus légère à Wazuh** (moins de 4 Go de RAM) | `docs/research/serveur-siem-dns.md` §9 |
| WireGuard (déjà présent comme option, non testé), mode ClientID (déjà présent, joker non testé) | `infra/README.md` §6.3 et §10.1 |

Les écarts du §7 (notifications d'alerte, renouvellement du certificat client, ergonomie de l'écran Politique) sont des
candidats naturels, ajoutés par ce guide et non issus des documents de conception.
