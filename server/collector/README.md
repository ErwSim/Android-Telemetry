# vigie-collector

Collecteur Go de Vigie : API d'ingestion (téléphone → serveur), stockage SQLite, API et fichiers de la
console web, export NDJSON vers Wazuh, PKI cliente, CLI d'enrôlement et simulateur. Spécification :
[`docs/contrat/contrat.md`](../../docs/contrat/contrat.md) (§3 à §7, commandes à distance §8, vue « pistage » §9,
détections §11.3).

## Construire

```sh
cd server/collector
go build -o bin/vigie-collector .          # Go 1.24, sans CGO ; console = page de substitution
go vet ./... && go test -race ./...
```

Pour embarquer la console : `(cd ../console && npm ci && npm run build) && rm -rf web/dist && cp -r ../console/dist web/dist`
puis `go build`. `web/dist/` n'est pas versionné ; sans lui, `web/fallback/` est servi.

Image Docker (contexte `server/`, construit aussi la console) : `docker build -t vigie-collector:local server/`.
Image finale `scratch`, utilisateur 65532, binaire `/usr/local/bin/vigie-collector`, `HEALTHCHECK` intégré
(`vigie-collector healthcheck`). Derrière un proxy à AC privée :
`docker build --network host --build-arg HTTPS_PROXY=… --secret id=ca_bundle,src=ca.crt …` (les images de
base se changent par `--build-arg NODE_IMAGE=… GO_IMAGE=…`).

## Lancer en développement (avec données simulées)

```sh
export VIGIE_DATA_DIR=$PWD/.dev VIGIE_LISTEN=127.0.0.1:8080 VIGIE_COOKIE_SECURE=false \
       VIGIE_EXPORT_NDJSON=$PWD/.dev/export/events.ndjson VIGIE_PUBLIC_INGEST_URL=http://127.0.0.1:8080
# facultatif : VIGIE_CONSOLE_DIR=$PWD/../console/dist (console servie depuis le disque)
go run . serve &
go run . enroll --name s25 --out .dev/s25.vigie
printf '%s\n' 'motdepasse-console' | go run . user set-password admin
go run . sim --enroll .dev/s25.vigie --backfill 48h --follow     # historique puis temps réel
```

Console : <http://127.0.0.1:8080/> (admin / motdepasse-console). En `http://` local, le simulateur pose
lui-même l'en-tête `X-Vigie-Client-Cert-Sha256` (accepté car 127.0.0.1 est un proxy de confiance par défaut).

Avec commandes à distance et vue « pistage » (faux AdGuard Home intégré au simulateur, aucun téléphone ni
AdGuard réel nécessaire) :

```sh
export VIGIE_ADGUARD_URL=http://127.0.0.1:3001 VIGIE_ADGUARD_USER=vigie VIGIE_ADGUARD_PASSWORD=adguard-demo \
       VIGIE_ADGUARD_LEVELS_FILE=$PWD/examples/adguard-levels.example.json VIGIE_ADGUARD_POLL_S=10
go run . serve &          # (avec les variables précédentes)
go run . sim --enroll .dev/s25.vigie --backfill 6h --follow \
       --command-code 'correct horse battery staple' \
       --fake-adguard 127.0.0.1:3001 --fake-adguard-user vigie --fake-adguard-password adguard-demo
```

Le simulateur ouvre le flux de commandes (`--commands poll` pour l'interrogation), vérifie chaque commande
comme l'agent (§8, avec le code `--command-code`), l'« exécute » (message sur la sortie d'erreur), renvoie le
résultat et l'événement `command.result`. Refus réalistes : mauvais code (`bad_signature`, et `locked_out`
après 5), `wipe` sans `--allow-wipe` (`disabled`), horloge décalée `--clock-skew 2h` (`expired`), pas de
`--command-code` (`no_code_configured`). Le faux AdGuard Home reçoit une requête par occurrence de chaque
`net.dns` simulé (ClientID = nom de l'appareil, `--fake-adguard-client`), décide comme AdGuard (listes
activées, règles utilisateur, `$important`) et sert `/control/querylog`, `/control/filtering/status`,
`set_rules`, `set_url`, `add_url` ; il n'écoute qu'une fois l'historique (`--backfill`) inscrit dans son
journal. Il connaît les URL de `examples/adguard-levels.example.json`.

## Commandes

| Commande | Rôle |
|---|---|
| `serve` | Serveur HTTP ; crée la base, applique les migrations et crée l'AC si absentes. |
| `enroll --name N --out F.vigie [--ingest-url URL] [--force]` | Nouvel appareil + fichier d'enrôlement (mode 0600). |
| `renew <device_id> --out F.vigie [--ingest-url URL] [--force]` | Nouveau jeton et nouveau certificat pour le **même** appareil (contrat §4), fichier 0600. Refusé pour un appareil inconnu ou révoqué ; un second `renew` avant bascule remplace le couple en attente. |
| `devices [--json]`, `revoke <device_id>` | Liste (avec la date d'expiration du certificat courant, « à renouveler » sous 30 jours, et « renouvellement en attente »), révocation (effective à la requête suivante, même serveur lancé ; invalide aussi le couple en attente). En JSON : `cert_not_after`, `renewal_pending`, `renewal_issued_at`, `pending_cert_not_after`. |
| `user set-password <nom>` | Compte console ; mot de passe ≥ 12 caractères, lu sans écho sur un terminal ou sur une ligne de stdin. |
| `sim --enroll F [--url U] [--backfill 24h] [--follow] [--rate 1] [--interval 15s] [--seed N]` | Simulateur (voir plus bas). |
| `sim … [--scenario sain\|fraude-sms\|cheval-de-troie\|proxy\|spam\|exfiltration\|contournement-dns\|espion\|tout] [--app-ops=false]` | Scénarios d'attaque (plusieurs séparés par des virgules) et absence d'`app.ops` ; voir « Détections ». |
| `sim … [--commands stream\|poll\|off] [--poll-interval 1m] [--command-code C] [--allow-wipe] [--clock-skew D] [--notification-content=false] [--fake-adguard ADDR --fake-adguard-user U --fake-adguard-password P --fake-adguard-client ID]` | Agent de commandes simulé (mode continu) et faux AdGuard Home (voir plus haut). |
| `healthcheck [--url U]`, `version` | Sonde `/healthz` (Compose), version. |

Variables : celles du contrat §7, plus `VIGIE_TILE_URL` (§6, défaut OpenStreetMap ; servie par
`GET /config.json` et reprise dans la CSP) et `VIGIE_LOG_LEVEL` (`debug`/`info`/`warn`/`error`), et :

| Variable | Défaut | Rôle |
|---|---|---|
| `VIGIE_CMD_KEEPALIVE_S` | `120` | Commentaire de maintien du flux de commandes (5 à 3600 s) ; à chaque maintien, les identifiants de l'appareil sont revérifiés (révocation, renouvellement) et les commandes à remettre de nouveau sont envoyées. |
| `VIGIE_ADGUARD_URL` | vide | API d'administration d'AdGuard Home (ex. `http://adguardhome:3000`), `http(s)://hôte[:port][/préfixe]` sans identifiants, requête ni fragment. Vide : vue « pistage » depuis `net.dns` seul. |
| `VIGIE_ADGUARD_USER` / `VIGIE_ADGUARD_PASSWORD` | vides | Authentification de base auprès d'AdGuard Home (jamais journalisée). |
| `VIGIE_ADGUARD_LEVELS_FILE` | vide | Fichier de correspondance niveau → listes (format ci-dessous), lu et validé au démarrage (erreur fatale s'il est invalide). Vide : `PUT /tracking/level` répond `503`. |
| `VIGIE_ADGUARD_POLL_S` | `60` | Intervalle de relevé du journal d'AdGuard Home (10 s au moins). |
| `VIGIE_ADGUARD_CLIENTS` | vide | Facultatif : `device_id=client,…` (client = ClientID DoT ou IP vue par AdGuard ; plusieurs paires par appareil possibles). Avec `device_id`, la vue ne compte alors que les requêtes de ces clients ; sans correspondance, tout le journal d'AdGuard est attribué à l'appareil demandé. |

## Fichier de niveaux AdGuard (`VIGIE_ADGUARD_LEVELS_FILE`)

JSON (UTF-8, 1 Mio au plus), produit par l'infrastructure. Exemple complet :
[`examples/adguard-levels.example.json`](examples/adguard-levels.example.json) (ses URL sont illustratives :
l'infrastructure doit vérifier celles qu'elle retient).

```json
{
  "version": 1,
  "lists": {
    "adguard_dns":    { "name": "AdGuard DNS filter", "url": "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt" },
    "hagezi_samsung": { "name": "HaGeZi - Native Tracker Samsung", "url": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/native.samsung.txt" },
    "exceptions":     { "name": "Exceptions Vigie", "url": "/opt/adguardhome/work/userfilters/vigie-allow.txt", "allowlist": true }
  },
  "levels": [
    { "key": "permissif", "name": "Permissif", "description": "…", "lists": ["adguard_dns"] },
    { "key": "equilibre", "name": "Équilibré", "description": "…", "lists": ["adguard_dns", "hagezi_samsung", "exceptions"] },
    { "key": "strict",    "name": "Strict",    "description": "…", "lists": ["adguard_dns", "hagezi_samsung", "exceptions"] }
  ]
}
```

- `version` : `1`. Tout champ inconnu est refusé.
- `lists` : identifiant (`[a-z0-9_-]{1,64}`) → `name` (1 à 128 caractères imprimables : nom donné à la liste
  si Vigie l'ajoute), `url` (`http://` ou `https://`, ou chemin absolu d'un fichier local d'AdGuard Home,
  2048 caractères au plus, chaque URL une seule fois) et `allowlist` (facultatif, défaut `false` : liste
  d'autorisation, `whitelist_filters` d'AdGuard). Une liste est reconnue dans AdGuard par son URL **exacte**
  et son genre (blocage / autorisation).
- `category` (facultatif) : ce que bloque la liste, parmi `threat` (hameçonnage, maliciels, serveurs de commande,
  arnaques), `ads`, `tracking`, `mixed` (liste générale qui mêle publicité, pistage et quelques menaces), `custom`,
  `allowlist`. **Seule `threat` change le comportement** : un blocage dû à une liste `threat` (reconnue dans
  AdGuard Home par son URL exacte) alimente `detect.threat_domain`. Une valeur inconnue est refusée (une faute de
  frappe ne doit pas éteindre la détection en silence) ; une liste d'autorisation ne peut pas être `threat`.
  Aucune déduction depuis le nom ou l'URL : sans `"category": "threat"`, aucune liste n'est une liste de menaces
  (`infra/adguard/niveaux.json` doit donc l'ajouter à `hagezi_tif`). Les blocages de la navigation sécurisée
  d'AdGuard Home (`FilteredSafeBrowsing`) comptent aussi comme menaces.
- `levels` : exactement les trois niveaux `permissif`, `equilibre`, `strict` (une fois chacun, dans n'importe
  quel ordre), avec `name` (64 caractères), `description` (500, peut être vide) et `lists` (identifiants de
  `lists`, sans doublon).
- Appliquer un niveau (`PUT /tracking/level`) : chaque liste du fichier est activée si elle figure dans le
  niveau, désactivée sinon (`POST /control/filtering/set_url`, nom actuel conservé) ; une liste absente
  d'AdGuard et requise est ajoutée (`POST /control/filtering/add_url`, AdGuard la télécharge : `502` s'il
  échoue). Les listes qu'AdGuard connaît mais que le fichier ne cite pas ne sont **jamais** touchées.
- Niveau courant (`level` de `GET /tracking/summary` et `/tracking/level`) : le premier niveau dont les
  listes du fichier sont exactement celles activées dans AdGuard ; absent si l'état ne correspond à aucun
  niveau (listes changées à la main) ou si AdGuard est injoignable.

## Détections (contrat §11.3)

Détections comportementales calculées côté serveur sur les données déjà reçues, pour être alerté d'un abus
**quel que soit le vecteur** (SMS, relais réseau, exfiltration, spam, contournement du filtrage). Chaque détection
est un événement du collecteur (`source = 'server'`, type `detect.*`, `boot_id` `server`) rattaché à l'appareil :
visible dans `/events`, diffusée sur `GET /stream`, exportée vers Wazuh avec `vigie.source = "server"`, et listée
par `GET /detections`. `data` : `package` (si connu), `label`, `window_from`, `window_to`, `summary` (phrase en
français), `evidence` (objet court et factuel : compteurs, quelques adresses ou domaines ; jamais de contenu de
notification ni de message). Sévérité (`sev`) : 2, ou 3 quand le signal est sans ambiguïté (voir chaque
détection). Fenêtres en heures et jours **UTC**.

**Fonctionnement** (`internal/detect`) : une fonction pure par détection (`rules.go`, testée seule), alimentée par
un travail d'arrière-plan (`engine.go`) toutes les `VIGIE_DETECT_INTERVAL_S`. L'ingestion marque dans
`detect_dirty` chaque heure (de `ts`) d'un appareil où arrive un événement utile (`net.dns`, `net.connect`,
`net.usage`, `app.ops`, `app.risk`, `app.installed`, `app.permission_changed`, `app.special_access`, `app.role`) ;
le relevé d'AdGuard Home marque les heures où il compte un blocage « menace ». Le travail ne relit que ces heures
(et leurs jours) dans les agrégats horaires — `usage_counts` (octets envoyés par application et par heure),
`top_counts` `connect_dest` (adresses et ports par application et par heure), `top_counts` `dns_hostname`,
`tracking_counts.threat`, `ops_counts` (migration 6 et 7) — et, pour les événements d'applications (rares), l'index
`(device_id, type, ts_ms)` : **aucun balayage de la table `events`**. Un lot en retard (journaux réseau livrés
1 h 30 à 2 h plus tard, ou des jours après une période hors ligne) remarque ses heures, qui sont réévaluées.
Idempotence : `detections` est unique sur (appareil, type, sujet, début de fenêtre), vérifié dans la transaction
qui écrit la détection et son événement ; réévaluer une fenêtre (lot tardif, redémarrage, passage suivant)
n'ajoute rien. Une heure remarquée pendant son évaluation reste à évaluer (compteur `gen`). Les lectures passent
par le pool en lecture seule (WAL : l'ingestion n'attend jamais) ; les écritures sont une courte transaction par
appareil et par tour de 256 heures ; un passage s'arrête après 20 s et reprend au suivant. À la mise à jour, la
migration 6 marque les deux derniers jours déjà stockés : les détections portent sur les données reçues ensuite.

**Mesure du coût** (`TestDetectionCost`, lancé par `VIGIE_DETECT_COST=89 go test ./internal/detect -run Cost -v` ;
16/11/2026, conteneur de développement, sans `-race`) : base de **3 052 379 événements** (89 jours simulés à
`--rate 2`, tous les scénarios d'attaque sur les 40 dernières heures, 520 Mo), soit 2 137 heures à évaluer.
Évaluation de tout l'arriéré : **1,9 s** (11 tours de 256 heures), **8 Mio de tas** au plus ; pendant ce temps,
l'ingestion de lots de 500 événements continue (latence médiane 13 ms, p99 36 ms, contre 5 et 21 ms sans le
travail). Passage courant après un lot tardif de deux heures : **23 ms**. Sur ces 89 jours, les seules détections
(31) concernent les applications des scénarios : aucune sur le parc sain.

| Détection | Ce qu'elle voit (fenêtre, sujet) | Seuil par défaut et justification | Limites et faux positifs prévisibles |
|---|---|---|---|
| `detect.threat_domain` | Une application a demandé (`net.dns`) un domaine qu'AdGuard Home a bloqué **au titre d'une liste `category: threat`** ou de sa navigation sécurisée, le même jour UTC (une heure de marge de chaque côté). Jour, sujet = application + domaine. Sév. 3, ou 2 pour le navigateur par défaut ou moins de 3 requêtes (un lien d'hameçonnage suivi une fois). | Aucun seuil : une liste de menaces est faite pour ne rien bloquer d'utile. | Rien sans AdGuard Home ni liste `threat` (journal au démarrage). Croisement par domaine exact sur la journée : si plusieurs appareils partagent AdGuard sans `VIGIE_ADGUARD_CLIENTS`, un blocage d'un appareil peut être attribué à la requête d'un autre qui a demandé le même domaine. Faux positifs : ceux de la liste elle-même (domaine légitime classé à tort) ; une application qui affiche des publicités piégées. |
| `detect.upload_spike` | Octets envoyés (`tx_bytes` de `net.usage`) par une application sur une heure > max(plancher, k × sa médiane horaire sur 14 jours). Médiane des heures **où l'application a envoyé quelque chose**. Heure, sujet = application. Sév. 2. | Plancher **1 Gio/h**, k = **10**. Un appel vidéo HD envoie 0,3 à 1 Gio/h, une sauvegarde de photos nocturne quelques centaines de Mio : sous un plancher plus bas, la détection sonnerait chaque semaine. L'exfiltration visée est massive (photothèque, enregistrements). | **Apprentissage** : tant que l'appareil a moins de `VIGIE_DETECT_UPLOAD_LEARN_DAYS` (7) jours d'historique `net.usage`, ou que l'application a moins de 24 heures actives sur 14 jours (application nouvelle), seul le plancher s'applique (`evidence.learning = true`) : la détection marche dès le premier jour pour les gros envois et ne s'affine qu'ensuite. Ne voit pas une exfiltration lente (quelques Mio par heure) ni ce qui passe par une autre application (navigateur, messagerie). `net.usage` est rangé dans l'heure de son `ts` (relevé de fin d'heure). Faux positifs : première sauvegarde complète d'une photothèque, envoi d'une longue vidéo, appel vidéo de plusieurs heures en très haute qualité, partage de connexion attribué à une application. |
| `detect.fanout` | Une application s'est connectée à plus de N adresses **distinctes** (`net.connect`, ports confondus) en une heure. Heure, sujet = application. Sév. 2. | **300** ; **100** pour une heure passée écran éteint (écran allumé 5 min au plus d'après `device.screen` ; état inconnu = allumé). Une heure de navigation intense ouvre 50 à 150 adresses écran allumé ; en arrière-plan, une application saine en contacte moins de 20. Un proxy résidentiel en relaie des centaines la nuit. | Ne voit que ce que la journalisation réseau du Device Owner rapporte (connexions TCP par `connect()`), pas le volume relayé. Faux positifs : client BitTorrent ou pair à pair, navigateur sur un site très chargé (écran allumé, rarement au-delà de 300), application de test de débit, scanner réseau, VPN qui serait vu comme une seule application. |
| `detect.mail_ports` | Une application qui n'est pas un client de messagerie connu s'est connectée aux ports **25, 465 ou 587** (envoi de courriel). Jour, sujet = application. Sév. 2, 3 à partir de 100 connexions ou 20 serveurs (volume de spam). | **1 connexion** : une application ordinaire n'a aucune raison d'envoyer du courriel elle-même. Liste des clients connus : [`internal/detect/mail_clients.txt`](internal/detect/mail_clients.txt), complétée par `VIGIE_DETECT_MAIL_CLIENTS`. | Le port 25 est souvent bloqué par les opérateurs (les tentatives sont vues quand même). Faux positifs : un client de messagerie absent de la liste (une alerte par jour jusqu'à l'ajout), une application qui envoie elle-même des rapports par SMTP. |
| `detect.dns_bypass` | Une application se connecte à un **résolveur DNS public connu** sur un port de `VIGIE_DETECT_DNS_BYPASS_PORTS` (443 : DNS sur HTTPS, 853 : DNS sur TLS) : ses requêtes échappent à AdGuard Home et à `net.dns`. Liste versionnée et lisible : [`internal/detect/resolvers.txt`](internal/detect/resolvers.txt) (Google, Cloudflare, Quad9, OpenDNS, AdGuard DNS public, NextDNS, Control D, CleanBrowsing, Mullvad, FDN…, seulement des adresses réservées au DNS). Jour, sujet = application. Sév. 2. | **1 connexion**. Le port 53 n'est pas suivi par défaut : se connecter à 8.8.8.8:53 est l'idiome courant des applications pour tester l'accès à Internet. | **Seconde heuristique du contrat (connexions massives vers des adresses jamais résolues) laissée de côté** : elle n'est pas fiable avec ces données — `net.dns` et `net.connect` arrivent par lots séparés, une adresse résolue peut servir des heures (cache, connexions longues), les applications pair à pair et d'appel (WebRTC, WhatsApp, Telegram) se connectent légitimement à des adresses apprises hors DNS, et les blocs CDN/anycast partagent des adresses entre noms ; elle sonnerait tous les jours. Ne voit pas un résolveur privé ou inconnu (DoH vers un domaine quelconque). Faux positifs : navigateur avec DoH intégré activé (Firefox, Chrome « DNS sécurisé »), application VPN ou « 1.1.1.1 » de Cloudflare, application de diagnostic réseau ; à exempter par `VIGIE_DETECT_DNS_BYPASS_EXEMPT` si c'est voulu. |
| `detect.sms_abuse` | D'après `app.ops` : une application autre que l'appli SMS par défaut (rôle `sms` d'`app.role` ou `default_apps` d'`app.special_access`, y compris un ancien titulaire du jour) a **envoyé ou tenté d'envoyer** des SMS — les tentatives refusées (`rejected_count`, par exemple par la garde SMS) comptent comme des envois —, ou une application en a envoyé ou tenté plus que le maximum du jour. Jour, sujet = application. Sév. 3. | **1** SMS pour une autre application (applications du système exceptées, et seulement quand l'appli SMS est connue) ; **200** par jour pour toute application (un usage intensif reste sous 100 ; le logiciel malveillant visé en envoie 2 000). | Muette sans `app.ops` (expérimental, peut ne jamais arriver) : pas d'erreur. Compteurs = bornes basses. Faux positifs : application d'opérateur ou de double SIM, application de sécurité qui envoie un SMS d'alerte, appli SMS tierce choisie dans la journée avant le relevé du rôle. |
| `detect.sensor_background` | D'après `app.ops` : micro (`record_audio`) ou caméra utilisés **en arrière-plan** (`background_count`) par une application au-delà d'un seuil par jour. Jour, sujet = application + opération. Sév. 2. | Micro **10**, caméra **3** par jour. Un appel en arrière-plan compte 1 ou 2 ; un logiciel espion enregistre par dizaines. Exemptés : applications du système, titulaires des rôles téléphone, assistant et filtrage d'appels. | Muette sans `app.ops`. Compte des accès, pas des durées : un seul long enregistrement compte 1. Faux positifs : appels de messagerie nombreux écran éteint, dictaphone ou enregistreur d'appels, application de babyphone, assistant vocal tiers. |
| `detect.new_app_risky` | Une application de niveau `high` vient d'être installée (`app.risk` dans les 24 h suivant son `app.installed`), ou une application installée depuis moins de 24 h obtient une capacité sensible (permission SMS/journal d'appels/appels accordée, apparition dans les services d'accessibilité, écouteurs de notifications, administrateurs, sources inconnues, superposition, VPN d'`app.special_access`, rôle SMS/téléphone/assistant/clavier/saisie automatique d'`app.role`). Fenêtre = 24 h après l'installation, sujet = application + motif. Sév. 2 (3 pour un `combo_*`), 1 pour superposition et VPN. | Pas de seuil. **Seulement une installation récente** : une application `high` déjà présente n'alerte pas (le score mesure des capacités déclarées : contrôle parental, antivirus, automatisation, identification d'appelant sortent `high`) ; Vigie lui-même est ignoré. | Repose sur `app.installed` : une installation faite pendant que l'agent ne tournait pas n'est pas vue. Faux positifs : installation volontaire d'une application de ce genre (une alerte par capacité, une fois), d'un VPN ou d'un clavier tiers. |

**Une détection qui sonnerait tous les jours sur un téléphone sain serait ignorée** : les défauts sont mesurés par
le scénario `sain` du simulateur (21 jours simulés avec appels vidéo, sauvegardes nocturnes, navigation intense,
client de messagerie sur le port 465, mises à jour, application installée hors store de risque moyen, `app.ops`
de l'appli SMS, du téléphone et de l'assistant) : **zéro détection** (`TestScenarioHealthyPhoneNoDetection`) ; de
même sur les 89 jours de la mesure du coût.

| Variable | Défaut | Rôle |
|---|---|---|
| `VIGIE_DETECT_ENABLED` | `true` | `false` : aucune détection calculée (les agrégats restent tenus). |
| `VIGIE_DETECT_DISABLE` | vide | Détections éteintes, séparées par des virgules (`fanout,mail_ports` ou `detect.fanout`…). |
| `VIGIE_DETECT_INTERVAL_S` | `300` | Intervalle entre deux passages (10 à 86400 s). |
| `VIGIE_DETECT_UPLOAD_FLOOR_MB` | `1024` | Plancher de `detect.upload_spike`, en Mio par heure. |
| `VIGIE_DETECT_UPLOAD_FACTOR` | `10` | k de k × médiane (1 à 1000). |
| `VIGIE_DETECT_UPLOAD_LEARN_DAYS` | `7` | Historique de l'appareil avant d'utiliser la médiane (0 à 14 jours). |
| `VIGIE_DETECT_FANOUT` / `VIGIE_DETECT_FANOUT_SCREEN_OFF` | `300` / `100` | Adresses distinctes par application et par heure (écran allumé / éteint). |
| `VIGIE_DETECT_MAIL_MIN` | `1` | Connexions par jour aux ports 25/465/587. |
| `VIGIE_DETECT_MAIL_CLIENTS` | vide | Paquets ajoutés aux clients de messagerie connus. |
| `VIGIE_DETECT_DNS_BYPASS_MIN` | `1` | Connexions par jour à un résolveur public. |
| `VIGIE_DETECT_DNS_BYPASS_PORTS` | `443,853` | Ports suivis (ajouter `53` pour le DNS en clair). |
| `VIGIE_DETECT_DNS_BYPASS_EXEMPT` | vide | Paquets autorisés à utiliser un résolveur public. |
| `VIGIE_DETECT_SMS_OTHER_MIN` | `1` | SMS (envoyés ou refusés) par jour d'une application autre que l'appli SMS. |
| `VIGIE_DETECT_SMS_DAILY_MAX` | `200` | SMS (envoyés ou refusés) par jour au-delà desquels toute application est signalée. |
| `VIGIE_DETECT_MIC_BG_MIN` / `VIGIE_DETECT_CAMERA_BG_MIN` | `10` / `3` | Accès en arrière-plan par jour. |

**API console** (préfixe `/api/console`) :

- `GET /detections?device_id&from&to&type&limit&cursor` → `{ "detections": [ { "id", "ts", "device_id", "type",
  "package", "label", "severity", "summary", "evidence", "window_from", "window_to" } ], "next_cursor" }`, de la plus
  récente à la plus ancienne. `id` = identifiant de l'événement `detect.*` (`GET /events/{id}`), `ts` = moment où la
  détection a été faite, `severity` = sévérité 0 à 3 (comme `sev`). `from`/`to` **facultatifs** (défaut : les
  30 derniers jours) et portent sur `ts` ; `type` = préfixes séparés par des virgules ; `limit` ≤ 500 (100).
- `GET /apps/risk?device_id` (requis) → `{ "apps": [ { …dernier app.risk…, "package", "ts" } ] }`, score décroissant.
- `GET /apps/ops?device_id&from&to` (`device_id` facultatif, `from`/`to` requis, heures entières) →
  `{ "apps": [ { "package", "label", "count", "background_count", "rejected_count", "last_ts", "ops": [ { "op",
  "count", "background_count", "rejected_count", "last_ts" } ] } ] }`, total décroissant.

`app.ops` est exporté vers Wazuh éclaté en `app.ops.app` (une ligne par élément, avec `from` et `to`), comme `net.usage`.

### Simulateur : parc sain et scénarios d'attaque

Le simulateur émet désormais aussi le profil de risque et l'usage du parc sain (§11.2) : `app.risk` de chaque
application au premier démarrage, à chaque mise à jour et installation (niveaux `low` 0-29, `medium` 30-59,
`high` 60-100, système et Vigie plafonnés à `low`), `app.ops` horaire (SMS de l'appli SMS, appels, contacts,
position, assistant, Bixby…, avec `rejected_count`), pas d'`app.role` au premier relevé (les applications par
défaut viennent de `app.special_access`). S'y ajoutent des comportements sains trompeurs : appel vidéo WhatsApp
(250 à 450 Mio envoyés), sauvegarde nocturne Samsung Cloud (jusqu'à 850 Mio), une heure de navigation intense
dans Chrome (50 à 90 adresses), Samsung Email sur le port 465. `--app-ops=false` simule l'absence d'`app.ops`.
Ces ajouts ont leur propre source aléatoire : à graine fixe, le reste du flux est inchangé.

`--scenario` (plusieurs séparés par des virgules) joue des attaques cohérentes dans le temps. Avec `--backfill`,
elles commencent 48 h avant la fin de l'historique (40 % de l'historique s'il est plus court) et durent jusqu'au
bout (et au-delà avec `--follow`) ; sans historique, une minute après le lancement. Les domaines de commande sont
bloqués par la liste de menaces du faux AdGuard Home (`--fake-adguard`, liste activée d'office et déclarée
`threat` dans `examples/adguard-levels.example.json`).

| Scénario | Séquence | Détections obtenues |
|---|---|---|
| `sain` (défaut) | rien de plus que le parc sain | aucune |
| `fraude-sms` | « Lampe Torche Pro » installée hors store (`app.risk` high, `combo_sms_fraud`, sans icône), `SEND_SMS` et `READ_CONTACTS` accordées 3 min après, ~85 SMS par heure en arrière-plan (≈ 2 000 par jour), contacts lus, appels au panneau `panel.sms-gateway-pay.example` ; au bout de 24 h, la garde SMS est activée (`security.policy`) et les envois continuent, refusés (`rejected_count`) | `new_app_risky` (risque élevé, envoi de SMS), `sms_abuse` (chaque jour, refus compris), `threat_domain` |
| `cheval-de-troie` | « Mise à jour du système » hors store (`combo_banking_trojan`), réception de SMS, accessibilité + lecture des notifications + superposition (`app.special_access`) 6 min après, balises vers deux serveurs de commande | `new_app_risky` (5 motifs), `threat_domain` (2 domaines par jour) |
| `proxy` | « Puzzle Relax » du Play Store (risque faible), de 1 h à 6 h (heure de Paris) 320 à 480 adresses par heure, 250 à 550 Mio envoyés par heure, domaine `relay.proxy-earn.example` | `fanout` (chaque heure de nuit), `threat_domain` |
| `spam` | « Nettoyeur Boost » du Play Store, 20 à 40 serveurs SMTP par heure (ports 587 et 25) | `mail_ports` (sév. 3, chaque jour) |
| `exfiltration` | « Coffre Photos » du Play Store, quelques Mio par heure puis, 36 h après le début (au plus tard 2 h avant la fin de l'historique ; sans historique, 1 h après), 3,1 à 3,9 Gio en une heure | `upload_spike` |
| `contournement-dns` | « Navigateur Rapide » (service VPN), 3 à 12 connexions par heure à 1.1.1.1:443, 1.0.0.1:443, 8.8.8.8:853, [2606:4700:4700::1111]:443 | `dns_bypass` (chaque jour), `new_app_risky` (VPN, sév. 1) |
| `espion` | « Battery Service » hors store (`combo_stalkerware`), micro, caméra et position en arrière-plan accordés, administrateur de l'appareil, ~4 enregistrements par heure, une photo toutes les 3 h | `new_app_risky` (risque élevé, administrateur), `sensor_background` (micro et caméra, chaque jour) |
| `tout` | tous les scénarios d'attaque | tout ce qui précède (`TestScenarioAttacks`) |

Lancer en local un serveur avec un scénario d'attaque (faux AdGuard Home compris) :

```sh
cd server/collector
export VIGIE_DATA_DIR=$PWD/.dev VIGIE_LISTEN=127.0.0.1:8080 VIGIE_COOKIE_SECURE=false \
       VIGIE_EXPORT_NDJSON=$PWD/.dev/export/events.ndjson VIGIE_PUBLIC_INGEST_URL=http://127.0.0.1:8080 \
       VIGIE_ADGUARD_URL=http://127.0.0.1:3001 VIGIE_ADGUARD_USER=vigie VIGIE_ADGUARD_PASSWORD=adguard-demo \
       VIGIE_ADGUARD_LEVELS_FILE=$PWD/examples/adguard-levels.example.json VIGIE_ADGUARD_POLL_S=10 \
       VIGIE_DETECT_INTERVAL_S=15
go run . serve &
go run . enroll --name s25 --out .dev/s25.vigie
printf '%s\n' 'motdepasse-console' | go run . user set-password admin
go run . sim --enroll .dev/s25.vigie --backfill 72h --follow --scenario tout \
       --fake-adguard 127.0.0.1:3001 --fake-adguard-user vigie --fake-adguard-password adguard-demo
```

Les détections apparaissent au passage qui suit l'arrivée des données (`VIGIE_DETECT_INTERVAL_S`), et celles qui
dépendent du journal d'AdGuard Home après son relevé (`VIGIE_ADGUARD_POLL_S` ; au premier relevé, seules les
24 dernières heures du journal sont lues).

## Choix de conception

- **SQLite WAL** (`modernc.org/sqlite`, pur Go) : un pool écrivain d'une connexion (`BEGIN IMMEDIATE`) et un
  pool de lecture `query_only`. `synchronous=FULL` : un lot acquitté (que l'agent supprime) survit à une
  coupure. Migrations versionnées par `PRAGMA user_version` (`internal/store/db.go`).
- **Requêtes console sur des millions de lignes** : index `(device_id, ts)`, `(device_id, type, ts)` et
  `(device_id, sev, ts) WHERE sev > 0`. `/events` découpe la requête en parcours d'index ordonnés (par
  appareil × type exact ou × sévérité), lus avec `LIMIT n+1` et fusionnés : un type rare reste rapide au milieu
  de `net.dns`. Curseur opaque `(ts, pk)`. Les statistiques horaires/journalières et les « top » viennent
  d'agrégats horaires tenus à l'ingestion (`event_counts`, `top_counts`) ; le pas `minute` relit les
  événements (2000 intervalles au plus). **`/stats/top` compte des occurrences, `/stats/timeline` des
  événements** : pour `dns_hostname`, `dns_package`, `connect_dest` et `connect_package`, un événement pèse
  `data.count` (entier entre 1 et 1 000 000 ; absent, fractionnaire, hors bornes ou non numérique : 1), à
  l'ingestion comme dans la migration 3 qui reconstruit ces agrégats ; les autres genres et `event_type`
  comptent 1 par événement, et la timeline aussi. Tables dérivées : `locations`, `device_latest` (dernier heartbeat,
  posture, position, inventaire).
- **Ingestion** : jeton haché (SHA-256, 256 bits d'entropie) comparé en temps constant ; empreinte du
  certificat crue seulement si l'appelant est dans `VIGIE_TRUSTED_PROXIES`. Limites : 1 Mio compressé /
  8 Mio décompressé / 500 événements / 256 Kio par événement / profondeur 16. Un événement est inséré ou
  reconnu comme doublon (`ON CONFLICT(id) DO NOTHING`) dans une transaction par lot. Débit : 5 requêtes/s
  (rafale 60) par appareil, 10 échecs d'authentification par IP puis 1 toutes les 30 s, 8 lots en parallèle.
- **Export Wazuh** : curseur persistant (`kv.export_cursor` = dernier `events.pk`, AUTOINCREMENT). Une
  goroutine lit la base dans l'ordre d'insertion, écrit des lignes complètes (écritures terminées par `\n`),
  fait `fsync`, puis avance le curseur. L'ingestion ne fait qu'un signal non bloquant : un volume plein ou
  absent ne la ralentit jamais, et un redémarrage reprend au curseur (au moins une fois : quelques lignes
  peuvent être dupliquées après un arrêt brutal). Au premier démarrage, l'historique n'est pas rejoué.
  Le fichier est créé (0640) dès le démarrage de `serve`, avant tout événement : `wazuh-logcollector`
  ouvre un fichier apparu après son propre démarrage **à la fin**, et en perdrait les premières lignes.
  Rotation par renommage (`.1`…`.KEEP`), jamais de troncature ; une ligne partielle laissée par un arrêt
  brutal est terminée par `\n` (ligne ignorée par Wazuh, événement réexporté). `vigie.data.location` est
  réservé au point `geo_point` posé par le collecteur sur `location.fix` : une clé `location` venue de
  l'appareil est retirée de l'export (elle ferait rejeter le document entier par l'indexeur).
- **Console** : sessions par cookie (`__Host-vigie_session` en HTTPS) opaques, hachées en base, 12 h
  d'inactivité, 7 jours au plus ; argon2id (m=64 Mio, t=3, p=2, 2 calculs simultanés au plus) ; 10 échecs
  par IP et par compte puis 1/min (`429` + `Retry-After`), le jeton étant pris avant la vérification du mot
  de passe (des tentatives simultanées ne contournent pas la limite) et rendu en cas de succès. `X-Requested-With: vigie` exigé sur toute requête
  modifiante. CSP exacte du contrat, `nosniff`, `DENY`, etc. SSE : abonné trop lent déconnecté (le
  navigateur se reconnecte), flux fermé à l'expiration de la session.
- **Renouvellement** : `renew` range un second couple (jeton haché + empreinte et PEM du certificat) dans les colonnes
  `next_*` de `devices` (migration 4). Les deux couples sont acceptés ; le **premier** `ingest` (une fois `device_id`
  du corps vérifié) ou `ping` authentifié avec le nouveau déclenche, en un seul `UPDATE` atomique, la bascule : le
  nouveau couple devient courant, l'ancien est refusé (`401`). Un jeton n'est valable qu'avec le certificat de
  **son** couple (pas de mélange ancien jeton + nouveau certificat, ni l'inverse). Jetons hachés, comparés en
  temps constant, jamais journalisés ; la bascule est journalisée sans secret. Un renouvellement jamais utilisé
  reste en attente sans limite de durée (l'ancien couple continue de servir jusqu'à son expiration).
- **Réponses `400`** : uniquement enveloppe de lot illisible ou invalide (gzip, JSON, champs de l'enveloppe du
  mauvais type, `events` absent/nul/non tableau, données après l'objet). L'enveloppe est lue sans limite de
  profondeur (`encoding/json` refuse au-delà de 10 000 niveaux, ce qui rendait tout le lot illisible pour un
  seul événement pathologique) : un défaut propre à un événement (type, `ts`, taille, imbrication…) va dans `rejected`.
- **Sens serveur → téléphone** : `/api/v1` n'a que `ingest`, `ping` et les trois routes de commandes du §8 ;
  aucune réponse ne transporte de configuration ni de politique.
- **Commandes à distance (§8)** : table `commands` (migration 5). `POST /commands` analyse une **copie** du
  `payload` (objet JSON unique, sans clé en double ni inconnue, `v` = 1, `id` ULID majuscule inédit et égal à
  `id` du corps s'il est fourni, `device_id` = celui du corps, appareil existant et non révoqué, type de la
  liste fermée, paramètres typés et bornés — `message` : 200 unités UTF-16, pas de caractère de contrôle sauf
  `\n` —, `issued_at` à ±10 min de l'heure du serveur, `expires_at` futur et validité ≤ 30 j) ; la chaîne
  d'origine est stockée et relayée **à l'octet près** (jamais re-sérialisée ; UTF-8 invalide et U+FFFD
  refusés pour qu'aucun remplacement ne la modifie). `sig` : obligatoire et au format base64 de 32 octets pour
  un type sensible, interdit sinon ; le collecteur **ne peut pas** la vérifier (il n'a pas le code). Limites
  vérifiées dans la transaction d'insertion : 20 créations par heure et 10 commandes ouvertes (pending ou
  delivered) par appareil (`429` + `Retry-After`) ; corps ≤ 32 Kio, payload ≤ 4 Kio. États : `pending` →
  `delivered` (passage atomique **avant** l'écriture vers l'agent : une annulation concurrente gagne — la
  commande n'est pas envoyée — ou reçoit `409`) → `executed`/`failed`/`refused` (premier résultat retenu ; un
  doublon, ou un refus `replay`, est acquitté `204` sans effet) ; `expired` (balayage toutes les 30 s, et
  affiché dès l'échéance) ; `cancelled` (seulement depuis `pending`). Un résultat tardif (commande expirée ou
  annulée) est enregistré : c'est l'état réel du téléphone. Une commande non acquittée par un résultat est
  renvoyée après 5 min (3 remises au plus ; l'agent, qui ne la réexécute jamais, renvoie alors son résultat
  d'origine, ou `replay` — non final — s'il ne l'a plus). Si l'écriture vers l'agent échoue, la commande
  repasse `pending`. **La signature n'est conservée que tant que la commande peut encore être remise** : dès
  qu'elle est terminée (résultat reçu, expirée, annulée), `sig` est remplacé en base par le repère `-`
  (`store.SigErased` ; la console continue de la voir « signée »). Une copie ultérieure de la base ou d'une
  sauvegarde ne contient donc plus de couple (`payload`, `sig`) des commandes passées, qui servirait à
  chercher hors ligne le code de commande du propriétaire ; un serveur compromis **en direct** voit toujours
  passer les nouvelles commandes signées.
- **Flux de commandes** : une connexion par appareil (la nouvelle ferme l'ancienne), 64 au plus
  (`503` + `Retry-After` au-delà), délai de lecture du serveur levé pour cette seule requête authentifiée,
  délai d'écriture de 30 s par message (une connexion morte est détectée au plus tard au maintien suivant),
  une seule goroutine par flux, fermeture de tous les flux à l'arrêt. `GET /devices` → `command_channel` :
  `connected` = flux ouvert en ce moment ; `mode` = `stream` (flux ouvert ou dernier contact par flux), `poll`
  (dernière interrogation sans flux ouvert) ou `unknown` ; `last_contact` = dernière ouverture, maintien,
  interrogation ou résultat.
- **Événements produits par le collecteur** : `command.issued` (sév. 0 simple, 1 `lock`/`clear_lock_message`,
  2 `wipe` ; `command_id`, `type`, `signed`, `created_by`, `expires_at`, `params` **sans** `message`,
  `message_set` pour `lock`), `command.cancelled` (`cancelled_by`), `command.reported` (résultat reçu par
  l'API : `status`, `detail`, `agent_at`, sévérité du §8) et `command.expired` (`delivered`, sév. 1). Ils sont
  stockés comme des événements de l'appareil visé (`source = 'server'`, `boot_id` = `server`, `seq` 0),
  visibles dans `/events` et la chronologie, et exportés avec `vigie.source = "server"` (les événements
  d'appareil n'ont pas de `source`). L'événement `command.result` de l'agent arrive, lui, par l'ingestion.
  Le message de verrouillage reste dans la base (console) : ni dans les journaux du processus, ni dans
  l'export. Ni `payload`, ni `sig`, ni jeton ne sont journalisés. `tracking.level_changed` et
  `tracking.override` (voir « Vue pistage ») sont produits de la même façon.
- **Vue « pistage » (§9)** : le journal d'AdGuard Home (`GET /control/querylog`, du plus récent au plus
  ancien, 500 entrées par page) est relevé toutes les `VIGIE_ADGUARD_POLL_S`, 40 pages au plus par relevé.
  **Lecture** (`readLog`, `internal/server/tracking.go`) : AdGuard Home v0.107.80 traite `older_than=T` en
  cherchant dans ses fichiers une entrée dont l'horodatage est **exactement** `T` (`internal/querylog` :
  `seekTS`, `seekRecord` ; vérifié sur une instance réelle) : si `T` tombe entre deux entrées, il ne renvoie
  rien des fichiers ; si `T` est postérieur à la dernière, il saute cette dernière entrée. Le collecteur ne
  passe donc jamais un instant arbitraire : la première page est demandée **sans** `older_than`, les suivantes
  avec l'horodatage exact de la plus ancienne entrée de la page précédente, et la fenêtre de temps est
  appliquée ici. Une entrée est comptée par le relevé dont la fenêtre `(repère précédent, maintenant − 60 s]`
  contient son horodatage : exactement une fois, quel que soit l'instant des relevés. Si un curseur reçoit une
  réponse courte avant la limite basse (fin réelle du journal, ou entrée du curseur absente des fichiers :
  restée en mémoire, ou supprimée par une rotation), les horodatages des trois entrées lues juste avant sont
  essayés avant de conclure. Chaque page est agrégée par
  heure, client (ClientID, sinon IP) et domaine (`tracking_counts` : requêtes, bloquées, motif lisible : nom
  de la liste, « Règle personnalisée : … », « Blocage manuel (Vigie) », service bloqué…) et validée **avec** la
  position de lecture (`kv.adguard_querylog` : repère, plages restantes avec leur curseur et ses remplaçants)
  dans la même transaction : un redémarrage reprend sans perte ni double compte. Ce qui n'a pas pu être lu
  dans le budget de pages (premier relevé : 24 h d'historique ; longue panne) est gardé comme
  « trou » à combler aux relevés suivants (16 au plus). Bloquée = motif `Filtered*` sauf `FilteredSafeSearch`.
  Le faux AdGuard Home du simulateur et des tests reproduit ce traitement réel d'`older_than` (deux fichiers,
  rotation, tampon mémoire : `adguard.Fake.search`, `fake_test.go`). Essai du 16/11/2026 contre un AdGuard
  Home réel v0.107.80 (conteneur local, `size_memory: 1`, trafic espacé puis en rafales, deux rotations du
  journal dont une faite par AdGuard Home lui-même, deux redémarrages du collecteur) : 2114 entrées inscrites
  par AdGuard Home, 2114 comptées, chacune une fois ; l'ancienne lecture (`older_than` = maintenant − 60 s)
  en comptait 8. Rattrapage d'un journal existant par un collecteur neuf : 824 sur 824, puis 1350 sur 1350
  avec `size_memory: 50` (trois pages).
  **Changements faits depuis la console** : `PUT /tracking/level` et `PUT /tracking/override` qui modifient
  réellement AdGuard Home produisent un événement du collecteur (`source = 'server'`, un par appareil non
  révoqué, exporté vers Wazuh avec `vigie.source = "server"`) : `tracking.level_changed` (`old` — absent si
  l'état ne correspondait à aucun niveau —, `new`, `changes`, `user` ; sév. 2 si le blocage est affaibli ou
  part d'un état inconnu, 1 sinon) et `tracking.override` (`domain`, `action`, `forced`, `previous` s'il y
  avait une règle, `user` ; sév. 2 pour une autorisation, le retrait d'un blocage ou le blocage forcé d'un
  domaine indispensable, 1 sinon). Une demande qui ne change rien ne produit rien.
  Croisements par agrégats horaires : `top_counts` (`dns_hostname` par paquet, pondéré par `count`) et
  `usage_counts` (octets reçus/émis par application, migration 5, reconstruite depuis `net.usage`). Rien ne
  balaie la table `events`. Purge avec la rétention. AdGuard injoignable : `adguard: false`, `PUT` → `503`,
  les agrégats déjà relevés restent servis ; rien d'autre n'est affecté.
- **Éditeurs** : [`internal/tracking/publishers.txt`](internal/tracking/publishers.txt), embarqué ; suffixe le
  plus long, sur frontière de label (`notgoogle.com` → `other`). Clés : `google`, `samsung`, `meta`,
  `microsoft`, `amazon`, `bytedance`, `ads`, `other`. Octets par éditeur (`tx_bytes`, `rx_bytes`) :
  **estimation** — les octets de chaque application sont répartis entre éditeurs au prorata de ses requêtes
  DNS vers leurs domaines.
- **Règles manuelles** (`PUT /tracking/override`) : domaine en minuscules, labels `[a-z0-9_-]` (forme `xn--`),
  2 labels au moins, TLD non numérique, 253 caractères au plus : aucun caractère de syntaxe de règle ne peut
  passer. Règles `||domaine^$important` / `@@||domaine^$important` écrites entre `! vigie:begin …` et
  `! vigie:end` parmi les règles utilisateur (lues par `GET /control/filtering/status`, réécrites par
  `POST /control/filtering/set_rules` seulement si elles changent ; bloc trié, retiré quand il est vide ;
  repères incohérents → `409 corrupt_rules`, rien n'est écrit). Une ligne trouvée entre les repères qui
  n'est pas une règle écrite par Vigie (règle ou commentaire ajouté là à la main dans AdGuard Home) n'est
  jamais supprimée : elle est déplacée juste après le bloc. Garde-fou : bloquer un domaine qui est (ou
  dont un sous-domaine est) indispensable — FCM, test de connectivité, NTP, mises à jour Samsung/Google, hôtes
  d'ingestion et de DNS privé de Vigie (`internal/tracking/essential.go`) — répond `409 essential_domain` avec
  `breaks: [{domain, breaks}]` sans `"force": true`.
- **Client AdGuard** : URL de la configuration uniquement, aucune redirection suivie, pas de proxy
  d'environnement, délai de 30 s (2 min pour un changement de niveau), réponses bornées (32 Mio pour le
  journal).
- **Fichiers** : base, WAL et `-shm` en 0600 (la base est créée 0600 avant que SQLite n'en dérive les
  autres), `.vigie` en 0600 même avec `--force`. La purge de rétention s'applique aussi aux dernières
  valeurs par appareil (position, heartbeat, posture) affichées par `/devices`.
- **PKI** : AC ECDSA P-256 (20 ans) dans `pki/ca.{crt,key}` (clé 0600), certificats clients 2 ans,
  `CN=<device_id>`, `clientAuth`.
- **Simulateur** : journée type autour de Paris (domicile 11e, métro ligne 1 jusqu'à La Défense en semaine,
  vélo et bois de Vincennes le week-end), Wi-Fi/cellules, écran et applications au premier plan, DNS et
  connexions par paquets Google/Samsung/tiers (~10 000 `net.dns` par jour avec `--rate 1`), usage horaire,
  inventaires quotidiens (parties liées par `inventory_id`), et un scénario plaçant tous les types rares (redémarrage, traceur BLE, 2G, AC
  utilisateur, `agent.tamper`, ADB, USB, appli installée hors Play Store, position simulée…) dans la fenêtre
  de `--backfill` (ou dans la première heure du mode continu). `seq` part de l'heure Unix en ms.
  L'hôte DNS privé (posture, politique, connectivité) est repris du fichier `.vigie`. Chaque changement de
  posture produit un `security.posture_change` par champ modifié (sauf `patch_age_days`, dérivé de la date) :
  ADB et options développeur, sources inconnues et Play Protect, DNS privé non strict, AC utilisateur ;
  `sensor.*` portent `screen_on` et `locked` (dont un micro et une caméra utilisés écran éteint et
  verrouillé par l'appli installée hors Play Store) ; `security.log` suit la table de noms du contrat.
  Comme le vrai agent : environ 1 `net.dns`/`net.connect` sur 15 est agrégé (`count` 2 à 60,
  `last_event_ts`), des `security.log` de niveau `info`/`warning`/`error` (parfois agrégés) s'ajoutent, des
  journaux `pre_reboot: true` précèdent chaque redémarrage, et `net.dns`, `net.connect` et `security.log`
  sont livrés **par lots tous les 1 h 30 à 2 h** avec leur `ts` d'origine (le reste est livré au fil de l'eau ;
  sans `--follow`, le dernier lot en attente part à la fin). À graine fixe (`--seed`), le flux est
  reproductible ; les tirages ajoutés ont leurs propres sources aléatoires, le reste de la simulation n'a pas changé.

## Limites connues

- Pistage : `older_than` d'AdGuard est strict : deux requêtes de la même nanoseconde à la frontière de deux
  pages pourraient être sautées (négligeable). Une entrée n'est comptée qu'une fois vieille de 60 s (les plus
  récentes attendent le relevé suivant). **`querylog.size_memory` d'AdGuard Home doit rester inférieur à 500**
  (la taille d'une page) : au-delà (1000 par défaut), un relevé de plus d'une page peut avoir pour curseur une
  entrée encore en mémoire, et AdGuard Home saute alors la dernière entrée de son fichier (une entrée perdue
  par relevé de ce genre). À l'inverse, **`size_memory: 1` fait perdre des entrées à AdGuard Home lui-même**
  dès que des requêtes arrivent en même temps (son tampon d'une entrée est écrasé avant d'être écrit) :
  mesuré sur une instance réelle v0.107.80 avec 8 clients simultanés, 187 entrées inscrites pour 240 réponses
  à `size_memory: 1`, 1350 pour 1360 à `size_memory: 50`. Ces entrées n'existent ni pour le collecteur ni
  pour Wazuh : c'est un réglage de l'infrastructure (voir le rapport de revue du 16/11/2026).
  Les `apps` d'un domaine et les `blocked`/`allowed`
  d'une application sont des estimations (AdGuard ne voit pas l'application ; `net.dns` ne voit pas le blocage).
- Commandes : le collecteur ne vérifie pas `sig` (il n'a pas le code). Sans le code, un serveur compromis
  peut faire sonner, vibrer ou localiser le téléphone autant qu'il veut, retenir, retarder ou rejouer dans
  leur période de validité les commandes signées qu'il a reçues, et afficher n'importe quel état dans la
  console. Il ne peut verrouiller ou effacer que s'il obtient le code : en le cherchant hors ligne à partir
  d'une commande signée (d'où l'exigence d'un code long et imprévisible, voir `android/README.md`), ou en
  modifiant la console qu'il sert pour le lire quand le propriétaire le saisit. L'annulation d'une commande
  n'engage que le serveur : seule l'expiration, ou le changement du code dans l'application, la rend
  caduque à coup sûr.

- Agrégats « top » et timeline horaire/journalière alignés sur des heures/jours **UTC** pleins : les bornes
  `from`/`to` sont arrondies à l'heure.
- `/apps` regroupe les parties d'inventaire par `inventory_id` (contrat §2) ; pour un agent qui ne l'envoie
  pas, repli sur une heuristique (même `parts`, moins d'une heure d'écart).
- Un événement dont `ts` dépasse l'heure du serveur de plus de 24 h ou précède 2000 est rejeté
  (`invalid_ts`, définitif) ; la purge de rétention se fait sur `ts`.
- `ts` est l'heure d'origine : `net.dns`, `net.connect`, `security.log` et `app.foreground` arrivent avec des
  heures, voire des jours de retard. Tous les agrégats sont rangés dans l'heure UTC de `ts` (jamais celle de
  réception) et un `ts` ancien est accepté dans la limite de `VIGIE_RETENTION_DAYS`. Un événement plus ancien
  que la rétention est **acquitté sans être stocké** (compté dans `accepted`, pour que l'agent le supprime ;
  ni agrégat, ni export Wazuh, ni diffusion SSE) : la purge l'aurait supprimé dans l'heure. `last_event_ts` n'est
  pas utilisé pour le classement. La console doit interroger les statistiques par plage de `ts`, pas « depuis
  la réception » : un événement tardif modifie les compteurs d'heures déjà passées.
- Limitation de débit en mémoire (réinitialisée au redémarrage, propre à une instance).
- Détections : fenêtres en jours et heures UTC ; la rétention s'applique aussi aux détections (fenêtre et moment
  de la détection tous deux plus anciens que la rétention) et au dernier `app.risk`/`app.role` de chaque
  application (`GET /apps/risk` perd une application dont le dernier `app.risk` a plus de `VIGIE_RETENTION_DAYS`).
- Caddy limite le corps des requêtes d'ingestion à 9 Mo (infra) : marge au-dessus des 8 Mio décompressés,
  les limites fines restent celles du collecteur.
