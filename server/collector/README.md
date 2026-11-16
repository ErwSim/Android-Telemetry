# vigie-collector

Collecteur Go de Vigie : API d'ingestion (téléphone → serveur), stockage SQLite, API et fichiers de la
console web, export NDJSON vers Wazuh, PKI cliente, CLI d'enrôlement et simulateur. Spécification :
[`docs/contrat/contrat.md`](../../docs/contrat/contrat.md) (§3 à §7, commandes à distance §8, vue « pistage » §9).

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
  renvoyée après 5 min (3 remises au plus ; l'agent répond `replay` s'il l'avait déjà traitée). Si l'écriture
  vers l'agent échoue, la commande repasse `pending`.
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
  l'export. Ni `payload`, ni `sig`, ni jeton ne sont journalisés.
- **Vue « pistage » (§9)** : le journal d'AdGuard Home (`GET /control/querylog?limit=500&older_than=…`, du
  plus récent au plus ancien) est relevé toutes les `VIGIE_ADGUARD_POLL_S`, avec 60 s de retard (AdGuard
  inscrit une requête à la fin de son traitement), 40 pages au plus par relevé. Chaque page est agrégée par
  heure, client (ClientID, sinon IP) et domaine (`tracking_counts` : requêtes, bloquées, motif lisible : nom
  de la liste, « Règle personnalisée : … », « Blocage manuel (Vigie) », service bloqué…) et validée **avec** la
  position de lecture (`kv.adguard_querylog`) dans la même transaction : un redémarrage reprend sans double
  compte. Ce qui n'a pas pu être lu (premier relevé : 24 h d'historique ; longue panne) est gardé comme
  « trou » à combler aux relevés suivants (16 au plus). Bloquée = motif `Filtered*` sauf `FilteredSafeSearch`.
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
  repères incohérents → `409 corrupt_rules`, rien n'est écrit). Garde-fou : bloquer un domaine qui est (ou
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
  pages pourraient être sautées (négligeable). Une requête dont le traitement a duré plus de 60 s n'est pas
  comptée. Les `apps` d'un domaine et les `blocked`/`allowed` d'une application sont des estimations (AdGuard
  ne voit pas l'application ; `net.dns` ne voit pas le blocage).
- Commandes : le collecteur ne vérifie pas `sig` ; un serveur compromis peut au pire faire sonner, vibrer ou
  localiser le téléphone (principe n° 2).

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
- Caddy limite le corps des requêtes d'ingestion à 9 Mo (infra) : marge au-dessus des 8 Mio décompressés,
  les limites fines restent celles du collecteur.
