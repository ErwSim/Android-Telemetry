# vigie-collector

Collecteur Go de Vigie : API d'ingestion (téléphone → serveur), stockage SQLite, API et fichiers de la
console web, export NDJSON vers Wazuh, PKI cliente, CLI d'enrôlement et simulateur. Spécification :
[`docs/contrat/contrat.md`](../../docs/contrat/contrat.md) (§3 à §7).

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

## Commandes

| Commande | Rôle |
|---|---|
| `serve` | Serveur HTTP ; crée la base, applique les migrations et crée l'AC si absentes. |
| `enroll --name N --out F.vigie [--ingest-url URL] [--force]` | Nouvel appareil + fichier d'enrôlement (mode 0600). |
| `devices [--json]`, `revoke <device_id>` | Liste, révocation (effective à la requête suivante, même serveur lancé). |
| `user set-password <nom>` | Compte console ; mot de passe ≥ 12 caractères, lu sans écho sur un terminal ou sur une ligne de stdin. |
| `sim --enroll F [--url U] [--backfill 24h] [--follow] [--rate 1] [--interval 15s] [--seed N]` | Simulateur (voir plus bas). |
| `healthcheck [--url U]`, `version` | Sonde `/healthz` (Compose), version. |

Variables : celles du contrat §7, plus `VIGIE_TILE_URL` (§6, défaut OpenStreetMap ; servie par
`GET /config.json` et reprise dans la CSP) et `VIGIE_LOG_LEVEL` (`debug`/`info`/`warn`/`error`).

## Choix de conception

- **SQLite WAL** (`modernc.org/sqlite`, pur Go) : un pool écrivain d'une connexion (`BEGIN IMMEDIATE`) et un
  pool de lecture `query_only`. `synchronous=FULL` : un lot acquitté (que l'agent supprime) survit à une
  coupure. Migrations versionnées par `PRAGMA user_version` (`internal/store/db.go`).
- **Requêtes console sur des millions de lignes** : index `(device_id, ts)`, `(device_id, type, ts)` et
  `(device_id, sev, ts) WHERE sev > 0`. `/events` découpe la requête en parcours d'index ordonnés (par
  appareil × type exact ou × sévérité), lus avec `LIMIT n+1` et fusionnés : un type rare reste rapide au milieu
  de `net.dns`. Curseur opaque `(ts, pk)`. Les statistiques horaires/journalières et les « top » viennent
  d'agrégats horaires tenus à l'ingestion (`event_counts`, `top_counts`) ; le pas `minute` relit les
  événements (2000 intervalles au plus). Tables dérivées : `locations`, `device_latest` (dernier heartbeat,
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
- **Flux à sens unique** : `/api/v1` n'a que `ingest` et `ping` ; aucune réponse ne transporte d'ordre.
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

## Limites connues

- Agrégats « top » et timeline horaire/journalière alignés sur des heures/jours **UTC** pleins : les bornes
  `from`/`to` sont arrondies à l'heure.
- `/apps` regroupe les parties d'inventaire par `inventory_id` (contrat §2) ; pour un agent qui ne l'envoie
  pas, repli sur une heuristique (même `parts`, moins d'une heure d'écart).
- Un événement dont `ts` dépasse l'heure du serveur de plus de 24 h ou précède 2000 est rejeté
  (`invalid_ts`, définitif) ; la purge de rétention se fait sur `ts`.
- Limitation de débit en mémoire (réinitialisée au redémarrage, propre à une instance).
- Caddy limite le corps des requêtes d'ingestion à 2 Mo (infra) : un lot non compressé ne peut donc pas
  atteindre les 8 Mio autorisés par le collecteur.
