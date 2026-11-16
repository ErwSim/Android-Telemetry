# Contrat Vigie v1 — événements et API

Référence commune de l'agent Android, du collecteur, de la console et des règles Wazuh.
Toute évolution passe d'abord par ce fichier.

## 1. Événement

```json
{
  "id": "01JCQ8Z3K4M5N6P7Q8R9S0T1V2",
  "ts": "2026-11-15T21:43:03.974Z",
  "seq": 18234,
  "boot_id": "b7e1…",
  "elapsed_ms": 86400123,
  "type": "location.fix",
  "sev": 0,
  "data": { }
}
```

| Champ | Type | Règle |
|---|---|---|
| `id` | chaîne | ULID (26 car.) généré sur l'appareil. Clé d'idempotence. |
| `ts` | chaîne | Horodatage de l'événement, RFC 3339 UTC, millisecondes. |
| `seq` | entier | Compteur strictement croissant par appareil, persistant (détection de trous). |
| `boot_id` | chaîne | Identifiant aléatoire régénéré à chaque démarrage de l'appareil. |
| `elapsed_ms` | entier | `SystemClock.elapsedRealtime()` au moment de l'événement (correction d'horloge). |
| `type` | chaîne | `<domaine>.<nom>`, minuscules, `[a-z0-9_.]`, voir catalogue. |
| `sev` | entier | Indice côté appareil : 0 info, 1 notable, 2 avertissement, 3 critique. |
| `data` | objet | Charge propre au type. Clés en `snake_case`. Champs absents plutôt que `null`. |

Conventions de `data` : durées en millisecondes (`*_ms`), tailles en octets (`*_bytes`), identifiants de paquet
Android dans `package` (et `uid` si connu), adresses MAC en minuscules avec `:`, empreintes en hexadécimal
minuscule SHA-256. Le collecteur accepte tout `type` conforme et stocke `data` tel quel (schéma à la lecture) ;
un type inconnu n'est jamais rejeté.

## 2. Catalogue des types (v1)

Les champs listés sont le minimum ; un collecteur peut en ajouter et doit alors compléter ce tableau.

### agent.*
| Type | Quand | `data` |
|---|---|---|
| `agent.started` / `agent.stopped` | démarrage/arrêt du service | `reason`, `agent_version` |
| `agent.heartbeat` | toutes les 15 min | `battery_pct`, `charging`, `uptime_ms`, `queue_depth`, `queue_bytes`, `dropped_total`, `device_owner` (bool), `collectors` (objet id → `running`/`disabled`/`unavailable`), `last_upload_ts` |
| `agent.buffer_overflow` | purge du tampon | `dropped`, `oldest_ts`, `newest_ts` |
| `agent.collector_error` | exception d'un collecteur | `collector`, `error` |
| `agent.config_changed` | réglage modifié dans l'app | `key`, `old`, `new` |
| `agent.tamper` (sev 3) | tentative de désactivation, permission retirée, arrêt forcé détecté | `kind`, `detail` |

### device.*
| Type | `data` |
|---|---|
| `device.inventory` (quotidien + au démarrage) | `manufacturer`, `model`, `android_release`, `sdk_int`, `security_patch`, `build_fingerprint`, `one_ui`, `kernel`, `bootloader`, `verified_boot_state`, `total_storage_bytes`, `total_ram_bytes` |
| `device.boot` / `device.shutdown` | `reason` |
| `device.screen` | `state` (`on`/`off`/`unlocked`) |
| `device.battery` | `pct`, `plugged` (`none`/`ac`/`usb`/`wireless`), `status`, `temperature_c`, `health` |
| `device.power_save` | `enabled` |
| `device.storage` | `free_bytes`, `total_bytes` |
| `device.thermal` | `status` |
| `device.time_changed` / `device.timezone_changed` | `delta_ms` / `tz` |
| `device.usb` | `connected`, `configured`, `functions` (liste de chaînes), `accessory`/`device` (objet) |
| `device.airplane_mode` | `enabled` |

### location.*
| Type | `data` |
|---|---|
| `location.fix` | `lat`, `lon`, `acc_m`, `alt_m`, `speed_mps`, `bearing_deg`, `provider`, `mock` (bool), `fix_ts` |
| `location.provider` | `provider`, `enabled` |

### net.*
| Type | `data` |
|---|---|
| `net.connectivity` | `transports` (liste : `wifi`,`cellular`,`vpn`,`ethernet`,`bluetooth`), `validated`, `metered`, `vpn`, `private_dns_active`, `private_dns_server`, `dns_servers`, `interface` |
| `net.wifi` | `event` (`connected`/`disconnected`), `ssid`, `bssid`, `rssi`, `freq_mhz`, `security`, `standard` |
| `net.wifi_scan` (optionnel) | `aps` : liste `{ssid,bssid,rssi,freq_mhz,security}` |
| `net.cell` | `tech`, `mcc`, `mnc`, `tac`, `ci`, `pci`, `band`, `signal_dbm`, `roaming`, `operator` |
| `net.cell_security` (sev ≥ 2) | `kind` (`downgrade_2g`, `null_cipher`, `identifier_disclosure`), `detail` |
| `net.dns` (Device Owner) | `package`, `uid`, `hostname`, `addresses`, `address_count` |
| `net.connect` (Device Owner) | `package`, `uid`, `ip`, `port` |
| `net.usage` (horaire) | `from`, `to`, `apps` : liste `{package,uid,rx_bytes,tx_bytes,transport}` |
| `net.bluetooth` | `event` (`state`/`connected`/`disconnected`), `enabled`, `name`, `address`, `type` |
| `net.ble_tracker` (sev 2) | `address`, `kind` (`airtag`,`smarttag`,`tile`,`unknown`), `rssi`, `first_seen`, `sightings` |
| `net.hotspot` / `net.nfc` | `enabled` |

### app.*
| Type | `data` |
|---|---|
| `app.inventory` (quotidien, découpé en plusieurs événements) | `inventory_id` (identique pour toutes les parties d'un même inventaire), `part` (à partir de 1), `parts`, `apps` : liste `{package,label,version_name,version_code,installer,system,enabled,suspended,hidden,target_sdk,first_install,last_update,signer_sha256,granted_dangerous}` |
| `app.installed` / `app.updated` / `app.removed` | `package`, `version_name`, `version_code`, `installer`, `signer_sha256` |
| `app.foreground` | `package`, `class`, `event` (`resumed`/`paused`) |
| `app.permission_changed` | `package`, `permission`, `granted` |
| `app.special_access` (au changement + quotidien) | `accessibility_services`, `notification_listeners`, `device_admins`, `overlay_apps`, `unknown_sources_apps`, `usage_access_apps`, `vpn_apps`, `default_apps` (objet) |
| `app.notification` | `package`, `event` (`posted`/`removed`), `category`, `channel`, `ongoing`, et seulement si l'option contenu est activée : `title`, `text` |

Note : `app.notification` est produit par l'**APK compagnon** `:notifier` (séparé et optionnel, voir §10), jamais par un service de l'APK Device Owner.

### sensor.*
| Type | `data` |
|---|---|
| `sensor.camera` | `camera_id`, `in_use`, `package` (si connu) |
| `sensor.microphone` | `recording`, `source`, `package` (si connu), `silenced` |

### security.*
| Type | `data` |
|---|---|
| `security.log` (Device Owner) | `tag` (nom de la constante `SecurityLog.TAG_*` en minuscules sans préfixe), `level`, `log_id`, `fields` (objet nommé selon le tag) |
| `security.posture` (au changement + quotidien) | `security_patch`, `patch_age_days`, `encrypted`, `lock_secure`, `adb_enabled`, `adb_wifi_enabled`, `dev_options`, `unknown_sources`, `private_dns_mode`, `private_dns_host`, `always_on_vpn`, `device_owner`, `verified_boot_state`, `user_ca_certs` (liste d'empreintes), `play_protect`, `usb_data_signaling` |
| `security.keyguard` | `event` (`unlock_failed`/`unlock_succeeded`), `failed_attempts` |
| `security.ca_cert` (sev 2) | `event` (`added`/`removed`), `sha256`, `subject` |
| `security.policy` | `action` (`private_dns_set`,`package_disabled`,`package_enabled`,`permission_denied`,`restriction_set`,`restriction_cleared`,`network_logging`,`security_logging`), `target`, `profile`, `ok`, `error` |

### Précisions du catalogue (ajoutées après le développement de l'infrastructure)

- `security.posture_change` (sev selon le champ) : émis **en plus** de `security.posture` pour chaque champ
  qui change : `field`, `old`, `new` (valeurs converties en chaînes). Permet une alerte par changement.
  `patch_age_days` (dérivé de la date) ne produit pas de `security.posture_change`.
- `sensor.camera` et `sensor.microphone` portent aussi `screen_on` (bool) et `locked` (bool) au moment de
  l'événement.
- `security.policy.action` admet aussi `permission_granted` (auto-attribution par le Device Owner),
  `force_stop_protection`, `always_on_vpn`, `backup_service`, `policy_reverted` (tout défaire) et
  `device_owner_cleared`.
- Valeurs retenues par le socle Android : `agent.started.reason` ∈ `boot`/`app`/`update`/`watchdog`/`restart` ;
  `agent.stopped.reason` ∈ `user`/`system` ; `agent.tamper.kind` ∈ `admin_disable_requested`/`admin_disabled`/
  `permission_revoked`/`force_stop`/`device_owner_lost` ; `device.shutdown.reason` ∈ `shutdown`/`reboot` ;
  l'enrôlement émet `agent.config_changed` avec `key = "enrollment.device_id"`.
- Côté agent : une réponse `200` dont les compteurs ne totalisent pas la taille du lot est traitée comme une
  erreur (on garde tout) ; un `413` sur un événement seul le supprime (compté dans `dropped_total`) ; `403`
  est traité comme `401`.
- Valeurs retenues par les collecteurs : `net.cell.tech` = nom `NETWORK_TYPE_*` en minuscules (`lte`, `nr`,
  `gsm`…) ou `none` hors service ; `net.connectivity.transports` peut aussi contenir `usb`, `satellite`,
  `thread`, `wifi_aware`, `lowpan` ; `device.usb.device` = `vendor_id`, `product_id`, `device_class`,
  `manufacturer`, `product` ; `device.usb.accessory` = `manufacturer`, `model`, `version` ;
  `net.cell_security.kind` n'est produit qu'avec `downgrade_2g` en v1 (les autres exigent des API système).
- Événements relevés après coup (`app.foreground`, `net.dns`, `net.connect`, `security.log`) : `ts` est
  l'heure **d'origine** de l'événement fournie par le système, pas l'heure du relevé (il n'y a pas de champ
  `event_ts`).
- Pour un événement à heure d'origine, `elapsed_ms` est estimé pour cet instant, et vaut 0 si l'événement
  précède le démarrage en cours de l'appareil.
- Types fixés : `net.cell.mcc` et `mnc` sont des chaînes, `ci` un entier ; `sensor.microphone.source` une
  chaîne ; `security.posture.always_on_vpn` un booléen ; `vendor_id`/`product_id` USB des entiers.
- L'agent compte 22 collecteurs (19 dans `:collectors`, dont `notifications` qui dépend de l'APK compagnon,
  et 3 dans `:policy`), tous présents dans `agent.heartbeat.collectors`.
- Agrégation : `net.dns`, `net.connect` et `security.log` peuvent porter `count` (entier ≥ 1, défaut 1 :
  nombre d'occurrences identiques regroupées sur la fenêtre) et `last_event_ts` (heure de la dernière
  occurrence) ; `ts` est alors l'heure de la première. Les statistiques du collecteur (`/stats/top`) pondèrent
  par `count`.
  Seul un entier de 1 à 1 000 000 est pris en compte (toute autre valeur vaut 1). La pondération ne concerne
  que les genres `dns_*` et `connect_*` ; `/stats/timeline` reste un nombre d'événements.
- Un événement dont `ts` est plus ancien que la durée de rétention du serveur est acquitté (compté dans
  `accepted`, donc supprimé du tampon de l'agent) mais n'est ni stocké ni exporté.
- `security.log` : `level` ∈ `info`/`warning`/`error` ; `pre_reboot` (bool) pour les journaux récupérés d'avant
  redémarrage ; `start_time` de `app_process_start` en millisecondes.
- `security.policy.action` admet aussi `permission_restored`, `setting_changed`, `setting_restored`.
- `security.posture.play_protect` est omis par l'agent (aucune lecture fiable sur Android récent).
- `security.log` : `fields` nomme la charge utile du tag ainsi (les indicateurs 0/1 de réussite deviennent des
  booléens `success`) ; tout tag non listé utilise `arg0`, `arg1`… dans l'ordre de la charge utile.

  | Tag | `fields` |
  |---|---|
  | `adb_shell_interactive` | — |
  | `adb_shell_cmd` | `command` |
  | `sync_recv_file`, `sync_send_file` | `path` |
  | `app_process_start` | `process`, `start_time`, `uid`, `pid`, `seinfo`, `apk_sha256` |
  | `keyguard_dismissed`, `keyguard_secured` | — |
  | `keyguard_dismiss_auth_attempt` | `success`, `strength` |
  | `os_startup` | `verified_boot_state`, `dm_verity_mode` |
  | `os_shutdown` | — |
  | `logging_started`, `logging_stopped`, `log_buffer_size_critical` | — |
  | `media_mount`, `media_unmount` | `mount_point`, `label` |
  | `crypto_self_test_completed` | `success` |
  | `key_generated`, `key_import`, `key_destruction` | `success`, `alias`, `uid` |
  | `key_integrity_violation` | `alias`, `uid` |
  | `cert_authority_installed`, `cert_authority_removed` | `success`, `subject`, `user_id` |
  | `cert_validation_failure` | `reason` |
  | `user_restriction_added`, `user_restriction_removed` | `admin_package`, `user_id`, `restriction` |
  | `password_changed` | `complexity`, `user_id` |
  | `wifi_connection` | `bssid`, `event_type`, `reason` |
  | `wifi_disconnection` | `bssid`, `reason` |
  | `bluetooth_connection` | `address`, `success`, `reason` |
  | `bluetooth_disconnection` | `address`, `reason` |
  | `package_installed`, `package_updated`, `package_uninstalled` | `package`, `version_code`, `user_id` |
  | `wipe_failure`, `remote_lock`, `backup_service_toggled` | `arg0`… |

## 3. API d'ingestion (téléphone → serveur)

Hôte dédié (ex. `ingest.exemple.fr`), TLS avec **certificat client obligatoire** (terminé par Caddy, CA privée
Vigie) **et** en-tête `Authorization: Bearer <jeton_appareil>`.

### `POST /api/v1/ingest`

En-têtes : `Content-Type: application/json`, `Content-Encoding: gzip` (recommandé).
Limites : 500 événements par lot, 1 Mio compressé, 8 Mio décompressé.

```json
{
  "device_id": "dev_8f3a…",
  "agent_version": "1.0.0",
  "sent_at": "2026-11-15T21:45:00.000Z",
  "events": [ { "id": "…", "ts": "…", "seq": 1, "boot_id": "…", "elapsed_ms": 1, "type": "…", "sev": 0, "data": {} } ]
}
```

Réponse `200` :

```json
{ "accepted": 498, "duplicates": 2, "rejected": [ { "id": "…", "reason": "invalid_type" } ], "server_time": "2026-11-15T21:45:00.412Z" }
```

- Le lot est traité de façon atomique par événement : `accepted` + `duplicates` + `rejected` = nombre reçu.
  L'agent supprime de son tampon les `accepted`, les `duplicates` **et** les `rejected` (un rejet est définitif).
- `401` jeton/certificat invalide ou appareil révoqué (l'agent garde ses données et réessaie plus tard),
  `413` lot trop gros (l'agent réduit la taille du lot), `429`/`5xx` réessayer avec backoff
  (respecter `Retry-After`).
- `device_id` doit correspondre au jeton, sinon `401`.
- `400` (enveloppe du lot illisible ou invalide) : l'agent coupe le lot en deux et renvoie chaque moitié ; un
  événement qui, envoyé seul, reçoit encore `400` est supprimé et compté dans `dropped_total`. Le serveur ne
  répond jamais `400` pour un défaut propre à un événement (il le met dans `rejected`).
  Un lot sans événement (`"events": []`) est valide et reçoit `200` : au premier `400` d'un passage, l'agent
  s'en sert comme sonde — si la sonde reçoit aussi `400`, la faute est dans l'enveloppe ou le serveur et rien
  n'est supprimé.

### `GET /api/v1/ping`

Même authentification. Réponse `200` `{ "server_time": "…", "device_id": "…" }`. Sert au test d'enrôlement.

Le serveur ne peut transmettre à l'agent que les commandes du §8 ; il n'existe aucun point d'API de
configuration ni de politique.

## 4. Fichier d'enrôlement `.vigie`

Produit par `vigie-collector enroll`, importé dans l'app (sélecteur de fichier). JSON :

```json
{
  "version": 1,
  "ingest_url": "https://ingest.exemple.fr",
  "device_id": "dev_8f3a…",
  "device_name": "s25",
  "device_token": "…",
  "client_cert_pem": "-----BEGIN CERTIFICATE-----…",
  "client_key_pem": "-----BEGIN PRIVATE KEY-----… (PKCS#8, ECDSA P-256)",
  "server_ca_pem": "… (optionnel : si présent, l'agent n'accepte que cette AC pour le serveur)",
  "private_dns_host": "dns.exemple.fr (optionnel)"
}
```

- `device_id` : `dev_` suivi de caractères `[a-z0-9]`, 64 caractères au plus. `device_token` : caractères
  `[A-Za-z0-9._~-]`, 128 au plus. L'agent refuse à l'import un fichier dont ces champs contiennent autre chose
  que de l'ASCII visible.
- Renouvellement : `vigie-collector renew <device_id> --out <fichier.vigie>` émet un nouveau jeton et un
  nouveau certificat pour le **même** `device_id` (l'historique n'est pas scindé) ; l'ancien jeton et l'ancien
  certificat restent acceptés jusqu'au premier envoi authentifié avec les nouveaux, puis sont refusés.
  L'agent importe le nouveau fichier sans perdre son tampon.
- La PKI cliente (AC privée ECDSA P-256 + un certificat par appareil, `CN=<device_id>`, usage `clientAuth`)
  est gérée par le collecteur lui-même ; l'AC est créée au premier démarrage dans son répertoire de données.
- L'agent importe la clé dans l'Android Keystore (non exportable) puis oublie le PEM.
- Le fichier contient des secrets : à transférer par câble (ADB) ou canal chiffré, puis à supprimer.

## 5. Export vers Wazuh

Le collecteur ajoute une ligne JSON par événement accepté dans un fichier NDJSON (volume partagé avec le
manager Wazuh). Tout est sous la clé racine `vigie` pour éviter les collisions de champs :

```json
{"vigie":{"device_id":"dev_8f3a…","device_name":"s25","id":"…","ts":"…","received_at":"…","seq":18234,"type":"net.dns","domain":"net","sev":0,"data":{"package":"com.google.android.gms","hostname":"app-measurement.com"}}}
```

`domain` est la partie de `type` avant le premier point. Les règles Wazuh filtrent sur `vigie.type`,
`vigie.sev` et `vigie.data.*`.

Contraintes du décodeur JSON de Wazuh (vérifiées, voir `docs/research/serveur-siem-dns.md`) :

- Chaque ligne commence par `{"` et ne dépasse jamais 32 Kio (Wazuh tronque, donc perd, au-delà de ~65 Ko) :
  au-delà, `data` est remplacé par `{"truncated": true}` dans l'export (l'événement complet reste dans la
  base du collecteur).
- Les **tableaux d'objets ne sont pas décodés**. Dans l'export, tout tableau d'objets de `data` est donc
  retiré et remplacé par `<clé>_count` ; pour les types ci-dessous le collecteur émet en plus **une ligne par
  élément**, avec un type dérivé et l'élément à plat dans `data` :

  | Type d'origine | Clé | Type dérivé (export seulement) |
  |---|---|---|
  | `app.inventory` | `apps` | `app.inventory.app` |
  | `net.usage` | `apps` | `net.usage.app` (avec `from`, `to`) |
  | `net.wifi_scan` | `aps` | `net.wifi_scan.ap` |

  Les lignes dérivées portent l'`id` d'origine suffixé de `#<index>`. Les tableaux de scalaires sont conservés.
- `location.fix` porte en plus `vigie.data.location = {"lat": …, "lon": …}` pour un éventuel mapping
  `geo_point` côté indexeur.
- Rotation du fichier **par renommage** uniquement (jamais de troncature : elle déclenche la règle Wazuh 592
  de niveau 8).

## 6. API console (navigateur → collecteur)

Préfixe `/api/console`. Session par cookie (`HttpOnly`, `Secure`, `SameSite=Strict`) obtenue par
`POST /api/console/login` `{ "username", "password" }` → `204` ; `POST /api/console/logout` ;
`GET /api/console/me` → `{ "username" }` ou `401`. Toutes les requêtes modifiantes exigent l'en-tête
`X-Requested-With: vigie`. Les dates sont en RFC 3339 ; `from`/`to` sont requis sauf mention contraire.

| Méthode et chemin | Paramètres | Réponse |
|---|---|---|
| `GET /devices` | — | `{ "devices": [ { "device_id", "name", "enrolled_at", "last_seen", "agent_version", "revoked", "last_heartbeat": {…data}, "last_location": { "ts","lat","lon","acc_m" }, "last_posture": {…data} } ] }` |
| `GET /events` | `device_id`, `type` (préfixes séparés par des virgules, ex. `net.,security.log`), `sev_min`, `from`, `to`, `q` (texte dans `data`), `limit` (≤ 500, défaut 100), `cursor` | `{ "events": [ {événement + "received_at"} ], "next_cursor": "…" }` (du plus récent au plus ancien) |
| `GET /events/{id}` | — | événement complet |
| `GET /locations` | `device_id`, `from`, `to`, `max_points` (défaut 2000, sous-échantillonnage régulier) | `{ "points": [ { "ts","lat","lon","acc_m","speed_mps","provider" } ] }` |
| `GET /stats/timeline` | `device_id`, `from`, `to`, `bucket` (`minute`/`hour`/`day`), `by` (`domain`/`type`/`sev`) | `{ "buckets": ["…"], "series": [ { "key": "net", "counts": [ … ] } ] }` |
| `GET /stats/top` | `device_id`, `from`, `to`, `kind` (`dns_hostname`,`dns_package`,`connect_dest`,`connect_package`,`usage_package`,`foreground_package`,`notification_package`,`event_type`), `limit` (défaut 20) | `{ "items": [ { "key", "count", "bytes" (si pertinent) } ] }` |
| `GET /apps` | `device_id` | dernier inventaire reconstitué : `{ "ts", "apps": [ … ] }` |
| `GET /posture` | `device_id` | `{ "current": {…}, "ts", "changes": [ { "ts", "field", "old", "new" } ] }` |
| `GET /alerts` | `from`, `to`, `level_min`, `limit` | `{ "wazuh": true, "alerts": [ { "ts","level","rule_id","description","type","device_id" } ] }` ; `{ "wazuh": false, "alerts": [] }` si l'indexeur n'est pas configuré |
| `GET /stream` | `device_id` (optionnel) | Server-Sent Events : un événement JSON par message |
| `GET /health` (sans auth, hors préfixe console : `/healthz`) | — | `200 ok` |

Erreurs : JSON `{ "error": "code", "message": "…" }` avec le code HTTP adéquat.

### Précisions (ajoutées après le développement de la console)

- `GET /devices` : chaque appareil porte aussi `last_heartbeat_ts`, `last_posture_ts` (RFC 3339, absents si
  inconnus).
- `GET /stats/top` accepte `package` (optionnel) : restreint aux événements dont `data.package` vaut cette
  valeur (ex. `kind=dns_hostname&package=com.google.android.gms` = domaines demandés par cette app).
  `connect_dest` a pour clé `ip:port`. `usage_package` renvoie `count` et `bytes` (= rx + tx).
- `GET /stats/timeline` accepte `type` (optionnel, préfixes séparés par des virgules, comme `/events`).
- `cursor` est une chaîne opaque. `GET /stream` émet des messages SSE par défaut (`data: <événement JSON>`),
  plus un commentaire de maintien toutes les 25 s.
- `first_install` et `last_update` de l'inventaire sont en RFC 3339.
- Sessions : expiration après 12 h d'inactivité (→ `401`) ; `POST /login` est limité en débit (→ `429` avec
  `Retry-After`).
- Fichiers statiques : un chemin avec extension inexistant renvoie `404` (pas `index.html`) ; les `.js` sont
  servis en `text/javascript`. En-tête CSP exact attendu par la console :
  `default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self' <origine des tuiles>; worker-src 'self'; font-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`.
- Tuiles de carte : variable `VIGIE_TILE_URL` (défaut `https://tile.openstreetmap.org/{z}/{x}/{y}.png`).
  L'origine des tuiles de la CSP en est déduite, et le collecteur répond lui-même à `GET /config.json` par
  `{ "tileUrl": "<VIGIE_TILE_URL>" }` (prioritaire sur le fichier statique de la console).

## 7. Interface d'exploitation du collecteur

Binaire unique `vigie-collector`, sous-commandes :

| Commande | Rôle |
|---|---|
| `serve` | Démarre le serveur HTTP (ingestion + API console + fichiers de la console). Crée la base et l'AC si absentes. |
| `enroll --name <nom> --out <fichier.vigie>` | Crée un appareil (identifiant, jeton, certificat client) et écrit le fichier d'enrôlement. |
| `devices` / `revoke <device_id>` | Liste / révoque (jeton et certificat refusés immédiatement). |
| `renew <device_id> --out <fichier.vigie>` | Nouveau jeton et nouveau certificat pour le même appareil (voir §4). `devices` affiche la date d'expiration du certificat. |
| `user set-password <nom>` | Crée ou met à jour un compte console (mot de passe lu sur l'entrée standard). |
| `sim --url … --enroll <fichier.vigie> [--rate …] [--backfill 24h]` | Simulateur : envoie par l'API d'ingestion des événements réalistes de tous les types du catalogue (tests, démonstration). |

Configuration par variables d'environnement :

| Variable | Défaut | Rôle |
|---|---|---|
| `VIGIE_LISTEN` | `:8080` | Adresse d'écoute HTTP (en clair, derrière Caddy). |
| `VIGIE_DATA_DIR` | `/data` | Base SQLite `vigie.db`, PKI `pki/ca.crt` et `pki/ca.key`. |
| `VIGIE_EXPORT_NDJSON` | vide (désactivé) | Chemin du fichier NDJSON pour Wazuh. Rotation par renommage (`.1`…). |
| `VIGIE_EXPORT_MAX_BYTES` / `VIGIE_EXPORT_KEEP` | `52428800` / `5` | Taille de rotation et nombre de fichiers conservés. |
| `VIGIE_TRUSTED_PROXIES` | `127.0.0.1/32` | CIDR dont on accepte les en-têtes de proxy. |
| `VIGIE_REQUIRE_CLIENT_CERT` | `true` | Exige que l'en-tête `X-Vigie-Client-Cert-Sha256` (posé par Caddy depuis un proxy de confiance : empreinte SHA-256 hex du certificat client vérifié) corresponde au certificat de l'appareil. |
| `VIGIE_PUBLIC_INGEST_URL` | — | URL écrite dans les fichiers `.vigie`. |
| `VIGIE_PRIVATE_DNS_HOST` | vide | Hôte DoT écrit dans les fichiers `.vigie`. |
| `VIGIE_SERVER_CA_FILE` | vide | AC serveur à inclure dans `.vigie` (mode AC interne). |
| `VIGIE_RETENTION_DAYS` | `90` | Purge des événements plus anciens. |
| `VIGIE_CONSOLE_DIR` | vide | Sert la console depuis ce répertoire au lieu des fichiers embarqués (développement). |
| `VIGIE_COOKIE_SECURE` | `true` | `false` uniquement en développement HTTP local. |
| `VIGIE_WAZUH_INDEXER_URL`, `…_USER`, `…_PASSWORD`, `…_CA_FILE`, `…_INSECURE` | vides | Accès en lecture à l'indexeur Wazuh pour `GET /alerts`. |

Côté Caddy : l'hôte d'ingestion n'expose que `/api/v1/*` (certificat client obligatoire, AC = `pki/ca.crt`
du collecteur, montée en lecture seule) et pose `X-Vigie-Client-Cert-Sha256` ; l'hôte console n'expose que
`/api/console/*`, `/healthz` et les fichiers statiques. Caddy supprime tout en-tête `X-Vigie-*` entrant.

## 8. Commandes à distance (console → collecteur → agent)

Liste fermée ; toute autre valeur de `type` est refusée par le collecteur **et** par l'agent.

| `type` | `params` | Niveau |
|---|---|---|
| `ring` | `duration_s` (1 à 300, défaut 60), `vibrate` (bool, défaut vrai) : sonnerie à plein volume même en silencieux | simple |
| `vibrate` | `duration_s` (1 à 60, défaut 10) | simple |
| `stop_ring` | — | simple |
| `locate` | — : position précise immédiate (acquisition jusqu'à 60 s) puis envoi immédiat du tampon | simple |
| `lock` | `message` (optionnel, ≤ 200 caractères, affiché sur l'écran de verrouillage) | **sensible** |
| `clear_lock_message` | — | **sensible** |
| `wipe` | — : réinitialisation d'usine | **sensible** + réglage « Autoriser l'effacement à distance » activé dans l'app (éteint par défaut) |

### Objet commande

```json
{ "id": "01JCQ8Z3K4M5N6P7Q8R9S0T1V2", "payload": "<texte JSON>", "sig": "<base64, absent pour une commande simple>" }
```

`payload` est une **chaîne** contenant le JSON suivant, construit par le navigateur ; le collecteur la relaie à
l'octet près et l'agent vérifie la signature sur ces octets avant de l'analyser :

```json
{"v":1,"id":"01JCQ8Z3K4M5N6P7Q8R9S0T1V2","device_id":"dev_…","type":"lock","params":{"message":"…"},"issued_at":"2026-11-16T10:00:00.000Z","expires_at":"2026-11-23T10:00:00.000Z"}
```

- `id` : ULID généré par le navigateur, identique dans l'objet et dans `payload`.
- Durée de validité (`expires_at` − `issued_at`) : 1 h par défaut pour une commande simple, 7 jours pour une
  commande sensible, 30 jours au plus.
- **Signature des commandes sensibles** : `sig = base64( HMAC-SHA256( K, octets UTF-8 de payload ) )` avec
  `K = PBKDF2-HMAC-SHA256( code, sel = "vigie-cmd-v1:" + device_id, 600 000 itérations, 32 octets )`.
  Le **code de commande** (12 caractères au moins) est choisi par le propriétaire dans l'app, qui ne conserve
  que `K` (chiffré au repos) ; il est ressaisi dans la console à chaque commande sensible, n'y est jamais
  mémorisé et n'est **jamais envoyé au serveur** (dérivation et signature par WebCrypto dans le navigateur).
  Le collecteur ne peut pas vérifier `sig` ; il exige seulement sa présence pour un type sensible.
- Vecteur de test (à reproduire dans les tests Kotlin, TypeScript et Go) : code `correct horse battery staple`,
  `device_id` `dev_0123456789abcdef` → `K` =
  `072a4a8b76845668eff857e6412bd6bde57cf158cf89b2fb9c844a7d66037492` ; pour le `payload`
  `{"v":1,"id":"01JCQ8Z3K4M5N6P7Q8R9S0T1V2","device_id":"dev_0123456789abcdef","type":"lock","params":{"message":"Téléphone perdu, appelez le 01 23 45 67 89"},"issued_at":"2026-11-16T10:00:00.000Z","expires_at":"2026-11-23T10:00:00.000Z"}`
  → `sig` = `GWiiJjYxiBHlG1lba410Zxb0kDHsINh4nS9u/GE/OaE=`.

### Vérifications de l'agent (dans cet ordre) et motifs de refus

Canal de commandes activé (`disabled`) ; `payload` analysable, `v` = 1, `id` identique (`malformed`) ;
`device_id` = le sien (`wrong_device`) ; `type` connu (`unknown_type`) ; pour un type sensible : code défini
(`no_code_configured`) et signature valide, comparée en temps constant (`bad_signature`) ; `wipe` autorisé
localement (`disabled`) ; non expirée, avec 5 min de tolérance d'horloge (`expired`) ; `id` jamais exécuté —
l'agent mémorise les 500 derniers (`replay`) ; paramètres dans les bornes (`bad_params`) ; Device Owner requis
pour `lock`, `clear_lock_message` et `wipe` (`not_device_owner`). Après 5 `bad_signature` en une heure, l'agent
refuse toute commande sensible pendant une heure (`locked_out`).

Chaque commande traitée produit un événement `command.result` : `command_id`, `type`, `status`
(`executed`/`failed`/`refused`), `detail` (motif), `signed` (bool). Sévérité : 0 pour une commande simple
exécutée, 2 pour `lock`/`wipe` exécutés, 3 pour `bad_signature` et `locked_out`, 1 pour les autres refus.
Pour `wipe`, l'agent émet l'événement, tente un envoi immédiat (10 s au plus), puis efface.
Rien dans une commande ne peut modifier un réglage, la politique ou l'enrôlement.

### API côté agent (hôte d'ingestion, même authentification que le §3)

| Méthode et chemin | Rôle |
|---|---|
| `GET /api/v1/commands/stream` | Connexion permanente (Server-Sent Events). À la connexion, le serveur envoie les commandes en attente non expirées, puis les nouvelles : `event: command` + `data: <objet commande>`. Commentaire de maintien toutes les 120 s (`VIGIE_CMD_KEEPALIVE_S`). Une seule connexion par appareil (une nouvelle remplace l'ancienne). |
| `GET /api/v1/commands` | Mode interrogation : `{ "commands": [ … ] }` (commandes en attente non expirées). |
| `POST /api/v1/commands/{id}/result` | `{ "status": "executed"｜"failed"｜"refused", "detail": "…", "at": "…" }` → `204`. Idempotent. |

L'agent choisit le mode par réglage : connexion permanente (défaut) ou interrogation toutes les 1 à 15 min ;
il se reconnecte avec backoff et au retour de la connectivité, et interroge aussi à chaque envoi de lot.

### API console (préfixe `/api/console`)

| Méthode et chemin | Paramètres | Réponse |
|---|---|---|
| `GET /commands` | `device_id`, `limit` (défaut 50) | `{ "commands": [ { "id","device_id","type","params","signed","status","created_at","created_by","expires_at","delivered_at","result_at","detail" } ] }` ; `status` ∈ `pending`/`delivered`/`executed`/`failed`/`refused`/`expired`/`cancelled` |
| `POST /commands` | corps `{ "device_id", "payload", "sig" }` | `201 { "id" }`. Le collecteur valide `payload` (type de la liste, bornes des paramètres, appareil existant et non révoqué, validité, `id` inédit, `sig` présent si et seulement si le type est sensible). Limites : 20 commandes par heure et 10 en attente par appareil (`429`). |
| `POST /commands/{id}/cancel` | — | `204` si encore `pending`, sinon `409` |

`GET /devices` porte en plus `command_channel` : `{ "connected": bool, "mode": "stream"｜"poll"｜"unknown", "last_contact": "…" }`.
Chaque création, annulation et résultat est journalisé par le collecteur et exporté vers Wazuh sous le type
`command.issued` / `command.cancelled` (événements produits par le serveur : `vigie.source = "server"`).

### Précisions (ajoutées après le développement du collecteur)

- `issued_at` doit être à moins de 10 min de l'heure du serveur à la création (sinon `400`) : une horloge de
  navigateur fausse empêche d'émettre une commande.
- `message` de `lock` : 200 unités UTF-16 au plus, aucun caractère de contrôle sauf le saut de ligne.
- Corps de `POST /commands` : seulement `device_id`, `payload`, `sig` (et `id` optionnel, identique à celui
  du `payload`) ; toute autre clé → `400`. Le `payload` n'admet ni clé inconnue ni clé en double.
- **Renvoi** : une commande livrée dont le résultat n'arrive pas est renvoyée après 5 min (3 fois au plus).
  L'agent qui reçoit un `id` déjà traité **renvoie le résultat d'origine** (il le conserve avec l'`id`) ; il
  ne répond `refused`/`replay` que s'il n'a plus ce résultat, et ce refus ne clôt pas la commande côté
  serveur. Le premier résultat reçu fait foi ; un résultat arrivé après expiration ou annulation est
  enregistré sans changer l'état.
- `command_channel.connected` = un flux est ouvert à l'instant ; un appareil en interrogation a
  `connected: false`, `mode: "poll"` et se juge sur `last_contact`. Une commande annulée porte
  `detail: "cancelled"`.
- Événements produits par le serveur (`vigie.source = "server"`, absents du tampon de l'agent) :
  `command.issued`, `command.cancelled`, `command.reported`, `command.expired`. Les événements de l'appareil
  ne portent pas de `source`.
- Pistage : AdGuard configuré mais injoignable → `adguard: false`, les agrégats déjà stockés restent servis.
  `status=blocked` = au moins une requête bloquée ; `allowed` = autorisé ou mixte. `override` vise le domaine
  exact. `level` est absent si l'état d'AdGuard ne correspond à aucun niveau ; `GET /tracking/level` renvoie
  `{ "adguard", "level", "levels" }`. Les octets par éditeur et les compteurs bloqué/autorisé par application
  sont des **estimations** (répartition au prorata des requêtes DNS), à présenter comme telles. Codes
  d'erreur supplémentaires : `502 adguard_error`, `409 corrupt_rules`, `503 levels_not_configured`,
  `503 adguard_unavailable`.
- Variables du collecteur ajoutées au §7 : `VIGIE_CMD_KEEPALIVE_S` (120), `VIGIE_ADGUARD_URL`,
  `VIGIE_ADGUARD_USER`, `VIGIE_ADGUARD_PASSWORD`, `VIGIE_ADGUARD_LEVELS_FILE`, `VIGIE_ADGUARD_POLL_S` (60),
  `VIGIE_ADGUARD_CLIENTS` (optionnel, `device_id=client,…`).

### Précisions (ajoutées après le développement de l'agent Android)

- Le canal de commandes est **coupé par défaut** dans l'app : le propriétaire l'active dans l'écran
  « Commandes à distance », y définit le code de commande, et autorise l'effacement à part (saisie de
  « EFFACER »).
- Le délai de lecture du flux côté agent est de 300 s : `VIGIE_CMD_KEEPALIVE_S` doit rester ≤ 240.
- Refus décidés par l'agent là où le texte ne disait rien : validité de plus de 30 jours ou `issued_at` à plus
  de 5 min dans le futur → `expired` ; `sig` présent sur une commande simple → `malformed` ; `type` illisible →
  `command.result.type = "unknown"`. `clear_lock_message` exécuté et tout `failed` ont la sévérité 1.
- `ring` : sonnerie sur le flux « alarme » ; si « Ne pas déranger » coupe les alarmes, le son reste muet et le
  résultat porte `detail = "dnd_alarms_muted"` (une app, même Device Owner, ne peut plus lever ce mode).
- `wipe` : `DevicePolicyManager.wipeDevice(0)` ; la protection contre la réinitialisation (compte Google
  requis au redémarrage) et les eSIM sont conservées.
- Le code de commande n'est normalisé en Unicode ni dans l'app ni dans la console : le saisir à l'identique
  (éviter les caractères accentués composés).

## 9. Vue « pistage » : ce qui est bloqué, ce qui passe

Le collecteur lit le journal des requêtes d'AdGuard Home par son API (`VIGIE_ADGUARD_URL`,
`VIGIE_ADGUARD_USER`, `VIGIE_ADGUARD_PASSWORD`), l'agrège par heure et par domaine (requêtes, bloquées,
autorisées, motif), et le croise avec `net.dns` (quelle application demande quel domaine) et `net.usage`
(octets envoyés et reçus par application). Les domaines sont rattachés à un éditeur (Google, Samsung, Meta,
Microsoft, Amazon, TikTok/ByteDance, publicité et mesure d'audience, autres) par un fichier de suffixes
versionné dans le collecteur. Le contenu des échanges n'est pas visible (TLS).

API console (préfixe `/api/console`, `from`/`to` requis sauf mention) :

| Méthode et chemin | Paramètres | Réponse |
|---|---|---|
| `GET /tracking/summary` | `device_id`, `from`, `to` | `{ "adguard": bool, "level": "equilibre", "levels": [ { "key","name","description" } ], "totals": { "queries","blocked","allowed" }, "publishers": [ { "key","name","queries","blocked","allowed","domains","apps","tx_bytes","rx_bytes" } ] }` |
| `GET /tracking/domains` | `device_id`, `from`, `to`, `publisher`, `status` (`blocked`/`allowed`/`all`), `q`, `limit` (≤ 200), `cursor` | `{ "domains": [ { "domain","publisher","queries","blocked","allowed","status" (`blocked`/`allowed`/`mixed`),"reason","override" (`block`/`allow`/absent),"apps": [ { "package","count" } ] } ], "next_cursor" }` trié par requêtes décroissantes |
| `GET /tracking/apps` | `device_id`, `from`, `to`, `publisher` (optionnel : éditeur des domaines contactés) | `{ "apps": [ { "package","label","queries","blocked","allowed","tx_bytes","rx_bytes","top_domains": [ { "domain","count","status" } ] } ] }` |
| `PUT /tracking/override` | corps `{ "domain", "action": "block"｜"allow"｜"default" }` | `204`. Écrit une règle AdGuard dans un bloc délimité géré par Vigie (les règles saisies à la main dans AdGuard ne sont pas touchées). |
| `GET /tracking/level` / `PUT /tracking/level` | corps `{ "level" }` | niveau de blocage courant ∈ `permissif`/`equilibre`/`strict` : active ou désactive les listes correspondantes dans AdGuard. La correspondance niveau → listes est un fichier fourni par l'infrastructure (`VIGIE_ADGUARD_LEVELS_FILE`). |

Sans AdGuard configuré ou joignable : `"adguard": false`, la vue est construite depuis `net.dns` seul
(`status` absent) et les deux `PUT` répondent `503`. Les domaines indispensables (liste d'exceptions Vigie :
FCM, test de connectivité, mises à jour) ne peuvent pas être bloqués depuis la console sans confirmation
explicite (`"force": true`), la réponse `409` expliquant ce que le blocage casserait.

### Précisions (ajoutées après le développement de la console)

- Clés d'éditeur : `google`, `samsung`, `meta`, `microsoft`, `amazon`, `bytedance`, `ads`, `other` (fichier
  `server/collector/internal/tracking/publishers.txt`). `reason` est un texte libre lisible.
- `409 essential_domain` : `{ "error": "essential_domain", "message": "…", "breaks": [ { "domain", "breaks" } ] }`.
- `/tracking/domains` et `/tracking/apps` portent aussi `adguard` (bool).
- Une commande sans paramètre a `"params": {}`.
- Événements produits par le serveur pour le pistage (`vigie.source = "server"`) : `tracking.level_changed`
  (`old`, `new`) et `tracking.override` (`domain`, `action`, `forced`).
- Le fichier de niveaux est `infra/adguard/niveaux.json` (source unique, lue par l'installation et par le
  collecteur). Le niveau en service est l'état des listes activées dans AdGuard, rien d'autre : la console le
  change, `install.sh` et `update.sh` le conservent, `install.sh --profile` l'applique sans le mémoriser.

## 10. Notifications (APK compagnon) et modes de localisation

- **APK compagnon** `io.github.erwsim.vigie.notifier` : contient le seul `NotificationListenerService`, n'a
  pas la permission `INTERNET`, a une icône et un écran qui explique ce qu'il fait, est signé par la même clé
  que l'agent et lui remet les notifications par un canal local protégé par une permission de niveau
  `signature`. Sans lui, le collecteur `notifications` de l'agent est « indisponible ».
- `app.notification` : `package`, `event` (`posted`/`removed`), `category`, `channel`, `ongoing`,
  `importance` ; et seulement si « Contenu des notifications » est activé (éteint par défaut) : `title`, `text`
  (512 caractères au plus chacun), avec `redacted` (bool) quand un code numérique de 4 à 8 chiffres a été
  masqué (masquage activé par défaut). Une liste d'apps exclues du contenu est réglable. Les notifications
  de l'agent lui-même et les notifications permanentes (`ongoing`) répétitives ne sont pas émises.
  `importance` est une chaîne parmi `none`/`min`/`low`/`default`/`high`/`max`. `redacted` n'est présent que
  lorsqu'il y a du contenu et que le masquage est actif. Un événement `removed` ne porte jamais de titre ni de
  texte. Le contenu des apps de SMS et de téléphone est exclu par défaut. Le filtrage du contenu se fait dans
  le compagnon, avant le canal local : contenu éteint, titre et texte ne quittent pas son processus.
- **Localisation** : réglage `mode` du collecteur `location` ∈ `gps` (défaut : GPS + passif), `gps_network`
  (ajoute le fournisseur réseau), `fused` (fournisseur fusionné). `location.fix.provider` dit le fournisseur
  réel de chaque position. L'app affiche pour chaque mode ce qui est transmis à Google.
