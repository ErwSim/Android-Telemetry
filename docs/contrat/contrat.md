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

Note : `app.notification` n'est **pas** produit par l'APK principal en v1 (un service d'écoute des notifications dans un APK Device Owner déclenche Play Protect, voir `docs/research/android-plateforme.md`). Le type est réservé à un éventuel module séparé et optionnel.

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
- L'agent compte 21 collecteurs (18 dans `:collectors`, 3 dans `:policy`), tous présents dans
  `agent.heartbeat.collectors`.
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

### `GET /api/v1/ping`

Même authentification. Réponse `200` `{ "server_time": "…", "device_id": "…" }`. Sert au test d'enrôlement.

Il n'existe **aucun** point d'API permettant au serveur d'envoyer une commande ou une configuration à l'agent.

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
