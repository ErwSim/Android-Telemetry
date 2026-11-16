# Watchpost contract: events and APIs

Common reference for the Android agent, the collector, the console and the Wazuh rules.
Every change starts in this file.

Section numbers are stable: other documents and code comments refer to them (§8 remote commands, §9 Tracking
page, §11 guards, risk profile and detections).

## 1. Event

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

| Field | Type | Rule |
|---|---|---|
| `id` | string | ULID (26 characters) generated on the device. Idempotency key. |
| `ts` | string | Event timestamp, RFC 3339 UTC, milliseconds. |
| `seq` | integer | Strictly increasing counter per device, persistent (gap detection). |
| `boot_id` | string | Random identifier regenerated at every device boot. |
| `elapsed_ms` | integer | `SystemClock.elapsedRealtime()` when the event occurred (clock correction). |
| `type` | string | `<domain>.<name>`, lowercase, `[a-z0-9_.]`, see the catalogue. |
| `sev` | integer | Device-side hint: 0 info, 1 notable, 2 warning, 3 critical. |
| `data` | object | Payload specific to the type. Keys in `snake_case`. Fields are omitted rather than set to `null`. |

Conventions for `data`: durations in milliseconds (`*_ms`), sizes in bytes (`*_bytes`), Android package names in
`package` (and `uid` when known), MAC addresses in lowercase with `:`, fingerprints as lowercase hexadecimal
SHA-256. The collector accepts any well-formed `type` and stores `data` as is (schema on read); an unknown type is
never rejected.

Events retrieved after the fact (`app.foreground`, `net.dns`, `net.connect`, `security.log`): `ts` is the
**original** time of the event as given by the system, not the time of retrieval (there is no `event_ts` field).
For such an event, `elapsed_ms` is estimated for that instant, and is 0 if the event precedes the current boot of
the device.

An event whose `ts` is older than the server retention period is acknowledged (counted in `accepted`, so removed
from the agent's buffer) but is neither stored nor exported.

## 2. Event type catalogue

The listed fields are the minimum; a collector may add fields, and must then complete this catalogue.
Events produced by the server itself are listed at the end of this section.

### agent.*

| Type | When | `data` |
|---|---|---|
| `agent.started` / `agent.stopped` | service start / stop | `reason`, `agent_version`. `started.reason` ∈ `boot`/`app`/`update`/`watchdog`/`restart`; `stopped.reason` ∈ `user`/`system` |
| `agent.heartbeat` | every 15 min | `battery_pct`, `charging`, `uptime_ms`, `queue_depth`, `queue_bytes`, `dropped_total`, `device_owner` (bool), `collectors` (object id → `running`/`disabled`/`unavailable`), `last_upload_ts` |
| `agent.buffer_overflow` | buffer purge | `dropped`, `oldest_ts`, `newest_ts` |
| `agent.collector_error` | a collector threw | `collector`, `error` |
| `agent.config_changed` | setting changed in the app | `key`, `old`, `new`. Enrollment emits it with `key = "enrollment.device_id"` |
| `agent.tamper` (sev 3) | attempt to disable the agent, permission removed, forced stop detected | `kind`, `detail`. `kind` ∈ `admin_disable_requested`/`admin_disabled`/`permission_revoked`/`force_stop`/`device_owner_lost` |

The agent has 25 collectors (22 in `:collectors`, including `notifications`, which depends on the companion APK,
and `app_ops`, which is experimental, plus 3 in `:policy`); all of them appear in `agent.heartbeat.collectors`.

### device.*

| Type | `data` |
|---|---|
| `device.inventory` (daily + at startup) | `manufacturer`, `model`, `android_release`, `sdk_int`, `security_patch`, `build_fingerprint`, `one_ui`, `kernel`, `bootloader`, `verified_boot_state`, `total_storage_bytes`, `total_ram_bytes` |
| `device.boot` / `device.shutdown` | `reason` (`shutdown`/`reboot` for `device.shutdown`) |
| `device.screen` | `state` (`on`/`off`/`unlocked`) |
| `device.battery` | `pct`, `plugged` (`none`/`ac`/`usb`/`wireless`), `status`, `temperature_c`, `health` |
| `device.power_save` | `enabled` |
| `device.storage` | `free_bytes`, `total_bytes` |
| `device.thermal` | `status` |
| `device.time_changed` / `device.timezone_changed` | `delta_ms` / `tz` |
| `device.usb` | `connected`, `configured`, `functions` (list of strings), `accessory` / `device` (object). `device` = `vendor_id`, `product_id` (integers), `device_class`, `manufacturer`, `product`; `accessory` = `manufacturer`, `model`, `version` |
| `device.airplane_mode` | `enabled` |

### location.*

| Type | `data` |
|---|---|
| `location.fix` | `lat`, `lon`, `acc_m`, `alt_m`, `speed_mps`, `bearing_deg`, `provider` (the actual provider of that fix), `mock` (bool), `fix_ts` |
| `location.provider` | `provider`, `enabled` |

### net.*

| Type | `data` |
|---|---|
| `net.connectivity` | `transports` (list: `wifi`, `cellular`, `vpn`, `ethernet`, `bluetooth`, and also `usb`, `satellite`, `thread`, `wifi_aware`, `lowpan`), `validated`, `metered`, `vpn`, `private_dns_active`, `private_dns_server`, `dns_servers`, `interface` |
| `net.wifi` | `event` (`connected`/`disconnected`), `ssid`, `bssid`, `rssi`, `freq_mhz`, `security`, `standard` |
| `net.wifi_scan` (optional) | `aps`: list of `{ssid,bssid,rssi,freq_mhz,security}` |
| `net.cell` | `tech` (lowercase `NETWORK_TYPE_*` name such as `lte`, `nr`, `gsm`, or `none` when out of service), `mcc` and `mnc` (strings), `tac`, `ci` (integer), `pci`, `band`, `signal_dbm`, `roaming`, `operator` |
| `net.cell_security` (sev ≥ 2) | `kind` (`downgrade_2g`, `null_cipher`, `identifier_disclosure`), `detail`. Only `downgrade_2g` is produced; the other kinds require system APIs |
| `net.dns` (Device Owner) | `package`, `uid`, `hostname`, `addresses`, `address_count` |
| `net.connect` (Device Owner) | `package`, `uid`, `ip`, `port` |
| `net.usage` (hourly) | `from`, `to`, `apps`: list of `{package,uid,rx_bytes,tx_bytes,transport}` |
| `net.bluetooth` | `event` (`state`/`connected`/`disconnected`), `enabled`, `name`, `address`, `type` |
| `net.ble_tracker` (sev 2) | `address`, `kind` (`airtag`, `smarttag`, `tile`, `unknown`), `rssi`, `first_seen`, `sightings` |
| `net.hotspot` / `net.nfc` | `enabled` |

Aggregation: `net.dns`, `net.connect` and `security.log` may carry `count` (integer ≥ 1, default 1: the number
of identical occurrences grouped over the window) and `last_event_ts` (time of the last occurrence); `ts` is then
the time of the first one. Only an integer from 1 to 1,000,000 is taken into account (any other value counts as
1). The collector statistics (`/stats/top`) weight by `count`, but only for the kinds `dns_*` and `connect_*`;
`/stats/timeline` remains a count of events.

### app.*

| Type | `data` |
|---|---|
| `app.inventory` (daily, split into several events) | `inventory_id` (identical for all parts of one inventory), `part` (from 1), `parts`, `apps`: list of `{package,label,version_name,version_code,installer,system,enabled,suspended,hidden,target_sdk,first_install,last_update,signer_sha256,granted_dangerous}` (`first_install` and `last_update` in RFC 3339) |
| `app.installed` / `app.updated` / `app.removed` | `package`, `version_name`, `version_code`, `installer`, `signer_sha256` |
| `app.foreground` | `package`, `class`, `event` (`resumed`/`paused`) |
| `app.permission_changed` | `package`, `permission`, `granted` |
| `app.special_access` (on change + daily) | `accessibility_services`, `notification_listeners`, `device_admins`, `overlay_apps`, `unknown_sources_apps`, `usage_access_apps`, `vpn_apps`, `default_apps` (object) |
| `app.notification` | see §10. Produced by the companion APK `:notifier` (separate and optional), never by a service of the Device Owner APK |
| `app.risk`, `app.role`, `app.ops` | see §11.2 |

### sensor.*

| Type | `data` |
|---|---|
| `sensor.camera` | `camera_id`, `in_use`, `package` (if known), `screen_on` (bool), `locked` (bool) |
| `sensor.microphone` | `recording`, `source` (string), `package` (if known), `silenced`, `screen_on` (bool), `locked` (bool) |

### security.*

| Type | `data` |
|---|---|
| `security.log` (Device Owner) | `tag` (name of the `SecurityLog.TAG_*` constant, lowercase, without the prefix), `level` (`info`/`warning`/`error`), `log_id`, `fields` (object named after the tag, see below), `pre_reboot` (bool, for logs retrieved from before a reboot), `start_time` (milliseconds, for `app_process_start`) |
| `security.posture` (on change + daily) | `security_patch`, `patch_age_days`, `encrypted`, `lock_secure`, `adb_enabled`, `adb_wifi_enabled`, `dev_options`, `unknown_sources`, `private_dns_mode`, `private_dns_host`, `always_on_vpn` (bool), `device_owner`, `verified_boot_state`, `user_ca_certs` (list of fingerprints), `usb_data_signaling`. `play_protect` is never sent by the agent (no reliable read on recent Android) |
| `security.posture_change` (sev depends on the field) | emitted **in addition to** `security.posture` for every field that changes: `field`, `old`, `new` (values converted to strings). Allows one alert per change. `patch_age_days` (derived from the date) never produces a `security.posture_change` |
| `security.keyguard` | `event` (`unlock_failed`/`unlock_succeeded`), `failed_attempts` |
| `security.ca_cert` (sev 2) | `event` (`added`/`removed`), `sha256`, `subject` |
| `security.policy` | `action`, `target`, `profile`, `ok`, `error`, and `permission` for the actions of the guards (see below) |

`security.policy.action` takes one of: `private_dns_set`, `package_disabled`, `package_enabled`,
`permission_denied`, `permission_granted` (self-grant by the Device Owner), `permission_restored`,
`restriction_set`, `restriction_cleared`, `setting_changed`, `setting_restored`, `network_logging`,
`security_logging`, `force_stop_protection`, `always_on_vpn`, `backup_service`, `policy_reverted` (restore
everything), `device_owner_cleared`, and the guard actions of §11.1 (`guard_enabled`, `guard_disabled`,
`quarantined`, `released`). `target` is the package (or component), or the guard key for `guard_enabled` and
`guard_disabled`.

`security.log`: `fields` names the tag's payload as follows (the 0/1 success flags become `success` booleans);
any tag not listed uses `arg0`, `arg1`… in payload order.

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

### Events produced by the server

These events are generated by the collector, never by the device. In the Wazuh export they carry
`watchpost.source = "server"` (§5); events from the device carry no `source`. They never appear in the agent's
buffer.

| Type | Defined in | Meaning |
|---|---|---|
| `command.issued`, `command.cancelled`, `command.reported`, `command.expired` | §8 | life of a remote command |
| `tracking.level_changed`, `tracking.override` | §9 | change of blocking level, or of the rule for one domain |
| `detect.*` | §11.3, §11.4 | detections computed by the collector |
| `detect.muted`, `detect.unmuted` | §11.4 | muting of a detection |

The device itself produces one command-related event, `command.result` (§8).

## 3. Ingestion API (phone → server)

Dedicated host (for example `ingest.example.org`), TLS with a **mandatory client certificate** (terminated by
Caddy, Watchpost private CA) **and** an `Authorization: Bearer <device_token>` header.

### `POST /api/v1/ingest`

Headers: `Content-Type: application/json`, `Content-Encoding: gzip` (recommended).
Limits: 500 events per batch, 1 MiB compressed, 8 MiB decompressed.

```json
{
  "device_id": "dev_8f3a…",
  "agent_version": "1.0.0",
  "sent_at": "2026-11-15T21:45:00.000Z",
  "events": [ { "id": "…", "ts": "…", "seq": 1, "boot_id": "…", "elapsed_ms": 1, "type": "…", "sev": 0, "data": {} } ]
}
```

Response `200`:

```json
{ "accepted": 498, "duplicates": 2, "rejected": [ { "id": "…", "reason": "invalid_type" } ], "server_time": "2026-11-15T21:45:00.412Z" }
```

- A batch is processed atomically per event: `accepted` + `duplicates` + `rejected` = number received.
  The agent removes the `accepted`, the `duplicates` **and** the `rejected` events from its buffer (a rejection is
  final). A `200` response whose counters do not add up to the batch size is treated as an error by the agent
  (it keeps everything).
- `401`: invalid token or certificate, or revoked device (the agent keeps its data and retries later). `403` is
  treated like `401`.
- `413`: batch too large (the agent reduces the batch size; a `413` on a single event removes that event, counted
  in `dropped_total`).
- `429` / `5xx`: retry with backoff (honour `Retry-After`).
- `device_id` must match the token, otherwise `401`.
- `400` (unreadable or invalid batch envelope): the agent splits the batch in two and resends each half; an event
  that still receives `400` when sent alone is dropped and counted in `dropped_total`. The server never answers
  `400` for a defect specific to one event (it puts it in `rejected`). A batch with no events (`"events": []`)
  is valid and receives `200`: at the first `400` of a pass, the agent uses it as a probe. If the probe also
  receives `400`, the fault lies in the envelope or in the server and nothing is dropped.

### `GET /api/v1/ping`

Same authentication. Response `200` `{ "server_time": "…", "device_id": "…" }`. Used by the enrollment test.

The server can send the agent only the commands of §8; there is no configuration or policy endpoint in the API.

## 4. Enrollment file `.watchpost`

Produced by `watchpost-collector enroll`, imported into the app (file picker). JSON:

```json
{
  "version": 1,
  "ingest_url": "https://ingest.example.org",
  "device_id": "dev_8f3a…",
  "device_name": "phone",
  "device_token": "…",
  "client_cert_pem": "-----BEGIN CERTIFICATE-----…",
  "client_key_pem": "-----BEGIN PRIVATE KEY-----… (PKCS#8, ECDSA P-256)",
  "server_ca_pem": "… (optional: if present, the agent accepts only this CA for the server)",
  "private_dns_host": "dns.example.org (optional)"
}
```

- `device_id`: `dev_` followed by characters `[a-z0-9]`, 64 characters at most. `device_token`: characters
  `[A-Za-z0-9._~-]`, 128 at most. At import, the agent refuses a file in which these fields contain anything
  other than visible ASCII.
- Renewal: `watchpost-collector renew <device_id> --out <file.watchpost>` issues a new token and a new
  certificate for the **same** `device_id` (the history is not split). The old token and certificate remain
  accepted until the first authenticated upload with the new ones, and are refused afterwards. The agent imports
  the new file without losing its buffer.
- The client PKI (private ECDSA P-256 CA, plus one certificate per device, `CN=<device_id>`, usage `clientAuth`)
  is managed by the collector itself; the CA is created on first start in its data directory.
- The agent imports the key into the Android Keystore (non-exportable) and then forgets the PEM.
- The file contains secrets: transfer it by cable (ADB) or over an encrypted channel, then delete it.

## 5. Export to Wazuh

The collector appends one JSON line per accepted event to an NDJSON file (volume shared with the Wazuh
manager). Everything sits under the root key `watchpost` to avoid field collisions:

```json
{"watchpost":{"device_id":"dev_8f3a…","device_name":"phone","id":"…","ts":"…","received_at":"…","seq":18234,"type":"net.dns","domain":"net","sev":0,"data":{"package":"com.google.android.gms","hostname":"app-measurement.com"}}}
```

`domain` is the part of `type` before the first dot. Events produced by the server (§2) add
`"source":"server"`. The Wazuh rules filter on `watchpost.type`, `watchpost.sev` and `watchpost.data.*`.

Constraints of the Wazuh JSON decoder (verified, see [`docs/research/server-siem-dns.md`](../research/server-siem-dns.md)):

- Every line starts with `{"` and never exceeds 32 KiB (Wazuh truncates, and therefore loses, beyond about 65 KB):
  beyond that, `data` is replaced by `{"truncated": true}` in the export (the full event remains in the
  collector's database).
- **Arrays of objects are not decoded.** In the export, every array of objects in `data` is therefore removed and
  replaced by `<key>_count`; for the types below the collector additionally emits **one line per element**, with a
  derived type and the element flattened into `data`:

  | Original type | Key | Derived type (export only) |
  |---|---|---|
  | `app.inventory` | `apps` | `app.inventory.app` |
  | `net.usage` | `apps` | `net.usage.app` (with `from`, `to`) |
  | `net.wifi_scan` | `aps` | `net.wifi_scan.ap` |
  | `app.ops` | `apps` | `app.ops.app` |

  Derived lines carry the original `id` suffixed with `#<index>`. Arrays of scalars are kept.
- `location.fix` additionally carries `watchpost.data.location = {"lat": …, "lon": …}` for an optional
  `geo_point` mapping on the indexer side.
- The file is rotated by **renaming** only (never by truncation: truncation triggers Wazuh rule 592 at level 8).
- Detections that are updated are re-exported only under the conditions of §11.3.

## 6. Console API (browser → collector)

Prefix `/api/console`. Cookie session (`HttpOnly`, `Secure`, `SameSite=Strict`) obtained with
`POST /api/console/login` `{ "username", "password" }` → `204`; `POST /api/console/logout`;
`GET /api/console/me` → `{ "username" }` or `401`. Every state-changing request requires the header
`X-Requested-With: watchpost`. A session expires after 12 hours of inactivity (→ `401`). `POST /login` is
rate-limited (→ `429` with `Retry-After`). Dates are RFC 3339; `from` and `to` are required unless stated
otherwise. `cursor` values are opaque strings.

| Method and path | Parameters | Response |
|---|---|---|
| `GET /devices` | — | `{ "devices": [ { "device_id", "name", "enrolled_at", "last_seen", "agent_version", "revoked", "last_heartbeat": {…data}, "last_heartbeat_ts", "last_location": { "ts","lat","lon","acc_m" }, "last_posture": {…data}, "last_posture_ts", "command_channel": {…} } ] }`. `last_heartbeat_ts` and `last_posture_ts` (RFC 3339) are absent when unknown. `command_channel` is described in §8 |
| `GET /events` | `device_id`, `type` (comma-separated prefixes, e.g. `net.,security.log`), `sev_min`, `from`, `to`, `q` (text within `data`), `limit` (≤ 500, default 100), `cursor` | `{ "events": [ {event + "received_at"} ], "next_cursor": "…" }` (newest first) |
| `GET /events/{id}` | — | the full event |
| `GET /locations` | `device_id`, `from`, `to`, `max_points` (default 2000, regular downsampling) | `{ "points": [ { "ts","lat","lon","acc_m","speed_mps","provider" } ] }` |
| `GET /stats/timeline` | `device_id`, `from`, `to`, `bucket` (`minute`/`hour`/`day`), `by` (`domain`/`type`/`sev`), `type` (optional, comma-separated prefixes, as for `/events`) | `{ "buckets": ["…"], "series": [ { "key": "net", "counts": [ … ] } ] }` |
| `GET /stats/top` | `device_id`, `from`, `to`, `kind` (`dns_hostname`, `dns_package`, `connect_dest`, `connect_package`, `usage_package`, `foreground_package`, `notification_package`, `event_type`), `package` (optional: restricts to events whose `data.package` equals this value, e.g. `kind=dns_hostname&package=com.google.android.gms` = domains requested by that app), `limit` (default 20) | `{ "items": [ { "key", "count", "bytes" (if relevant) } ] }`. The key of `connect_dest` is `ip:port`. `usage_package` returns `count` and `bytes` (= rx + tx) |
| `GET /apps` | `device_id` | last reconstructed inventory: `{ "ts", "apps": [ … ] }` |
| `GET /posture` | `device_id` | `{ "current": {…}, "ts", "changes": [ { "ts", "field", "old", "new" } ] }` |
| `GET /alerts` | `from`, `to`, `level_min`, `limit` | `{ "wazuh": true, "alerts": [ { "ts","level","rule_id","description","type","device_id" } ] }`; `{ "wazuh": false, "alerts": [] }` if the indexer is not configured |
| `GET /stream` | `device_id` (optional) | Server-Sent Events: one JSON event per message (default SSE messages, `data: <event JSON>`), plus a keep-alive comment every 25 s |

The remote commands, the Tracking page and the detections have their own endpoints, defined in §8, §9 and §11.
`GET /healthz` (no authentication, outside the console prefix) answers `200 ok`.

Errors: JSON `{ "error": "code", "message": "…" }` with the appropriate HTTP status.

Static files: a path with an extension that does not exist returns `404` (not `index.html`); `.js` files are served
as `text/javascript`. The exact CSP header expected by the console is:
`default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self' <tile origin>; worker-src 'self'; font-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`.

Map tiles: the variable `WATCHPOST_TILE_URL` (default `https://tile.openstreetmap.org/{z}/{x}/{y}.png`). The tile
origin in the CSP is derived from it, and the collector itself answers `GET /config.json` with
`{ "tileUrl": "<WATCHPOST_TILE_URL>" }` (which takes precedence over the console's static file).

## 7. Collector operations interface

Single binary `watchpost-collector`, subcommands:

| Command | Purpose |
|---|---|
| `serve` | Starts the HTTP server (ingestion + console API + console files). Creates the database and the CA if absent. |
| `enroll --name <name> --out <file.watchpost>` | Creates a device (identifier, token, client certificate) and writes the enrollment file. |
| `devices` / `revoke <device_id>` | Lists / revokes (token and certificate are refused immediately). `devices` also shows the certificate expiry date. |
| `renew <device_id> --out <file.watchpost>` | New token and new certificate for the same device (see §4). |
| `user set-password <name>` | Creates or updates a console account (password read from standard input). |
| `sim --url … --enroll <file.watchpost> [--rate …] [--backfill 24h] [--scenario …] [--app-ops=false]` | Simulator: sends realistic events of every catalogue type through the ingestion API (tests, demonstration). Scenarios are listed in §11.3. |

Configuration by environment variables:

| Variable | Default | Purpose |
|---|---|---|
| `WATCHPOST_LISTEN` | `:8080` | HTTP listen address (plain, behind Caddy). |
| `WATCHPOST_DATA_DIR` | `/data` | SQLite database `watchpost.db`, PKI `pki/ca.crt` and `pki/ca.key`. |
| `WATCHPOST_EXPORT_NDJSON` | empty (disabled) | Path of the NDJSON file for Wazuh. Rotation by renaming (`.1`…). |
| `WATCHPOST_EXPORT_MAX_BYTES` / `WATCHPOST_EXPORT_KEEP` | `52428800` / `5` | Rotation size and number of files kept. |
| `WATCHPOST_TRUSTED_PROXIES` | `127.0.0.1/32` | CIDRs from which proxy headers are accepted. |
| `WATCHPOST_REQUIRE_CLIENT_CERT` | `true` | Requires the `X-Watchpost-Client-Cert-Sha256` header (set by Caddy from a trusted proxy: hexadecimal SHA-256 fingerprint of the verified client certificate) to match the device's certificate. |
| `WATCHPOST_PUBLIC_INGEST_URL` | — | URL written into `.watchpost` files. |
| `WATCHPOST_PRIVATE_DNS_HOST` | empty | DoT host written into `.watchpost` files. |
| `WATCHPOST_SERVER_CA_FILE` | empty | Server CA to include in `.watchpost` (internal CA mode). |
| `WATCHPOST_RETENTION_DAYS` | `90` | Purge of older events. |
| `WATCHPOST_CONSOLE_DIR` | empty | Serves the console from this directory instead of the embedded files (development). |
| `WATCHPOST_COOKIE_SECURE` | `true` | `false` only for local HTTP development. |
| `WATCHPOST_TILE_URL` | OpenStreetMap | Map tile URL template (§6). |
| `WATCHPOST_WAZUH_INDEXER_URL`, `…_USER`, `…_PASSWORD`, `…_CA_FILE`, `…_INSECURE` | empty | Read access to the Wazuh indexer for `GET /alerts`. |
| `WATCHPOST_CMD_KEEPALIVE_S` | `120` | Keep-alive interval of the command stream (§8). |
| `WATCHPOST_ADGUARD_URL`, `…_USER`, `…_PASSWORD` | empty | Access to the AdGuard Home API (§9). |
| `WATCHPOST_ADGUARD_LEVELS_FILE` | empty | Levels file (§9). |
| `WATCHPOST_ADGUARD_POLL_S` | `60` | Query-log polling interval. |
| `WATCHPOST_ADGUARD_CLIENTS` | empty (optional) | `device_id=client,…` mapping. |
| `WATCHPOST_DETECT_*` | see §11.3 | Detection thresholds. |

On the Caddy side: the ingestion host exposes only `/api/v1/*` (client certificate mandatory, CA = the
collector's `pki/ca.crt`, mounted read-only) and sets `X-Watchpost-Client-Cert-Sha256`; the console host
exposes only `/api/console/*`, `/healthz` and the static files. Caddy removes any incoming `X-Watchpost-*` header.

## 8. Remote commands (console → collector → agent)

Closed list; any other `type` is refused by the collector **and** by the agent.

The command channel is **off by default** in the app. The user turns it on in the **Remote commands** screen,
sets the command passphrase there, and allows remote erase separately (by typing `ERASE`).

| `type` | `params` | Level |
|---|---|---|
| `ring` | `duration_s` (1 to 300, default 60), `vibrate` (bool, default true): ring at full volume even in silent mode | simple |
| `vibrate` | `duration_s` (1 to 60, default 10) | simple |
| `stop_ring` | — | simple |
| `locate` | —: immediate precise position (acquisition up to 60 s), then immediate flush of the buffer | simple |
| `lock` | `message` (optional, at most 200 UTF-16 code units, displayed on the lock screen; no control characters except line feed, and U+2028 and U+2029 are refused like control characters) | **sensitive** |
| `clear_lock_message` | — | **sensitive** |
| `wipe` | —: factory reset | **sensitive** + the "Allow remote erase" setting turned on in the app (off by default) |

A command without parameters has `"params": {}`.

Behaviour of the simple commands on the device:

- `ring` plays on the "alarm" stream. If Do Not Disturb silences alarms, the sound stays muted and the result
  carries `detail = "dnd_alarms_muted"` (an app, even a Device Owner, can no longer lift that mode).
- `wipe` calls `DevicePolicyManager.wipeDevice(0)`; factory reset protection (Google account required after
  restart) and eSIMs are kept. The agent emits the result event, attempts an immediate upload (10 s at most),
  then erases.

Nothing in a command can change a setting, the policy or the enrollment.

### 8.1 Command object

```json
{ "id": "01JCQ8Z3K4M5N6P7Q8R9S0T1V2", "payload": "<JSON text>", "sig": "<base64, absent for a simple command>" }
```

`payload` is a **string** containing the JSON below, built by the browser; the collector relays it byte for
byte, and the agent verifies the signature over those bytes before parsing them:

```json
{"v":1,"id":"01JCQ8Z3K4M5N6P7Q8R9S0T1V2","device_id":"dev_…","type":"lock","params":{"message":"…"},"issued_at":"2026-11-16T10:00:00.000Z","expires_at":"2026-11-23T10:00:00.000Z"}
```

- `id`: ULID generated by the browser, identical in the object and in `payload`.
- The `payload` admits neither unknown keys nor duplicate keys.
- `issued_at`: the console aligns it with the server clock (the `Date` header). The collector accepts a
  difference of at most 10 minutes (otherwise `400`: a wrong browser clock prevents issuing a command); the
  agent refuses an `issued_at` more than 5 minutes in the future.
- Validity (`expires_at` − `issued_at`), enforced by the console, by the collector (`400` beyond the limit) and by
  the agent (`expired` beyond the limit):

  | Command | Default | Maximum |
  |---|---|---|
  | simple command | 1 h | 30 days |
  | `lock`, `clear_lock_message` | 7 days | 30 days |
  | `wipe` | 15 min | 24 h |

### 8.2 Signature of sensitive commands

`sig = base64( HMAC-SHA256( K, UTF-8 bytes of payload ) )` with
`K = PBKDF2-HMAC-SHA256( passphrase, salt = "watchpost-cmd-v1:" + device_id, 600,000 iterations, 32 bytes )`.

- The **command passphrase** is chosen by the user in the app, which keeps only `K` (encrypted at rest). It is
  typed again into the console for every sensitive command, is never remembered there and is **never sent to the
  server** (derivation and signature by WebCrypto in the browser).
- It must be at least 12 characters long **and** is refused if too weak (fewer than 6 distinct characters, or
  digits only below 20 characters). The app and the console recommend five random words.
- The passphrase is not Unicode-normalised, in the app or in the console: type it identically (avoid composed
  accented characters).
- The collector cannot verify `sig`; it only requires its presence for a sensitive type (and its absence for a
  simple one), and clears `sig` from its database as soon as a command reaches a final state.

Test vector (to be reproduced in the Kotlin, TypeScript and Go tests): passphrase `correct horse battery staple`,
`device_id` `dev_0123456789abcdef` →
`K` = `05fd656216f9ae34c3be8e6afcfa857c535e9e0ef438ab6c2de7130891abdb8b`; for the `payload`
`{"v":1,"id":"01JCQ8Z3K4M5N6P7Q8R9S0T1V2","device_id":"dev_0123456789abcdef","type":"lock","params":{"message":"Lost phone — please call +1 555 0100"},"issued_at":"2026-11-16T10:00:00.000Z","expires_at":"2026-11-23T10:00:00.000Z"}`
→ `sig` = `VVQ7B/b3fOzaG+sWd7Fqi7NKVRzdu5L3+NEIKurMXdE=`.

**What the signature guarantees, and its limits.** No sensitive command runs without a valid signature for the
passphrase set on the phone. But:

1. the server holds the `payload` and `sig` of every command issued, so it can search for the passphrase offline:
   the guarantee holds only with a high-entropy passphrase (at least five randomly drawn words, reserved for this
   use);
2. the page where the passphrase is typed is served by the server: a compromised server can read it the next time
   it is typed;
3. a signed command remains executable until `expires_at`: cancelling it or seeing it as "expired" in the console
   binds only the server; only changing the passphrase on the phone invalidates a command that was already signed.

### 8.3 Checks made by the agent (in this order) and refusal reasons

| Check | Reason on failure |
|---|---|
| command channel turned on | `disabled` |
| `payload` parseable, `v` = 1, `id` identical to the object's; no `sig` on a simple command | `malformed` |
| `device_id` is its own | `wrong_device` |
| `type` known | `unknown_type` |
| sensitive type: a passphrase is set | `no_code_configured` |
| sensitive type: signature valid, compared in constant time | `bad_signature` |
| `wipe` allowed locally ("Allow remote erase") | `disabled` |
| not expired, with 5 min of clock tolerance; validity within the maximum of §8.1 (30 days, 24 h for `wipe`); `issued_at` not more than 5 min in the future | `expired` |
| `id` never executed before (the agent remembers the last 500) | `replay` |
| parameters within bounds | `bad_params` |
| Device Owner, required for `lock`, `clear_lock_message` and `wipe` | `not_device_owner` |

- After 5 `bad_signature` refusals within an hour, the agent refuses every sensitive command for an hour
  (`locked_out`).
- The anti-replay memory of signed commands is distinct from that of simple commands.
- A sensitive command refused by the agent with `disabled` or `no_code_configured` is **consumed**: its `id`
  enters the signed anti-replay memory and it will never run, even if the setting changes afterwards.
- An unreadable `type` yields `command.result.type = "unknown"`.

Each command processed produces a `command.result` event: `command_id`, `type`, `status`
(`executed`/`failed`/`refused`), `detail` (reason), `signed` (bool). Severity: 0 for a simple command executed,
1 for an executed `clear_lock_message`, for any `failed` and for the refusals not listed below, 2 for an executed
`lock` or `wipe`, 3 for `bad_signature` and `locked_out`.

### 8.4 Agent-side API (ingestion host, same authentication as §3)

| Method and path | Purpose |
|---|---|
| `GET /api/v1/commands/stream` | Permanent connection (Server-Sent Events). On connection the server sends the pending commands that have not expired, then the new ones: `event: command` + `data: <command object>`. Keep-alive comment every 120 s (`WATCHPOST_CMD_KEEPALIVE_S`; it must stay ≤ 240, because the agent's read timeout on the stream is 300 s). One connection per device (a new one replaces the old one). |
| `GET /api/v1/commands` | Polling mode: `{ "commands": [ … ] }` (pending commands that have not expired). |
| `POST /api/v1/commands/{id}/result` | `{ "status": "executed"｜"failed"｜"refused", "detail": "…", "at": "…" }` → `204`. Idempotent. |

The agent chooses the mode by setting: permanent connection (default) or polling every 1 to 15 min. It
reconnects with backoff and when connectivity returns, and also polls on every batch upload.

### 8.5 Console API (prefix `/api/console`)

| Method and path | Parameters | Response |
|---|---|---|
| `GET /commands` | `device_id`, `limit` (default 50) | `{ "commands": [ { "id","device_id","type","params","signed","status","created_at","created_by","expires_at","delivered_at","result_at","detail" } ] }`; `status` ∈ `pending`/`delivered`/`executed`/`failed`/`refused`/`expired`/`cancelled` |
| `POST /commands` | body `{ "device_id", "payload", "sig" }` (and optionally `id`, identical to the `payload`'s); any other key → `400` | `201 { "id" }`. The collector validates `payload` (type from the list, parameter bounds, device exists and is not revoked, validity, unseen `id`, `sig` present if and only if the type is sensitive). Limits: 20 commands per hour and 10 pending per device (`429`). |
| `POST /commands/{id}/cancel` | — | `204` if still `pending`, otherwise `409`. A cancelled command carries `detail: "cancelled"`. |

`GET /devices` carries in addition `command_channel`:
`{ "connected": bool, "mode": "stream"｜"poll"｜"unknown", "last_contact": "…" }`. `connected` means that a stream
is open at that instant; a device in polling mode has `connected: false`, `mode: "poll"`, and is judged on
`last_contact`.

Life of a command:

- **Resending.** A delivered command whose result does not arrive is sent again after 5 minutes (3 times at
  most). An agent that receives an `id` it has already processed **sends the original result again** (it keeps it
  together with the `id`); it answers `refused`/`replay` only if it no longer has that result, and that refusal
  does not close the command on the server side.
- **Results.** The first result received is authoritative. A result received after expiry or cancellation
  **updates** the state of the command (the phone is authoritative); until a result arrives for a command that
  was delivered, the console shows "Expired with no reply: may have been executed".
- Each creation, cancellation and result is logged by the collector and exported to Wazuh as server events
  (`watchpost.source = "server"`): `command.issued`, `command.cancelled`, `command.reported`, `command.expired`.

## 9. Tracking page: what is blocked, what gets through

The collector reads the AdGuard Home query log through its API (`WATCHPOST_ADGUARD_URL`,
`WATCHPOST_ADGUARD_USER`, `WATCHPOST_ADGUARD_PASSWORD`), aggregates it by hour and by domain (queries, blocked,
allowed, reason), and cross-references it with `net.dns` (which application requests which domain) and `net.usage`
(bytes sent and received per application). Domains are attributed to a publisher (Google, Samsung, Meta,
Microsoft, Amazon, TikTok/ByteDance, advertising and audience measurement, others) by a versioned file of suffixes
in the collector (`server/collector/internal/tracking/publishers.txt`). The content of exchanges is not visible
(TLS). Publisher keys: `google`, `samsung`, `meta`, `microsoft`, `amazon`, `bytedance`, `ads`, `other`. `reason`
is free human-readable text.

Console API (prefix `/api/console`; `from` and `to` required unless stated):

| Method and path | Parameters | Response |
|---|---|---|
| `GET /tracking/summary` | `device_id`, `from`, `to` | `{ "adguard": bool, "level": "balanced", "levels": [ { "key","name","description" } ], "totals": { "queries","blocked","allowed" }, "publishers": [ { "key","name","queries","blocked","allowed","domains","apps","tx_bytes","rx_bytes" } ] }` |
| `GET /tracking/domains` | `device_id`, `from`, `to`, `publisher`, `status` (`blocked`/`allowed`/`all`), `q`, `limit` (≤ 200), `cursor` | `{ "adguard": bool, "domains": [ { "domain","publisher","queries","blocked","allowed","status" (`blocked`/`allowed`/`mixed`),"reason","override" (`block`/`allow`/absent),"apps": [ { "package","count" } ] } ], "next_cursor" }` sorted by descending queries |
| `GET /tracking/apps` | `device_id`, `from`, `to`, `publisher` (optional: publisher of the domains contacted) | `{ "adguard": bool, "apps": [ { "package","label","queries","blocked","allowed","tx_bytes","rx_bytes","top_domains": [ { "domain","count","status" } ] } ] }` |
| `PUT /tracking/override` | body `{ "domain", "action": "block"｜"allow"｜"default", "force" (optional) }` | `204`. Writes an AdGuard rule in a delimited block managed by Watchpost (rules typed by hand in AdGuard are not touched). `override` targets the exact domain. |
| `GET /tracking/level` / `PUT /tracking/level` | body `{ "level" }` | current blocking level ∈ `permissive`/`balanced`/`strict`: turns the corresponding lists on or off in AdGuard. `GET` returns `{ "adguard", "level", "levels" }`. |

Semantics and limits:

- `status=blocked` means at least one blocked query; `allowed` means allowed or mixed.
- `level` is absent when the state of AdGuard matches no level. The level in force is the state of the lists
  enabled in AdGuard, nothing else: the console changes it, `install.sh` and `update.sh` keep it, and
  `install.sh --profile` applies it without remembering it.
- The mapping from level to lists is the file `infra/adguard/levels.json` (single source, read by the installation
  and by the collector through `WATCHPOST_ADGUARD_LEVELS_FILE`). It carries a `category` field per list
  (`threat`, `ads`, `tracking`, `mixed`, `custom`, `allowlist`); `detect.threat_domain` (§11.3) trusts only the
  `threat` lists.
- Bytes per publisher and the blocked/allowed counters per application are **estimates** (distributed in
  proportion to DNS queries) and must be presented as such.
- AdGuard not configured or unreachable: `"adguard": false`, the view is built from `net.dns` alone (`status` is
  absent), the aggregates already stored keep being served, and both `PUT` endpoints answer `503`.
- Essential domains (the Watchpost exceptions list: FCM, connectivity check, updates) cannot be blocked from the
  console without explicit confirmation (`"force": true`); the `409` response explains what blocking would break:
  `{ "error": "essential_domain", "message": "…", "breaks": [ { "domain", "breaks" } ] }`.
- Additional error codes: `502 adguard_error`, `409 corrupt_rules`, `503 levels_not_configured`,
  `503 adguard_unavailable`.
- AdGuard's `querylog.size_memory` must be about 50 (at 1, AdGuard itself loses entries under concurrent queries;
  above 500, the collector's polling may skip some).
- Server events (`watchpost.source = "server"`): `tracking.level_changed` (`old`, `new`) and `tracking.override`
  (`domain`, `action`, `forced`). Both also carry `user` (console account), and `changes` / `previous` where
  relevant; one event per non-revoked device; severity 2 when blocking is weakened.

## 10. Notifications (companion APK) and location modes

- **Companion APK** `io.github.erwsim.watchpost.notifier`: contains the only `NotificationListenerService`, does
  not have the `INTERNET` permission, has an icon and a screen explaining what it does, is signed with the same
  key as the agent and hands notifications to it over a local channel protected by a `signature`-level
  permission. Without it, the agent's `notifications` collector is "unavailable".
- `app.notification`: `package`, `event` (`posted`/`removed`), `category`, `channel`, `ongoing`, `importance` (a
  string among `none`/`min`/`low`/`default`/`high`/`max`). Only if "Notification content" is turned on (off by
  default): `title`, `text` (512 characters at most each), with `redacted` (bool) when a numeric code of 4 to 8
  digits was masked (masking is on by default). `redacted` is present only when there is content and masking is
  active. A `removed` event never carries a title or text. A list of apps excluded from content collection can be
  edited; the content of SMS and phone apps is excluded by default. The agent's own notifications and repetitive
  ongoing (`ongoing`) notifications are not emitted. Content filtering happens in the companion, before the local
  channel: with content turned off, title and text never leave its process.
- **Location**: the setting `mode` of the `location` collector ∈ `gps` (default: GPS + passive), `gps_network`
  (adds the network provider), `fused` (fused provider). `location.fix.provider` gives the actual provider of
  each fix. The app shows, for each mode, what is transmitted to Google.

## 11. Guards, app risk profile and detections

Goal: protect against malware **whatever its vector** (SMS, calls, accessibility, network relays,
exfiltration…), by locking down the capabilities it needs, scoring every application at install time, and
detecting abnormal behaviour.

### 11.1 Guards (agent, module `:policy`, Device Owner required)

Policy items that can be enabled one by one in the Policy screen, off by default, reversible with
"Restore everything" and with the ADB rescue, logged by `security.policy` (`profile = "guard:<key>"`).

| Key | Effect |
|---|---|
| `sms` | Denies `SEND_SMS` to every application except a chosen list (pre-filled with the default SMS app); option to also deny `READ_SMS`/`RECEIVE_SMS`. Applies to applications already installed and to those installed afterwards. |
| `calls` | Denies `CALL_PHONE` (and optionally `ANSWER_PHONE_CALLS`, `READ_CALL_LOG`) except a chosen list (default dialer). |
| `accessibility` | Only approved accessibility services (and those of the system) can be enabled. |
| `input_methods` | Only approved keyboards (and those of the system) can be enabled. |
| `quarantine` | Every newly installed non-system application is denied a set of risky permissions (SMS, calls, call log, contacts, microphone, camera, background location, nearby devices) until the user releases it in Watchpost. Applications already present when the guard is turned on are not touched. |

Permissions covered in addition to those named above: `RECEIVE_MMS`, `RECEIVE_WAP_PUSH`, `WRITE_CALL_LOG`,
`GET_ACCOUNTS`, `UWB_RANGING`/`RANGING`.

Safeguards:

- Lists can never exclude the default SMS app, the default dialer or the default keyboard in service, nor a
  system component.
- A guard that fails on one package reports it without blocking the others.
- **Who is spared.** The guards `sms`, `calls` and `quarantine` spare only system applications and the holder of the
  **matching** role (the SMS app for `sms`, the dialer for `calls`). A keyboard or home screen chosen by the user
  is **not** spared. A guard's list follows only its own role: when the role changes, the agent grants the new
  holder the permissions of the role by lifting the denial, and reports it. A malicious application **chosen as
  the default SMS app** is therefore reported, not blocked.
- The `accessibility` and `input_methods` guards never turn off a service that is already enabled (the platform
  refuses the list otherwise): it is added to the list automatically and the preview says so.
- Delay between the installation of an application and the application of the guard: a few seconds, up to 15
  minutes if the agent's process was stopped.
- "Release" restores the state from before quarantine ("ask" for a fresh installation).

Events: `security.policy` with `action` ∈ `permission_denied`/`permission_restored`/`guard_enabled`/
`guard_disabled`/`quarantined`/`released`, `target` (package or component, or the guard key for `guard_*`), and
`permission` where applicable. Severity 1 for `guard_*`, `quarantined` and `released`.

### 11.2 Risk profile and usage (agent, module `:collectors`)

| Type | When | `data` |
|---|---|---|
| `app.risk` | at installation, at update, and daily if the score or the reasons change | `package`, `label`, `version_code`, `installer`, `from_store` (bool), `score` (0 to 100), `level` (`low`/`medium`/`high`), `reasons` (list of codes), `granted` (the subset of `reasons` whose capability is actually granted: intent versus state) |
| `app.role` | on change (the first reading serves as a reference, without an event) | `role` (`sms`/`dialer`/`browser`/`home`/`keyboard`, and `assistant`/`autofill` when readable), `old`, `new` (packages; absent = unknown). Severity 2 for `sms`/`dialer`/`assistant`/`keyboard`/`autofill`, 1 otherwise |
| `app.ops` (experimental, off by default, requires `DUMP` granted over ADB) | hourly, only for operations that were used | `from`, `to`, `apps`: list of `{package, op, count, background_count, rejected_count, last_ts}` with `op` ∈ `send_sms`/`read_sms`/`receive_sms`/`call_phone`/`read_contacts`/`read_call_log`/`record_audio`/`camera`/`fine_location`/`get_accounts` |

About `app.ops`: `rejected_count` counts accesses refused by the system at the operation level. A send blocked
by a **guard** is refused earlier, at the permission check, and probably does not appear there. The counters are
lower bounds. In the Wazuh export, `app.ops` is split into `app.ops.app` (one line per element), like
`net.usage` (§5).

**Reasons** (closed list, each code documented in the app): `sideloaded`, `unknown_installer`,
`no_launcher_icon`, `sms_send`, `sms_read`, `calls`, `accessibility_service`, `notification_listener`,
`device_admin`, `overlay`, `install_packages`, `vpn_service`, `boot_receiver`, `background_location`,
`mic_camera_background`, `old_target_sdk`, `debuggable`, `combo_banking_trojan` (accessibility + overlay + SMS
or notifications), `combo_sms_fraud` (SMS sending + start at boot without being the SMS app),
`combo_stalkerware` (no icon + location or microphone + start at boot).

**Score and levels.** Levels: `low` 0 to 29, `medium` 30 to 69, `high` 70 to 100; the weighting is in
`android/README.md`. System applications and the Watchpost agent itself are scored but capped at `low` (score
≤ 29, reasons kept).

**The score measures declared capabilities, not acts.** `app.risk` is based on declared capabilities (requested
permissions, declared components) and not on granted permissions: the profile must be useful at installation time
and in the quarantine screen, before any grant, and must remain high when a guard prevents the grant. The
`granted` list tells intent from state. A declared capability is
worth its points, plus a bonus if it is granted; any application installed from outside a store is at least
`medium`. The event's `level` field is authoritative: the collector and the console do not recompute the level.
It follows that legitimate parental control, antivirus, automation and caller-identification applications come
out `high`, and a discreet piece of malware published on a store can come out `low`: the score is an indicator
of attention, not a verdict.

### 11.3 Detections (collector, server events `watchpost.source = "server"`)

Computed periodically from the data already received, exported to Wazuh and served to the console. Each
detection carries `device_id`, `package` if known, `window_from`, `window_to`, `updated_at`, `evidence` (short
object) and `severity` (integer from 0 to 3, same scale as `sev`). Thresholds can be tuned with environment
variables (`WATCHPOST_DETECT_*`, see `server/collector/README.md`, which also documents the `evidence` keys of
every type).

| Type | Condition |
|---|---|
| `detect.threat_domain` | an application requested a domain that AdGuard blocked under a threat list (cross-reference of `net.dns` × AdGuard reason) |
| `detect.upload_spike` | bytes sent by an application over one hour > max(floor, k × its hourly median over 14 days) |
| `detect.fanout` | an application connected to more than N distinct addresses within one hour |
| `detect.mail_ports` | an application that is not a known mail client connects to ports 25, 465 or 587 |
| `detect.dns_bypass` | an application connects to a known public DoH/DoT resolver (ports 443 and 853) |
| `detect.sms_abuse` | from `app.ops`: an application other than the default SMS app sent SMS, or the sending volume exceeds a threshold |
| `detect.sensor_background` | from `app.ops`: microphone or camera used in the background by an application, above a threshold |
| `detect.new_app_risky` | an application with `level = high` was just installed, or an application installed less than 24 h ago obtains a sensitive capability |
| `detect.sms_permission` | without `app.ops`, see §11.4 |
| `detect.default_app_changed` | without `app.ops`, see §11.4 |
| `detect.inventory_mismatch` | see §11.4 |
| `detect.flood` | see §11.4 |

Default thresholds:

- `detect.upload_spike`: more than 1 GiB per hour and more than 10 × the median (the floor alone during the
  first 7 days).
- `detect.fanout`: 300 distinct addresses per hour (100 with the screen off).
- `detect.mail_ports`, `detect.dns_bypass`: a single connection to a mail port or to a known public DoH/DoT
  resolver. For `detect.dns_bypass` only the known public resolvers are considered; the heuristic of "addresses
  never resolved by the phone's DNS" is not reliable with this data and is not implemented.
- `detect.sms_abuse`: one SMS sent or refused by an application other than the SMS app, or 200 per day.
- `detect.sensor_background`: microphone 10 and camera 3 background accesses per day.

Grouping and export:

- One detection **per application, per type and per UTC day** (for `detect.new_app_risky`: the 24 hours following
  the installation). A new occurrence updates the existing detection (`evidence` accumulates domains,
  capabilities and counters).
- Towards Wazuh, an update is re-exported (`update: true`, `detection_id`) only if the severity increases or a
  new element appears, at most once per hour.

Console API:

| Method and path | Parameters | Response |
|---|---|---|
| `GET /detections` | `device_id`, `from`, `to` (optional: last 30 days), `type`, `package`, `limit`, `cursor` | `{ "detections": [ { "id","ts","type","package","label","severity","summary","evidence","device_id","window_from","window_to","updated_at" } ], "next_cursor" }` |
| `GET /apps/risk` | `device_id` (required) | last `app.risk` per application, sorted by descending score: `{ "apps": [ { …last app.risk…, "ts" } ] }` |
| `GET /apps/ops` | `device_id`, `from`, `to` (required) | aggregate of `app.ops` per application and per operation: `{ "apps": [ { "package","label","count","background_count","rejected_count","last_ts","ops": [ … ] } ] }` |
| `POST /detections/mute`, `DELETE /detections/mute` | body `{ "device_id", "type", "package", "reason" }` | `204`. See §11.4 |
| `GET /detections/mutes` | `device_id` | `{ "mutes": [ { "device_id","type","package","reason","created_at","created_by" } ] }` |

Simulator scenarios: `sim --scenario healthy|sms-fraud|banking-trojan|proxy|spam|exfiltration|dns-bypass|stalkerware|silent-sms|all`.
`silent-sms` reproduces a store application that is granted `SEND_SMS` 25 to 30 hours after installation; with
`--app-ops=false` it produces a single detection, `detect.sms_permission` (a store application with this profile
is scored only `medium`, so nothing is raised at installation), and no `detect.sms_abuse`.

### 11.4 Coverage without `app_ops`, muting, recurrence and cap

Why this section exists: **without `app.ops`** (experimental, never seen working, probably unavailable on
Android 16), a bulk SMS send by a discreet application would trigger no detection, because SMS do not travel over
IP. The following rules close that gap as far as is possible.

**Detections without `app.ops`** (collector, from `app.inventory`, `app.permission_changed`, `app.role`):

- `detect.sms_permission` (severity 2): an application that is neither the default SMS app nor a system
  application **holds** `SEND_SMS`. One detection per application at first observation (initial inventory
  included), then again only if the permission is removed and granted again. `evidence`: `level`, `score`,
  `reasons`, `granted`, `since`, `until` (if the holding has ended), `source`.
- `detect.default_app_changed` (severity 3 for `sms`, 2 for `dialer`, `keyboard`, `assistant`): the default
  application of one of these roles changed (the classic route of SMS trojans: getting designated as the default
  SMS app). `evidence`: `role`, `old`, `new`, risk profile of the new application.
- `detect.inventory_mismatch` (severity 3, cannot be muted): an application declared "system" in the inventory
  while its installer or an earlier `app.installed` says otherwise. The application is then treated as an
  ordinary application by the other detections. An `app.inventory` cannot make an application pass as "system"
  against its `installer` or its history without this being reported.

With or without `app.ops`, the **SMS guard** remains the real protection: the console and the guides say so, and
the console shows "not monitored" for SMS sending as long as the `app_ops` collector is not running.

**Muting.** `POST /api/console/detections/mute` `{ "device_id", "type", "package", "reason" }` → `204`; `DELETE`
with the same fields lifts it; `GET /api/console/detections/mutes?device_id`. A covered detection is still
computed and stored (`muted: true`) but is neither exported to Wazuh nor notified, and the console collapses it.
Both `POST` and `DELETE` require `X-Requested-With: watchpost`. Errors: `400 not_mutable`,
`400 invalid_parameter`, `404 not_found`. Types that cannot be muted: `detect.sms_abuse`,
`detect.default_app_changed`, `detect.inventory_mismatch`, `detect.flood`. Each muting is a server event
`detect.muted` (severity 1) / `detect.unmuted` (severity 0), with fields `type`, `package`, `reason`, `user`.

**Recurrence.** For `detect.dns_bypass`, `detect.mail_ports` and `detect.upload_spike`, a detection whose
(type, application) pair was already reported within the last 30 days carries `recurring: true` and its severity
is capped at 1.

**Cap.** At most 200 detections per device per day; beyond that, a single `detect.flood` (severity 3: the device
sends incoherent data or is compromised) with `evidence` = `suppressed`, `limit`.
