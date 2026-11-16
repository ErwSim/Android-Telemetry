# watchpost-collector

Watchpost Go collector: ingestion API (phone → server), SQLite storage, API and files of the web console,
NDJSON export to Wazuh, client PKI, enrollment CLI and simulator. Specification:
[`docs/contract/contract.md`](../../docs/contract/contract.md) (§3 to §7, remote commands §8, Tracking page §9,
detections §11.3).

## Build

```sh
cd server/collector
go build -o bin/watchpost-collector .          # Go 1.24, no CGO; console = fallback page
go vet ./... && go test -race ./...
```

To embed the console: `(cd ../console && npm ci && npm run build) && rm -rf web/dist && cp -r ../console/dist web/dist`
then `go build`. `web/dist/` is not versioned; without it, `web/fallback/` is served.

Docker image (context `server/`, also builds the console): `docker build -t watchpost-collector:local server/`.
Final image `scratch`, user 65532, binary `/usr/local/bin/watchpost-collector`, built-in `HEALTHCHECK`
(`watchpost-collector healthcheck`). Behind a proxy with a private CA:
`docker build --network host --build-arg HTTPS_PROXY=… --secret id=ca_bundle,src=ca.crt …` (the base images
are changed with `--build-arg NODE_IMAGE=… GO_IMAGE=…`, for example `NODE_IMAGE=mirror.gcr.io/library/node:22-bookworm-slim`
and `GO_IMAGE=mirror.gcr.io/library/golang:1.24-bookworm` when Docker Hub answers `429`).

## Run in development (with simulated data)

```sh
export WATCHPOST_DATA_DIR=$PWD/.dev WATCHPOST_LISTEN=127.0.0.1:8080 WATCHPOST_COOKIE_SECURE=false \
       WATCHPOST_EXPORT_NDJSON=$PWD/.dev/export/events.ndjson WATCHPOST_PUBLIC_INGEST_URL=http://127.0.0.1:8080
# optional: WATCHPOST_CONSOLE_DIR=$PWD/../console/dist (console served from disk)
go run . serve &
go run . enroll --name phone --out .dev/phone.watchpost
printf '%s\n' 'console-password' | go run . user set-password admin
go run . sim --enroll .dev/phone.watchpost --backfill 48h --follow     # history, then real time
```

Console: <http://127.0.0.1:8080/> (admin / console-password). Over local `http://`, the simulator sets the
`X-Watchpost-Client-Cert-Sha256` header itself (accepted because 127.0.0.1 is a trusted proxy by default).

With remote commands and the Tracking page (fake AdGuard Home built into the simulator, no phone or real
AdGuard needed):

```sh
export WATCHPOST_ADGUARD_URL=http://127.0.0.1:3001 WATCHPOST_ADGUARD_USER=watchpost WATCHPOST_ADGUARD_PASSWORD=adguard-demo \
       WATCHPOST_ADGUARD_LEVELS_FILE=$PWD/examples/adguard-levels.example.json WATCHPOST_ADGUARD_POLL_S=10
go run . serve &          # (with the previous variables)
go run . sim --enroll .dev/phone.watchpost --backfill 6h --follow \
       --command-code 'correct horse battery staple' \
       --fake-adguard 127.0.0.1:3001 --fake-adguard-user watchpost --fake-adguard-password adguard-demo
```

The simulator opens the command stream (`--commands poll` for polling), checks each command like the agent
does (§8, with the passphrase given by `--command-code`), "executes" it (message on the error output), and
sends back the result and the `command.result` event. Realistic refusals: wrong passphrase (`bad_signature`,
and `locked_out` after 5), `wipe` without `--allow-wipe` (`disabled`), skewed clock `--clock-skew 2h`
(`expired`), no `--command-code` (`no_code_configured`). The fake AdGuard Home receives one query per
occurrence of each simulated `net.dns` (ClientID = device name, `--fake-adguard-client`), decides like
AdGuard does (enabled lists, user rules, `$important`) and serves `/control/querylog`,
`/control/filtering/status`, `set_rules`, `set_url`, `add_url`; it only starts listening once the history
(`--backfill`) is in its log. It knows the URLs of `examples/adguard-levels.example.json`.

## Commands

| Command | Role |
|---|---|
| `serve` | HTTP server; creates the database, applies the migrations and creates the CA if missing. |
| `enroll --name N --out F.watchpost [--ingest-url URL] [--force]` | New device + enrollment file (mode 0600). |
| `renew <device_id> --out F.watchpost [--ingest-url URL] [--force]` | New token and new certificate for the **same** device (contract §4), file 0600. Refused for an unknown or revoked device; a second `renew` before the switch replaces the pending pair. |
| `devices [--json]`, `revoke <device_id>` | List (with the expiry date of the current certificate, "to renew" within 30 days, and "renewal pending"), revocation (effective at the next request, even with the server running; it also invalidates the pending pair). In JSON: `cert_not_after`, `renewal_pending`, `renewal_issued_at`, `pending_cert_not_after`. |
| `user set-password <name>` | Console account; password ≥ 12 characters, read without echo on a terminal or as one line of stdin. |
| `sim --enroll F [--url U] [--backfill 24h] [--follow] [--rate 1] [--interval 15s] [--seed N]` | Simulator (see below). |
| `sim … [--scenario healthy\|sms-fraud\|banking-trojan\|proxy\|spam\|exfiltration\|dns-bypass\|stalkerware\|silent-sms\|all] [--app-ops=false]` | Attack scenarios (several separated by commas) and absence of `app.ops`; see "Detections". |
| `sim … [--commands stream\|poll\|off] [--poll-interval 1m] [--command-code C] [--allow-wipe] [--clock-skew D] [--notification-content=false] [--fake-adguard ADDR --fake-adguard-user U --fake-adguard-password P --fake-adguard-client ID]` | Simulated command agent (continuous mode) and fake AdGuard Home (see above). |
| `healthcheck [--url U]`, `version` | `/healthz` probe (Compose), version. |

Variables: those of contract §7, plus `WATCHPOST_TILE_URL` (§6, default OpenStreetMap; served by
`GET /config.json` and reflected in the CSP) and `WATCHPOST_LOG_LEVEL` (`debug`/`info`/`warn`/`error`), and:

| Variable | Default | Role |
|---|---|---|
| `WATCHPOST_CMD_KEEPALIVE_S` | `120` | Keep-alive comment of the command stream (5 to 3600 s); at each keep-alive, the device credentials are checked again (revocation, renewal) and the commands to hand over again are sent. |
| `WATCHPOST_ADGUARD_URL` | empty | AdGuard Home administration API (e.g. `http://adguardhome:3000`), `http(s)://host[:port][/prefix]` without credentials, query or fragment. Empty: Tracking page built from `net.dns` alone. |
| `WATCHPOST_ADGUARD_USER` / `WATCHPOST_ADGUARD_PASSWORD` | empty | Basic authentication against AdGuard Home (never logged). |
| `WATCHPOST_ADGUARD_LEVELS_FILE` | empty | Level → lists mapping file (format below), read and validated at startup (fatal error if invalid). Empty: `PUT /tracking/level` answers `503`. |
| `WATCHPOST_ADGUARD_POLL_S` | `60` | Polling interval of the AdGuard Home log (10 s at least). |
| `WATCHPOST_ADGUARD_CLIENTS` | empty | Optional: `device_id=client,…` (client = DoT ClientID or IP as seen by AdGuard; several pairs per device are possible). With `device_id`, the view then counts only the queries of those clients; without a match, the whole AdGuard log is attributed to the requested device. |

## AdGuard levels file (`WATCHPOST_ADGUARD_LEVELS_FILE`)

JSON (UTF-8, 1 MiB at most), produced by the infrastructure. Full example:
[`examples/adguard-levels.example.json`](examples/adguard-levels.example.json) (its URLs are illustrative:
the infrastructure must check the ones it keeps).

```json
{
  "version": 1,
  "lists": {
    "adguard_dns":    { "name": "AdGuard DNS filter", "url": "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt" },
    "hagezi_samsung": { "name": "HaGeZi - Native Tracker Samsung", "url": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/native.samsung.txt" },
    "exceptions":     { "name": "Watchpost exceptions", "url": "/opt/adguardhome/work/userfilters/watchpost-allow.txt", "allowlist": true }
  },
  "levels": [
    { "key": "permissive", "name": "Permissive", "description": "…", "lists": ["adguard_dns"] },
    { "key": "balanced",   "name": "Balanced",   "description": "…", "lists": ["adguard_dns", "hagezi_samsung", "exceptions"] },
    { "key": "strict",     "name": "Strict",     "description": "…", "lists": ["adguard_dns", "hagezi_samsung", "exceptions"] }
  ]
}
```

- `version`: `1`. Any unknown field is refused.
- `lists`: identifier (`[a-z0-9_-]{1,64}`) → `name` (1 to 128 printable characters: name given to the list if
  Watchpost adds it), `url` (`http://` or `https://`, or absolute path of a local AdGuard Home file, 2048
  characters at most, each URL only once) and `allowlist` (optional, default `false`: allowlist, AdGuard's
  `whitelist_filters`). A list is recognized in AdGuard by its **exact** URL and its kind (block / allow).
- `category` (optional): what the list blocks, among `threat` (phishing, malware, command servers, scams),
  `ads`, `tracking`, `mixed` (general-purpose list mixing advertising, tracking and some threats), `custom`,
  `allowlist`. **Only `threat` changes the behavior**: a block due to a `threat` list (recognized in AdGuard
  Home by its exact URL) feeds `detect.threat_domain`. An unknown value is refused (a typo must not silently
  turn the detection off); an allowlist cannot be `threat`. Nothing is deduced from the name or the URL:
  without `"category": "threat"`, no list is a threat list (`infra/adguard/levels.json` must therefore add it
  to `hagezi_tif`). AdGuard Home's Safe Browsing blocks (`FilteredSafeBrowsing`) also count as threats.
- `levels`: exactly the three levels `permissive`, `balanced`, `strict` (once each, in any order), with `name`
  (64 characters), `description` (500, may be empty) and `lists` (identifiers of `lists`, no duplicates).
- Applying a level (`PUT /tracking/level`): each list of the file is enabled if it is in the level, disabled
  otherwise (`POST /control/filtering/set_url`, current name kept); a list that is absent from AdGuard and
  required is added (`POST /control/filtering/add_url`, AdGuard downloads it: `502` if that fails). The lists
  that AdGuard knows but the file does not mention are **never** touched.
- Current level (`level` of `GET /tracking/summary` and `/tracking/level`): the first level whose lists from
  the file are exactly those enabled in AdGuard; absent if the state matches no level (lists changed by hand)
  or if AdGuard is unreachable.

## Detections (contract §11.3 and §11.4)

**Read this first: what protects against mass SMS sending.** SMS do not go through the IP network: only
`app.ops` (an experimental collector of the agent, which requires `DUMP` granted through ADB and may never work
on Android 16) counts them. **The real protection is the app's SMS guard** (contract §11.1): it prevents any
app other than the SMS app and the system from obtaining `SEND_SMS`. The detections warn, they prevent
nothing.

| What is detected | Without `app.ops` | With `app.ops` |
|---|---|---|
| An app (neither the SMS app nor a system app) **holds** `SEND_SMS` | `detect.sms_permission` (sev. 2), at the first observation, initial inventory included, then at each new grant after a revocation | same |
| An app becomes the default SMS app, dialer, keyboard or assistant | `detect.default_app_changed` (sev. 3 for SMS) | same |
| An app installed less than 24 h ago is rated `high` or obtains a sensitive capability | `detect.new_app_risky` | same |
| An app **sends** SMS (or tries to, SMS guard refusals included), and how many | **nothing**: neither the number nor the time of the sends is known | `detect.sms_abuse` (sev. 3), from the first hour |
| Microphone or camera in the background | **nothing** (only the raw `sensor.*` events) | `detect.sensor_background` |
| Network: threat servers, mass data upload, relays, spam, DoH | `threat_domain`, `upload_spike`, `fanout`, `mail_ports`, `dns_bypass` | same |

A discreet store app that obtains `SEND_SMS` about a day after its installation and then sends in bulk
(~2,000 SMS per day, a server absent from the threat lists) gives, **without `app.ops`**: **a single
detection**, `detect.sms_permission` at the grant — nothing at installation (a store app with this profile is
only rated `medium` by the agent, and `detect.new_app_risky` requires `high` or a capability acquired within
24 h), and never the volume sent; **with `app.ops`**, `detect.sms_abuse` as well (`silent-sms` scenario of the
simulator, trials below). A real phone often has, at the first observation, a few non-system apps that hold
`SEND_SMS` (visual voicemail, carrier app, connected watch…): one detection each, only once — this is an
intended initial review; `POST /detections/mute` files them away once examined.

Behavioral detections computed on the server from the data already received, to be alerted to an abuse
**whatever the vector** (SMS, network relay, exfiltration, spam, filter bypass). Each detection is an event of
the collector (`source = 'server'`, type `detect.*`, `boot_id` `server`) attached to the device: visible in
`/events`, broadcast on `GET /stream`, exported to Wazuh with `watchpost.source = "server"`, and listed by
`GET /detections`. `data`: `package` (if known), `label`, `window_from`, `window_to`, `summary` (sentence in
English), `evidence` (short, factual object: counters, a few addresses or domains; never notification or
message content). Severity (`sev`): 2, or 3 when the signal is unambiguous (see each detection). Windows in
**UTC** hours and days.

**How it works** (`internal/detect`): one pure function per detection (`rules.go`, tested on its own), fed by
a background job (`engine.go`) every `WATCHPOST_DETECT_INTERVAL_S`. Ingestion marks in `detect_dirty` each
hour (of `ts`) of a device in which a useful event arrives (`net.dns`, `net.connect`, `net.usage`, `app.ops`,
`app.risk`, `app.installed`, `app.permission_changed`, `app.special_access`, `app.role`); the AdGuard Home
poll marks the hours in which it counts a "threat" block. The job only rereads those hours (and their days) in
the hourly aggregates — `usage_counts` (bytes sent per application and hour), `top_counts` `connect_dest`
(addresses and ports per application and hour), `top_counts` `dns_hostname`, `tracking_counts.threat`,
`ops_counts` (migrations 6 and 7) — and, for the application events (rare), the index
`(device_id, type, ts_ms)`: **no scan of the `events` table**. A late batch (network logs delivered 1 h 30 to
2 h later, or days after an offline period) marks its hours again, which are evaluated again.
**Grouping and updates**: **one detection per application, per type and per window** — the UTC day for all of
them, the 24 h following the installation for `detect.new_app_risky`. The hourly conditions of the contract
(`upload_spike`, `fanout`) are still evaluated hour by hour, then grouped over the day (`evidence` of the peak
hour, plus `hours`, `first_hour`, `peak_hour`); `threat_domain` lists the application's domains of the day,
`new_app_risky` the capabilities acquired, `sensor_background` the microphone and the camera. Uniqueness of
`detections` on (device, type, subject = application, window start), checked in the transaction. When a window
is evaluated again (late batch, restart, new occurrences), the existing detection is **updated in place**
(`evidence`, `summary`, highest severity, merged items, `updated_at`) instead of creating another one.
**What is exported**: a `detect.*` event at creation; on an update, a new event of the same type (same fields,
plus `"update": true` and `"detection_id"` = `id` of the detection) **only if** the severity increases or an
item appears (new domain, new capability, new operation, new port, new resolver, SMS refusal), and **at most
once per hour** and per detection (what is held back goes out with the next update of the window); a mere
increase of the counters is not emitted again (the console sees it through the API). The Wazuh rules can
therefore alert on `watchpost.data.update` absent, and follow the aggravations separately. An hour marked
during its evaluation stays to be evaluated (counter `gen`). Reads go through the read-only pool (WAL:
ingestion never waits); writes are one short transaction per device and per round of 256 hours; a run stops
after 20 s and resumes at the next one. On upgrade, migration 6 marks the last two days already stored: the
detections cover the data received afterwards.

**Cost measurement** (`TestDetectionCost`, run with `WATCHPOST_DETECT_COST=89 go test ./internal/detect -run Cost -v`;
2026-11-16, without `-race`, grouped detections): database of **3,061,912 events** (89
simulated days at `--rate 2`, all attack scenarios over the last 40 hours, ~520 MB), i.e. 2,137 hours to
evaluate. Evaluation of the whole backlog (89 days evaluated again in full): **1.0 s** (11 rounds of 256 hours),
**5 MiB of heap** at most; simultaneous ingestion of batches of 500 events is not slowed down (median 5 ms,
p99 11 ms, with or without the job). Regular run after a late batch: **28 ms**. Over these 89 days, the 15
detections concern the 7 applications of the scenarios (`threat_domain` outside the measurement: no AdGuard):
none on the healthy fleet.

| Detection | What it sees (window, subject) | Default threshold and rationale | Limits and foreseeable false positives |
|---|---|---|---|
| `detect.threat_domain` | An application asked (`net.dns`) for a domain that AdGuard Home blocked **because of a `category: threat` list** or its Safe Browsing, on the same UTC day (one hour of margin on each side). One per application and per day, with its domains. Sev. 3, or 2 for the default browser or fewer than 3 requests (a phishing link followed once). | No threshold: a threat list is made to block nothing useful. | Nothing without AdGuard Home or a `threat` list (logged at startup). Matching by exact domain over the day: if several devices share AdGuard without `WATCHPOST_ADGUARD_CLIENTS`, a block for one device may be attributed to the request of another that asked for the same domain. False positives: those of the list itself (legitimate domain wrongly classified); an application that displays booby-trapped ads. |
| `detect.upload_spike` | Bytes sent (`tx_bytes` of `net.usage`) by an application over an hour > max(floor, k × its hourly median over 14 days). Median of the hours **in which the application sent something**. Evaluated per hour, one per application and per day (peak hour). Sev. 2. | Floor **1 GiB/h**, k = **10**. An HD video call sends 0.3 to 1 GiB/h, a night photo backup a few hundred MiB: under a lower floor, the detection would ring every week. The exfiltration targeted is massive (photo library, recordings). | **Learning**: as long as the device has less than `WATCHPOST_DETECT_UPLOAD_LEARN_DAYS` (7) days of `net.usage` history, or the application has fewer than 24 active hours over 14 days (new application), only the floor applies (`evidence.learning = true`): the detection works from the first day for large uploads and only refines itself afterwards. Does not see a slow exfiltration (a few MiB per hour) nor what goes through another application (browser, messenger). `net.usage` is filed in the hour of its `ts` (end-of-hour reading). False positives: first full backup of a photo library, upload of a long video, a multi-hour very-high-quality video call, tethering attributed to an application. |
| `detect.fanout` | An application connected to more than N **distinct** addresses (`net.connect`, all ports) in one hour. Evaluated per hour, one per application and per day (peak hour). Sev. 2. | **300**; **100** for an hour spent screen off (screen on 5 min at most according to `device.screen`; unknown state = on). An hour of intense browsing opens 50 to 150 addresses with the screen on; in the background, a healthy application contacts fewer than 20. A residential proxy relays hundreds of them at night. | Only sees what the Device Owner network logging reports (TCP connections through `connect()`), not the volume relayed. False positives: BitTorrent or peer-to-peer client, browser on a very busy site (screen on, rarely beyond 300), speed-test application, network scanner, a VPN that would be seen as a single application. |
| `detect.mail_ports` | An application that is not a known mail client connected to ports **25, 465 or 587** (sending e-mail). Day, subject = application. Sev. 2, 3 from 100 connections or 20 servers (spam volume). | **1 connection**: an ordinary application has no reason to send e-mail itself. List of known clients: [`internal/detect/mail_clients.txt`](internal/detect/mail_clients.txt), extended by `WATCHPOST_DETECT_MAIL_CLIENTS`. | Port 25 is often blocked by carriers (the attempts are seen all the same). False positives: a mail client missing from the list (one alert per day until it is added), an application that sends reports itself through SMTP. |
| `detect.dns_bypass` | An application connects to a **known public DNS resolver** on a port of `WATCHPOST_DETECT_DNS_BYPASS_PORTS` (443: DNS over HTTPS, 853: DNS over TLS): its requests escape AdGuard Home and `net.dns`. Versioned, readable list: [`internal/detect/resolvers.txt`](internal/detect/resolvers.txt) (Google, Cloudflare, Quad9, OpenDNS, public AdGuard DNS, NextDNS, Control D, CleanBrowsing, Mullvad, FDN…, only addresses reserved for DNS). Day, subject = application. Sev. 2. | **1 connection**. Port 53 is not followed by default: connecting to 8.8.8.8:53 is the common idiom for applications to test Internet access. | **Second heuristic of the contract (massive connections to addresses never resolved) left out**: it is not reliable with this data — `net.dns` and `net.connect` arrive in separate batches, a resolved address can serve for hours (cache, long connections), peer-to-peer and calling applications (WebRTC, WhatsApp, Telegram) legitimately connect to addresses learned outside DNS, and CDN/anycast blocks share addresses between names; it would ring every day. Does not see a private or unknown resolver (DoH to any domain). False positives: browser with built-in DoH enabled (Firefox, Chrome "secure DNS"), VPN application or Cloudflare's "1.1.1.1", network diagnostic application; to be exempted through `WATCHPOST_DETECT_DNS_BYPASS_EXEMPT` if intended. |
| `detect.sms_abuse` | According to `app.ops`: an application other than the default SMS app (role `sms` of `app.role` or `default_apps` of `app.special_access`, including a former holder of the day) **sent or tried to send** SMS — refused attempts (`rejected_count`, for example by the SMS guard) count as sends —, or an application sent or tried more than the day's maximum. Day, subject = application. Sev. 3. | **1** SMS for another application (system applications excepted, and only when the SMS app is known); **200** per day for any application (heavy use stays under 100; the malware targeted sends 2,000). | Silent without `app.ops` (experimental, may never arrive): no error. Counters = lower bounds. False positives: carrier or dual-SIM application, security application that sends an alert SMS, third-party SMS app chosen during the day before the role is read. |
| `detect.sensor_background` | According to `app.ops`: microphone (`record_audio`) or camera used **in the background** (`background_count`) by an application beyond a threshold per day. One per application and per day (microphone and camera together). Sev. 2. | Microphone **10**, camera **3** per day. A background call counts 1 or 2; stalkerware records dozens of times. Exempted: system applications, holders of the phone, assistant and call screening roles. | Silent without `app.ops`. Counts accesses, not durations: a single long recording counts 1. False positives: many messenger calls with the screen off, voice recorder or call recorder, baby monitor application, third-party voice assistant. |
| `detect.new_app_risky` | An application of level `high` has just been installed (`app.risk` within 24 h of its `app.installed`), or an application installed less than 24 h ago obtains a sensitive capability (SMS/call log/calls permission granted, appearance in the accessibility services, notification listeners, administrators, unknown sources, overlay, VPN of `app.special_access`, SMS/dialer/assistant/keyboard/autofill role of `app.role`). One per installation (window = the following 24 h), which lists the capabilities acquired. Sev. 2 (3 for a `combo_*`), 1 for overlay and VPN. | No threshold. **Only a recent installation**: a `high` application already present does not alert (the score measures declared capabilities: parental control, antivirus, automation, caller identification come out `high`); Watchpost itself is ignored. | Relies on `app.installed`: an installation made while the agent was not running is not seen. False positives: deliberate installation of an application of this kind (one detection per installation), of a third-party VPN or keyboard. |

**A detection that rang every day on a healthy phone would be ignored**: the defaults are measured by the
`healthy` scenario of the simulator (21 simulated days with video calls, night backups, intense browsing, a
mail client on port 465, updates, an app installed outside a store with medium risk, `app.ops` of the SMS app,
the dialer and the assistant): **zero detections** (`TestScenarioHealthyPhoneNoDetection`); likewise over the
89 days of the cost measurement.

| Variable | Default | Role |
|---|---|---|
| `WATCHPOST_DETECT_ENABLED` | `true` | `false`: no detection computed (the aggregates are still kept). |
| `WATCHPOST_DETECT_DISABLE` | empty | Detections turned off, separated by commas (`fanout,mail_ports` or `detect.fanout`…). |
| `WATCHPOST_DETECT_INTERVAL_S` | `300` | Interval between two runs (10 to 86400 s). |
| `WATCHPOST_DETECT_UPLOAD_FLOOR_MB` | `1024` | Floor of `detect.upload_spike`, in MiB per hour. |
| `WATCHPOST_DETECT_UPLOAD_FACTOR` | `10` | k of k × median (1 to 1000). |
| `WATCHPOST_DETECT_UPLOAD_LEARN_DAYS` | `7` | Device history needed before the median is used (0 to 14 days). |
| `WATCHPOST_DETECT_FANOUT` / `WATCHPOST_DETECT_FANOUT_SCREEN_OFF` | `300` / `100` | Distinct addresses per application and hour (screen on / off). |
| `WATCHPOST_DETECT_MAIL_MIN` | `1` | Connections per day to ports 25/465/587. |
| `WATCHPOST_DETECT_MAIL_CLIENTS` | empty | Packages added to the known mail clients. |
| `WATCHPOST_DETECT_DNS_BYPASS_MIN` | `1` | Connections per day to a public resolver. |
| `WATCHPOST_DETECT_DNS_BYPASS_PORTS` | `443,853` | Ports followed (add `53` for plain DNS). |
| `WATCHPOST_DETECT_DNS_BYPASS_EXEMPT` | empty | Packages allowed to use a public resolver. |
| `WATCHPOST_DETECT_SMS_OTHER_MIN` | `1` | SMS (sent or refused) per day by an application other than the SMS app. |
| `WATCHPOST_DETECT_SMS_DAILY_MAX` | `200` | SMS (sent or refused) per day above which any application is reported. |
| `WATCHPOST_DETECT_MIC_BG_MIN` / `WATCHPOST_DETECT_CAMERA_BG_MIN` | `10` / `3` | Background accesses per day. |

**Contract §11.4 in the collector**:

- `detect.sms_permission` (sev. 2, one per "holding" of `SEND_SMS`: window = start of the holding, one hour;
  holding = first grant seen in `app.permission_changed`, or first inventory that shows it, then each grant that
  follows a revocation; a holding that has ended since is reported too). Excluded: the default SMS app
  (`app.role`, otherwise `default_apps` of `app.special_access`), system apps (contradicted claim excluded),
  Watchpost.
- `detect.default_app_changed` (sev. 3 for `sms`, 2 for `dialer`, `keyboard`, `assistant`; one per `app.role`
  event whose `new` is known; the agent emits nothing at the first reading, so every `app.role` is a change).
- `detect.inventory_mismatch` (an addition of the collector, to carry over to the contract: it is the "reported"
  of §11.4).
- **Mute**: a covered detection is computed and stored with `muted: true`, **without an event** (no Wazuh
  export, no SSE stream); an update of a muted detection is not exported again. Lifting the mute does not
  export the past again. Types that cannot be muted: `detect.sms_abuse`, `detect.default_app_changed`,
  `detect.inventory_mismatch`, `detect.flood`. Server events `detect.muted` (sev. 1) and `detect.unmuted`
  (sev. 0): `type`, `package`, `reason`, `user`.
- **Recurrence**: `dns_bypass`, `mail_ports`, `upload_spike`: a **new** detection whose (type, app) already has a
  detection whose window starts within the 30 days before its own carries `recurring: true` (in the API and in
  the event data) and its severity is capped at 1 (updates included).
- **Cap**: 200 new detections per device and per UTC day (of creation); beyond that, nothing is stored except
  one `detect.flood` (sev. 3, exported once) per device and per day, whose `evidence.suppressed` counts the
  discarded detections (updated in place, not exported again). Muted detections count.

**Console API** (prefix `/api/console`) — additions to contract §11.3 and §11.4 to carry over (the console
follows them):

- `GET /detections?device_id&package&from&to&type&limit&cursor` → `{ "detections": [ { "id", "ts", "device_id",
  "type", "package", "label", "severity", "summary", "evidence", "window_from", "window_to", "updated_at", "muted",
  "recurring" } ],
  "next_cursor" }`, from the most recent to the oldest (by `ts`). `id` = identifier of the `detect.*` event that
  created the detection (`GET /events/{id}`); `ts` = time of creation; `updated_at` = last update (absent if
  never updated); `severity` = integer **0 to 3, same scale as `sev`** (in practice 1 to 3; highest value
  reached); `window_from`/`window_to` = window (RFC 3339 UTC); `package` = exact filter (`[A-Za-z0-9_.:-]`, 255
  at most, otherwise `400`); `from`/`to` **optional** (default: the last 30 days), apply to `ts`; `type` =
  comma-separated prefixes; `limit` ≤ 500 (100); `cursor` opaque.
- `GET /apps/risk?device_id` (required, otherwise `400`) → `{ "apps": [ { "package", "label", "version_code",
  "installer", "from_store", "score", "level", "reasons", …other fields of the event…, "ts" } ] }`: the latest
  `app.risk` of each application as received, plus `ts` (time of that `app.risk`), score descending then
  package; `{ "apps": [] }` without data.
- `GET /apps/ops?device_id&from&to` (`device_id` optional, `from`/`to` required, whole hours) →
  `{ "apps": [ { "package", "label", "count", "background_count", "rejected_count", "last_ts", "ops": [ { "op",
  "count", "background_count", "rejected_count", "last_ts" } ] } ] }`, applications by descending `count`,
  operations too; `label` and `last_ts` absent if unknown; `{ "apps": [] }` without `app.ops`.

- `POST /detections/mute` body `{ "device_id", "type", "package", "reason" }` (only keys allowed; `package`
  required, `[A-Za-z0-9_.:-]`, 255 at most; `type` = a known `detect.*` type; `reason` optional, 200 characters
  at most, no control characters; header `X-Requested-With: watchpost`) → `204` (idempotent: a second call
  replaces the reason, without a new event); `400 not_mutable` for a type that cannot be muted, `400
  invalid_parameter` / `invalid_json`, `404 not_found` for an unknown device.
- `DELETE /detections/mute`, same body → `204`, `404 not_found` if there is no such mute.
- `GET /detections/mutes?device_id` (optional) → `{ "mutes": [ { "device_id", "type", "package", "reason",
  "created_at", "created_by" } ] }`.

`evidence` keys per type (always an object; lists of scalars only, for Wazuh's decoder):

| Type | `evidence` |
|---|---|
| `detect.threat_domain` | `domains` (10 at most, most requested first), `domain_count`, `requests` (`net.dns` requests of the application), `blocked` (blocks counted by AdGuard), `lists` (readable reasons of the lists) |
| `detect.upload_spike` | `tx_bytes` (peak hour), `threshold_bytes`, `median_bytes` (absent during learning), `history_hours`, `learning`, `screen_on_minutes` (if known), `hours`, `first_hour`, `peak_hour` |
| `detect.fanout` | `addresses` (distinct, peak hour), `connections`, `threshold`, `ports` (5 at most), `sample` (5 addresses at most), `screen_on_minutes` (if known), `hours`, `first_hour`, `peak_hour` |
| `detect.mail_ports` | `connections`, `addresses`, `ports`, `sample` (3 addresses at most) |
| `detect.dns_bypass` | `connections`, `resolvers` (`address:port`, 5 at most), `providers` |
| `detect.sms_abuse` | `reason` (`not_default_sms_app` or `volume`), `sent`, `background`, `rejected`, `read_contacts` (if used), `default_sms_app` (if known) |
| `detect.sensor_background` | `ops` (`record_audio`, `camera`), `microphone_background`, `microphone_count`, `camera_background`, `camera_count` (depending on the operation) |
| `detect.new_app_risky` | `high_risk` (bool), `capabilities` (codes: `accessibility`, `notification_listener`, `device_admin`, `unknown_sources`, `overlay`, `vpn`, `role:<role>`, `permission:<NAME>`), `installer`, `installed_at`, `score`, `level`, `reasons`, `granted`, `from_store` (if an `app.risk` is known), `minutes_to_first_capability` |
| `detect.sms_permission` | `permission` (`SEND_SMS`), `source` (`permission_changed` or `inventory`), `since`, `until` (holding ended), `installer`, `default_sms_app` (if known), `score`, `level`, `reasons` (if an `app.risk` is known) |
| `detect.default_app_changed` | `role`, `old` (absent if unknown), `new`, `score`, `level`, `reasons`, `granted` (profile of the new app, if known) |
| `detect.inventory_mismatch` | `installer`, `contradictions` (`installer:<package>`, `app.installed`) |
| `detect.flood` | `suppressed`, `limit` |

`app.ops` is exported to Wazuh split into `app.ops.app` (one line per element, with `from` and `to`), like `net.usage`.

### Simulator: healthy fleet and attack scenarios

The simulator also emits the risk profile and the usage of the healthy fleet (§11.2): `app.risk` of each
application at first start, at each update and installation (**declared** capabilities, `granted` list of the
capabilities granted; an attack application is rated at installation, then again when a capability is
granted) (levels `low` 0-29, `medium` 30-69, `high` 70-100, system and Watchpost capped at `low`), hourly
`app.ops` (SMS of the SMS app, calls, contacts, location, assistant, Bixby…, with `rejected_count`), no
`app.role` at the first reading (the default applications come from `app.special_access`). Misleading healthy
behaviors are added to it: WhatsApp video call (250 to 450 MiB sent), Samsung Cloud night backup (up to 850
MiB), an hour of intense browsing in Chrome (50 to 90 addresses), Samsung Email on port 465. `--app-ops=false`
simulates the absence of `app.ops`. These additions have their own random source: with a fixed seed, the rest
of the stream is unchanged.

`--scenario` (several separated by commas) plays attacks that are consistent over time. With `--backfill`, they
start 48 h before the end of the history (40 % of the history if it is shorter) and last until the end (and
beyond with `--follow`); without history, one minute after launch. The command domains are blocked by the
threat list of the fake AdGuard Home (`--fake-adguard`, list enabled by default and declared `threat` in
`examples/adguard-levels.example.json`).

| Scenario | Sequence | Detections obtained |
|---|---|---|
| `healthy` (default) | nothing more than the healthy fleet | none |
| `sms-fraud` | (also gives `sms_permission`) "Flashlight Pro" installed outside a store (`app.risk` high, `combo_sms_fraud`, no icon), `SEND_SMS` and `READ_CONTACTS` granted 3 min later, ~85 SMS per hour in the background (≈ 2,000 per day), contacts read, calls to the panel `panel.sms-gateway-pay.example`; after 24 h, the SMS guard is enabled (`security.policy`) and the sends go on, refused (`rejected_count`) | `new_app_risky` (one: high risk + SMS sending), `sms_abuse` and `threat_domain` (one per day, refusals included) |
| `banking-trojan` | "System Update" outside a store (`combo_banking_trojan`), SMS reception, accessibility + notification reading + overlay (`app.special_access`) 6 min later, made the default SMS app 8 min later (`app.role`), beacons to two command servers | `new_app_risky` (one: high risk + capabilities), `default_app_changed` (sev. 3), `threat_domain` (one per day, 2 domains) |
| `proxy` | "Puzzle Relax" from the Play Store (low risk), from 1 am to 6 am (Paris time) 320 to 480 addresses per hour, 250 to 550 MiB sent per hour, domain `relay.proxy-earn.example` | `fanout` and `threat_domain` (one per day) |
| `spam` | "Cleaner Boost" from the Play Store, 20 to 40 SMTP servers per hour (ports 587 and 25) | `mail_ports` (sev. 3, one per day) |
| `exfiltration` | "Photo Vault" from the Play Store, a few MiB per hour then, 36 h after the start (at the latest 2 h before the end of the history; without history, 1 h after), 3.1 to 3.9 GiB in one hour | `upload_spike` |
| `dns-bypass` | "Fast Browser" (VPN service), 3 to 12 connections per hour to 1.1.1.1:443, 1.0.0.1:443, 8.8.8.8:853, [2606:4700:4700::1111]:443 | `dns_bypass` (one per day), `new_app_risky` (VPN, sev. 1) |
| `stalkerware` | "Battery Service" outside a store (`combo_stalkerware`), microphone, camera and background location granted, device administrator, ~4 recordings per hour, a photo every 3 h | `new_app_risky` (one: high risk + administrator), `sensor_background` (one per day, microphone and camera) |
| `silent-sms` | a discreet store app: "Promo Coupons" from the Play Store, no icon (declared capabilities `sms_send` + start at boot: `medium`, since it comes from a store), small hourly call to a server absent from the lists, `SEND_SMS` granted 25 to 30 h after the installation, then ~85 SMS per hour | `sms_permission` (at the grant), `sms_abuse` (one per day, with `app.ops` only) |
| `all` | all the attack scenarios | everything above (`TestScenarioAttacks`) |

Run a server locally with an attack scenario (fake AdGuard Home included):

```sh
cd server/collector
export WATCHPOST_DATA_DIR=$PWD/.dev WATCHPOST_LISTEN=127.0.0.1:8080 WATCHPOST_COOKIE_SECURE=false \
       WATCHPOST_EXPORT_NDJSON=$PWD/.dev/export/events.ndjson WATCHPOST_PUBLIC_INGEST_URL=http://127.0.0.1:8080 \
       WATCHPOST_ADGUARD_URL=http://127.0.0.1:3001 WATCHPOST_ADGUARD_USER=watchpost WATCHPOST_ADGUARD_PASSWORD=adguard-demo \
       WATCHPOST_ADGUARD_LEVELS_FILE=$PWD/examples/adguard-levels.example.json WATCHPOST_ADGUARD_POLL_S=10 \
       WATCHPOST_DETECT_INTERVAL_S=15
go run . serve &
go run . enroll --name phone --out .dev/phone.watchpost
printf '%s\n' 'console-password' | go run . user set-password admin
go run . sim --enroll .dev/phone.watchpost --backfill 72h --follow --scenario all \
       --fake-adguard 127.0.0.1:3001 --fake-adguard-user watchpost --fake-adguard-password adguard-demo
```

The detections appear at the run that follows the arrival of the data (`WATCHPOST_DETECT_INTERVAL_S`), and
those that depend on the AdGuard Home log after its poll (`WATCHPOST_ADGUARD_POLL_S`; at the first poll, only
the last 24 hours of the log are read).

### What the detections do not see, and what will ring wrongly

Trials on the real collector, through the ingestion API with an enrolled device (sequences written by hand,
outside the simulator), pinned by `internal/detect/blind_spots_test.go`.

**A discreet app that sends ~2,000 SMS per day triggered no detection without `app.ops`** in the first trial
(a store app rated `medium`, `SEND_SMS` granted 30 h after the installation, 48 h of sends). Fixed by contract
§11.4: it now triggers `detect.sms_permission` at the grant (and `detect.default_app_changed` if it makes
itself the default SMS app); `internal/detect/blind_spots_test.go` requires it. The number of SMS sent stays
invisible without `app.ops`: see the table at the top of "Detections".

Other limits found:

- (Fixed by §11.4: `app.risk` now rates the **declared** capabilities, with a `granted` list of the
  capabilities granted, read by `detect.new_app_risky` as a capability acquired.) In the first trial, the agent's
  `app.risk` score counted `sms_send`, `calls`, location and microphone only when **granted**
  (`android/README.md`): at installation, an SMS-fraud app installed outside a store comes out `medium` (32),
  and `high` (77) only at the daily run that follows the grant. The `sms-fraud` scenario of the simulator
  emits `high` with `sms_send` from the installation: the final detection is the same, not its delay. With the
  SMS guard active, the permission is never granted and the score stays low.
- A device whose agent is compromised (stolen credentials) can lie. Since §11.4: an inventory that declares an
  app "system" whose installer is an APK file installer (`com.google.android.packageinstaller`,
  `com.android.packageinstaller`, `com.android.shell`) or that has an `app.installed` (a system app is
  preinstalled) is not believed — the app stays subject to `sms_abuse`, `sms_permission` and
  `sensor_background` — and this is reported by `detect.inventory_mismatch` (sev. 3, cannot be muted); the
  risk profile is not used for this check (the agent keeps the reasons of system apps, which would contradict
  all of them). A consistent lie (system app declared, empty installer, no `app.installed`) stays
  undetectable. Flooding the console is bounded: 200 detections per device and per day, then a single
  `detect.flood` (sev. 3). A malicious app **without** the agent's credentials can do none of this; it can
  stay under the thresholds (299 addresses per hour, 199 SMS per day if it is the default SMS app).
- Late batches: a batch 6 days old creates the detection with its original window and `ts` = time of the
  computation; sent twice (same `id`), it counts only once; older than the retention, it is acknowledged
  without effect; a `ts` in the future is rejected (`invalid_ts`).

**Foreseeable false positives on a healthy phone** (obtained by trial; the `healthy` scenario of the simulator
stays just under each threshold and does not show them):

| Detection | Ordinary habit that triggers it | Remedy |
|---|---|---|
| `detect.upload_spike` | first backup of photos or videos (3 GiB in one hour), WhatsApp/Android backup to Drive by Google Play services, one-hour HD video call (≈ 1.3 GiB), tethering | higher `WATCHPOST_DETECT_UPLOAD_FLOOR_MB`; read together with the screen state |
| `detect.dns_bypass` | Firefox (DNS over HTTPS to Cloudflare), Chrome set to a secure DNS provider, Telegram (dns.google as a fallback), VPN apps and Tailscale clients; Google Play services if they query dns.google (not verified on a device) — **one per app and per day, indefinitely** | `WATCHPOST_DETECT_DNS_BYPASS_EXEMPT` |
| `detect.mail_ports` | mail client missing from `mail_clients.txt` (trial: Yandex Mail) | `WATCHPOST_DETECT_MAIL_CLIENTS` |
| `detect.fanout` | podcast or RSS app refreshing ~130 feeds at night (screen off: threshold 100, and each host counts twice over IPv4 + IPv6), BitTorrent client, very dense hour of browsing (> 300 addresses) | `WATCHPOST_DETECT_FANOUT_SCREEN_OFF` |
| `detect.new_app_risky` | any new app that legitimately obtains a followed capability: VPN, password manager (accessibility), watch app (notifications), new SMS app; parental control, antivirus and automation come out `high` | only once per installation |
| `detect.sms_abuse` (with `app.ops`) | non-system app that sends an SMS with the user's consent: visual voicemail, watch app, number verification | `WATCHPOST_DETECT_SMS_OTHER_MIN` |

## Design choices

- **SQLite WAL** (`modernc.org/sqlite`, pure Go): a one-connection writer pool (`BEGIN IMMEDIATE`) and a
  `query_only` read pool. `synchronous=FULL`: an acknowledged batch (which the agent deletes) survives a power
  cut. Migrations versioned by `PRAGMA user_version` (`internal/store/db.go`).
- **Console queries over millions of rows**: indexes `(device_id, ts)`, `(device_id, type, ts)` and
  `(device_id, sev, ts) WHERE sev > 0`. `/events` splits the query into ordered index scans (per device × exact
  type or × severity), read with `LIMIT n+1` and merged: a rare type stays fast in the middle of `net.dns`.
  Opaque cursor `(ts, pk)`. The hourly/daily statistics and the "top" lists come from hourly aggregates kept at
  ingestion (`event_counts`, `top_counts`); the `minute` step rereads the events (2000 intervals at most).
  **`/stats/top` counts occurrences, `/stats/timeline` events**: for `dns_hostname`, `dns_package`,
  `connect_dest` and `connect_package`, an event weighs `data.count` (integer between 1 and 1,000,000; absent,
  fractional, out of bounds or non-numeric: 1), at ingestion as in migration 3 which rebuilds these aggregates;
  the other kinds and `event_type` count 1 per event, and so does the timeline. Derived tables: `locations`,
  `device_latest` (latest heartbeat, posture, position, inventory).
- **Ingestion**: hashed token (SHA-256, 256 bits of entropy) compared in constant time; certificate fingerprint
  believed only if the caller is in `WATCHPOST_TRUSTED_PROXIES`. Limits: 1 MiB compressed / 8 MiB decompressed /
  500 events / 256 KiB per event / depth 16. An event is inserted or recognized as a duplicate (`ON CONFLICT(id)
  DO NOTHING`) in one transaction per batch. Rate: 5 requests/s (burst 60) per device, 10 authentication
  failures per IP then 1 every 30 s, 8 batches in parallel.
- **Wazuh export**: persistent cursor (`kv.export_cursor` = last `events.pk`, AUTOINCREMENT). A goroutine reads
  the database in insertion order, writes whole lines (writes ending with `\n`), runs `fsync`, then advances
  the cursor. Ingestion only sends a non-blocking signal: a full or missing volume never slows it down, and a
  restart resumes at the cursor (at least once: a few lines may be duplicated after an abrupt stop). At the
  first start, the history is not replayed. The file is created (0640) as soon as `serve` starts, before any
  event: `wazuh-logcollector` opens a file that appeared after its own start **at the end**, and would lose
  its first lines. Rotation by renaming (`.1`…`.KEEP`), never truncation; a partial line left by an abrupt
  stop is terminated by `\n` (line ignored by Wazuh, event exported again). `watchpost.data.location` is
  reserved for the `geo_point` set by the collector on `location.fix`: a `location` key coming from the device
  is removed from the export (it would make the indexer reject the whole document).
- **Console**: opaque session cookies (`__Host-watchpost_session` over HTTPS), hashed in the database, 12 h of
  inactivity, 7 days at most; argon2id (m=64 MiB, t=3, p=2, 2 simultaneous computations at most); 10 failures
  per IP and per account then 1/min (`429` + `Retry-After`), the token being taken before the password
  verification (simultaneous attempts do not get around the limit) and given back on success.
  `X-Requested-With: watchpost` required on every modifying request. Exact CSP of the contract, `nosniff`,
  `DENY`, etc. SSE: a subscriber that is too slow is disconnected (the browser reconnects), stream closed when
  the session expires.
- **Renewal**: `renew` puts a second pair (hashed token + fingerprint and PEM of the certificate) in the `next_*`
  columns of `devices` (migration 4). Both pairs are accepted; the **first** `ingest` (once the body's
  `device_id` is verified) or authenticated `ping` with the new one triggers the switch, in a single atomic
  `UPDATE`: the new pair becomes current, the old one is refused (`401`). A token is only valid with the
  certificate of **its** pair (no mixing of old token + new certificate, nor the reverse). Tokens hashed,
  compared in constant time, never logged; the switch is logged without a secret. A renewal that is never used
  stays pending with no time limit (the old pair keeps serving until it expires).
- **`400` answers**: only an unreadable or invalid batch envelope (gzip, JSON, envelope fields of the wrong
  type, `events` absent/null/not an array, data after the object). The envelope is read without a depth limit
  (`encoding/json` refuses beyond 10,000 levels, which made the whole batch unreadable because of a single
  pathological event): a defect specific to one event (type, `ts`, size, nesting…) goes into `rejected`.
- **Server → phone direction**: `/api/v1` only has `ingest`, `ping` and the three command routes of §8; no
  response carries configuration or policy.
- **Remote commands (§8)**: table `commands` (migration 5). `POST /commands` analyzes a **copy** of the `payload`
  (single JSON object, no duplicate or unknown key, `v` = 1, upper-case ULID `id` never used before and equal
  to the body's `id` if provided, `device_id` = the body's, existing and non-revoked device, type of the
  closed list, typed and bounded parameters — `message`: 200 UTF-16 units, no control character except `\n` —,
  `issued_at` within ±10 min of the server time, future `expires_at` and validity ≤ 30 d); the original string
  is stored and relayed **byte for byte** (never reserialized; invalid UTF-8 and U+FFFD are refused so that no
  replacement modifies it). `sig`: mandatory and in the base64-of-32-bytes format for a sensitive type,
  forbidden otherwise; the collector **cannot** verify it (it does not have the passphrase). Limits checked in
  the insertion transaction: 20 creations per hour and 10 open commands (pending or delivered) per device
  (`429` + `Retry-After`); body ≤ 32 KiB, payload ≤ 4 KiB. States: `pending` → `delivered` (atomic switch
  **before** the write to the agent: a concurrent cancellation wins — the command is not sent — or receives
  `409`) → `executed`/`failed`/`refused` (first result kept; a duplicate, or a `replay` refusal, is
  acknowledged `204` without effect); `expired` (sweep every 30 s, and displayed as soon as the deadline
  passes); `cancelled` (only from `pending`). A late result (expired or cancelled command) is recorded: it is
  the real state of the phone. A command not acknowledged by a result is sent again after 5 min (3 deliveries
  at most; the agent, which never executes it again, then sends back its original result, or `replay` —
  non-final — if it no longer has it). If the write to the agent fails, the command goes back to `pending`.
  **The signature is kept only while the command can still be handed over**: as soon as it is finished (result
  received, expired, cancelled), `sig` is replaced in the database by the marker `-` (`store.SigErased`; the
  console keeps seeing it as "signed"). A later copy of the database or of a backup therefore no longer
  contains a (`payload`, `sig`) pair of past commands, which would be used to search the user's command
  passphrase offline; a server compromised **live** still sees the new signed commands go by.
- **Command stream**: one connection per device (the new one closes the old one), 64 at most (`503` +
  `Retry-After` beyond), server read timeout lifted for this single authenticated request, write timeout of
  30 s per message (a dead connection is detected at the next keep-alive at the latest), a single goroutine per
  stream, all streams closed at shutdown. `GET /devices` → `command_channel`: `connected` = stream open right
  now; `mode` = `stream` (stream open or last contact through a stream), `poll` (last polling without an open
  stream) or `unknown`; `last_contact` = last opening, keep-alive, polling or result.
- **Events produced by the collector**: `command.issued` (sev. 0 simple, 1 `lock`/`clear_lock_message`, 2
  `wipe`; `command_id`, `type`, `signed`, `created_by`, `expires_at`, `params` **without** `message`,
  `message_set` for `lock`), `command.cancelled` (`cancelled_by`), `command.reported` (result received by the
  API: `status`, `detail`, `agent_at`, severity of §8) and `command.expired` (`delivered`, sev. 1). They are
  stored like events of the targeted device (`source = 'server'`, `boot_id` = `server`, `seq` 0), visible in
  `/events` and the timeline, and exported with `watchpost.source = "server"` (device events have no
  `source`). The agent's `command.result` event arrives through ingestion. The lock message stays in the
  database (console): neither in the process logs nor in the export. Neither `payload`, nor `sig`, nor token is
  logged. `tracking.level_changed` and `tracking.override` (see "Tracking page") are produced the same way.
- **Tracking page (§9)**: the AdGuard Home log (`GET /control/querylog`, from the most recent to the oldest, 500
  entries per page) is polled every `WATCHPOST_ADGUARD_POLL_S`, 40 pages at most per poll. **Reading**
  (`readLog`, `internal/server/tracking.go`): AdGuard Home v0.107.80 handles `older_than=T` by looking in its
  files for an entry whose timestamp is **exactly** `T` (`internal/querylog`: `seekTS`, `seekRecord`; verified
  on a real instance): if `T` falls between two entries, it returns nothing from the files; if `T` is later
  than the last one, it skips that last entry. The collector therefore never passes an arbitrary instant: the
  first page is requested **without** `older_than`, the following ones with the exact timestamp of the oldest
  entry of the previous page, and the time window is applied here. An entry is counted by the poll whose
  window `(previous marker, now − 60 s]` contains its timestamp: exactly once, whatever the instant of the
  polls. If a cursor receives a short answer before the lower bound (real end of the log, or cursor entry
  missing from the files: still in memory, or deleted by a rotation), the timestamps of the three entries read
  just before are tried before concluding. Each page is aggregated per hour, client (ClientID, otherwise IP)
  and domain (`tracking_counts`: queries, blocked, readable reason: name of the list, "Custom rule: …",
  "Manual block (Watchpost)", blocked service…) and committed **with** the reading position
  (`kv.adguard_querylog`: marker, remaining ranges with their cursor and its replacements) in the same
  transaction: a restart resumes without loss or double count. What could not be read within the page budget
  (first poll: 24 h of history; long outage) is kept as a "gap" to fill at the following polls (16 at most).
  Blocked = reason `Filtered*` except `FilteredSafeSearch`. The fake AdGuard Home of the simulator and of the
  tests reproduces this real handling of `older_than` (two files, rotation, memory buffer:
  `adguard.Fake.search`, `fake_test.go`). Trial (2026-11-16) against a real AdGuard Home v0.107.80 (local
  container, `size_memory: 1`, spaced traffic then bursts, two rotations of the log, one done by AdGuard Home
  itself, two restarts of the collector): 2114 entries written by AdGuard Home, 2114 counted, each once; the
  previous reading (`older_than` = now − 60 s) counted 8. Catch-up of an existing log by a new collector: 824
  out of 824, then 1350 out of 1350 with `size_memory: 50` (three pages). **Changes made from the console**:
  `PUT /tracking/level` and `PUT /tracking/override` that actually modify AdGuard Home produce a collector
  event (`source = 'server'`, one per non-revoked device, exported to Wazuh with `watchpost.source =
  "server"`): `tracking.level_changed` (`old` — absent if the state matched no level —, `new`, `changes`, `user`;
  sev. 2 if the blocking is weakened or starts from an unknown state, 1 otherwise) and `tracking.override`
  (`domain`, `action`, `forced`, `previous` if there was a rule, `user`; sev. 2 for an allow, the removal of a
  block or the forced block of an essential domain, 1 otherwise). A request that changes nothing produces
  nothing. Cross-references through hourly aggregates: `top_counts` (`dns_hostname` per package, weighted by
  `count`) and `usage_counts` (bytes received/sent per application, migration 5, rebuilt from `net.usage`).
  Nothing scans the `events` table. Purged with the retention. AdGuard unreachable: `adguard: false`, `PUT` →
  `503`, the aggregates already polled are still served; nothing else is affected.
- **Publishers**: [`internal/tracking/publishers.txt`](internal/tracking/publishers.txt), embedded; longest suffix,
  on label boundary (`notgoogle.com` → `other`). Keys: `google`, `samsung`, `meta`, `microsoft`, `amazon`,
  `bytedance`, `ads`, `other`. Bytes per publisher (`tx_bytes`, `rx_bytes`): **estimate** — the bytes of each
  application are split between publishers in proportion to its DNS requests to their domains.
- **Manual rules** (`PUT /tracking/override`): lower-case domain, labels `[a-z0-9_-]` (`xn--` form), 2 labels at
  least, non-numeric TLD, 253 characters at most: no rule-syntax character can get through. Rules
  `||domain^$important` / `@@||domain^$important` written between `! watchpost:begin …` and
  `! watchpost:end` among the user rules (read by `GET /control/filtering/status`, rewritten by
  `POST /control/filtering/set_rules` only if they change; block sorted, removed when empty; inconsistent
  markers → `409 corrupt_rules`, nothing is written). A line found between the markers that is not a rule
  written by Watchpost (rule or comment added there by hand in AdGuard Home) is never deleted: it is moved right
  after the block. Safeguard: blocking a domain that is (or has a subdomain that is) essential — FCM,
  connectivity check, NTP, Samsung/Google updates, Watchpost ingestion and private DNS hosts
  (`internal/tracking/essential.go`) — answers `409 essential_domain` with `breaks: [{domain, breaks}]`
  without `"force": true`.
- **AdGuard client**: URL from the configuration only, no redirect followed, no environment proxy, 30 s
  timeout (2 min for a level change), bounded responses (32 MiB for the log).
- **Files**: database, WAL and `-shm` in 0600 (the database is created 0600 before SQLite derives the others
  from it), `.watchpost` in 0600 even with `--force`. The retention purge also applies to the latest
  per-device values (position, heartbeat, posture) displayed by `/devices`.
- **PKI**: ECDSA P-256 CA (20 years) in `pki/ca.{crt,key}` (key 0600), client certificates 2 years,
  `CN=<device_id>`, `clientAuth`.
- **Simulator**: typical day around Paris (home in the east of the city, metro line to the business district
  on weekdays, bike and a park at the weekend), Wi-Fi/cells, screen and foreground applications, DNS and
  connections per Google/Samsung/third-party package (~10,000 `net.dns` per day with `--rate 1`), hourly usage,
  daily inventories (parts linked by `inventory_id`), and a scenario placing all the rare types (reboot, BLE
  tracker, 2G, user CA, `agent.tamper`, ADB, USB, app installed outside the Play Store, mock location…) in the
  window of `--backfill` (or in the first hour of continuous mode). `seq` starts from the Unix time in ms. The
  private DNS host (posture, policy, connectivity) is taken from the `.watchpost` file. Each posture change
  produces one `security.posture_change` per modified field (except `patch_age_days`, derived from the date):
  ADB and developer options, unknown sources and Play Protect, non-strict private DNS, user CA; `sensor.*`
  carry `screen_on` and `locked` (including a microphone and a camera used screen off and locked by the app
  installed outside the Play Store); `security.log` follows the name table of the contract. Like the real
  agent: about 1 `net.dns`/`net.connect` in 15 is aggregated (`count` 2 to 60, `last_event_ts`), `security.log`
  entries of level `info`/`warning`/`error` (sometimes aggregated) are added, logs with `pre_reboot: true`
  precede each reboot, and `net.dns`, `net.connect` and `security.log` are delivered **in batches every 1 h 30
  to 2 h** with their original `ts` (the rest is delivered as it comes; without `--follow`, the last pending
  batch goes out at the end). With a fixed seed (`--seed`), the stream is reproducible; the draws added have
  their own random sources, the rest of the simulation has not changed.

## Known limits

- Tracking: AdGuard's `older_than` is strict: two requests of the same nanosecond at the boundary of two pages
  could be skipped (negligible). An entry is counted only once it is 60 s old (the most recent ones wait for the
  next poll). **AdGuard Home's `querylog.size_memory` must stay below 500** (the size of a page): beyond that
  (1000 by default), a poll of more than one page may have as cursor an entry still in memory, and AdGuard Home
  then skips the last entry of its file (one entry lost per poll of this kind). Conversely, **`size_memory: 1`
  makes AdGuard Home itself lose entries** as soon as requests arrive at the same time (its one-entry buffer is
  overwritten before being written): measured on a real v0.107.80 instance with 8 simultaneous clients, 187
  entries written for 240 answers at `size_memory: 1`, 1350 for 1360 at `size_memory: 50`. These entries exist
  neither for the collector nor for Wazuh: this is an infrastructure setting. The `apps` of a domain and the
  `blocked`/`allowed` of an application are estimates (AdGuard does not see the application; `net.dns` does
  not see the blocking).
- Commands: the collector does not verify `sig` (it does not have the passphrase). Without the passphrase, a
  compromised server can make the phone ring, vibrate or locate itself as much as it wants, hold back, delay or
  replay within their validity period the signed commands it received, and display any state in the console.
  It can only lock or erase if it obtains the passphrase: by searching for it offline from a signed command
  (hence the requirement of a long and unpredictable passphrase, see `android/README.md`), or by modifying the
  console it serves in order to read it when the user types it. Canceling a command only binds the server: only
  expiry, or changing the passphrase in the app, makes it surely void.

- "Top" aggregates and hourly/daily timeline aligned on whole **UTC** hours/days: the `from`/`to` bounds are
  rounded to the hour.
- `/apps` groups the inventory parts by `inventory_id` (contract §2); for an agent that does not send it,
  fallback to a heuristic (same `parts`, less than one hour apart).
- An event whose `ts` is more than 24 h beyond the server time or earlier than 2000 is rejected (`invalid_ts`,
  final); the retention purge is done on `ts`.
- `ts` is the original time: `net.dns`, `net.connect`, `security.log` and `app.foreground` arrive hours, even
  days late. All aggregates are filed in the UTC hour of `ts` (never that of reception) and an old `ts` is
  accepted within the limit of `WATCHPOST_RETENTION_DAYS`. An event older than the retention is **acknowledged
  without being stored** (counted in `accepted`, so that the agent deletes it; no aggregate, no Wazuh export, no
  SSE broadcast): the purge would have deleted it within the hour. `last_event_ts` is not used for the
  ranking. The console must query the statistics by `ts` range, not "since reception": a late event modifies
  the counters of hours already past.
- Rate limiting in memory (reset at restart, specific to one instance).
- Detections: windows in UTC days and hours; the retention also applies to the detections (window and time of
  the detection both older than the retention) and to the latest `app.risk`/`app.role` of each application
  (`GET /apps/risk` loses an application whose latest `app.risk` is older than `WATCHPOST_RETENTION_DAYS`).
- Caddy limits the body of ingestion requests to 9 MB (infra): margin above the 8 MiB decompressed, the fine
  limits remain those of the collector.
