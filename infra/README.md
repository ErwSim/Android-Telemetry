# Watchpost: server infrastructure

Docker Compose deployment of the server side of Watchpost on **a public Linux VPS with 8 GB of RAM or
more**: **Caddy** TLS front end, **Watchpost collector** (ingestion + console), **AdGuard Home**
(filtering private DNS over DNS-over-TLS) and **Wazuh** 4.14.10 single node (manager, indexer,
dashboard), plus an optional **WireGuard** tunnel. Installation takes three commands; every secret is
generated on the server and is never committed.

```
Internet ──► 80/443 Caddy ─┬─ console.D  ─► collector:8080 (console + /api/console, including commands and tracking)
                           ├─ ingest.D   ─► collector:8080 (/api/v1, client certificate REQUIRED;
                           │                 including the SSE command stream /api/v1/commands/stream)
                           ├─ siem.D     ─► wazuh.dashboard:5601   ┐ IP list + Caddy password,
                           ├─ adguard.D  ─► adguardhome:3000       ┘ then the service's own account
                           └─ dns.D      (certificate only)
         ──► 853 AdGuard Home (DoT, dns.D certificate provided by Caddy, hot-reloaded)
collector ──events.ndjson──► wazuh.manager ◄──querylog.json── AdGuard Home
collector ──API :3000 (internal network, watchpost-collector account)──► AdGuard Home (Tracking page, levels)
wazuh.manager ──Filebeat──► wazuh.indexer (wazuh-alerts-*, wazuh-archives-*) ◄── wazuh.dashboard
```

## 1. Prerequisites

| | Minimum | Recommended |
|---|---|---|
| RAM | 8 GB (Wazuh is not supported below) | 8 GB + 2 GB of swap |
| CPU | 2 vCPU | 4 vCPU |
| Disk | 30 GB SSD | 50 GB SSD (≈ 90 days of archives for one phone) |
| System | Debian 12 / Ubuntu 24.04, kernel ≥ 5.10 | |
| Software | Docker Engine **≥ 26** and the `docker compose` v2 plugin, `git`, `openssl`, `curl` | |
| Network | Fixed public IPv4, ports 80, 443, 853/tcp reachable | IPv6 as well |

Install Docker: <https://docs.docker.com/engine/install/> (official repository; the distributions'
`docker.io` packages are often too old). `install.sh` sets `vm.max_map_count=262144` (required by the
indexer) and makes it persistent in `/etc/sysctl.d/99-watchpost-wazuh.conf`.

## 2. DNS records

With a domain `watchpost.example.org` (any subdomain of a domain you own, or a free DuckDNS/deSEC
name), create at your DNS provider, **before** the installation:

| Name | Type | Value |
|---|---|---|
| `console.watchpost.example.org` | A (and AAAA) | VPS IP address |
| `ingest.watchpost.example.org` | A (and AAAA) | VPS IP address |
| `siem.watchpost.example.org` | A (and AAAA) | VPS IP address |
| `adguard.watchpost.example.org` | A (and AAAA) | VPS IP address |
| `dns.watchpost.example.org` | A (and AAAA) | VPS IP address |
| `*.dns.watchpost.example.org` | A (and AAAA) | VPS IP address, **only** in ClientID mode (§6.3) |

Let's Encrypt validates each name through port 80 (HTTP-01 challenge): the names must already point
to the VPS. A short TTL (300 s) makes a server change easier.

## 3. Installation

```bash
git clone <this repository> watchpost && cd watchpost/infra
sudo ./install.sh --domain watchpost.example.org --email you@example.org --tls acme
sudo ./firewall/ufw.sh            # host firewall (SSH, 80, 443, 853)
sudo ./enroll.sh phone            # enrollment file of the phone: phone.watchpost
```

Without options, `install.sh` asks questions. It:

1. checks Docker, Compose, the RAM, the disk, `vm.max_map_count`;
2. writes `infra/.env` (mode 600) with **all the generated secrets** (passwords of the indexer, of the
   Wazuh API, of AdGuard and of the collector's AdGuard account, of the Caddy administration account,
   of the console); existing values are kept from one run to the next;
3. generates the Wazuh internal PKI (`secrets/wazuh-certs/`, openssl, no download);
4. generates the configuration (`data/`): hashed indexer accounts (bcrypt), with the demonstration
   accounts of the image (`kibanaro`, `logstash`, `readall`, `snapshotrestore`, public passwords)
   removed; the dashboard's `wazuh.yml`, `AdGuardHome.yaml`, the Caddy administration account;
5. builds the collector image (`server/Dockerfile`) if it is missing (`--build` to force it);
6. starts the indexer; on the first start, the accounts are created from `internal_users.yml`;
   afterwards, a Watchpost account (admin, kibanaserver, watchpost_reader) whose password no longer
   matches `.env` is corrected, one by one, through the security API (users created in the dashboard
   are kept); checks the admin password; sets the index template and the retention policies;
7. starts the collector, fetches the CA of its client certificates for Caddy (mTLS), starts Wazuh,
   Caddy (certificates are obtained), then AdGuard Home as soon as the `dns.D` certificate exists;
8. creates the `admin` console account (`watchpost-collector user set-password`) **on the first
   installation only** and imports the "Watchpost" Wazuh dashboards;
9. prints the summary: addresses, DNS records, ports to open, where the passwords are.

It can be **rerun**: run it again after any change to `.env` or an update of the repository
(verified: two successive runs leave `.env` byte-for-byte identical and the stack healthy).
It does not undo what you set in the interfaces: console password changed with `set-password`, DNS
blocking level and rules set from the console (§6.2), AdGuard settings, users created in the Wazuh
dashboard.

Useful options: `--profile permissive|balanced|strict` (applies a DNS blocking level, §6.2),
`--clientid` (§6.3), `--admin-allow
"203.0.113.0/24 2001:db8::/32"` (§5), `--rotate-passwords` (§8.3), `--reset-console-password`
(§8.3), `--reset-adguard` (§6.2), `--renew-wazuh-certs` / `--renew-wazuh-ca` (§8.6), `--build`,
`--no-start`.

**Where are the passwords?** `infra/secrets/credentials.txt` (readable summary) and `infra/.env`
(source of truth), mode 600, never committed. Back them up (§8.2).

### On the phone

1. Transfer `phone.watchpost` over a cable (`adb push phone.watchpost /sdcard/Download/`), import it
   into Watchpost Agent, then destroy it on both sides (`shred -u phone.watchpost`): it contains the
   private key and the token of the device.
2. Settings → Connections → More connection settings → Private DNS → *Private DNS provider
   hostname*: `dns.watchpost.example.org` (the Watchpost app can enforce it in Device Owner mode). In
   strict mode, if the server is unreachable the phone **has no DNS at all**: this is intended (no
   leak in clear text), but keep in mind that an outage of the VPS shows up immediately on the phone.

### Internal TLS mode (tests, local network)

`--tls internal` uses Caddy's internal CA instead of Let's Encrypt (no public port 80 nor real domain
needed). You must then trust `data/caddy/server-root-ca.crt`: in the browser, and on Android
(Settings → Security → Encryption → Install a certificate → CA certificate) for the private DNS to
work. The `.watchpost` files contain this CA (`server_ca_pem`) for the agent. This is the mode used
for the test runs described in §11.

## 4. What is exposed on the Internet, and why

| Port | Service | Why |
|---|---|---|
| 80/tcp | Caddy | Let's Encrypt ACME HTTP-01 challenge, redirect to HTTPS |
| 443/tcp | Caddy | Console, ingestion (mTLS), Wazuh dashboard and AdGuard (protected, §5) |
| 853/tcp | AdGuard Home | DNS-over-TLS: the only protocol of Android's "private DNS" |
| 51820/udp | WireGuard | **Only** with the optional `wireguard` profile |

Nothing else is published: no 53 (plain DNS), no 1514/1515 (Wazuh agents: there are none, `remoted`
listens only on the container's loopback and enrollment requires a random password), no 55000 (Wazuh
API), no 9200 (indexer), no 3000 (AdGuard), no 2019 (Caddy admin). The containers communicate over a
private Docker network (`172.31.250.0/24`, can be changed with `WATCHPOST_SUBNET`).

> **Docker and ufw**: the ports published by Docker bypass the `ufw`/INPUT rules. The list above is
> therefore guaranteed by `docker-compose.yml`, not by the firewall; `firewall/ufw.sh` and
> `firewall/nftables.conf` protect the rest of the host (SSH…) and explain how to filter a published
> port (`DOCKER-USER` chain).

Container hardening: pinned images, `no-new-privileges`, all capabilities dropped for Caddy, the
collector (`scratch` image, UID 65532) and AdGuard (except the ones it needs), memory limits, bounded
Docker logs (3 × 20 MB). The Wazuh containers keep their original settings (the manager image needs
root for s6-overlay and Filebeat).

## 5. Protection of the administration interfaces

`siem.D` (Wazuh dashboard) and `adguard.D` go through **two barriers**:

1. **Caddy**: list of allowed addresses (`WATCHPOST_ADMIN_ALLOW`, default: all), then HTTP
   authentication (`basic_auth`, `admin` account, generated password, bcrypt-hashed);
2. the service's **own account** (Wazuh `admin`, AdGuard `admin`).

Why: these two interfaces are large web applications whose history includes vulnerabilities
exploitable **before** authentication; the Caddy barrier hides them from the bots that sweep the
Internet, without adding a service (Authelia, SSO) nor a client certificate to install in the
browser. The IP list is optional because the IP address of a mobile connection changes: if you
administer from a fixed connection or through WireGuard, restrict it:

```bash
sudo ./install.sh --admin-allow "203.0.113.7/32 2001:db8:1234::/48"
```

Caddy's `Authorization` header is removed before the dashboard (otherwise it would take it for
indexer credentials). The Watchpost console (`console.D`) does not have this barrier: it has its own
authentication (argon2id, attempt limiting, `__Host-` cookie, strict CSP) and it is the everyday
interface. Ingestion requires a client certificate issued by the collector **and** the device token;
Caddy exposes only `/api/v1/*` there, removes every incoming `X-Watchpost-*` header and sets
`X-Watchpost-Client-Cert-Sha256`, which the collector accepts only from Caddy's fixed address.

### 5.1 Remote commands (v1.1): what goes through

Since v1.1 (revised principle no. 2 of `docs/ARCHITECTURE.md`, contract §8), the console can send the
phone commands from a **closed list**: ring, vibrate, stop ringing, locate (simple); lock with a
message, remove that message, erase (sensitive).

- **Path**: browser → `console.D` (`/api/console/commands*`, console session) → collector →
  `ingest.D` → agent, through the `GET /api/v1/commands/stream` stream (Server-Sent Events) that the
  agent opens itself with its client certificate and its token (or by polling `GET /api/v1/commands`).
  The result comes back through `POST /api/v1/commands/{id}/result` and a `command.result` event.
  Nothing is opened towards the phone: the phone connects. The `/api/console/*` routes go only through
  `console.D`; `ingest.D` exposes only `/api/v1/*` (404 otherwise).
- **What the server can do**: relay a command from the list, as the browser built it (the collector
  passes it on byte for byte), at most 20 per hour and 10 pending per device. A compromised server can
  at worst make the phone ring, vibrate or report its location.
- **What it cannot do**: sign a sensitive command. The signature (HMAC-SHA256) is computed in the
  browser with a key derived from a **command passphrase** typed every time, never sent to the server
  nor stored by it; the agent checks it and refuses (`bad_signature`), then closes itself to sensitive
  commands for one hour after 5 failures (`locked_out`). Erase is, in addition, disabled by default in
  the app. No command can change a setting, the policy or the enrollment; the channel can be turned
  off in the app.
- **What is logged**: every issue, cancellation, expiry and result is an event (`command.issued`,
  `.cancelled`, `.expired`, `.reported` produced by the collector with `watchpost.source = "server"`,
  `command.result` produced by the device), exported to Wazuh (§7.2). The **lock message is never
  exported** (only `message_set`) nor logged: it stays in the collector database for the console.
- **Caddy and the SSE stream**: response passed on without buffering (`flush_interval -1`), no Caddy
  timeout cuts a response in progress (`read_body`/`read_header` only cover reading the request,
  `idle` the idle connections between two requests); the collector sends a keepalive every 120 s
  (`WATCHPOST_CMD_KEEPALIVE_S`). Caddy's access log has **one line per connection** (written when it
  closes), not one per message; the `Authorization` header (token) is masked in it. The body size
  limits (9 MB on `ingest.D`, 1 MB on `console.D`) are unchanged.
  Verified (§11): stream open for more than 5 min through Caddy over HTTP/1.1 and HTTP/2 without a cut.

## 6. Filtering private DNS (AdGuard Home)

### 6.1 Resolver, upstream, DNSSEC

- **DoT on 853** with the `dns.D` certificate obtained by Caddy (`caddy_data` volume; only the
  directory of this certificate is mounted, read-only). AdGuard watches the file and **reloads the
  renewed certificate without restarting** (verified, §11).
- **Upstream: Quad9** (`https://dns.quad9.net/dns-query` and `tls://dns.quad9.net`): a Swiss
  non-profit foundation, no logging of IP addresses, no ECS on this endpoint, **DNSSEC validation**;
  fallback: **Mullvad DNS** (DoH, no filtering, no logging). Neither Google nor Cloudflare.
  AdGuard requests DNSSEC from the upstream (`enable_dnssec`): an answer with an invalid signature
  comes back as SERVFAIL and the AD bit is passed on to the phone.
- Plain DNS (53): active only on the internal Docker network (WireGuard), never published.

### 6.2 Blocklists and levels

Three **blocking levels**; the level → lists mapping is **a single committed file**,
[`adguard/levels.json`](adguard/levels.json), read both by `install.sh` (which builds the AdGuard
lists) and by the collector (`WATCHPOST_ADGUARD_LEVELS_FILE`, Tracking page of the console).

| ID | List | Permissive | Balanced | Strict |
|---|---|---|---|---|
| 1 | `adguard/watchpost-base.txt` (committed): essential exceptions + Google/Samsung telemetry commented line by line | ✓ | ✓ | ✓ |
| 2 | `adguard/watchpost-strict.txt` (committed): Firebase Remote Config, Galaxy Store, Samsung push and cloud… | | | ✓ |
| 10 | HaGeZi **Multi PRO** (advertising, tracking, telemetry; rare false positives) | | ✓ | |
| 11 | HaGeZi **Multi PRO++** (more aggressive) | | | ✓ |
| 20 | HaGeZi **Native Tracker Samsung** | | ✓ | ✓ |
| 30 | HaGeZi **Threat Intelligence Feeds (medium)**: malware, phishing, C2 | ✓ | ✓ | ✓ |
| 90 | `data/adguard/userfilters/personal-rules.txt` (your rules, not committed, backed up), outside the levels, always active | ✓ | ✓ | ✓ |

**Balanced** (default on the first installation): Play Services, Play Store, FCM push notifications
and banking apps (Play Integrity) keep working thanks to the `@@…$important` exceptions of
`watchpost-base.txt` (connectivity check, `mtalk*.google.com`, FCM, Firebase installations, Play,
Google accounts, Google updates and Samsung FOTA); Firebase Analytics, Crashlytics, Firebase logs,
Play Services telemetry, Google and Samsung ad networks, Samsung diagnostics are blocked. **Strict**:
PRO++ instead of PRO, plus `watchpost-strict.txt`. **Permissive**: the minimum considered useful, the
threat feed (protection, not comfort: it breaks nothing ordinary) and `watchpost-base.txt` (about
twenty Google and Samsung telemetry and advertising domains chosen one by one, without visible effect,
plus the exceptions that guarantee push, Play and updates); no general advertising list, to work
around a misbehaving app without giving up protection against malicious domains.

Each list of `levels.json` has a **category** (`category`): `threat` (threats: phishing, malware,
command-and-control servers), `ads`, `tracking`, `mixed` (general list that mixes advertising,
tracking and a few threats), `custom`, `allowlist`. Only `threat` changes a behaviour: a block caused
by a `threat` list feeds the collector's `detect.threat_domain` detection (§7.4); without any `threat`
list, this detection stays silent. Here: HaGeZi TIF (30) is `threat`; Multi PRO and PRO++ are
`mixed`; Watchpost base, Watchpost strict and Samsung are `tracking`. The collector refuses to start
on an unknown category; `merge-config.py` checks it at installation time. If you add a threat list to
the file, give it `"category": "threat"` (the name or the address is not enough).

All the lists are **present** in AdGuard whatever the level; a level is only a set of **enabled**
lists (a disabled list is neither downloaded nor loaded in memory). The HaGeZi lists (GPL-3.0) are
downloaded by AdGuard from jsDelivr (paths checked in the `hagezi/dns-blocklists` repository) and
refreshed every 12 h.

**Changing the level**: in the console (Tracking page), or `sudo ./install.sh --profile strict`
(`permissive`, `balanced`). Both do the same thing: enable exactly the lists of the level.

**Source of truth of the level: the state of the lists in the AdGuard Home configuration**, and
nothing else. The console changes it through the AdGuard API (which writes it immediately into
`AdGuardHome.yaml`); `install.sh` (and therefore `update.sh`) **keeps** it; only `--profile` changes
it, once: it is stored nowhere else (`WATCHPOST_DNS_PROFILE` from v1 is no longer used: read once for
the migration, then removed from `.env`). The current level is the one whose enabled lists are
exactly those of the file (`install.sh` prints it; "custom" if you enabled or disabled a list by hand
in AdGuard). A list added to the file by a repository update takes the state of the level in service.

**Rules set by the console** (`PUT /tracking/override`): the collector writes them into a
`! watchpost:begin … ! watchpost:end` block of AdGuard's "custom filtering rules"
(`||domain^$important` or `@@||domain^$important`). `install.sh` never touches the custom rules, and
`--reset-adguard` copies this block into the regenerated configuration (as well as the level).

**Who decides what** (`adguard/merge-config.py`): on every `install.sh`, the configuration managed by
Watchpost is **merged** into the one in service (AdGuard is stopped for a few seconds, which forces it
to write its up-to-date configuration before the merge).

| Managed by Watchpost (reapplied on every `install.sh`, from `.env` and the repository) | Decided in the console (kept) | Yours (kept) |
|---|---|---|
| `admin` and `watchpost-collector` accounts and their passwords; TLS/DoT and certificate; DNS listener; upstreams (Quad9, Mullvad) and DNSSEC; allowed clients (ClientID mode) and the "Phone (Watchpost)" client; query log read by Wazuh and the collector (including `size_memory: 50`, below); **presence**, address, name and identifier of the lists of `levels.json` and of list 90 | blocking level (enabled lists); `! watchpost:begin … ! watchpost:end` block of the custom rules | other custom rules, added lists (other addresses), allowlists, clients, blocked services, DNS rewrites, rate limiting, cache, statistics, log retention |

Verified (§11): level changed in the console and rule set by the console kept by a rerun of
`install.sh`; `--profile` applied, then seen identically by the console. To start from scratch:
`sudo ./install.sh --reset-adguard` (the previous configuration is kept in
`data/adguard/conf/AdGuardHome.yaml.before-reset-*`; console level and block kept). Rules you want to
version by hand remain possible in `data/adguard/userfilters/personal-rules.txt`.

**Query log (`querylog.size_memory: 50`, v1.2)**: number of entries AdGuard keeps in memory before
writing them to disk. At 1 (the value of v1 and v1.1), AdGuard itself loses entries under concurrent
queries (measured: 187 entries written for 240 answers with 8 clients); above 500 (one page of its
API), the collector's polling can skip some. 50 is reapplied by every `install.sh`, **including on an
existing installation** (verified: 1 → 50 on a rerun). Consequence: the log reaches Wazuh in batches
of 50 queries (a few seconds to a few minutes of delay with one phone).

### 6.3 Open resolver risk

A public DoT server answers anyone who knows its name. Since DoT runs over TCP+TLS, it cannot be used
for amplification (unlike UDP DNS), but it can be used as a free resolver.

**Default mode (simple, reasonably protected)**: no public port 53; rate limiting per client (50
queries/s per IPv4 /24 or IPv6 /56); `refuse_any`; version queries refused; **everything is logged**
and goes to Wazuh (you can see who uses the resolver).

**Hardened option, `--clientid`**: AdGuard only accepts the secret identifier of the phone,
presented through the DoT host name `tel-xxxxxxxxxxxx.dns.D` (+ the fixed address of the WireGuard
container). Any other connection receives REFUSED. Requirements:

- a wildcard DNS record `*.dns.D`;
- a wildcard certificate `*.dns.D`, which Let's Encrypt issues only through the **DNS-01
  challenge**: you need a DNS provider with an API and a token (`--dns-provider cloudflare|desec|duckdns
  --dns-token …`); `install.sh` then builds a Caddy image with the matching module
  (`caddy/Dockerfile.dns`, a few minutes, Internet access required);
- the private DNS host name to type on the phone becomes `tel-….dns.D` (printed by `install.sh`,
  written into the `.watchpost` files).

```bash
sudo ./install.sh --clientid --dns-provider desec --dns-token 'deSEC-token'
```

The ClientID mode was verified in internal TLS mode (§11); actually obtaining a wildcard through
DNS-01 cannot be tested without a real domain and token. The Docker subnet is deliberately not
allowed: its gateway is the address seen for every connection relayed by `docker-proxy` (IPv6 without
ip6tables), which would reopen the resolver.

### 6.4 Tracking page: collector access to AdGuard Home

The collector reads the AdGuard query log and changes levels and rules through the **AdGuard API on
the internal Docker network** (`WATCHPOST_ADGUARD_URL=http://adguardhome:3000`); nothing more is
published (port 3000 is not, `adguard.D` keeps its two barriers). It uses a dedicated account,
**`watchpost-collector`**, whose password is generated by `install.sh`
(`ADGUARD_COLLECTOR_PASSWORD` in `.env`, bcrypt-hashed in `AdGuardHome.yaml`, passed to the collector
through an environment variable, never logged). **AdGuard Home has a single account type: this
account is a full AdGuard administrator.** The secret is therefore treated like `admin`'s (`.env` in
600, encrypted backups, `--rotate-passwords`); a separate account makes it possible to change it
without touching the one you use, and to see that it serves only the collector.

Collector variables set by `docker-compose.yml`: `WATCHPOST_ADGUARD_URL`, `WATCHPOST_ADGUARD_USER`,
`WATCHPOST_ADGUARD_PASSWORD`, `WATCHPOST_ADGUARD_LEVELS_FILE` (= `adguard/levels.json`, mounted
read-only), `WATCHPOST_ADGUARD_POLL_S` (`.env`, default 60), `WATCHPOST_CMD_KEEPALIVE_S` (`.env`,
default 120) and, in ClientID mode (§6.3), `WATCHPOST_ADGUARD_CLIENTS`: `install.sh` and `enroll.sh`
write `<device_id>=<ClientID>` into it for each active device, so that the page attributes to the
phone only the queries of its ClientID. Outside ClientID mode, the IP address of a phone keeps
changing: the variable stays empty and the whole AdGuard log is attributed to the device being viewed
(with several phones, a "threat" block of one of them can therefore be attached to an application of
another one that requested the same domain the same day). The `WATCHPOST_DETECT_*` variables of the
detections are in §7.4.

**Reading the AdGuard log (limit found in the §11.1 test, fixed since in the collector)**: AdGuard
Home v0.107.80 only finds, for `older_than=T`, the exact timestamp of an entry. The collector
therefore no longer passes an arbitrary instant: first page without `older_than`, then the exact
timestamp of the oldest entry read; each entry is counted once (details: `server/collector/README.md`,
query log polling). Condition on the infrastructure side: `size_memory` strictly between 1 and 500,
hence 50 (§6.2).

## 7. Wazuh

### 7.1 Ingestion and archives

- The collector writes `events.ndjson` (contract §5) into the `watchpost_export` volume, mounted
  read-only in the manager (`/var/watchpost`); AdGuard writes `querylog.json` into `adguard_querylog`
  (`/var/adguard`). Two `<localfile>` in `json` format (see `wazuh/manager/ossec.conf`).
- `logall_json` + Filebeat (archives enabled by `watchpost-init.sh`): **all** events go to
  `wazuh-archives-4.x-YYYY.MM.DD`, the alerts (level ≥ 3) to `wazuh-alerts-4.x-*`.
- The `Answer`/`OrigAnswer` field of the AdGuard log (DNS answer in base64) is removed by Filebeat
  before indexing (it stays in `archives.json` on disk, purged after 14 days).
- **Rename-based** rotation of both files: no loss observed, and rule 591 ("file rotated") is
  neutralised for them by rule 100290 (level 0). A truncation would still be reported by rule 592
  (log tampering).
- `@timestamp`/`timestamp` = ingestion time by Wazuh. The real time of a device event is
  `data.watchpost.ts` (a history sent late arrives "all at once").

### 7.2 Watchpost rules (`wazuh/rules/`, identifiers 100100-100549)

| Area | Detections (level) |
|---|---|
| Agent | tampering `agent.tamper` (12), collection or upload disabled (5), buffer full (6), stopped (3) |
| Absence | no event for 60 min (7, `WATCHPOST_WATCH_SILENCE_MIN`), resumed (3), sequence gaps (6, or 3 if explained by a purge), counter gone backwards (8); watcher `wazuh/watch/watchpost_watch.py` every 10 min |
| Posture (`security.posture_change`, one alert per changed field) | verified boot degraded (12), encryption lost (10), Device Owner lost (10), private DNS disabled/not strict (10) or pointed to an unexpected host (10, generated CDB list), wireless ADB (9), secure lock removed (8), ADB (7), unknown sources (6), Play Protect disabled (5), developer options (4), patch installed and returns to normal (3) |
| Posture (`security.posture`, full state) | patch > 6 months (9) / > 3 months (6), at most once a week; the other findings are marked without an alert (level 2, group `watchpost_posture_state`) so as not to duplicate the change alerts |
| Sensors | microphone (10) or camera (10) used while the device is locked; microphone outside a call (6) or camera (8) used with the screen off; every use marked (2) |
| Apps | installed outside Play/Galaxy Store (8) or without an installer/ADB (8), new accessibility app (10), device administrator (10), notification listener (8), VPN (7), sensitive permission granted (5) |
| Security | user CA added (10, a single alert: `security.ca_cert`; the system log and the posture are marked), repeated failed unlocks (10: 5 in 10 min, or ≥ 10 consecutive), `security.log` (fields named according to the contract table): ADB shell (10), ADB command/transfer (8), logging stopped (12), critical buffer (7), key integrity violation (12), crypto self-test (10), dm-verity not enforced (7), wipe failure (8), restriction removed (5), key operation failure (5), media mounted (3), credential changed (3) |
| Network | null cellular cipher (12), 2G downgrade / IMSI catcher (10), BLE tracker following (10), simulated position (9), open Wi-Fi (4), network without private DNS (5), clock change ≥ 1 h (5), USB with ADB (5) |
| Tracking | DNS query from an app to Google/Samsung telemetry (2: no alert, marked for the dashboards) |
| AdGuard | threat feed domain requested (10), repeated (12), burst of blocks (5) |
| Remote commands (issued by the collector, `watchpost.source = "server"` required: a device cannot imitate them) | erase requested (12), lock requested (10), message removal (5), location requested (5), other command issued (3), burst of 8 commands in 10 min (8, fired by a simple command so as never to hide a level 10-12 alert), sensitive command expired without a result (6), other expiry and cancellation (3), result received by the API `command.reported` (2: marked only) |
| Remote commands (result reported by the phone, `command.result`) | erase executed (12), sensitive command channel locked after 5 invalid signatures `locked_out` (12), invalid signature `bad_signature`: someone is trying to command the phone without the passphrase (10), lock executed (10), command failed (6), command refused for another reason (5), simple command executed (3), `replay` refusal of a resend (2) |
| Notifications (`app.notification`, companion APK) | marked without an alert (2); the title and the text never appear in a description |
| Collector detections (v1.2, `detect.*`, `watchpost.source = "server"` required) | see §7.4: from 3 (trace) to 12, and 13 when several detection types target the same application within 24 h |
| Risk profile (`app.risk`) | marked (2); high risk at installation, correlated with `app.installed` of the same package within the hour (9), with a `combo_*` reason (11); high risk outside installation (4); nothing on `low` |
| Roles (`app.role`) | new default SMS app (8), keyboard (8), phone (7), assistant or autofill (7), other role (3) |
| Operations (`app.ops.app`) | marked (2); SMS sending refused = attempt blocked by a guard (4); other access refused (3) |
| SMS permissions (`app.permission_changed`) | `SEND_SMS`, `READ_SMS`, `RECEIVE_SMS`, `RECEIVE_MMS` granted (8: defence in depth, independent of the collector); `CALL_PHONE` among the sensitive permissions (5) |
| Guards (`security.policy`, `profile = "guard:…"`) | guard **disabled** (8), release from quarantine (5), enabling, quarantine, permission restored (3), permission denied (2: marked); a failure is still alerted by 100187 (5) |
| Tracking page (`tracking.*`, emitted by the collector) | blocking weakened: level lowered or set from an unknown state (8), domain **force-allowed** (8), forced block of an essential domain (6), manual block removed (5), other change (3) |
| Fallback | severity 3 / 2 reported by the agent for a type without a dedicated rule (10 / 6); for a `detect.*` type without a dedicated rule (added to the collector after these rules): 10 / 6, 3 otherwise |

MITRE ATT&CK **Mobile** mappings (T1629.003, T1638, T1461, T1453, T1517, T1626.001…): the MITRE
database embedded in Wazuh only knows the Enterprise matrix (a mobile `<mitre>` tag is rejected and
disappears from the alert); they are therefore carried by the `attack_mobile_<ID>` groups.

**Tests**: `wazuh/tests/cases/*.log` (210 cases, one file per case, the last line must fire the
expected rule); `./wazuh/tests/run-tests.sh` replays them with `wazuh-logtest` in the manager;
`wazuh/tests/generate-cases.py` regenerates them.

Limits (of Wazuh, documented in the rules): an event fires only **one** rule (the child rules are
tried by decreasing level), hence the `security.posture_change` events (one per field); a defect
**already present at enrollment** produces no change, hence no alert: check the initial posture in
the console. A microphone used with the screen off during a call (source `voice_communication`,
proximity sensor) does not alert. `wazuh-logtest` does not apply the `ignore` option of the rules
(checked in the real flow). The result of a command arrives twice (`command.result` from the device,
`command.reported` from the collector): only the first one alerts. The correlation rules
(`if_matched_group`) must follow in the file the rules of the group they observe (otherwise they see
no past event: observed). **A single analysis thread** (`analysisd.event_threads=1`,
`rule_matching_threads=1`, set by `watchpost-init.sh`): with one thread per CPU, events arriving in the
same millisecond (the collector writes its detections in bursts) were evaluated in parallel and the
correlations 100489 and 100502/100503 missed them one time out of two in testing; with one thread,
20 out of 20. Throughput measured with one thread: 121,000 events analysed and indexed in 54 s.

Blocking level changes and the rules set by the Tracking page are exported since v1.2
(`tracking.level_changed`, `tracking.override`, one event per non-revoked device) and alerted when
they weaken the blocking (above).

### 7.3 Retention, map, dashboards

- ISM policies: alerts 180 days (`WAZUH_ALERTS_RETENTION_DAYS`), archives 90 days
  (`WAZUH_ARCHIVES_RETENTION_DAYS`), monitoring 30 days. Change `.env`, then `./install.sh`.
- `watchpost` index template (order 1, complements Wazuh's): 1 shard without replica;
  `data.watchpost.data.location` as **geo_point** (map); leaves of `data.watchpost.data.*` as
  `keyword` (the same field name carries different types depending on the event: without this the
  indexer rejected documents); known numeric fields typed for the charts. A template applies only to
  indices created after it (daily indices: effect the day after a change). The free-form fields of
  v1.1 (`title` and `text` of `app.notification`, 512 characters each, any content; `params.*` and
  `message_set` of the commands; `watchpost.source`) are indexed as `keyword` (beyond 1024
  characters a value stays in the document without being indexed: never a rejection); the lock
  message is not exported. Verified (§11): a 512-character notification with quotes, backslashes,
  line breaks and emojis indexed, export = archives one for one, retention policies attached to the
  day's indices. The notification content is therefore in `wazuh-archives-*` (90 days) if the
  "content" option is enabled in the app.
- Imported dashboards: **"Watchpost — phone security"** (alerts over time, by rule, by ATT&CK Mobile
  technique, list, map of positions), **"Watchpost — tracking and DNS"** (apps that contact
  telemetry, blocked domains, events by type) and, since v1.2, **"Watchpost — detections and
  applications"** (detections by type and application, applications with a medium or high risk,
  guard refusals and actions), + saved searches (including "collector detections" and "risk profile
  of the applications"). Import verified (`_import` API, objects read back, non-empty queries);
  display in a browser was not checked for the third one.
  The map background is loaded by the browser from the OpenSearch tile service (third party); the
  Watchpost console has its own map.

### 7.4 Collector detections (v1.2): rules, what to do when they fire

The collector computes behavioural detections on the received data (contract §11.3 and §11.4,
`server/collector/README.md`) and exports them as `detect.*` events with
`watchpost.source = "server"`. One detection per application, per type and per UTC day (24 h after
installation for `new_app_risky`). An **update** (`update: true`, exported again only if a new item
appears, at most once per hour) gives a level 5 alert, without notification; if it takes to severity
3 a detection emitted below 3 within 24 h: "escalated detection" (100452, 12). A detection with
`recurring: true` (already reported within 30 days, severity capped at 1) is only a trace (100456,
3). Two different **types** for the same application within 24 h: 100489, level 13, which replaces
the alert of the second type and names it.

| Detection | Rule (level) | What to do |
|---|---|---|
| `threat_domain`: the application requested a domain blocked by a `threat` list | 100460 (12); browser or fewer than 3 queries: 100461 (10) | Probable malware command server: identify the application, uninstall it (or quarantine it), check its special access. Browser: phishing link followed, check that no password was typed. Never allow the domain in the console. |
| `sms_abuse`: sending (or attempt) of SMS by an app other than the SMS app, or volume (requires `app_ops`) | 100462 (12) | SMS fraud: enable the SMS guard if not done, uninstall the application, check the bill with the carrier, block premium-rate SMS with the carrier. |
| `sms_permission` (§11.4): an app that is neither the SMS app nor a system app holds `SEND_SMS` | 100475 (10) | Find out why it can send SMS; otherwise remove the permission or uninstall; SMS guard. |
| `default_app_changed` (§11.4) `sms` role | 100476 (12); other roles: 100477 (3, already alerted by `app.role`) | If you did not choose this SMS app, set Messages back as the default and uninstall the application. |
| `sensor_background`: microphone or camera in the background above the threshold (requires `app_ops`) | microphone 100463 (10), camera 100464 (10) | Probable spyware: remove microphone and camera, uninstall; if it is a device administrator, remove that first. |
| `new_app_risky`: app installed less than 24 h ago that obtains a sensitive capability | sev. 3: 100470 (12); 2: 100471 (9); 1 (VPN, overlay): 100472 (4); high risk without capability: 100473/100474 (3, already alerted by `app.risk` 100502/100503) | Check that the installation was intended; otherwise uninstall (quarantine would have refused these permissions). |
| `mail_ports`: ordinary app that sends e-mail | 100467 (8); spam volume: 100468 (10) | Spam sent from the phone: uninstall. Legitimate mail client missing from the list: `WATCHPOST_DETECT_MAIL_CLIENTS`. |
| `fanout`: hundreds of addresses in one hour | 100466 (8) | Relay / residential proxy (your connection resold): uninstall. Peer-to-peer or speed test: ignore, or raise `WATCHPOST_DETECT_FANOUT`. |
| `dns_bypass`: public DoH/DoT resolver used | 100469 (7) | The app escapes DNS filtering. Browser with "secure DNS": turn it off, or exempt it (`WATCHPOST_DETECT_DNS_BYPASS_EXEMPT`, or mute in the console). |
| `upload_spike`: massive upload in one hour | 100465 (7) | Backup or video: nothing. Otherwise ("vault" gallery, unknown app): possible exfiltration, uninstall and change the exposed passwords. |
| `inventory_mismatch` (§11.4, cannot be muted): the device declares "system" an app that its installer or an earlier `app.installed` contradict | 100481 (12) | An app that passes itself off as a system app would escape the other detections: check its installer in the console, uninstall it if it is not original. |
| `flood` (§11.4): more than 200 detections in the day | 100478 (12) | Inconsistent data or compromised device: look at the console, the state of the agent and the posture. |
| `muted` / `unmuted` (§11.4): mute set / lifted in the console (`POST`/`DELETE /api/console/detections/mute`; `sms_abuse`, `default_app_changed`, `inventory_mismatch`, `flood` refused: `400 not_mutable`) | 100479 (6) / 100480 (3) | Unwanted mute = someone used the console: change the console password. |
| `detect.*` type without a dedicated rule | 100454 (sev. 3: 10), 100455 (sev. 2: 6), 100450 (3) | Read the summary; update the repository. |

**What fires for the "silent SMS" attack** (store application without an icon, `SEND_SMS` granted
25 to 30 h after installation, then mass sending; `silent-sms` scenario of the simulator, replayed
here, §11.2):

| | Without `app_ops` (probable real case) | With `app_ops` |
|---|---|---|
| At installation | `app.risk` `medium`: marked, no alert (no `new_app_risky`) | same |
| When `SEND_SMS` is granted | 100161 (8, `app.permission_changed`) **and** `detect.sms_permission` 100475 (**10, notified** at the default threshold) | same |
| While sending | nothing: the SMS are not counted | `detect.sms_abuse` 100462 (12), or 100489 (13) if another detection targets the same app within 24 h; guard refusal: 100522 (4) |
| If it makes itself the default SMS app | 100511 (8, `app.role`) and `detect.default_app_changed` 100476 (12) | same |

**Without the agent's experimental `app_ops` collector, the sending of SMS itself is not counted**:
`sms_abuse` and `sensor_background` stay silent (SMS do not go through the IP network). Protection
against SMS fraud then relies on the app's **SMS guard** (which refuses `SEND_SMS` to everything except
the SMS app), on `detect.sms_permission` and `detect.default_app_changed`, and, independently of the
collector, on the Wazuh permission alerts (100161: `SEND_SMS`/`READ_SMS`/`RECEIVE_SMS` granted,
level 8) and role alerts (100511: new default SMS app, 8; 100512: phone, 7). These last two are not
notified at the default threshold (10): lower `WATCHPOST_NOTIFY_LEVEL` to 8 to receive them.

Double alerts avoided or accepted: `new_app_risky` without capability repeats the `app.risk` of the
installation (marked only); `default_app_changed` outside `sms` repeats `app.role` (marked);
`default_app_changed` `sms` (12) and `app.role` `sms` (8) coexist on purpose (the second one does not
depend on the collector); an app installed outside a store and with a high risk gives 100151 (8)
**and** 100502/100503 (9/11): two facts; a threat domain gives the AdGuard alert 100402 (10, per
query, without the application) **and** `threat_domain` (one per day, with the application).

**Variables** (`.env`, created empty by `install.sh` and never overwritten; empty = collector
default; after a change: `./install.sh`). An invalid value prevents the collector from starting
(`docker compose logs collector`).

| Variable | Collector default | Role |
|---|---|---|
| `WATCHPOST_DETECT_ENABLED` | `true` | `false`: no detection |
| `WATCHPOST_DETECT_DISABLE` | empty | detections turned off, e.g. `fanout,mail_ports` |
| `WATCHPOST_DETECT_INTERVAL_S` | `300` | interval between two passes (10 to 86400 s) |
| `WATCHPOST_DETECT_UPLOAD_FLOOR_MB` / `_UPLOAD_FACTOR` / `_UPLOAD_LEARN_DAYS` | `1024` / `10` / `7` | `upload_spike`: floor in MiB/h, k × median, learning days |
| `WATCHPOST_DETECT_FANOUT` / `_FANOUT_SCREEN_OFF` | `300` / `100` | distinct addresses per hour (screen on / off) |
| `WATCHPOST_DETECT_MAIL_MIN` / `_MAIL_CLIENTS` | `1` / empty | SMTP connections per day; added mail clients |
| `WATCHPOST_DETECT_DNS_BYPASS_MIN` / `_PORTS` / `_EXEMPT` | `1` / `443,853` / empty | public resolvers: connections, watched ports, exempted applications |
| `WATCHPOST_DETECT_SMS_OTHER_MIN` / `_SMS_DAILY_MAX` | `1` / `200` | SMS per day (other app / any app) |
| `WATCHPOST_DETECT_MIC_BG_MIN` / `_CAMERA_BG_MIN` | `10` / `3` | background accesses per day |

## 8. Operations

### 8.1 Updates

```bash
sudo ./update.sh        # backup, git pull, images, collector rebuild, install.sh
```

The versions are pinned (`docker-compose.yml`): Wazuh 4.14.10, AdGuard Home v0.107.80,
Caddy 2.11.9. To upgrade, change the file (the three Wazuh images together, after reading the
release notes), then run `update.sh`. The blocklists update themselves.

### 8.2 Backup and restore

```bash
sudo ./backup.sh                        # backups/watchpost-YYYYMMDD-HHMMSS.tar.gz (secrets included)
gpg -c backups/watchpost-….tar.gz       # encrypt before taking the archive off the server
sudo ./restore.sh backups/watchpost-….tar.gz
```

The backup contains `.env`, `secrets/`, `data/` and the volumes of the collector (**database and
device CA: without it, the phones must be enrolled again**), of Caddy (certificates), of AdGuard and
the manager state. The Wazuh index is not included by default (large; the events stay in the
collector database): `--with-siem` includes it, stopping Wazuh. Verified: destruction of every volume
and of the configuration, then `restore.sh` → healthy stack, enrolled phone accepted.

### 8.3 Passwords

```bash
sudo ./install.sh --rotate-passwords
```

regenerates every password of `.env` and applies them everywhere: indexer accounts (through the
security API, account by account: users created in the dashboard are kept), Filebeat, dashboard,
Wazuh API, collector, AdGuard (`admin` and `watchpost-collector`: verified, old password refused by
AdGuard, collector reconnected with the new one), Caddy, and the `admin` console account (verified:
old password refused, new one accepted, user added in the dashboard still valid).

Rule per account:

| Account | Source of truth | Changing the password |
|---|---|---|
| Watchpost console `admin` | the collector database | `docker compose exec collector watchpost-collector user set-password admin`: kept by `install.sh`; `--reset-console-password` sets the one from `.env` again |
| Indexer `admin`, `kibanaserver`, `watchpost_reader`; API `wazuh-wui` | `.env` | change `.env`, then `./install.sh` (not in the dashboard: Filebeat, the dashboard and the collector use these accounts; a change made elsewhere is reset to the `.env` value) |
| Other Wazuh dashboard users | the dashboard | in the dashboard (never touched by `install.sh`) |
| AdGuard `admin`, AdGuard `watchpost-collector` (collector account, administrator like every AdGuard account), Caddy `admin` access, WireGuard | `.env` | change `.env`, then `./install.sh` |

### 8.4 Troubleshooting

| Symptom | Lead |
|---|---|
| State of the services | `docker compose ps` (all must be `healthy`), `docker compose logs -f <service>` |
| The phone has no Internet any more | Private DNS unreachable: `python3 tools/dot-query.py dns.D example.org`; `docker compose logs adguardhome`; temporarily turn off private DNS on the phone |
| An app is broken | AdGuard query log (`adguard.D`) or "tracking and DNS" dashboard: find the blocked domain, add `@@\|\|domain^$important` to `data/adguard/userfilters/personal-rules.txt`, `./install.sh` |
| No certificate | DNS not propagated yet or port 80 closed: `docker compose logs caddy` |
| Nothing in Wazuh | `./wazuh/tests/run-tests.sh`; `docker compose exec wazuh.manager tail /var/ossec/logs/ossec.log`; indexing errors: `docker compose logs wazuh.manager \| grep 'Cannot index'` |
| Indexer read-only, dashboard `unhealthy` ("create-index blocked") | disk too full (thresholds 90/95/97 %): reduce retention, free space; the block lifts by itself when space comes back |
| After a host restart | everything restarts by itself (`restart: unless-stopped`); a defect of the wazuh-manager image (initialisation interrupted on restart) is worked around by `wazuh/manager/cont-init/00-watchpost-pre` |

### 8.5 Notifications (optional)

Without notifications, a severe alert is only seen by opening the console or the dashboard. In
`.env` (disabled while `WATCHPOST_NOTIFY_URL` and `WATCHPOST_NOTIFY_SMTP_HOST` are empty), then
`./install.sh`:

| Variable | Role |
|---|---|
| `WATCHPOST_NOTIFY_LEVEL` | minimum Wazuh level notified (default 10); the agent silence (rule 100301) and the sequence reset (100305) are always notified |
| `WATCHPOST_NOTIFY_URL` | webhook: `POST` of a JSON `{"title","message","priority","tags"}` |
| `WATCHPOST_NOTIFY_TOPIC` | ntfy topic: added to the JSON (`"topic"`); with ntfy, `WATCHPOST_NOTIFY_URL` is the root of the server, e.g. `https://ntfy.sh` |
| `WATCHPOST_NOTIFY_TOKEN` | optional token, sent as `Authorization: Bearer …` |
| `WATCHPOST_NOTIFY_SMTP_HOST`, `_PORT` (587), `_TLS` (`starttls`, `tls` or `none`), `_USER`, `_PASSWORD`, `_FROM`, `_TO` (comma-separated addresses) | e-mail through an SMTP relay (the one of your mail provider) |

Example with ntfy: `WATCHPOST_NOTIFY_URL='https://ntfy.sh'` and
`WATCHPOST_NOTIFY_TOPIC='a-long-and-secret-name'`, then subscribe to this topic in the ntfy app.
Content: rule title, level, device name, event type, times, ATT&CK Mobile techniques: **never** the
raw log, the event data (GPS position, identifiers, content) nor a secret: the notification goes to a
third party. A public ntfy topic can be read by anyone who knows its name: choose it long and random,
or use your own ntfy server with a token. Verified with a local receiver: level 12 alert and agent
silence received (webhook and e-mail), alerts below the threshold not sent. Implementation: Wazuh
integration `custom-watchpost-notify` (`wazuh/notify/`), configured when the manager starts.
The expiry dates of the device certificates are not notified: `./enroll.sh --list` (§8.7).

Detections (v1.2): at the default threshold (10), the following are notified: threat domains
contacted, SMS fraud, SMS permission held by another app, change of the default SMS app, microphone or
camera in the background, a recent app that obtains severe capabilities, spam, the detection limit,
escalations and correlations (13); not the upload spikes, the address fan-out, the DNS bypass, the
detection updates nor the traces. The title names the application (its label and its package) and
the fact; no notification content nor lock message.

Remote commands (v1.1): at the default threshold (10), the following are notified: lock and erase
requested, lock and erase executed, an invalid signature and the locking of the channel after 5
invalid signatures. The notification never contains the **lock message** (the collector does not
export it) nor the **content of a notification** of the phone (`app.notification` is level 2 and its
description repeats neither title nor text). Verified with a local receiver (§11).

### 8.6 Wazuh internal certificates

The internal PKI (indexer, manager, dashboard, admin) is valid for 5 years (CA: 10 years). The expiry
date is recalled at the end of every `install.sh` (warning under 90 days).

```bash
sudo ./install.sh --renew-wazuh-certs   # new certificates, same CA (normal case)
sudo ./install.sh --renew-wazuh-ca      # new CA and new certificates (CA compromised or expired)
```

The previous files are kept in `secrets/wazuh-certs/old-<date>/`; the Wazuh containers (and the
collector, with `--renew-wazuh-ca`) are recreated, Caddy reloaded. Verified for both: healthy stack,
indexer data kept, new events indexed, alerts read by the console, dashboard reachable through Caddy.

### 8.7 Devices: list, renewal, revocation

```bash
sudo ./enroll.sh --list                 # devices, last contact, certificate expiry ("renew" under 30 days)
sudo ./enroll.sh --renew phone          # phone-renewal.watchpost: new token and certificate, same device
sudo ./enroll.sh --revoke phone         # or dev_…: token and certificate refused immediately
```

After `--renew`, import the new file into the app (then destroy it): the old pair stays accepted
until the first upload made with the new one, then it is refused. Verified through Caddy in mTLS: old
pair accepted (200), new pair accepted (200), old pair refused afterwards (401). Device certificates
last 2 years.

## 9. Memory sizing (8 GB host)

| Service | Limit | Measured at rest (test) |
|---|---|---|
| wazuh.indexer | 3 GB (Java heap `WAZUH_INDEXER_HEAP=2g`) | 2.4 GB |
| wazuh.manager | 1.5 GB | 0.3 GB |
| wazuh.dashboard | 1 GB (Node heap 640 MB) | 0.2-0.5 GB |
| adguardhome | 768 MB | 110 MB with the real lists loaded (strict level: PRO++, Samsung, threats ≈ 620,000 rules; balanced: 107 MB) |
| collector | 512 MB | < 50 MB |
| caddy | 256 MB | 15 MB |

Total of the limits ≈ 7 GB; plan 2 GB of swap. On a larger host, increase `WAZUH_INDEXER_HEAP` (at
most half of the RAM) and `WAZUH_INDEXER_MEM_LIMIT` (heap + 1 GB). Under 8 GB:
`WAZUH_INDEXER_HEAP=1g` and `WAZUH_INDEXER_MEM_LIMIT=2g`, at your own risk.

## 10. Options

### 10.1 WireGuard (`wireguard` profile)

```bash
sudo docker compose --profile wireguard up -d wireguard
ssh -L 51821:127.0.0.1:51821 vps     # wg-easy interface: http://127.0.0.1:51821 (admin / WG_ADMIN_PASSWORD)
sudo ./firewall/ufw.sh --wireguard
```

The tunnel gives the phone a fixed address, uses AdGuard as internal DNS and sends all its traffic
through the VPS. **Drawbacks**: Android accepts only one active VPN (incompatible with a local
VpnService-type firewall); battery and latency; all the bandwidth goes through the VPS; if the VPS
goes down, no more Internet in "always-on VPN" mode; the content stays TLS-encrypted (only the
metadata is visible); WireGuard kernel module required. Enable it only if you need it.
Not tested here (Compose configuration validated only).

### 10.2 Tiles of the console map (`WATCHPOST_TILE_URL`)

The console loads the base map from `WATCHPOST_TILE_URL` (default:
`https://tile.openstreetmap.org/{z}/{x}/{y}.png`). The tile server therefore sees the IP address of
the browser and **the areas viewed** (hence the places the phone visits). To avoid this:

- choose a provider whose privacy policy suits you (an API key is often required):
  `WATCHPOST_TILE_URL='https://tiles.provider.example/{z}/{x}/{y}.png'` in `.env`, then
  `./install.sh` (the console CSP follows automatically);
- or self-host a tile server (for example tileserver-gl or a PMTiles file of your region behind
  Caddy): several GB of disk and some work, not provided here.

The URL must use `https://` with the `{z}`, `{x}`, `{y}` placeholders.

## 11. What was verified (test run, internal TLS mode)

Test conditions: Docker 29, 16 GB of RAM, no outbound Internet access for the containers. Proven:
full installation, then rerun (idempotent); indexer, manager, dashboard healthy with the generated
passwords (old passwords and demonstration accounts refused); password rotation; real collector:
enrollment, simulator (48 types, including `security.posture_change` and the sensors with screen
state) sent through Caddy in mTLS, 13,131 lines exported = 13,131 documents in `wazuh-archives-*` (no
indexer rejection), alerts in `wazuh-alerts-*` read by the console (`/api/console/alerts`); rotation
by renaming without loss nor alert; mTLS (refusal without a certificate and with another CA,
acceptance with the enrolled certificate); DoT with Caddy's certificate, blocking of a domain of
`watchpost-base.txt`, reload of the renewed certificate without restart; ClientID mode (unknown
identifier → REFUSED); geo_point; import and display of the dashboards; backup, then restore after
total destruction; 121 rule cases.

Not verified here (limits of the test environment): Let's Encrypt (no inbound/outbound access),
DNS-01 challenge and Caddy image with a DNS module, download of the HaGeZi lists and resolution
through Quad9 (no Internet in the containers), WireGuard, original `ulimits` (the test host caps
`nofile` at 20,000: test override only), memory consumption with the lists loaded.

### 11.1 Version 1.1 (test run, internal TLS mode)

Stack installed with the collector image rebuilt from the current code, three devices enrolled, the
collector's simulator acting as a command agent **through Caddy in mTLS**
(`sim --enroll phone.watchpost --follow --command-code 'correct horse battery staple'`, container on
the `watchpost` network). Proven:

- **SSE stream**: `curl -N` on `https://ingest.D/api/v1/commands/stream` (certificate and token of a
  device) open 7 min over HTTP/1.1 and HTTP/2, keepalives received every 120 s, no cut by Caddy; a
  command issued in the meantime arrives within the second (no buffering); a single access log line
  per connection, token masked; the simulator reconnects by itself after the collector is recreated;
- **commands**: `ring` issued by `POST /api/console/commands` → executed, result returned
  (`executed`); `lock` signed with the passphrase of the contract test vector (§8, key derived for the
  device identifier) → executed; `lock` signed with another passphrase → `bad_signature`; 5 invalid
  signatures → `locked_out`; cancellation of a pending command; matching Wazuh alerts
  (100230-100245) in `wazuh-alerts-*`, webhook received for levels ≥ 10, without lock message nor
  notification content; lock message absent from `events.ndjson`, from the archives and from the
  alerts;
- **routing**: `/api/console/*` → 404 on `ingest.D`; `/api/v1/*` → 404 on `console.D`; TLS refusal
  without a client certificate or with another CA; certificate of one device + token of another →
  401; forged `X-Watchpost-Client-Cert-Sha256` header ignored; 2 MB body → 413 on `console.D`;
- **real AdGuard**: real HaGeZi lists downloaded by AdGuard (from a fake test CDN, see below); DoT
  queries (`tools/dot-query.py`) to domains of `watchpost-base.txt` blocked and visible on the
  Tracking page with their reason; `PUT /tracking/override` → domain blocked by a DoT query (before:
  not blocked; after: `0.0.0.0`), essential domain refused (`409 essential_domain`);
  `PUT /tracking/level` strict, then permissive → lists 2/11/20 and 10 enabled or disabled in
  AdGuard (PRO++ downloaded when enabled);
- **source of truth**: `install.sh` rerun → level `permissive` and `watchpost:begin` block kept,
  `.env` byte-for-byte identical; `install.sh --profile strict` → the console reads `strict` (at the
  next polling, ≤ 60 s); `--reset-adguard` → configuration regenerated, level and block kept;
  `--rotate-passwords` → `watchpost-collector` account changed, old password refused, Tracking page
  reachable;
- **indexing**: 435 lines exported = 435 documents in `wazuh-archives-*` (including 25 server
  events), no rejection; `run-tests.sh`: 143 cases out of 143.

Test-only adjustments (additional Compose file outside the repository, through
`WATCHPOST_COMPOSE_EXTRA`): fake `cdn.jsdelivr.net` CDN (network alias, test CA added to AdGuard's
store, upstream `[/jsdelivr.net/]127.0.0.11` set through the API for the duration of the test)
serving the real HaGeZi lists fetched from GitHub; `nofile`/`memlock` capped; indexer disk thresholds
as absolute values (large disk almost full in proportion). Not verified here: `update.sh` (rebuild
from the image registries), real expiry of a command (1 h at least), real phone and real Android
agent.

### 11.2 Version 1.2 (test run, internal TLS mode)

Stack installed with the collector image rebuilt from the current code (`docker build` with
`mirror.gcr.io`), five devices enrolled with `enroll.sh`, simulator in a container on the `watchpost`
network **through Caddy in mTLS**: `sim --enroll phone-fraud.watchpost --backfill 72h --scenario
sms-fraud`, then `--scenario all` and `--scenario healthy` (one device each; then `sms-fraud` and
`all` replayed on two new devices after switching to a single analysis thread). Proven:

- **indexing**: 298,231 lines exported (including three files after rotation) = 298,231 Watchpost
  documents in `wazuh-archives-*`, no rejection (`docker compose logs wazuh.manager | grep 'Cannot
  index'` empty), `evidence` fields of variable types included;
- **detections**: the 8 types of §11.3 exported and indexed, each with the expected rule (100460,
  100462, 100465, 100466, 100468, 100470, 100472) or, when the same application already had a
  detection of another type within 24 h, with the correlation 100489 (13); always the case for
  `sensor_background` and `dns_bypass`, preceded by `new_app_risky` of the same application: their
  own rules (100463, 100469) are only verified by `run-tests.sh`; `app.risk` at installation: 100503
  for the three `combo_*` applications; SMS sending refused after the guard was enabled: 100522;
  `guard_enabled`: 100531; **healthy scenario: zero detection**, zero `detect.*` alert;
- **`detect.threat_domain` with the real AdGuard Home and the real `levels.json`**: the real HaGeZi
  TIF list (353,203 domains, fetched from GitHub) served by a fake `cdn.jsdelivr.net` at the exact
  address of the file, plus the 4 command domains of the scenarios added at the end (the simulator
  requests no others); DoT queries through `tools/dot-query.py` → `0.0.0.0`, collector polling,
  `threat_domain` detections (sev. 3) for the applications that had requested these domains. A real
  domain of the list (`pl.0003201.site`) is blocked the same way; it produced no detection for lack of
  a simulated `net.dns` for it;
- **Tracking page**: `PUT /tracking/level` permissive → 100541 (8); `PUT /tracking/override` allow →
  100543 (8), block → 100542 (3) (one event per device);
- **notifications** (local webhook and SMTP receiver): alerts ≥ 10 received, including the severe
  detections and the correlations; none below the threshold; no title nor text of a phone
  notification in the 155 bodies received;
- **`install.sh` rerun**: `.env` identical (`sha256sum -c`), level `permissive` and `watchpost:begin`
  block kept, `size_memory` set back from 1 to 50, dashboards imported;
- `run-tests.sh`: 210 cases out of 210.

**Second run (collector with §11.4, image rebuilt twice)**: scenarios `silent-sms --app-ops=false`,
`banking-trojan`, `all`, `healthy`, then `dns-bypass` on a device with a mute, and `silent-sms
--app-ops=false` replayed with the simulator aligned on the real thresholds of the risk profile.
Proven: 320,585 lines exported = 320,585 documents, no rejection; **`silent-sms` without `app_ops` →
a single detection, `detect.sms_permission`, rule 100475 (10), received by the webhook and through
SMTP** (plus 100161, 8, when the permission is granted); `banking-trojan` → `default_app_changed`
exported (`evidence.role = sms`) and alerted (100489 live because it is correlated with
`new_app_risky`; the exported line, replayed alone in `wazuh-logtest`, gives 100476, 12); real
`app.role` → 100511 (8); `all` → `sms_permission` 100475, `recurring` → 100456; **mute** through
`POST /api/console/detections/mute` → `detect.muted` exported (`type`, `package`, `reason`, `user`)
and alerted (100479); the covered detection is `muted: true` in the API and **absent from the
export**; type that cannot be muted → `400 not_mutable`; `healthy`: no detection. Not produced by the
simulator, verified by `run-tests.sh` only: `inventory_mismatch`, `flood`, `unmuted`.

Found and fixed during the test: correlations missed one time out of two with several analysis
threads (§7.2); correlation rule placed before the rules of its group (never fired). Test-only
adjustments (outside the repository, `WATCHPOST_COMPOSE_EXTRA`): fake CDN, `nofile` capped, indexer
disk thresholds as absolute values. Not verified here: real phone, real `app_ops` collector, Multi
PRO lists (not served by the fake CDN), §11.4 types emitted by the real collector.

## 12. Files

```
infra/
├── install.sh  enroll.sh  backup.sh  restore.sh  update.sh
├── docker-compose.yml
├── lib/common.sh                    shared functions
├── caddy/                           Caddyfile, TLS modes, DNS sites, Dockerfile.dns (DNS-01)
├── adguard/                         AdGuardHome.yaml template, Watchpost rules (base, strict),
│                                    levels.json (blocking levels, also read by the collector),
│                                    merge-config.py (merge into the configuration in service)
├── wazuh/
│   ├── gen-certs.sh                 Wazuh internal PKI (openssl)
│   ├── indexer/  dashboard/          configuration (*.tmpl templates rendered into data/)
│   ├── manager/                     ossec.conf, initialisation scripts
│   ├── rules/                       Watchpost and AdGuard rules
│   ├── watch/watchpost_watch.py     silence / sequence watcher
│   ├── setup/indexer-setup.sh       index template, ISM policies
│   ├── dashboards/                  saved objects (ndjson) and their generator
│   └── tests/                       test cases, run-tests.sh
├── firewall/                        ufw.sh, nftables.conf
├── tools/dot-query.py               diagnostic DoT client
├── .env              (generated)    settings and secrets
├── secrets/          (generated)    credentials.txt, Wazuh PKI, hash cache
└── data/             (generated)    rendered configuration, personal AdGuard rules
```
