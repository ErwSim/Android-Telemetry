# 01 — Install the server

This guide installs the Watchpost server stack on a VPS: the TLS front end (Caddy), the Watchpost collector and
console, Wazuh (manager, indexer, dashboard) and AdGuard Home (filtering private DNS). The installation itself is
three commands; everything is explained in detail in [`infra/README.md`](../../infra/README.md), which this guide
does not copy: it points you to it, orders the steps and says what to check.

Time: about one hour, part of it waiting (image downloads, Wazuh start-up).
Next: [02 — build the APK](02-build-apk.md) (you can do it while the server starts).

> **Verification status.** The stack was installed, replayed, backed up and then restored in **internal TLS mode**
> on a 16 GB machine without outbound Internet access for the containers. The following points have **never been
> tested**: real Let's Encrypt, downloading the blocking lists, upstream resolution through Quad9, ClientID mode
> (DNS-01 wildcard), WireGuard, memory use with the lists loaded, ARM processors. Section 9 says how to check each
> one after the installation.

## 1. Choose the VPS

| | Minimum | Recommended |
|---|---|---|
| Memory | **8 GB** (Wazuh is not supported below that) | 8 GB and 2 GB of swap |
| Processor | 2 vCPU | 4 vCPU |
| Disk | 30 GB SSD | 50 GB SSD (about 90 days of archives for one phone) |
| System | Debian 12 or Ubuntu 24.04 (kernel 5.10 or later) | |
| Network | fixed public IPv4 address; ports **80/tcp, 443/tcp and 853/tcp** reachable from the Internet | IPv6 as well |
| Architecture | x86_64 (the only one tested) | |

Check with the host before you pay: that inbound port 853 is not filtered (it is the phone's DNS over TLS) and that
the provider's firewall, if there is one, lets you open 80, 443 and 853.

The installation does not create swap: if your image has none, create 2 GB of it (see your distribution's
documentation).

## 2. Domain name and DNS records

You need a domain (or a sub-domain of a domain you own; a free DuckDNS or deSEC name also works). In what follows,
`watchpost.example.org` is that base domain. At your DNS provider, **before** the installation, create five
A records pointing to the VPS's IPv4 address:

```
console.watchpost.example.org    A   <VPS IP>
ingest.watchpost.example.org     A   <VPS IP>
siem.watchpost.example.org       A   <VPS IP>
adguard.watchpost.example.org    A   <VPS IP>
dns.watchpost.example.org        A   <VPS IP>
```

- Add AAAA (IPv6) records only if you have **checked** that the VPS is reachable over IPv6; an AAAA record that
  leads nowhere makes certificate validation fail. Start with the A records alone (this guide's recommendation, not
  tested).
- The wildcard `*.dns.watchpost.example.org` is useful only for ClientID mode (outside the scope of this guide, see
  `infra/README.md` §6.3).
- A short TTL (300 s) makes it easier to change servers.

Let's Encrypt validates each name through port 80: the names must already point to the VPS **at the time** of the
installation. Check propagation from the VPS (`getent hosts` exists everywhere) and from your PC:

```bash
getent hosts console.watchpost.example.org ingest.watchpost.example.org siem.watchpost.example.org adguard.watchpost.example.org dns.watchpost.example.org
```

```powershell
foreach ($h in 'console','ingest','siem','adguard','dns') { Resolve-DnsName "$h.watchpost.example.org" -Type A }
```

All five names must return the VPS address. If one is missing, wait: starting the installation before propagation
causes repeated validation failures at Let's Encrypt, which rate-limits attempts.

## 3. Prepare the VPS

Connect over SSH with an account that has `sudo`. Install Docker Engine **26 or later** and the `docker compose` v2
plugin from the official repository (<https://docs.docker.com/engine/install/>): the distributions' `docker.io`
packages are often too old, and `install.sh` refuses to continue with a Docker older than version 26. Then the
tools the scripts use:

```bash
sudo apt update && sudo apt install -y git openssl curl ufw
docker --version && docker compose version     # Docker >= 26, Compose v2
```

Get the repository (replace the address with that of your repository):

```bash
git clone <repository address> watchpost && cd watchpost/infra
```

Everything that follows is run from `watchpost/infra`.

## 4. Install

```bash
sudo ./install.sh --domain watchpost.example.org --email you@example.org --tls acme
```

- `--tls acme`: Let's Encrypt certificates (public VPS). `--tls internal` (Caddy's internal CA, for trials on a
  local network) exists but requires installing Caddy's CA on every client: `infra/README.md` §3.
- `--profile permissive|balanced|strict` applies a **DNS blocking level** (the same one as the console's Tracking
  page). **Do not switch to strict now**: the default level (`balanced`) is the one that keeps the phone usable; the
  level "in force" is afterwards the actual state of AdGuard's lists, which the console changes and `install.sh`
  keeps (guide 05, §2.2).
- Without options, `install.sh` asks questions. The `--help` option lists everything.

What the script does (summary; details in `infra/README.md` §3): checks Docker, memory and disk; sets
`vm.max_map_count` for the indexer; **generates all the secrets** in `infra/.env` and `infra/secrets/`; builds the
collector image (a few minutes); starts the indexer, the collector, Wazuh, Caddy (which obtains the certificates)
and then AdGuard Home; creates the `admin` console account; imports the Wazuh dashboards; prints a summary.

Wait for it to finish without interrupting it. The first run downloads several Wazuh images and builds the
collector: allow several minutes. The Wazuh dashboard may need several more minutes to be ready; the script says so
("not ready yet") without it being an error.

The script is **replayable**: after any change to `infra/.env` or to the repository, run
`sudo ./install.sh --yes` again. It keeps the existing secrets **and what you set in the interfaces**: the console
password changed with `set-password`, AdGuard Home settings, users created in the Wazuh dashboard. To start again
from scratch on one specific point, it has explicit options: `--reset-console-password` (sets the password from
`.env` again), `--reset-adguard` (regenerates the whole AdGuard configuration; the old one is kept),
`--renew-wazuh-certs` and `--renew-wazuh-ca` (Wazuh's internal certificates, guide 05 §8). At the end the script
announces the notifications (disabled by default, guide 05 §3) and the expiry date of Wazuh's internal certificates.

Retrieve the generated passwords:

```bash
sudo cat secrets/credentials.txt
```

They are used for: the Watchpost console (`admin`), the first barrier of the administration interfaces (Caddy,
`admin` account), the Wazuh dashboard (`admin`) and AdGuard Home (`admin`); a second AdGuard account,
`watchpost-collector`, is used by the collector to read the query log and to change the levels and rules of the
Tracking page (**AdGuard has only one type of account: it is a full administrator**, treat its password like the
others). **Copy this file into your password manager**: it is not versioned and exists only here (and in your
backups, section 7).

If the script stops with an error: it prints the offending line; also look at `sudo docker compose ps` and
`sudo docker compose logs <service>`. Common failures (no certificate, indexer in read-only mode…) are in
`infra/README.md` §8.4.

## 5. Firewall

```bash
sudo ./firewall/ufw.sh              # SSH (rate-limited), 80, 443 and 853
```

If your SSH does not listen on port 22: `SSH_PORT=2222 sudo ./firewall/ufw.sh`. **A wrong port locks you out**: open
a second SSH session before running the script and do not close it until the first one reconnects.

Two important points, from `infra/README.md` §4:

- **Docker bypasses ufw** for the ports it publishes. The only published ports are 80, 443 and 853 (guaranteed by
  `docker-compose.yml`, not by ufw); ufw protects the rest of the host, SSH included.
- If the provider has its own firewall, open 80/tcp, 443/tcp, 853/tcp there (and 22/tcp, or your SSH port).

Nothing else must be reachable: not 53, not 9200, not 55000, not 1514/1515. You check this from your PC (the command
must fail or time out for each of these ports):

```bash
nc -vz -w 3 <VPS IP> 9200
```

```powershell
Test-NetConnection <VPS IP> -Port 9200
```

## 6. First access

| Interface | Address | Credentials |
|---|---|---|
| Watchpost console | `https://console.watchpost.example.org` | `admin` and the console password (`credentials.txt`) |
| Wazuh (dashboard) | `https://siem.watchpost.example.org` | **two logins**: first Caddy (`admin` + the "administration access" password), then Wazuh (`admin` + the Wazuh password) |
| AdGuard Home | `https://adguard.watchpost.example.org` | two logins likewise: Caddy, then AdGuard (`admin`) |

- Watchpost console: with no enrolled device, it shows "This device has never sent data" or an empty device list:
  this is normal. The pages (Overview, Detections, Map, Events, Network, Tracking, Apps, Security, Commands, Alerts)
  are described in [guide 05](05-operations.md). The **Tracking** page relies on AdGuard Home: it is complete only
  if AdGuard is reachable (`docker compose ps`).
- Wazuh: three dashboards are already imported, "Watchpost — phone security", "Watchpost — tracking and DNS" and
  "Watchpost — detections and apps" (in the dashboard menu, dashboards section; the exact label may vary with the
  version). They stay empty until a device sends data.
- AdGuard Home: at every `install.sh`, the configuration **managed by Watchpost** (`admin` account, TLS and DoT,
  Quad9 and Mullvad upstreams, DNSSEC, the profile's lists, the log read by Wazuh) is applied again, and the rest is
  **kept**: custom rules from the interface, added lists, allowlists, clients, DNS rewrites, log duration. AdGuard is
  stopped for a few seconds during the merge: the phone's DNS is briefly unavailable (see `infra/README.md` §6.2 for
  the full rule). You can also put rules in `infra/data/adguard/userfilters/custom-rules.txt` (guide 05).
- If the console rejects your password several times in a row, it rate-limits attempts (10 failures per address and
  per account, then one per minute).
- **Changing the console password**: the source of truth is the collector's database.
  `sudo docker compose exec collector watchpost-collector user set-password admin` (from `infra/`, input without
  echo, 12 characters minimum) changes the password and closes the open sessions; `install.sh` will no longer
  overwrite it. The password in `.env` and in `secrets/credentials.txt` is then out of date: note the new one.
  `sudo ./install.sh --reset-console-password` sets the one from `.env` again. The other passwords (indexer, Wazuh
  API, AdGuard, Caddy access) are changed in `.env` and then `sudo ./install.sh --yes`; `--rotate-passwords`
  regenerates them all (guide 05 §8).

## 7. Backups

```bash
sudo ./backup.sh                          # backups/watchpost-YYYYMMDD-HHMMSS.tar.gz
gpg -c backups/watchpost-YYYYMMDD-HHMMSS.tar.gz   # encrypt before taking the archive off the server
```

The archive contains **all the secrets** (`.env`, `secrets/`) and the collector database with the **authority that
signs the phones' certificates**: without it, every device must be re-enrolled. It does not contain the Wazuh index
(large; the events remain in the collector's database) unless you use `--with-siem` (which stops Wazuh during the
copy). The collector is stopped for a few seconds; the phone keeps its events in its buffer and sends them again.

- Copy the **encrypted** archive off the server, for example from your PC:
  `scp you@vps:~/watchpost/infra/backups/watchpost-….tar.gz.gpg .`
- Old backups are not deleted automatically: clean `infra/backups/` from time to time.
- The restore (`sudo ./restore.sh backups/watchpost-….tar.gz`) was verified after destroying all the volumes on the
  **same** machine; it has never been tried on a new server. The planned procedure for a new server is in the header
  of `restore.sh` (install Docker, clone, copy the archive, run the script, update the DNS records).
- The APK signing key (guide 02) is **not** in this backup: back it up separately.
- Scheduling the backup (cron) is possible but not provided; if you do it, check the first run.

## 8. Enroll the phone

The server produces one `.watchpost` file per device, containing the ingestion address, the identifier, the token,
the **client certificate and its private key**, and the private DNS host name:

```bash
sudo ./enroll.sh phone                 # produces ./phone.watchpost (permissions 600)
sudo ./enroll.sh --list                # devices: identifier, last contact, certificate expiry ("renew" within 30 days)
sudo ./enroll.sh --renew phone         # new file for the SAME device (guide 05 §8): phone-renewal.watchpost
sudo ./enroll.sh --revoke phone        # (name or dev_…) revokes a device: token and certificate refused at once
```

Do this step at the time of [guide 03](03-phone.md), not before (the file must stay outside the application for as
short a time as possible). It is transferred by cable from your PC: first fetch it from the server
(`scp you@vps:~/watchpost/infra/phone.watchpost .`), then the `push-enrollment` script copies it to the phone.
**Then delete every copy** (VPS, PC, phone): `shred -u phone.watchpost` on the server; on Windows,
`Remove-Item .\phone.watchpost` (the recycle bin and SSD storage do not guarantee erasure: this is why the file has
permissions 600 and must never travel over an unencrypted channel).

The device certificate is valid for **2 years**: `--list` shows its expiry; renewal keeps the same device identifier
and the same history (guide 05 §8).

The **alert notifications** (ntfy-compatible webhook and/or e-mail) are disabled until you fill in
`WATCHPOST_NOTIFY_URL` or `WATCHPOST_NOTIFY_SMTP_HOST` in `infra/.env`: see [guide 05, §3](05-operations.md); without
them, nothing warns you when the phone stops sending or a serious alert fires. The **remote command channel**
requires no server configuration: it is put into service on the phone ([guide 03, §15](03-phone.md)).

## 9. Check the installation

Each line says what is expected. Do them all once: they replace the trials that the development environment could
not run.

**Services**

```bash
sudo docker compose ps
```

All services must be `healthy` (the Wazuh dashboard can take several minutes).

**Let's Encrypt certificates (never tested)**

```bash
curl -sS -o /dev/null -w '%{http_code}\n' https://console.watchpost.example.org/healthz       # 200
echo | openssl s_client -connect dns.watchpost.example.org:853 -servername dns.watchpost.example.org 2>/dev/null | openssl x509 -noout -issuer -dates
```

The first command must print `200` with no certificate error; the second, a Let's Encrypt issuer and valid dates
(DNS over TLS uses the `dns.…` certificate obtained by Caddy). On failure: `sudo docker compose logs caddy` (DNS not
yet propagated, port 80 closed).

**Filtering DNS and blocking lists (never tested)** — from the `infra` folder on the VPS or from your PC (Python 3 is
enough):

```bash
python3 tools/dot-query.py dns.watchpost.example.org example.org                 # a real address
python3 tools/dot-query.py dns.watchpost.example.org app-measurement.com         # 0.0.0.0: blocked
python3 tools/dot-query.py dns.watchpost.example.org connectivitycheck.gstatic.com  # a real address: exception
```

The second domain is in Watchpost's local list, so it is blocked even if the download of the HaGeZi lists failed. To
check that download, open AdGuard Home (DNS blocklists section, the exact label may vary): the HaGeZi lists must
show a non-zero number of rules and an update date; otherwise, `sudo docker compose logs adguardhome`. Upstream
resolution (Quad9) is validated by the first example.

**Memory (never tested with the lists loaded)**

```bash
free -h
sudo docker stats --no-stream
```

The container limits add up to about 7 GB; if the server swaps heavily or a container is killed
(`sudo docker compose ps` shows a restart), add swap or read `infra/README.md` §9.

**Ingestion: the client certificate is indeed required**

```bash
curl -sS https://ingest.watchpost.example.org/api/v1/ping
```

Must fail at the TLS handshake (a curl error, no HTTP code): without an enrolled certificate, nothing gets in.

**Wazuh rules**

```bash
./wazuh/tests/run-tests.sh
```

Must finish with 0 failures (exit code 0): more than 200 cases (209 in the last run documented in
`infra/README.md`, 210 case files today: rules for version 1, for remote commands, for detections, for guards and
for tracking). This is the proof that the rules are loaded in the manager.

**Port 853 from a mobile network**: some networks filter DNS over TLS. The decisive test is made with the phone, in
[guide 03](03-phone.md) (stage 1, "private DNS only").

**First certificate renewal**: the `dns.…` certificate is renewed by Caddy (about every 60 days, the usual Let's
Encrypt policy) and AdGuard reloads it without restarting; this was verified in internal TLS mode. After the first
real renewal, run the `openssl s_client` command above again and check that the expiry date has changed.

## 10. Next

- [Build the APK](02-build-apk.md) and then [configure the phone](03-phone.md).
- Day-to-day operations, updates, retention: [guide 05](05-operations.md).
- Options not covered here: WireGuard (`infra/README.md` §10.1, not tested), self-hosted map tiles (§10.2: by
  default the console's map loads OpenStreetMap tiles, so OpenStreetMap sees the areas you look at; see guide 05).
