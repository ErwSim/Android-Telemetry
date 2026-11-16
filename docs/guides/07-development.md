# 07 — Development

This guide gets you working on the project on your PC: clone, build, test, run the server stack locally with the
simulator (without a phone), find the contract and the status file, and see the leads already identified for later
versions. It assumes you have read the root [README](../../README.md).

> **Verification status.** The build and test commands come from the components' READMEs and were run on Linux.
> **None has been run on Windows.** The PowerShell adaptations given here are untried transcriptions.

## 1. Clone and choose a branch

```bash
git clone <repository address> watchpost
cd watchpost
git branch -a                 # find the working branch
git log --oneline -5
```

Work on your own branch:

```bash
git switch -c my-branch       # or git checkout -b my-branch
```

Project conventions are in [`CLAUDE.md`](../../CLAUDE.md) (read by Claude Code if you use it, and useful to any
contributor): English for everything (code, user interface, documentation, commit messages), and the non-negotiable
principles.

## 2. Where things are

| File | Role |
|---|---|
| [`CLAUDE.md`](../../CLAUDE.md) | the repository's guidelines, reading order, rules |
| [`docs/STATUS.md`](../STATUS.md) | **status file**: what exists, what is verified or not, known limits, next steps. To be read first and **updated at the end of every working session** |
| [`docs/ARCHITECTURE.md`](../ARCHITECTURE.md) | decisions, six non-negotiable principles, components |
| [`docs/contract/contract.md`](../contract/contract.md) | **the contract**: event format, ingestion and console APIs, `.watchpost` file, Wazuh export, collector variables. Every change starts **in this file** |
| [`docs/research/`](../research/) | platform facts, verified or not (Android/Samsung; SIEM, DNS, proxy), with confidence levels |
| [`android/ARCHITECTURE-CODE.md`](../../android/ARCHITECTURE-CODE.md) | Gradle modules, **recipe for adding a collector**, test conventions |
| [`android/README.md`](../../android/README.md), [`infra/README.md`](../../infra/README.md), [`server/collector/README.md`](../../server/collector/README.md), [`server/console/README.md`](../../server/console/README.md) | reference for each component |

Rules to remember: no stealth; the server sends the phone only commands from a closed list (the sensitive ones signed
with a passphrase it does not know), **never configuration or policy**; no Google dependency in the agent; third
parties' private content reduced to the minimum (notification reading lives in the optional companion APK); every
collector can be turned off; everything is reversible. **Never commit secrets** (`.env`, keys, `.watchpost`, `.p12`,
keystore); say clearly what was run and what was not.

## 3. Prerequisites per component

| Component | Tools | Remark |
|---|---|---|
| Android agent (`android/`) | JDK 17 or later (21 verified), Android SDK (`platforms;android-37.0`, `build-tools;36.0.0`, `platform-tools`); see [guide 02](02-build-apk.md) | Gradle 9.9.1 and AGP 9.5.1 come from the wrapper and the project |
| Collector (`server/collector/`) | Go 1.24 | no CGO; `go test -race` requires a C compiler (on Windows, use `go test ./...` without `-race` if you have none) |
| Console (`server/console/`) | Node 22, npm | `npm run verify` requires Chromium through a globally installed Playwright |
| Infrastructure (`infra/`) | Docker Engine 26 or later, bash, openssl, curl | **bash** scripts: on Windows, WSL2 with Docker (not tried); in practice they are tested on the VPS or a Linux machine |
| Wazuh rules | the Docker stack running | `./wazuh/tests/run-tests.sh` goes through `docker compose exec` |

## 4. Build and test, component by component

**Android agent and companion** (from `android/`; modules `:core`, `:collectors`, `:policy`, `:app` and `:notifier`):

```bash
./gradlew lint test assembleDebug assembleRelease        # Windows: .\gradlew.bat …
./gradlew :policy:test                                    # a single module (:core, :collectors, :policy, :app)
```

This is the complete verification required before committing (`android/ARCHITECTURE-CODE.md`). Lint: 0 errors (no
baseline, `abortOnError`). The tests are **pure JVM tests** (392 at the last count in `android/README.md`): there is no
emulator-based test and no Robolectric (a deliberate gap: it could not be used in the environment the tests were
developed in; it is worth reconsidering on your machine). The shared test bench is in `:core`'s `testFixtures`
(`CollectorHarness`, `Contract` reference). No test is instrumented: any behaviour on a device is verified with
[guide 06](06-on-device-checks.md).

**Collector** (from `server/collector/`):

```bash
go build -o bin/watchpost-collector .
go vet ./... && go test -race ./...
```

To embed the console in the binary: `(cd ../console && npm ci && npm run build) && rm -rf web/dist && cp -r ../console/dist web/dist`
then `go build`. Without `web/dist/` (not versioned), the page in `web/fallback/` is served. Docker image (context
`server/`, which also builds the console): `docker build -t watchpost-collector:local server/`.

**Console** (from `server/console/`):

```bash
npm ci
npm run typecheck && npm run lint && npm test
npm run build
npm run verify        # Chromium walkthrough against the mock server serving dist/
```

**Wazuh rules** (stack running, from `infra/`): `./wazuh/tests/run-tests.sh` (210 case files;
`./wazuh/tests/run-tests.sh 015 100181` filters by substring of the case name). The cases are regenerated with
`wazuh/tests/generate-cases.py`.

## 5. Working without a phone: the collector and the simulator locally

The simulator (`watchpost-collector sim`) sends realistic events of every catalogue type through the ingestion API (a
typical day around Paris, including rare events: reboot, BLE tracker, 2G, `agent.tamper`, ADB…). It can also play a
**command agent** (which connects to the command stream and executes the orders signed by the console), a **fake
AdGuard Home** and **attack scenarios** that are coherent over time: this is how to work on commands, tracking and
detections without a phone.

**Collector + simulator + console, without Docker** (from `server/collector/`):

```bash
export WATCHPOST_DATA_DIR=$PWD/.dev WATCHPOST_LISTEN=127.0.0.1:8080 WATCHPOST_COOKIE_SECURE=false \
       WATCHPOST_EXPORT_NDJSON=$PWD/.dev/export/events.ndjson WATCHPOST_PUBLIC_INGEST_URL=http://127.0.0.1:8080
# optional: WATCHPOST_CONSOLE_DIR=$PWD/../console/dist  (console served from disk)
go run . serve &
go run . enroll --name phone --out .dev/phone.watchpost
printf '%s\n' 'console-password' | go run . user set-password admin
go run . sim --enroll .dev/phone.watchpost --backfill 48h --follow
```

Console: <http://127.0.0.1:8080/> (`admin` / `console-password`).

```powershell
cd server\collector
$env:WATCHPOST_DATA_DIR = "$PWD\.dev"; $env:WATCHPOST_LISTEN = '127.0.0.1:8080'; $env:WATCHPOST_COOKIE_SECURE = 'false'
$env:WATCHPOST_EXPORT_NDJSON = "$PWD\.dev\export\events.ndjson"; $env:WATCHPOST_PUBLIC_INGEST_URL = 'http://127.0.0.1:8080'
# terminal 1:
go run . serve
# terminal 2 (same environment variables):
go run . enroll --name phone --out .dev\phone.watchpost
'console-password' | go run . user set-password admin
go run . sim --enroll .dev\phone.watchpost --backfill 48h --follow
```

(untried transcription). The `.dev/` folder is ignored by git. Over local `http://`, the simulator sets the
`X-Watchpost-Client-Cert-Sha256` header itself (accepted because `127.0.0.1` is a trusted proxy by default).

**Attack scenarios, commands and fake AdGuard** (from `server/collector/`, details in its README):

```bash
export WATCHPOST_DATA_DIR=$PWD/.dev WATCHPOST_LISTEN=127.0.0.1:8080 WATCHPOST_COOKIE_SECURE=false \
       WATCHPOST_EXPORT_NDJSON=$PWD/.dev/export/events.ndjson WATCHPOST_PUBLIC_INGEST_URL=http://127.0.0.1:8080 \
       WATCHPOST_ADGUARD_URL=http://127.0.0.1:3001 WATCHPOST_ADGUARD_USER=watchpost WATCHPOST_ADGUARD_PASSWORD=adguard-demo \
       WATCHPOST_ADGUARD_LEVELS_FILE=$PWD/examples/adguard-levels.example.json WATCHPOST_ADGUARD_POLL_S=10 \
       WATCHPOST_DETECT_INTERVAL_S=15
go run . serve &
go run . enroll --name phone --out .dev/phone.watchpost
printf '%s\n' 'console-password' | go run . user set-password admin
go run . sim --enroll .dev/phone.watchpost --backfill 72h --follow --scenario all \
       --fake-adguard 127.0.0.1:3001 --fake-adguard-user watchpost --fake-adguard-password adguard-demo \
       --command-code 'correct horse battery staple'
```

- `--scenario healthy|sms-fraud|banking-trojan|proxy|spam|exfiltration|dns-bypass|stalkerware|silent-sms|all` (several
  separated by commas); `silent-sms` reproduces a store application that is granted `SEND_SMS` 25 to 30 hours after
  installation; `--app-ops=false` simulates the absence of the experimental counters (the scenario then gives a single
  detection, `detect.sms_permission`, never `detect.sms_abuse`).
- `--commands stream|poll|off`, `--poll-interval`, `--command-code`, `--allow-wipe`, `--clock-skew`: the simulated
  command agent (the contract's test passphrase is `correct horse battery staple`, with `device_id`
  `dev_0123456789abcdef` for the test vector).
- Detections appear at the pass that follows the arrival of the data (`WATCHPOST_DETECT_INTERVAL_S`), those that depend
  on AdGuard's log after its polling (`WATCHPOST_ADGUARD_POLL_S`). These commands were not re-run for this guide: they
  are those of the collector's README.

**Developing the console against the real collector** (another terminal, from `server/console/`):

```bash
WATCHPOST_API_TARGET=http://127.0.0.1:8080 npm run dev        # http://localhost:5173
```

**Console alone, with a mock server**: `npm run mock` (http://127.0.0.1:8787, `admin` / `watchpost`) then
`npm run dev`. The mock server generates seven days of telemetry and accepts `POST /__mock/control` (failures, expired
session, latency).

**Checking the agent against the real collector, without a phone.** Three cross tests of the `:app` module, ignored as
long as their variables are not set (instructions in the header of each file; commands not run for this guide):
`CrossServerTest` (the agent's real buffer and real upload, with the typical collector events),
`CrossCommandsTest` (the command channel: commands created through the console API with a `payload` and a signature
built like the console does, delivered by the real SSE stream and then by polling, verified by the real verifier;
variables `WATCHPOST_CROSS_ENROLL`, `WATCHPOST_CROSS_URL`, `WATCHPOST_CROSS_CONSOLE_USER`,
`WATCHPOST_CROSS_CONSOLE_PASSWORD`, and `WATCHPOST_CROSS_TS_*` / `WATCHPOST_CROSS_REDELIVERY_*` for the cases signed by
the console's passphrase and the resend after 5 minutes) and `CrossDetectionsTest` (the real code of the `app_risk`,
`app_role` and `app_ops` collectors tells an SMS fraud to the real collector). Example for the first one, against the
collector launched above:

```bash
cd android
WATCHPOST_CROSS_ENROLL=$PWD/../server/collector/.dev/phone.watchpost WATCHPOST_CROSS_URL=http://127.0.0.1:8080 \
  ./gradlew :app:testDebugUnitTest --tests '*CrossServerTest*' --rerun
```

**Full Docker stack locally** (Caddy, Wazuh, AdGuard): possible with
`sudo ./install.sh --domain watchpost.lan --tls internal` (Caddy's internal CA; you must then trust
`infra/data/caddy/server-root-ca.crt`, resolve the names to the machine, and have 8 GB of free RAM). This is the mode
of the trials documented in `infra/README.md` §11. There is **no documented step-by-step** for plugging the simulator
into it through Caddy in mTLS; the trial installation is described in `infra/README.md` §11.1 and §11.2 (simulator in a
container of the `watchpost` network), and this is work to be tidied up if you need it.

## 6. Working loop with feedback from the device

1. Do the first trial week with [guide 06](06-on-device-checks.md) and note every discrepancy (report template).
2. Turn each report (identifier V…, exact text, version, traces) into a reproduction, by a **test** when possible: the
   contract (`Contract`) and the test bench (`CollectorHarness`) serve that purpose.
3. A change to an event's format starts with `docs/contract/contract.md`, then the Wazuh rules
   (`infra/wazuh/rules/` and their test cases), then the collector, then the console, then the agent.
4. Update `docs/STATUS.md` (what is now verified on a device) and, for the user documentation, the root README
   (verification status table) and the guides concerned.

## 7. Known gaps

- **Unenrolling** always erases key, token and pending events (intended, announced by the application): only "Import a
  new .watchpost file" keeps the buffer.
- **Alert notifications**: optional and off by default; SMTP with TLS and authentication, and a real ntfy server, are
  not tested (`infra/README.md` §8.5). Device certificate expiries are not notified. The level-8 alerts (SMS
  permission granted, new default SMS app) are not sent at the default threshold (10).
- **Not verified on a device, by construction**: the whole command channel (`wipe` included), the guards and the
  quarantine, the `app.ops` counters (format never observed on a Samsung), the companion and Play Protect,
  `pm unhide`/`pm unsuspend` from the ADB shell (probably refused), the private DNS fallback with a non-affiliated
  user, a real `400` response (bisection); see [guide 06](06-on-device-checks.md).

## 8. Leads already identified

| Lead | Where it is described |
|---|---|
| **Per-application local VPN** (NetGuard/RethinkDNS style): attribution of **all** flows, UDP and hard-coded IPs included (`ConnectivityManager.getConnectionOwnerUid`). Only one VPN is active on Android, incompatible with WireGuard | `docs/ARCHITECTURE.md` ("no local VPN"), platform research §3.5 and §8 |
| **Unlock code (or authentication) before weakening a guard** or releasing a quarantine: today Watchpost's screen does not ask for it, and an accessibility service that is already enabled can tap there | `android/README.md`, "What the guards cannot prevent" |
| **System-enforced SMS rate limit** (capping SMS sending rather than only counting it, since SMS do not travel over the IP network) | not studied in the repository's documents; the current counting (`app.ops`) is experimental |
| **Notification companion exclusion lists editable in the agent** (today edited in the companion and stored in the agent's settings, which has no editable "list" setting type in its own screen) | `android/README.md`, "Notifications (companion APK) › Configuring" |
| **Knox SDK**, to be reconsidered only if a licence key is obtained (per-app firewall, Knox audit log) | platform research §8 |
| **Self-hosted map tiles** (tileserver-gl, PMTiles file) | `infra/README.md` §10.2 |
| **Camera/microphone attribution through `DUMP`**: promote the experimental setting if trials validate it | `android/README.md` (Camera and Microphone collectors), research §4 and §6 |
| **Additional DPM policies**: `setMtePolicy`, `setSystemUpdatePolicy`, `setAppFunctionsPolicy`, `setNearbyAppStreamingPolicy`, `setContentProtectionPolicy` | research §3.10 |
| **GNSS jamming or spoofing detection** (`GnssStatus`, raw measurements) and exposure of the XTRA/SUPL trade-off in the interface | research §5 |
| **Collection before the first unlock** (Direct Boot) | `android/README.md` ("How it works") |
| **Developer verification**: register the signing key ("limited distribution" account) or go through silent updates via the Device Owner | research §9 |
| **A lighter alternative to Wazuh** (less than 4 GB of RAM) | `docs/research/server-siem-dns.md` §9 |
| WireGuard (already present as an option, not tested), ClientID mode (already present, wildcard not tested) | `infra/README.md` §6.3 and §10.1 |

Leads that do not come from the design documents but stand out from this work: test the alert notifications with a
real ntfy server and an authenticated SMTP relay; sign the sensitive commands from a copy of the console kept off the
server (`server/console/README.md`, "What signing in the browser guarantees").
