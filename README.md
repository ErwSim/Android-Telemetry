# Watchpost

Watchpost is a self-hosted security-telemetry and anti-tracking toolchain for a **personal Android phone** (Android
16 or later, developed against Samsung One UI 8/9, stock ROM, no root). An application installed on the phone, the
**Watchpost Agent**, observes what the phone does (positions, network, applications, sensors, security posture),
sends these observations to a server that you administer, applies locally an anti-tracking and anti-malware policy
that you choose, and receives from that same server a small number of commands from a closed list (ring, locate,
lock, erase) that you enable yourself.

## What Watchpost is, and what it is not

- It is a **personal** tool, installed by you, on **your** phone, that makes visible what the phone really does.
- It is **not a tool for monitoring other people** and it is **not stealthy**: the agent shows a permanent
  notification and keeps its icon, the application's home screen shows what is collected, every command received from
  the server is shown as a notification, and Android itself displays the "device managed" notice once Device Owner
  mode is active. There is no hiding function and there will not be one.
- **Principle on what the server can do to the phone**: the server decides nothing important. The phone pushes its
  events; in the other direction, the server can transmit only **commands from a closed list** (ring, vibrate, stop
  ringing, locate, lock with a message, clear that message, erase), **never** configuration, policy or a change of
  enrollment: all policy is set in the application, on the phone. The sensitive commands (lock, erase) carry a
  signature computed in your browser from a **command passphrase** that the server does not know; the command channel
  is **off by default** and remote erase is **forbidden by default**, to be allowed separately.
- **This protection has limits, stated plainly** (contract §8): it is worth something only with a high-entropy
  passphrase (five randomly drawn words, reserved for this use); the page where you type the passphrase is served by
  the server, so a compromised server can read it the next time you type it; a signed command remains executable
  until it expires whatever the console says ("cancelled" or "expired" binds only the server); only changing the
  passphrase on the phone invalidates a command that was already signed. A compromised server **can** therefore make
  the phone ring, locate it, and, if it obtains your passphrase, lock or erase it (if you allowed erasing).
- No Google dependency in the agent (no Play Services, no Firebase). No SMS content, no call log, no keystrokes, no
  screenshots, no accessibility service in the agent. Notification reading lives in a **separate, optional companion
  APK**; title and text are collected only if you turn that on.

## What Watchpost does today (versions 1, 1.1 and 1.2)

| Version | Content |
|---|---|
| **1** | collectors, offline buffer, upload over mTLS, filtering private DNS (AdGuard Home), SIEM (Wazuh), web console, anti-tracking policy (balanced and strict profiles), ADB rescue |
| **1.1** | **remote commands**; **Tracking** page of the console (blocked or allowed per publisher, domain and application; block or allow a domain; permissive, balanced, strict levels); **notification companion APK**; **location modes** (GPS only by default, "GPS + network", "Fused", with what then goes to Google); alert notifications by webhook or e-mail; renewal of a device without losing its history |
| **1.2** | protection against malware that sends SMS in bulk without the messaging app showing anything, and more generally against malware whatever its vector: **capability guards** (SMS, calls, accessibility, keyboards, quarantine of new applications); **risk profile** of applications; tracking of **default applications** (SMS, dialer, keyboard…); **experimental** counting of sensitive operations; **server-side detections** and the Detections page of the console; the corresponding Wazuh rules and correlations |

## Overview

```
 Samsung Galaxy phone                          Server (Docker Compose, 8 GB of RAM or more)
┌───────────────────────────┐               ┌────────────────────────────────────────────┐
│ Watchpost Agent           │  HTTPS mTLS   │ Caddy (TLS; client certificate required on │
│ (Device Owner)            │──────────────►│ ingest.*)                                  │
│  collectors ─► buffer     │  gzip batches │   └► watchpost-collector (Go, SQLite)      │
│  (Room/SQLite) ─► upload  │               │         ├► web console (map, tracking,     │
│                           │◄──────────────│         │   detections, commands)          │
│  commands (closed list,   │  command      │         └► events.ndjson ─► Wazuh manager  │
│  channel off by default)  │  stream       │ Wazuh indexer + dashboard (alerts, SIEM)   │
│ local policy:             │               │   └► notifications (webhook, e-mail)       │
│  enforced private DNS,    │  DNS over TLS │ AdGuard Home (filtering DNS, DoT)          │
│  disabled applications,   │  port 853     │   └► query log ─► Wazuh                    │
│  restrictions, guards     │──────────────►│                                            │
│ Watchpost Notifications   │               │                                            │
│  (companion APK, optional)│               │                                            │
└───────────────────────────┘               └────────────────────────────────────────────┘
```

Paths between the phone and the server: the **ingestion** of events and the **command stream** (HTTPS with a client
certificate; the phone opens the connection in both directions), the **private DNS** (DNS over TLS to AdGuard Home,
which blocks tracking domains and logs), and the **console** (which you open in a browser).

## What Watchpost collects

25 collectors, each of which can be turned off in the application (Collectors tab):

- **Location**: GPS and passive provider by default. Two other modes are an explicit choice: "GPS + network" and
  "Fused" go through Google Play services, and the application says, for each mode, what then goes to Google.
- **Network**: connectivity, Wi-Fi (SSID and BSSID), cell, Bluetooth, NFC, hotspot, Bluetooth trackers (AirTag,
  SmartTag, Tile), 2G downgrade, data volumes per application.
- **Applications**: daily inventory, installations, updates, removals, permissions, special access (accessibility,
  administrator, overlay, VPN), foreground application, **risk profile**, **default applications**, and, on an
  experimental basis, **usage of sensitive operations** (SMS sending, calls, microphone, camera…).
- **Device**: screen, battery, storage, USB, boot and shutdown.
- **Sensors**: camera and microphone use (the fact, the time, the screen state; never the content).
- **Notifications** (with the companion APK only): the application, the category, the importance; the title and text
  only if you turn that on, with masking of 4 to 8 digit codes and a list of excluded applications (SMS, phone,
  common banks, authenticators, password managers).
- **Device Owner mode only**: the system network log (DNS requests and TCP connections per application), the system
  security log (ADB, unlocks, certificates, package installations…), the security posture (encryption, verified boot,
  ADB, added certificate authorities…).

Details are in [`android/README.md`](android/README.md) ("Collectors" table) and the exact event format in
[`docs/contract/contract.md`](docs/contract/contract.md).

## What Watchpost blocks or changes

Nothing is applied automatically: you choose in the application's **Policy** screen, read the preview, then apply.
Every action is logged and reversible ("Restore everything", removal of the Device Owner, ADB rescue).

- **Enforced private DNS** towards your AdGuard Home: blocking lists (Google and Samsung telemetry, advertising,
  trackers, malicious domains) and a query log. Three levels, changeable from the console.
- **Samsung, Google and Meta telemetry, advertising or diagnostic applications** hidden or suspended (**balanced**
  profile, the default: Google Play services, the Play Store, push notifications and banking applications keep
  working). The **strict** profile adds a thorough de-Googling and de-Samsungising that deliberately breaks functions.
- A few **denied permissions** for Google or Samsung applications, and **security restrictions** (2G, unknown sources,
  adding certificates…).
- **Capability guards** (off by default, one by one): deny `SEND_SMS` or `CALL_PHONE` to every application except a
  list, allow only approved accessibility services and keyboards, **quarantine** every new application (risky
  permissions denied until you release it).

## What Watchpost cannot do (real limits)

- **Against software that sends SMS without your knowledge**, the real protection is the **SMS guard**, which you must
  enable; detecting the sending itself relies on **experimental** counters that have **never been seen working**. An
  application that gets itself designated default SMS app is not blocked, only flagged. Read
  [guide 08](docs/guides/08-sms-and-malware.md) before believing yourself protected.
- The **detections** and the **risk profile** are **hints**, not verdicts: the score measures *declared*
  capabilities, so a parental control, an antivirus or an automation application comes out "high", and a discreet
  piece of malware published on a store can come out "low". "Nothing to report" is not a guarantee.
- **No reliable attribution of the camera and the microphone to an application**: Android does not give the package
  to ordinary applications. Watchpost knows *that* they are used, not always *by whom* (an experimental attribution
  exists, off by default, never tested).
- **The system network log sees only DNS and TCP connections** going through the system library. UDP/QUIC traffic,
  hard-coded IP addresses and an application's own encrypted DNS escape it. It is delivered in batches, up to 1 h 30
  late. AdGuard's log (all the phone's DNS, live) and the per-application volumes complete the picture. The bytes
  per publisher of the Tracking page are **estimates**.
- **Google Play services telemetry cannot be filtered by DNS without breaking the Play Store**: part of it goes
  through shared domains (`play.googleapis.com`, `www.googleapis.com`). Only the strict profile (disabling Google
  Play services) removes it, at the price of push notifications, most banking applications and the Play Store.
- **The guards have blind spots**: system applications or the default SMS app/dialer are never touched, an
  accessibility service that is already enabled (it can switch the guards off), a few seconds to 15 minutes before a
  new application is quarantined, frozen permission groups, applications of another user or profile.
- **The notification companion** reads only what Android hands it; the exclusion list is a list of package names and
  therefore necessarily incomplete; Play Protect's reaction to its installation is unknown.
- **Nothing is collected between a reboot and the first unlock** (Direct Boot is not used); the ADB rescue does not
  answer before then either.
- **Device Owner mode has side effects** on a Samsung: Dual Messenger, private space and work profile become
  impossible (and Secure Folder very probably too), Android backup is turned off (the balanced profile turns it back
  on), Android displays "device managed" and a network-monitoring notification. See [guide 03](docs/guides/03-phone.md).
- Wazuh triggers **only one rule per event**, and a defect **already present at enrollment** produces no alert: read
  the initial posture in the console. Alert notifications (webhook, e-mail) are off until you configure them.

## Verification status

Stated plainly: **nothing that touches the phone has ever been run on a real device**, including everything that
versions 1.1 and 1.2 add. [Guide 06](docs/guides/06-on-device-checks.md) is the roadmap for the first week of trial.

| Item | Tested by execution | Never tested on a device | Not tested at all |
|---|---|---|---|
| Go collector (ingestion, storage, API, Wazuh export, device renewal, commands, tracking, detections) | `go vet`, `go test -race`, real runs with the simulator and its attack scenarios, Docker image built and run, security reviews; renewal and command stream through Caddy in mTLS | — | — |
| Web console (including Commands, Tracking, Detections, Risk) | typing, lint, Vitest tests, Chromium walkthroughs against a mock server **and** against the real collector (eight detection types, healthy fleet) | — | real OpenStreetMap tiles; rendering of the Wazuh "detections and apps" dashboard in a browser |
| Server stack (Docker Compose, internal TLS mode) | complete and replayed installation, mTLS, DNS over TLS, real AdGuard Home (blocking, levels, rules written by the console), export to Wazuh without loss, 210 Wazuh rule cases, preservation of user settings, renewal of the Wazuh certificates, webhook and e-mail notifications (local receiver), backup then restore | — | real Let's Encrypt, DNS-01 challenge (ClientID mode), real HaGeZi lists over the Internet (tested through a fake CDN), Multi PRO lists, upstream resolution through Quad9, WireGuard, memory with the lists loaded, ARM, SMTP with TLS and authentication, real ntfy, `update.sh` |
| Android agent: code | compilation, lint, 392 JVM tests (last count in `android/README.md`), conformance of the collectors to the contract, cross tests of the real upload, command and detection code against the real collector, signed release and companion APKs (same key) inspected | — | — |
| Android agent: behaviour | — | **everything**: Device Owner on a Galaxy phone, 24 h service, Keystore and client TLS, real logs, GPS, battery, interface, policy, private DNS and fallback, ADB rescue, command channel (ring, locate, lock, **erase**), guards and quarantine, default roles, `app.ops` counters, location modes, companion and Play Protect | Robolectric (not used), instrumented tests |
| ADB bash scripts (`android/scripts/*.sh`, including the companion's) | syntax, review, run against a fake `adb` | run on a phone | — |
| PowerShell scripts (`android/scripts/*.ps1`) | checked line by line against the `.sh` ones | — | neither run nor analysed by PowerShell |
| These guides | commands checked against the scripts and the code; `apksigner` and `aapt2` run on the built APKs (agent and companion) | — | no guide has been followed end to end by a person |

Sources: [`docs/STATUS.md`](docs/STATUS.md), `infra/README.md` §11, `android/README.md` (last section).

## The guides

To be followed in order for a first installation:

1. [Install the server](docs/guides/01-server.md): VPS, DNS, installation, firewall, first access, backups.
2. [Build the APK](docs/guides/02-build-apk.md): Windows or Linux/macOS, keystore (to be kept!), verification.
3. [Prepare and configure the phone](docs/guides/03-phone.md): Device Owner, permissions, enrollment, then
   **gradual** commissioning of the policy. The critical guide.
4. [Rollback](docs/guides/04-rollback.md): undoing everything, from the gentlest to the most radical. Keep it open
   during guide 03.
5. [Operations](docs/guides/05-operations.md): console, Wazuh alerts, AdGuard, updates, renewals.
6. [Checks to run on the device](docs/guides/06-on-device-checks.md): everything that has never been verified, ordered
   by risk.
7. [Development](docs/guides/07-development.md): clone, build, test, run the server locally with the simulator,
   further leads.
8. [Am I protected against software that sends SMS without my knowledge?](docs/guides/08-sms-and-malware.md): what
   prevents it, the blind spot, what detects it, what has never been seen working.

## The three essential warnings

1. **Keep the signing keystore, encrypted and off the computer.** Android accepts an update only if it is signed with
   the same key; for a Device Owner application, there is no workaround, and the notification companion must be
   signed with the same key as the agent (guide 02).
2. **You activate the Device Owner on your everyday phone, with no prior test on another device.** Keep USB debugging
   on, a PC at hand and [guide 04](docs/guides/04-rollback.md) open; apply the policy in stages, never all at once
   (guide 03). None of the "irreversible" functions (remote erase) is enabled before having been tried on a
   sacrificial or fully backed-up device.
3. **An enforced private DNS whose server goes down cuts Internet on the phone.** This is intended (no cleartext
   leak), but test it first with the DNS lock off (it is off by default), on Wi-Fi, at home, and run `rescue-revert`
   empty before any policy: the rescue answers only after the first unlock that follows a reboot (guides 03 and 04).

## Repository layout

```
watchpost/
├── README.md                    this file
├── CLAUDE.md                    guidelines for contributors (read first to develop)
├── docs/
│   ├── ARCHITECTURE.md          decisions, non-negotiable principles, components
│   ├── STATUS.md                status and verification state (resume file)
│   ├── contract/contract.md     event format and APIs: the common reference
│   ├── research/                research notes (Android/Samsung platform, SIEM/DNS server)
│   └── guides/                  the guides above
├── android/                     Watchpost Agent (Kotlin); README.md, ARCHITECTURE-CODE.md
│   ├── core/  collectors/  policy/  app/  notifier/    Gradle modules (notifier = companion APK)
│   └── scripts/                 ADB scripts in pairs (.sh and .ps1)
├── server/
│   ├── collector/               Go collector (ingestion, API, Wazuh export, CLI, simulator)
│   └── console/                 web console (React, Vite)
└── infra/                       Docker Compose, Caddy, AdGuard Home, Wazuh, installation scripts; README.md
```

Secrets (`.env`, `.watchpost`, `.p12`, keystore, passwords) are generated locally and are never versioned.
