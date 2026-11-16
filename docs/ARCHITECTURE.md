# Watchpost architecture

Watchpost is a self-hosted security-telemetry and anti-tracking toolchain for a personal Android phone. It
targets Android 16 and later (`minSdk 36`) on recent Samsung Galaxy devices running One UI 8 or 9, with the
stock ROM and no root. An app installed on the phone, the Watchpost Agent, observes what the phone does and
sends it to a server that its user administers; the user chooses the local policy, and the server can send the
phone only a small closed list of commands.

## Design decisions

| Subject | Decision |
|---|---|
| Administration mode | **Device Owner**, activated through ADB after temporarily removing the accounts. The agent runs in a degraded mode until that is done. |
| Server | A VPS or dedicated machine with **8 GB of RAM or more**, a public IP address, Docker Compose. |
| SIEM/XDR | **Wazuh**, single node (manager + indexer + dashboard). |
| Default de-Googling | **Balanced** profile: Google Play Services, the Play Store, FCM push and banking apps keep working. A strict profile is available. |
| APK build | Local build, with Gradle and the Android SDK, on the user's own machine. |

## Non-negotiable principles

1. **No stealth.** The agent shows a permanent notification, keeps its launcher icon, and its home screen shows
   what is collected. There is no hiding function. This is not a tool for monitoring other people.
2. **The server decides nothing important.** The phone pushes its events to the server. In the other direction,
   the server can send only **commands from a closed list** (ring, vibrate, locate, lock with a message, erase),
   never configuration or policy: all policy (DNS, disabled packages, restrictions) is set in the app, locally.
   The sensitive commands (lock, erase) carry a signature computed in the user's browser from a **passphrase the
   server does not know**: a compromised server can at worst make the phone ring or ask it for its position
   (and, if it obtains the passphrase, lock or erase it, see contract §8). Remote erase is also off by default
   in the app. The command channel can be turned off with a switch.
3. **Zero Google dependency in the agent**: no Play Services, Firebase or ML Kit. Location uses
   `LocationManager`, GPS only by default; the "network" and "fused" providers (which go through Google Play
   Services) are an explicit setting, and the app says what then goes to Google.
4. **Third parties' private content reduced to the minimum**: no SMS content, no call log, no keystrokes, no
   screenshots, no accessibility service. Notification reading lives in a **separate, optional companion
   APK** (never in the Device Owner APK); title and text are collected only if the user turns that on, with
   masking of numeric codes and a list of excluded apps.
5. **Every collector can be turned off** individually in the app.
6. **Everything the agent changes is reversible** (disabled packages, restrictions, DNS) from the app, and a
   procedure to remove the Device Owner entirely is documented.

## Overview

```
 Samsung Galaxy phone                           Server (Docker Compose)
┌───────────────────────────┐               ┌────────────────────────────────────────────┐
│ Watchpost Agent           │  HTTPS mTLS   │ Caddy (TLS, mTLS on ingest.*)              │
│ (Device Owner)            │──────────────►│   └► watchpost-collector (Go, SQLite)      │
│  collectors ─► buffer     │  gzip batches │         ├► web console (map, tables)       │
│  (Room/SQLite) ─► upload  │               │         └► events.ndjson ─► Wazuh manager  │
│                           │               │ Wazuh indexer + dashboard (SIEM/XDR)       │
│ local policy:             │  DoT :853     │ AdGuard Home (filtering DNS, DoT)          │
│  enforced private DNS,    │──────────────►│   └► query log ─► Wazuh                    │
│  disabled packages,       │               │ (optional) WireGuard                       │
│  restrictions, guards     │               │                                            │
└───────────────────────────┘               └────────────────────────────────────────────┘
```

## Components and directories

| Directory | Component | Technology |
|---|---|---|
| `android/` | **Watchpost Agent**: Device Owner app, collectors, offline buffer, upload, privacy/security policy; **Watchpost Notifications**: optional companion APK (`:notifier`) | Kotlin, Gradle, Room, WorkManager, OkHttp. Package `io.github.erwsim.watchpost` |
| `server/collector/` | **watchpost-collector**: ingestion API, storage, console API, NDJSON export to Wazuh, enrollment CLI, simulator | Go, SQLite (pure Go) |
| `server/console/` | **Web console**: map of positions, timeline, per-app network, inventory, posture, Tracking page, remote commands, detections, alerts | TypeScript, React, Vite, MapLibre |
| `infra/` | Deployment: `docker-compose.yml`, Caddy, AdGuard Home, Wazuh (Watchpost rules and decoders), PKI, installation script, optional WireGuard | Docker Compose, shell |
| `docs/` | Architecture, contract, research, installation and operations guides | Markdown (English) |

## Android agent

- A permanent **foreground service** (started at boot) hosts the "real-time" collectors (location, screen,
  connectivity, sensors); **WorkManager** runs the periodic collections (inventory, posture, network usage)
  and the upload.
- **Collectors**: a common `Collector` interface (id, required permissions/capabilities, `start/stop` or
  `collectOnce`), each in its own file and enabled by a setting. A collector whose capability is missing (not
  Device Owner, permission absent) declares itself "unavailable" without crashing.
- **Offline buffer**: Room table `outbox`; every event receives a unique identifier and a sequence number. The cap
  is configurable (default 200 MB / 30 days); on overflow, the oldest events of lowest severity are purged first
  and `agent.buffer_overflow` is emitted.
- **Upload**: gzip batches over HTTPS with a client certificate (key in the Android Keystore) plus a device
  token; idempotent (the server deduplicates on `id`); local deletion only after acknowledgement; retry with
  exponential backoff; option "large volumes on Wi-Fi only".
- **Local policy (Device Owner)**: enforced private DNS towards the AdGuard server, profiles for disabling
  Google/Samsung packages (balanced / strict), permission denials for apps, security user restrictions, network
  and security logging, and optional capability guards (SMS, calls, accessibility, keyboards, quarantine of new
  apps). Every action is logged (`security.policy`).
- **Enrollment**: import of a `.watchpost` file produced by the server (URL, device identifier, token, PKCS#12
  client certificate, private DNS host).
- **Remote commands**: a closed list received over a channel that is off by default; sensitive commands are
  verified against a signature before they run (contract §8).

### Decisions from the platform research (`docs/research/android-platform.md`)

- Target: Android 16/17 (One UI 8/9), `minSdk 36`. Device Owner activation through ADB only.
- The main APK (Device Owner) contains **no** notification-listener service (it lives in the companion APK
  `:notifier`), **no** accessibility service, **no** SMS permissions and **no** overlay (Play Protect triggers).
  No Knox SDK.
- Device Owner network logs = DNS + TCP `connect()` per app, delivered in batches (about 1 h 30); UDP/QUIC
  escape them. They are complemented on the server side by the AdGuard log (all DNS, live) and by per-app
  volumes (`NetworkStatsManager`). **No local VPN** (complexity, battery, conflict with WireGuard): a possible
  later addition.
- Location: GPS + passive provider by default; "GPS + network" and "fused" modes are the user's choice (they go
  through Play Services).
- Package disabling: an embedded deny list (never `kgclient`, OTA packages, `rkpdapp`, the launcher, the dialer,
  the Play Store in the balanced profile…) because `setApplicationHidden` has no safeguard of its own.
- Never `DISALLOW_DEBUGGING_FEATURES` and never cutting USB signalling: ADB remains the escape hatch.
- A `testOnly` build variant by default so that the Device Owner can be removed through ADB
  (`dpm remove-active-admin`); the app can also undo everything and then call `clearDeviceOwnerApp`.

## Server

- **watchpost-collector** validates (mTLS verified by Caddy + token), deduplicates, stores in SQLite, feeds the
  console, and writes every event into an NDJSON file read by the Wazuh manager (`<localfile>` JSON).
- **Wazuh** applies the Watchpost rules (`infra/wazuh/`) and raises alerts; all events are also archived.
- **AdGuard Home** serves the phone's private DNS over DoT with blocking lists (Google/Samsung telemetry,
  advertising, trackers); its query log also goes to Wazuh. The collector can read it and change the blocking
  level (Tracking page).
- **Console** protected by local authentication; enrollment and revocation of devices are done only on the
  command line on the server.

## Contract

The event format and the APIs are defined in [`docs/contract/contract.md`](contract/contract.md). It is the common
reference: every change is made in that file first.
