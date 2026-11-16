# Watchpost Agent (Android)

Security-telemetry agent that the user installs on their **own** phone (target: Android 16/17, Samsung One UI
8/9, not rooted), promoted to **Device Owner** over ADB. It collects events, keeps them in an offline buffer and
uploads them in batches (HTTPS + client certificate) to the enrolled Watchpost collector.

Principles (see `../docs/ARCHITECTURE.md`): permanent notification and visible icon, nothing sent anywhere
except the enrolled address, the server can only send commands from a closed list (ring, vibrate, locate,
lock, erase; the sensitive ones signed with a passphrase it does not know, channel off by default), no Google
dependency (no Play Services, Firebase or ML Kit; the "network" and "fused" location modes go through Google
Play services only when you explicitly choose them), no private third-party content, every collector can be
disabled, everything is reversible.

Developers (adding collectors, Device Owner module): read **`ARCHITECTURE-CODE.md`**.

## Contents of this version

"Tested" here means: JVM tests. **Nothing has been run on a phone or on an emulator** (see the last section).

| Item | Status |
|---|---|
| Room buffer (transactional `seq`, cap 200 MiB / 30 days, "oldest of lowest severity" purge + `agent.buffer_overflow`); age purge protected against a wall-clock jump (`AgeHorizon`) | done, tested (JVM) |
| Origin timestamp of events read after the fact (`app.foreground`, `net.dns`, `net.connect`, `security.log`) | done, tested |
| Upload: batches ≤ 500 events and ≤ 1 MiB gzip, deletion after acknowledgement, 400 (poisoned batch: bisection) / 401 / 413 / 429 / 5xx, `Retry-After`, jittered backoff, "large volumes on Wi-Fi only", resume when the network returns | done, tested (MockWebServer); **never exercised on a device nor against a real server returning 400** |
| `.watchpost` enrollment: key in the Android Keystore, encrypted token, mTLS, server CA pinning, `GET /api/v1/ping` test, unenrollment | done; parsing and mTLS tested, Android Keystore **not tested** |
| Foreground service (`specialUse` + `location`), start at boot and after an update, restart (sticky + 15 min maintenance), `agent.started/stopped/heartbeat/collector_error/config_changed` | done, not tested on a device |
| 25 collectors: 22 without privilege (`:collectors`, including `notifications`, which depends on the companion APK, and `app_risk`, `app_role`, `app_ops` of contract §11.2) and 3 Device Owner ones (`:policy`), see "Collectors" | done; logic and contract conformance tested, real behavior not tested |
| Remote commands (contract §8): full verification (HMAC signature, anti-replay, expiry, lockout), SSE channel or polling, ring / vibrate / locate / lock + message / erase, "Remote commands" screen | done; verification, channel (MockWebServer) and wipe safeguards tested (JVM); **never run on a device**, consumption **not measured** |
| Location modes (contract §10): GPS only (default), GPS + network, fused, with fallback | done; logic tested, real providers not tested |
| Device Owner: admin receiver, permission self-grant and force-stop protection (with `security.policy`), `agent.tamper`, voluntary removal without false alert | done; logic tested, not tested on a device |
| Device Owner policy: profiles, enforced Private DNS and fallback, packages, permissions, restrictions, settings, always-on VPN, "Restore everything", Device Owner removal, ADB rescue | done; engine tested against a fake gateway, not tested on a device |
| Capability guards (contract §11.1): SMS, calls, accessibility, keyboards, quarantine of new apps, editable exception lists ("package list" setting), "Quarantined apps" screen, notifications | done; tested against the fake gateway (including crash, unreadable state, "Restore everything" after the 32 combinations); **never run on a device** |
| Material 3 interface (Home, Collectors with per-collector settings, Local event log, Settings, Enrollment, Policy) | done, not tested on a device |

## Versions and tooling

| Item | Version | Note |
|---|---|---|
| Gradle (wrapper) | 9.9.1 | `gradle/wrapper/` is versioned |
| Android Gradle Plugin | 9.5.1 | Kotlin built into AGP (no `kotlin-android` plugin applied) |
| Kotlin | 2.4.21 | KSP 2.3.14 (Room) |
| `compileSdk` / `targetSdk` / `minSdk` | 37 / 37 / 36 | SDK platform `android-37.0`, build-tools 36.0.0 |
| JDK | 17 minimum (verified with 21) | |
| Libraries | Room 2.8.5, WorkManager 2.12.0, OkHttp 5.5.1, kotlinx-serialization 1.13.0, coroutines 1.11.0, Compose BOM 2026.09.00 (Material 3) | AndroidX only on the Google side |

## Building

Prerequisites: JDK 17+, Android SDK (`ANDROID_HOME`, or `sdk.dir=` in `android/local.properties`) with
`platforms;android-37.0` and `build-tools;36.0.0` (AGP downloads them if the licenses are accepted).

```bash
cd android
./gradlew assembleDebug                 # Windows: .\gradlew.bat assembleDebug
./gradlew lint test                     # checks (Android lint + JVM tests)
```

### Signing the release build (once, then keep it)

```bash
./scripts/generate-keystore.sh          # Windows: .\scripts\generate-keystore.ps1
./gradlew assembleRelease               # → app/build/outputs/apk/release/app-release.apk
```

The script creates `android/keystore/watchpost-release.jks` and `android/keystore.properties` (both ignored by
git). You can also provide `WATCHPOST_KEYSTORE_FILE`, `WATCHPOST_KEYSTORE_PASSWORD`, `WATCHPOST_KEY_ALIAS`,
`WATCHPOST_KEY_PASSWORD` in the environment (the script itself reads `WATCHPOST_KEYSTORE_PASSWORD` as the
password to use instead of a random one). Without a key, `assembleRelease` produces an **unsigned** APK.

> **Back up the key (encrypted, off the computer).** Android only accepts an update signed by the same key.
> For a Device Owner there is no workaround: without the original key, you have to remove the Device Owner (or
> factory-reset the phone) before installing a build signed differently. The APK is signed with scheme v3
> (enough for Android 9+, and it allows a future key rotation).

### Build parameters

| Parameter | Default | Role |
|---|---|---|
| `-Pwatchpost.testOnly=true\|false` | `true` | `android:testOnly`. Requires `adb install -t` (the scripts do it). `true` keeps a last resort if the app no longer starts: `adb shell dpm remove-active-admin` (see "Removing the Device Owner"). `false`: only Watchpost (Policy screen or ADB rescue) can remove the role, or a factory reset. |
| `-Pwatchpost.versionCode=N` | `1` | Must be **increased** at every update. |
| `-Pwatchpost.versionName=x.y.z` | `0.1.0` | Displayed and sent version (`agent_version`). |

## Installing and enabling

All the scripts are in `android/scripts/`, in two parallel sets: `*.sh` (Linux/macOS) and `*.ps1` (Windows
PowerShell). The `.ps1` files are not signed: Windows refuses them with its default execution policy.
Launch them like this, without changing anything in the machine's configuration (the exception only applies
to that process): `powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\install-apk.ps1 [options]`.
A file path passed to a script (`install-apk`, `push-enrollment`) is relative to the directory you launch it
from. The scripts need `adb` (Android SDK Platform-Tools) in the `PATH` and a phone with USB debugging.
With several devices connected: `export ANDROID_SERIAL=…` / `$env:ANDROID_SERIAL = '…'`. The scripts that ask
for confirmation expect a typed `yes` or `no`.

1. **Prepare the phone**: Developer options › USB debugging; temporarily turn off Samsung's "Auto Blocker",
   which blocks USB commands.
2. **Install**: `./scripts/install-apk.sh [app.apk]` (`adb install -r -t`).
3. **Enable the Device Owner**: `./scripts/enable-device-owner.sh`. The script checks that no other owner
   exists, that there is a single user (no Secure Folder, Dual Messenger, Private Space, work profile, guest) and
   **no account**: Android refuses otherwise. Temporarily remove the accounts (Google, Samsung, messengers…),
   enable, then add them back: the Device Owner does not forbid them. Known effects of Device Owner mode:
   Android backup turned off (can be turned back on), Secure Folder, Dual Messenger and Private Space
   unavailable, "managed device" mention.
4. **Open Watchpost**: as Device Owner, the app grants itself its runtime permissions (location,
   notifications, Bluetooth, phone…) and turns on force-stop protection (each action emits
   `security.policy`). Each permission is auto-granted only **once** per Device Owner activation:
   if you remove one afterwards in Settings, Watchpost does not take it back by itself (the collector
   becomes "unavailable", `agent.tamper` `permission_revoked` is emitted, the Collectors tab offers to
   grant it again). Without Device Owner (degraded mode), grant the permissions from the Collectors tab. In
   both cases, `./scripts/grant-adb-permissions.sh` also grants those that can only be obtained over ADB:
   usage access (`PACKAGE_USAGE_STATS` + app-op: `net_usage`, `foreground`), `WRITE_SECURE_SETTINGS` (the
   policy's anti-tracking setting), `DUMP` (experimental camera/microphone attribution, off by default). In
   degraded mode it also grants the runtime permissions (`BLUETOOTH_SCAN`, `BLUETOOTH_CONNECT`,
   `READ_PHONE_STATE`, location…).
5. **Battery**: `./scripts/battery-exemptions.sh`, then by hand on Samsung: Settings › Battery ›
   Background usage limits › Never sleeping apps › Watchpost.
6. **Turn Auto Blocker back on** if you wish (its interaction with a third-party Device Owner has not been
   verified, see the platform research).

## Enrolling

1. On the server: `sudo ./enroll.sh phone` from `infra/` (Docker Compose installation, produces
   `./phone.watchpost`); with the collector running on its own:
   `watchpost-collector enroll --name phone --out phone.watchpost`.
2. Copy it over the cable: `./scripts/push-enrollment.sh path/to/phone.watchpost` (→ `Download`; the path is
   relative to the directory you launch the script from).
3. In the app: Settings › Enrollment › "Import a .watchpost file", check the summary, "Enroll this device".
   The private key is imported into the Android Keystore (non-exportable) then forgotten; the token is
   encrypted by a Keystore AES key; a `GET /api/v1/ping` test is run; the app tries to delete the file.
4. Delete every copy of the file: `./scripts/push-enrollment.sh --remove phone.watchpost` and on the PC.

If `server_ca_pem` is present, only that CA is accepted for the server. Otherwise, only the system CAs
(never those added by the user). HTTP redirects are refused. Before enrollment, events stay on the phone (within
the buffer limit). "Unenroll" erases key, token and pending events; local collection continues.

**Renewing without unenrolling** (the client certificate expires after 2 years; the Enrollment screen shows
the date and flags it 30 days ahead): produce a new `.watchpost` file on the server, then
Enrollment › "Import a new .watchpost file". Before you confirm, the screen says what happens to the pending
events:

| New file | Buffer |
|---|---|
| same ingestion address, same `device_id` (renewal) | kept |
| same address, other `device_id` | kept, sent under the new identifier (`agent.config_changed` `enrollment.device_id` flags it) |
| other ingestion address | **erased**: nothing collected for one server is ever sent to another |

To renew a device's certificate (valid for 2 years) without splitting its history, the server issues a file
for the **same** identifier: `sudo ./enroll.sh --renew <name|dev_…>` from `infra/` (or
`watchpost-collector renew <device_id> --out <file.watchpost>`). The old token and the old certificate stay
accepted until the first upload with the new ones. `enroll` without `--renew` creates a new device (second
case of the table). The token (512 visible ASCII characters at most) and the identifier are validated at import.

## Updating

```bash
./gradlew assembleRelease -Pwatchpost.versionCode=2 -Pwatchpost.versionName=0.2.0
./scripts/install-apk.sh
```

Same signing key is mandatory, `versionCode` strictly increasing. The agent restarts by itself after the update
(`MY_PACKAGE_REPLACED`). The data (buffer, enrollment, settings) is kept.

## Removing the Device Owner and uninstalling

**Recommended path**: in the app, **Policy › Remove Device Owner** (confirmation). Watchpost undoes its
whole policy, turns off the network and security logs, removes force-stop protection, emits
`security.policy` `device_owner_cleared`, then gives up the role (`clearDeviceOwnerApp`). As the removal is
announced, it is **not** reported as `agent.tamper`. Works with any APK, testOnly or not. You can then
uninstall Watchpost normally and turn Android backup back on in Settings.

Fallbacks, from the most to the least recommended:

1. **Without the interface, over ADB**: `./scripts/remove-device-owner.sh [--uninstall]` (`-Uninstall` in
   PowerShell). It sends Watchpost the same order as the screen, through the rescue (see "ADB rescue without
   the interface"), then checks that the role is gone. `rescue-revert.sh --remove-owner` redirects to it.
   If an item cannot be undone, Watchpost **keeps the role** (only it can retry) and the script
   asks whether to force the removal.
2. **If Watchpost no longer answers** (app that does not start) and the APK is **testOnly**: the same script
   then offers `adb shell dpm remove-active-admin`. Watchpost undoes nothing itself in that case. According to
   the AOSP code (main branch), Android lifts the removed administrator's policies by itself, hidden
   packages included; the script checks the real state of each package Watchpost had hidden or suspended
   (`dumpsys package`) and only tries `pm unhide` / `pm unsuspend` for those that still are. These two
   commands may be refused to the ADB shell (`MANAGE_USERS` is not in the AOSP shell manifest;
   a package suspended by an administrator is not one the shell can restore): the way out is then to give
   the role back to Watchpost (`enable-device-owner`) and run `rescue-revert` again, the applied state having been kept.
   The removal is reported by `agent.tamper` (`admin_disabled`, `device_owner_lost`), which is expected.
3. Non-testOnly APK and unusable app: update the app (same signing key) to repair it, otherwise factory-reset
   the phone.

## How it works (summary)

- **Permanent foreground service**, types `specialUse` (+ `location` if the permission is granted);
  notification "Watchpost is collecting…" with the number of pending events and the time of the last upload.
- **WorkManager**: periodic upload (15 min by default) and when the network returns, periodic collections
  (heartbeat 15 min, daily inventory), maintenance every 15 min (buffer age, integrity,
  service restart if needed).
- **Upload also triggered** by any `sev >= 2` event and by a buffer of more than 500 events.
- **Batch refused with `400`** (contract §3: unreadable envelope, deterministic): instead of blocking the queue
  until the age purge, the agent splits the batch in two and resends each half (about 2·log2(500) ≈ 18
  requests per faulty event, at most 60 `400`/`413` refusals per pass, then normal `PROTOCOL` backoff
  from 5 min to 6 h). An event that still gets `400` **alone** is deleted, counted in `dropped_total`
  and traced by an `agent.collector_error` (`collector` = `upload`, type and id of the event, never its
  content; 5 at most per pass). Safeguard: before any deletion, the agent sends a batch with **no
  event** (same envelope); if that also gets `400`, the fault is in the envelope or the server, nothing
  is deleted (`last_error` = `http_400_envelope`, backoff). A `5xx`, `429`, `401`/`403` never splits
  a batch. A sudden stop during bisection loses nothing: only the buffer is durable, the bisection
  resumes on what remains.
- **Wall-clock jump and age purge**: the purge uses a "horizon" (`AgeHorizon`) that advances at
  most twice as fast as the monotonic clock (`elapsedRealtime`) and never beyond the wall clock.
  A forward jump of more than 30 days therefore no longer empties the buffer (a clock that stays wrong ages
  events at most twice as fast); a backward jump does not make the events written afterwards get purged. After
  a reboot, the horizon can only advance by 2 days beyond its last value.
- **Grouped writes**: up to 3 s in memory before a single transaction (immediate if `sev >= 2`). A
  sudden stop can lose those few seconds, never create a gap or a duplicate `seq`.
- **Direct Boot** not used: nothing is collected between a reboot and the first unlock (the
  buffer and the enrollment are in credential-encrypted storage). `device.boot` is emitted after
  the unlock.
- **Certificate Transparency** (enforced by default with `targetSdk 37`) is disabled in
  `network_security_config.xml`: a private server CA has no SCT. The app only contacts the enrolled host
  and, in private-CA mode, pinning is stricter than CT.
- **`agent.tamper`**: administrator request or deactivation, permission removed, force stop detected
  (`ApplicationExitInfo`), loss of the Device Owner role. A voluntary removal by the app (Policy screen or
  ADB rescue) is announced beforehand: it produces `security.policy` `device_owner_cleared` and
  no `agent.tamper`.
- **Timestamps**: `ts` is the time of the event. For events that the system delivers after the fact
  (`app.foreground`, `net.dns`, `net.connect`, `security.log`), it is the origin time given by the system
  (for a grouping, the first occurrence; `count` and `last_event_ts` in `data`), and `elapsed_ms`
  is estimated for that instant (0 if the event precedes the current boot). `seq` stays the emission
  order: `ts` is therefore not necessarily increasing with `seq`.

## Collectors

The Collectors tab lists the 25 collectors (the 22 of `:collectors` then the 3 of `:policy`): switch,
state (active, disabled, enabled but agent stopped, unavailable with the reason), missing permissions,
emitted types and the collector's **own settings**. It flags "Disabled by default" (`wifi_scan`),
"Device Owner required" (logs) and "Experimental setting" (camera/microphone attribution). "ADB" permissions:
`./scripts/grant-adb-permissions.sh`. Type names, field names and value types: `../docs/contract/contract.md`
§2 and its precisions, checked by the JVM tests (single reference `Contract` of the shared test bench).

| Collector (id) | Emits | Required capability | Cost |
|---|---|---|---|
| Heartbeat (`heartbeat`) | `agent.heartbeat` | — | WorkManager 15 min |
| Device (`device`) | `device.inventory`, `boot`, `shutdown`, `screen`, `battery`, `power_save`, `storage`, `thermal`, `time_changed`, `timezone_changed`, `airplane_mode` | — | broadcasts + daily reading |
| USB (`usb`) | `device.usb` (cable, functions including `adb`, device or accessory plugged in) | — | broadcasts, ≤ 60/h |
| Location (`location`) | `location.fix`, `location.provider` | precise location (+ background) | adaptive + passive GPS; "GPS + network" and "fused" modes optional (see below) |
| Connectivity (`connectivity`) | `net.connectivity` | — (ACCESS_NETWORK_STATE) | system callback, ≤ 60/h |
| Wi-Fi (`wifi`) | `net.wifi` connected/disconnected | precise location for SSID/BSSID (otherwise omitted) | system callback, no scanning |
| Neighbouring Wi-Fi networks (`wifi_scan`, **disabled by default**) | `net.wifi_scan` (≤ 60 access points) | precise location | passive (other apps' scans); optional active ≥ 30 min; ≤ 1 event / 15 min |
| Mobile hotspot (`hotspot`) | `net.hotspot` | — | system broadcast |
| NFC (`nfc`) | `net.nfc` | NFC hardware | system broadcast |
| Mobile network (`cell`) | `net.cell`, `net.cell_security` (`downgrade_2g`, sev. 2) | telephony; precise location for cell identifiers and "Phone" (READ_PHONE_STATE) for cell-by-cell tracking and signal (optional) | TelephonyCallback, ≤ 1 event / 20 s except on a technology change |
| Bluetooth (`bluetooth`) | `net.bluetooth` (state, connections) | "Nearby devices" for connections (optional) | broadcasts, ≤ 120/h |
| Trackers following you (`ble_tracker`) | `net.ble_tracker` (sev. 2) | BLUETOOTH_SCAN + precise location | low-power BLE scan filtered by the hardware, results grouped over 60 s, Bluetooth on |
| Network volumes per app (`net_usage`) | hourly `net.usage` per app and transport | usage access (ADB) **or** Device Owner | WorkManager 1 h, 2 queries |
| Apps (`apps`) | `app.inventory` (parts < 16 KiB, `inventory_id`), `app.installed/updated/removed`, `app.permission_changed` | — (QUERY_ALL_PACKAGES) | broadcasts + package walk every hour, labels once a day |
| Special access (`special_access`) | `app.special_access` | — | on change (packages, settings, screen off ≤ 1/15 min) + daily |
| Foreground app (`foreground`) | `app.foreground` (app changes only) | usage access (ADB or Settings) | 60 s reading with the screen on only + WorkManager 15 min; 100 to 400/day |
| Notifications (`notifications`) | `app.notification` (title and text only on option) | companion APK "Watchpost Notifications" installed, same key, notification access (see "Notifications") | relayed by the companion; ≤ 20 / app / 10 min, a few dozen per day |
| Camera (`camera`) | `sensor.camera` (+ `screen_on`, `locked`) | — | system callback, ≤ 120/h |
| Microphone (`microphone`) | `sensor.microphone` (+ `screen_on`, `locked`) | — | system callback, ≤ 120/h |

Details and limits:

- **Absent fields** rather than dummy values: `<unknown ssid>`, `02:00:00:00:00:00`, `CellInfo.UNAVAILABLE`,
  RSSI −127 are never emitted.
- **`net.cell`**: `tech` = lowercase name of `NETWORK_TYPE_*` (`gsm`, `edge`, `umts`, `lte`, `nr`…) and
  `none` when out of service. **`net.cell_security`**: only the downgrade to 2G (data or voice) is
  detectable without privilege; null ciphering and identifier requests are system APIs. Effective measure:
  `DISALLOW_CELLULAR_2G` (`:policy` module).
- **`net.ble_tracker`**: AirTag/Find My accessory away from its paired phone, SmartTag (0xFD5A), Tile (0xFEED/0xFEEC),
  Google Find Hub in unknown-tracker-alert mode (0xFEAA, frame 0x41). Alert if seen ≥ 4 times (once a minute
  at most), over ≥ 30 min, during a movement ≥ 500 m (adjustable), positions taken from the passive cache; nothing
  without a known position. A change of the tracker's address (rotation) resets the count.
- **Location modes** ("Location mode" setting of the collector, contract §10):

  | Mode | Providers requested | What goes to Google | Expected gain |
  |---|---|---|---|
  | `gps` (default) | `GPS_PROVIDER` (+ passive if enabled) | nothing by Watchpost (GNSS assistance XTRA/SUPL is handled by the system) | —; often no position indoors |
  | `gps_network` | GPS + `NETWORK_PROVIDER` | surrounding Wi-Fi networks and cell towers (network provider = Google Play services, only active if "Google Location Accuracy" is enabled) | approximate indoor position within seconds; a bit more consumption |
  | `fused` | `FUSED_PROVIDER` only | same (fused provider of Google Play services) | fast position, often accurate indoors, less GNSS time |

  `location.fix.provider` is the real provider of each position (`gps`, `network`, `fused`, `passive`). An absent
  or disabled provider is ignored; if none is left, fall back to GPS only (re-evaluated at each
  provider change and every minute while in fallback). The adaptive rate (movement /
  stationary, significant motion) and `mock` detection apply in all three modes. In `gps_network`,
  a network position arriving less than half an interval after a GPS position is not emitted.
  `location.provider` is emitted for GPS and the providers of the chosen mode.
- **`net.usage`**: the system counts in slices of about 2 h and distributes pro rata: estimated hourly
  values, window ended at least 30 min ago, catch-up ≤ 24 h, 100 apps at most per event.
- **`app.special_access`**: accessibility services and administrators (public APIs); notification
  listeners (secure setting `enabled_notification_listeners`, omitted if unreadable); overlay,
  installation of unknown apps, usage access (app-op of each app that requests the permission);
  `vpn_apps` = apps that **declare** a VpnService (which app owns the active VPN is not visible);
  `default_apps`: browser, home, phone, SMS, keyboard, assistant and autofill if readable.
- **`app.foreground`**: `ts` is the time of the usage event given by the system, not that of the reading
  (which can be up to 60 s late).
- **Experimental attribution** ("Experimental attribution (DUMP)" setting of the Camera and
  Microphone collectors, off by default): with `DUMP` granted over ADB, `Debug.dumpService("appops", --op …)` is
  parsed to fill `package` when a single app uses the camera or microphone. Text format not guaranteed,
  SELinux denial possible: without certainty, `package` stays absent. No attribution for location (no
  type in the contract).
- **Not written** (by choice): notification listening, accessibility, SMS/calls (principle 4); everything that
  requires the Device Owner (network and security logs, posture, policy: `:policy` module).

## Risk profile and usage

Three collectors of `:collectors` answer one question: **which application is able to do, or is currently
doing, what banking-trojan, SMS-fraud and stalkerware apps do** (for example mass-sending phishing SMS that
the SMS app never shows), whatever the vector. Specification: `../docs/contract/contract.md` §11.2.
Nothing has run on a device: everything below is tested on the JVM (logic, shared bench), not on a phone.

| Collector (id) | Emits | Required capability | Cost |
|---|---|---|---|
| Risk profile of apps (`app_risk`) | `app.risk` | — (QUERY_ALL_PACKAGES) | at each installation and update, then daily (6 component queries + 1 package walk); about a hundred events on the first pass, then only the changes |
| Default apps (changes) (`app_role`) | `app.role` | — | on change (packages, settings, screen off ≤ 1/15 min) + WorkManager 1 h; a few system calls |
| Sensitive operations usage (`app_ops`, **experimental, disabled by default**) | `app.ops` | `DUMP` **and** `PACKAGE_USAGE_STATS` granted over ADB | WorkManager 1 h: 10 bounded reads (8 s, 3 MB each), 300 lines at most |

### `app.risk`: the score, its reasons, its weighting

The score is the **pure** function `RiskScorer.score(AppFacts)` (`collectors/…/risk/RiskModel.kt`): it only reads
what `PackageManager` exposes (installer, requested and granted permissions, declared components, launcher icon,
`targetSdk`, debuggable flag), never the content of an app. **It is about the *declared* capabilities**
(contract §11.4): the profile must be useful before any grant (installation, quarantine screen) and
stay high when a guard prevents the grant. The reasons based on a runtime permission (`sms_send`,
`sms_read`, `calls`, `background_location`, `mic_camera_background`, `combo_sms_fraud`) are worth their **declared**
points; if the permission is also **granted**, they gain the "+ granted" column and enter the
`granted` list of the event (a subset of `reasons`: intent versus state). The points
add up, the score is capped at 100. **Levels**: `low` 0 to 29, `medium` 30 to 69, `high` 70 to 100. System
apps (`FLAG_SYSTEM`) and Watchpost are scored but **capped at 29** (`low`); their reasons stay listed,
except those that make no sense for a preinstalled app (installer, icon, target version, debugging).
Each code has a label and an explanation in English (`collectors/src/main/res/values/strings_risk.xml`, keys
`risk_reason_<code>` and `risk_reason_<code>_desc`, reachable through `RiskReason.fromCode(code)?.labelRes`). A test
checks that this table and the code say the same thing.

| Code | Declared | + granted | Condition (on what the system exposes) |
|---|---|---|---|
| `sideloaded` | 35 | 0 | user app whose installer is absent, a package installer, a file manager or the ADB shell (and not Play, Galaxy Store, F-Droid) |
| `unknown_installer` | 25 | 0 | user app installed by another app that is not a store (excludes `sideloaded`) |
| `no_launcher_icon` | 12 | 0 | user app without an enabled `MAIN`/`LAUNCHER` activity (a disabled icon counts as absent) |
| `sms_send` | 16 | 4 | `SEND_SMS` requested (+ granted) |
| `sms_read` | 6 | 6 | `READ_SMS`, `RECEIVE_SMS`, `RECEIVE_MMS` or `RECEIVE_WAP_PUSH` requested (+ granted) |
| `calls` | 3 | 7 | `CALL_PHONE`, `READ_CALL_LOG`, `WRITE_CALL_LOG`, `ANSWER_PHONE_CALLS` or `PROCESS_OUTGOING_CALLS` requested (+ granted) |
| `accessibility_service` | 25 | 0 | declares an accessibility service (protected by `BIND_ACCESSIBILITY_SERVICE`), enabled or not |
| `notification_listener` | 15 | 0 | declares a notification listener (`BIND_NOTIFICATION_LISTENER_SERVICE`) |
| `device_admin` | 15 | 0 | declares an admin receiver (`BIND_DEVICE_ADMIN`) |
| `overlay` | 12 | 0 | requests `SYSTEM_ALERT_WINDOW` (the request counts: the "granted" state of special access is not reliable in the package flags) |
| `install_packages` | 20 | 0 | requests `REQUEST_INSTALL_PACKAGES` or `INSTALL_PACKAGES` |
| `vpn_service` | 10 | 0 | declares a `VpnService` (`BIND_VPN_SERVICE`) |
| `boot_receiver` | 5 | 0 | declares a `BOOT_COMPLETED` receiver **and** requests `RECEIVE_BOOT_COMPLETED` |
| `background_location` | 6 | 4 | `ACCESS_BACKGROUND_LOCATION` requested (+ granted) |
| `mic_camera_background` | 3 | 5 | microphone or camera requested **and** microphone/camera foreground-service-type permission requested (or, before Android 14, a foreground service) (+ granted) |
| `old_target_sdk` | 8 | 0 | user app whose `targetSdk` < 30 |
| `debuggable` | 10 | 0 | user app marked `FLAG_DEBUGGABLE` |
| `combo_banking_trojan` | 30 | 0 | `accessibility_service` + `overlay` + (`sms_read` or `notification_listener`), on the declared capabilities |
| `combo_sms_fraud` | 20 | 6 | `sms_send` + `boot_receiver`, without being the default SMS app (+ granted if `SEND_SMS` is) |
| `combo_stalkerware` | 30 | 0 | `no_launcher_icon` + (location or microphone requested, approximate included) + `boot_receiver` |

A combination adds to the points of the reasons it combines: this is what separates a trojan from an app that
has only one of these powers. **Why these weights**: on declared capabilities, a messenger or a bank that
declares SMS, call and microphone rights (without holding them) quickly accumulates points; only the
**origin** (outside a store: 35) then separates an SMS-fraud app (outside a store + sending + boot = 76, `high`)
from a store messenger that declares the same rights (65, `medium`): the margin is 5 points on each side of the
threshold of 70, which is thin and stated as such. "Outside a store" alone is already `medium`. A reading that fails never
downgrades an app (unknown icon = present, unknown components = absent); an empty package list
is a failed reading, not "no apps".

**Emission.** At each `PACKAGE_ADDED` / `PACKAGE_REPLACED` (always), then every day for only the apps whose
score, reasons, `granted` list or version changed since the last emission (persistent state
`risk_state`); the first pass emits them all once. Severity: `low` 0, `medium` 1, `high` 2. Fields:
`package`, `label`, `version_code`, `installer` (absent if unknown), `from_store`, `score`, `level`, `reasons`
(declared), `granted` (among them, those whose permission is granted).

**What the score misranks** (test set `RiskCorpus`: 23 legitimate apps and 14 malicious profiles, built
from the usual functions and permissions of each family, **not extracted from real APKs**; measured with the
declared capabilities):

- *"High" false positives* (4 of 23): parental control, antivirus suite, automation app (Tasker-like) and
  caller identification with SMS rights. Their powers are those of spyware or a trojan, by construction: no
  capability-based score separates them. Only "who installed it and why" does, and neither the system nor this
  agent knows it.
- *"Medium" false positives* (5): store messenger that declares SMS rights (65, 5 points from the threshold),
  password manager and button remapper (accessibility + overlay), launcher that locks through
  accessibility, third-party SMS app chosen as default. A bank that declares SMS reading: 6, `low`.
- *No alert* on: messenger without SMS rights, bank, keyboard, browser, simple launcher, VPN, dialer,
  authenticator, file manager, navigation (all below 30). Any app installed outside a store is
  at least `medium` (35): including your own installations over ADB (except Watchpost, capped).
- *Detected before any grant*: SMS fraud outside a store (76) and spyware without an icon (82) are `high` with
  zero permissions granted; the grant only adds 10 points to SMS fraud and the `granted` list.
- *False negatives*: a dropper published on the store (only the install request gives it away: 20, `low`).
  Underestimated but `medium`: SMS fraud without a start at boot (55, triggered by push, so no
  combination) or distributed by the store (51), spyware with a harmless icon (40), dropper outside a store (55),
  ransom locker (67). Accessibility adware outside a store: 72, `high`.
- Fundamental limit: the score judges **declared capabilities**, not acts. An accessibility service enabled
  later, an icon that the app disables afterwards, are only seen at the daily pass (or on update),
  not instantly. `app.ops` measures the real usage.

### `app.role`: default apps

Read **without system privilege**, from the API 37 `android.jar`: `RoleManager` only gives an app
`isRoleAvailable`, `isRoleHeld` (for itself) and `createRequestRoleIntent`. `getRoleHolders` is a system API
(`OBSERVE_ROLE_HOLDERS`, signature level): a Device Owner has no more rights here. The following are therefore
tracked through the corresponding public APIs (`DefaultApps`, a single implementation):

| Role | Reading | Reliability |
|---|---|---|
| `sms` | `Telephony.Sms.getDefaultSmsPackage` | reliable |
| `dialer` | `TelecomManager.getDefaultDialerPackage` | reliable |
| `browser`, `home` | app that resolves the default intent (`MATCH_DEFAULT_ONLY`) | reliable |
| `keyboard` | secure setting `default_input_method` (public constant) | reliable |
| `assistant`, `autofill` | hidden secure settings `assistant`, `autofill_service` | **not guaranteed**: some systems refuse the reading; an absent value means "unknown", never "removed" |

**Not readable, therefore omitted** (never guessed): `call_screening`, `call_redirection`, `emergency`, `notes`, `wallet`
(no public accessor for another app). `keyboard` and `autofill` are not Android roles but
settings: they are added because a malicious keyboard or autofill service reads everything that is typed;
the contract does not name them (to be added there).

**Relation with `app.special_access`**: both use the same reading. `special_access.default_apps` gives the
**current state** (daily and at each change); `app.role` gives the dated **transition** (`old` → `new`, the
first reading being only a reference, without an event). A value is therefore never stated twice in a
contradictory way; only the time of reading can differ by a few seconds. Severity 2 for `sms`, `dialer`,
`assistant`, `keyboard`, `autofill`, 1 for `browser` and `home`. `old` is absent if there was no value,
`new` absent if the role is no longer assigned.

### `app.ops`: real usage (experimental)

Disabled by default ("Sensitive operations usage (experimental)" card). For each of the ten operations of the
contract, it counts **how many accesses the system allowed** to each app during the last hour, including those in the
background (system states `bg` and `cch`; `fgsvc` counts as foreground). One event per hour, only
for apps that used an operation, 300 lines at most (cut into 12 KiB parts), `from`/`to` = the
two readings. **The first reading is only a reference** (no event).

- **Prerequisites**: `DUMP` **and** `PACKAGE_USAGE_STATS`, through `scripts/grant-adb-permissions.sh`. The source code of the
  service (`AppOpsService.dump` → `DumpUtils.checkDumpAndUsageStatsPermission`) requires both: `DUMP` alone is
  refused. The experimental camera/microphone attributions (`AppOpsDump`) have the same requirement.
- **Source**: `Debug.dumpService("appops", fd, ["--history", "--op", OP])`, i.e. the text of
  `adb shell dumpsys appops --history --op SEND_SMS`. Only the **history** gives counters (`[bg-s] =
  access=37`); the current state only gives the date of the last access, read (one reading per used operation)
  to fill `last_ts`. A counter is the **difference** between two readings of the history sums
  (the dates of the history snapshots are not reliable: relative to an "epoch start"). A sum
  that drops (old snapshots expired) counts as 0: it is a lower bound. A reading more than 24 h after the previous
  one is a new reference.
- **What is counted**: `count` = allowed accesses (`access=`), `rejected_count` = accesses **refused** by the
  system (`reject=`), `background_count` = share of `count` in the background. An operation that was only refused is
  emitted too (`count` 0); a refused SMS send has severity 2. Honesty about refusal: the system
  only records it when the app-op is queried and says no (ignored mode). A send blocked earlier, at the runtime
  permission check (which is what the `sms` guard of `:policy` does, denying the permission), may never
  reach the app-op and therefore never appear: **not verified** (telephony sources not found), to be
  tested with the guard active. One SMS send = one send request, not a number of parts; in "passive" history
  mode or when disabled the system counts nothing (the collector declares itself unavailable). Apps
  that share a UID appear under each of their packages.
- **Clean failure**: permission denied, unknown option, empty output, absent history (including Android 16's SQLite
  store behind a flag, whose dump then prints no `History:` section) or disabled, unrecognized
  format, output too large, timeout, `dumpService` refused: if **none** of the ten operations is readable,
  the collector becomes "unavailable" with the reason in English, emits **a single** `agent.collector_error`
  (`<code>: <reason>`, a new one only if the reason changes), and retries only after 6 h. If only a few
  operations fail, the others continue and the failing operation keeps its reference.
- **Frugality**: 10 reads per hour (8 s and 3 MB at most each, 60 s in total), plus one state read per
  used operation (4 s). The service holds its history locks while writing the output (effect not measured, probably a few
  milliseconds).
- **Format**: taken from the AOSP sources of Android 14, 15 and 16 (`AppOpsService`, `HistoricalRegistry` and
  `LegacyHistoricalRegistry`, `AppOpsManager.keyToString`, `TimeUtils.formatDuration`), identical across the three;
  **never observed on a Samsung phone**. The tests read excerpts written from these sources, not
  captures.

**To verify on the phone**: (1) `adb shell dumpsys appops --history --op SEND_SMS` does produce
`[bg-s] = access=N` lines on One UI (otherwise `app.ops` will declare itself unavailable, harmlessly); (2) `Debug.dumpService`
is not refused by SELinux for the app (and the output reaches the agent); (3) the size of a read
(a `--history --op` prints the headers of all packages, a few hundred KiB); (4) that sending an SMS
from an app does increment `SEND_SMS` for *its* package; (5) the `RoleManager` list: `app.special_access`
and `app.role` after a change of browser, keyboard and SMS app; (6) a few scores at random against
reality, especially parental-control or automation apps if you have any.

## Notifications (companion APK)

The agent's `notifications` collector says **which apps display notifications**. Reading
notifications is **not** in the Device Owner APK: it lives in a separate, optional APK, **Watchpost
Notifications** (`io.github.erwsim.watchpost.notifier`, `:notifier` module), which contains the project's only
`NotificationListenerService` (principle 4; a DPC that also listens to notifications has already been
blocked by Play Protect, see `../docs/research/android-platform.md` §2.4 and §9: if the companion is, the agent
is not affected). The companion has **neither** the `INTERNET` permission **nor** any sensitive permission, embeds
no library (no AndroidX, no network, no Google), and has an icon and a screen that explain what it does,
its state and how to remove it. It keeps nothing: no history, no content, no file (state in memory).

### What is relayed (`app.notification`, contract §10)

| Always | Only if "Notification content" is enabled (off by default) |
|---|---|
| `package`, `event` (`posted`/`removed`), `category`, `channel`, `ongoing`, `importance` (`none`, `min`, `low`, `default`, `high`, `max`) | `title`, `text` (512 characters at most, counted in code points), `redacted` (true if a code was masked; absent if masking is disabled) |

- **Content off** (default): the title and text never leave the companion's process (filtering
  is done on its side, before the channel, from the settings read from the agent; the agent applies the same rule a
  second time on reception).
- **Code masking** (on by default): any run of 4 to 8 digits is replaced by `••••` before
  truncation (a code is never cut in two). Details of the rule and its limits below.
- **Apps excluded from content** (only the app name goes): pre-filled with common banking and payment apps
  (the pre-filled list targets French banks), authenticators, password managers, **SMS and phone** (no SMS
  content nor call log, principle 4). It is a list of **package names**: an app is only recognized
  by its exact name, so the list is necessarily incomplete (other bank, regional variant, renamed app);
  names not checked one by one on a device. Add your sensitive apps.
- **Ignored apps** (nothing goes): empty by default.
- **Never relayed**: the notifications of Watchpost and of the companion; updates of a notification that
  changed nothing; more than one update per notification every 30 s; updates of
  **ongoing** notifications (`ongoing`, foreground service, music, download, timer, call,
  navigation, workout: only the first display and the removal go; "Download complete", which
  is no longer ongoing, goes once); group summaries (each notification of the group goes, not
  the summary); the removal of a notification that was not relayed; beyond **20 events per app and per
  10 minutes** (removals of relayed notifications always go through). Notifications already displayed
  when the companion starts are not relayed. Typical volume: a few dozen events per day.
- Android 15+ already hides the content of notifications it recognizes as one-time codes from "untrusted"
  listeners such as the companion: Watchpost's masking is a second layer.

**Masking rule** (`notifier/protocol/…/CodeRedactor.kt`, tested by `CodeRedactorTest`): a run of digits
(all scripts) whose groups are separated by **one** space, non-breaking space or hyphen (`123456`,
`123 456`, `123-456`, `G-123456`, `code123456`) is masked entirely if it has 4 to 8 digits; if longer
(phone, IBAN, card), only its groups of 4 to 8 digits are. A part of a decimal number
(`1234,56`) or of a slash-separated date (`16/11/2026`) is left alone.
- **Wrongly masked**: years (`2026`), amounts without decimals (`1500 €`, `1 500 €`), ISO dates (`2026-11-16`),
  postal codes (`75011`), 4-digit blocks of phone numbers written in blocks of 4 (`+44 20 7946 0958`),
  IBAN blocks, order or tracking numbers of 4 to 8 digits.
- **Let through**: codes of 3 digits or of 9 and more, alphanumeric codes (`A1B2C3`), codes written with a
  dot or a comma (`123.456`, `1234.5678`), with two separators or a slash between the groups,
  a code in small groups joined by a space to another number (`123 456 2026`: only `2026` is masked),
  codes written out in words. Phone numbers in blocks of 2 digits (`06 12 34 56 78`) are not masked.

### Installing and enabling

1. Build with **the same keystore** as the agent (same build): `./gradlew :notifier:assembleRelease`
   → `notifier/build/outputs/apk/release/notifier-release.apk` (same signing configuration as `:app`,
   read from `keystore.properties` or the `WATCHPOST_*` variables; `-Pwatchpost.testOnly`, `-Pwatchpost.versionCode`
   and `-Pwatchpost.versionName` also apply). A companion signed with another key is refused at
   installation next to the agent (`INSTALL_FAILED_DUPLICATE_PERMISSION`) and could not hand anything over to it
   anyway. Debug with debug, release with release.
2. `./scripts/install-notifier.sh [notifier.apk]` (`adb install -r -t`, then compares the signing keys
   of the agent and the companion). The installation order of agent/companion does not matter.
3. Notification access: `./scripts/notifier-access.sh` (`adb shell cmd notification allow_listener
   io.github.erwsim.watchpost.notifier/io.github.erwsim.watchpost.notifier.NotifierListenerService`, then a check
   in `settings get secure enabled_notification_listeners`). Without ADB: the companion's "Notification access setting"
   button, or Settings › Notifications › … › Notification access (the path varies
   with the One UI version). An app installed outside an app store may appear greyed out there
   (**"Restricted setting"**): Settings › Apps › Watchpost Notifications › ⋮ › "Allow restricted
   settings", then grant the access; the ADB command is not affected by this block.
4. Open "Watchpost Notifications": access granted, listener service connected, agent present (same key), collection
   active, content enabled or not according to the agent, last relayed notification and counters.
5. In Watchpost, Collectors tab › Notifications: the collector goes from "unavailable" (companion absent,
   signed with another key or without access, reason displayed) to "active" (at the latest at the next
   maintenance pass, 15 min; immediately if the companion reports its listener service).

### Configuring

- **In Watchpost** (Collectors › Notifications): the collector's switch (off: the companion
  relays nothing any more), "Notification content" (off by default), "Mask numeric codes"
  (on by default). Each change emits `agent.config_changed` and notifies the companion.
- **In the companion**: the two app lists (one package name per line, `#` for a comment),
  "Save in Watchpost" or "Restore the default lists". They are **stored in the agent** (keys
  `notifications.content_excluded_packages` and `notifications.ignored_packages` of its settings; the agent's
  settings framework has no editable "list" type), each change emits `agent.config_changed`
  (`old`/`new`: names separated by commas, 1,000 characters at most). Invalid entries are refused and
  displayed; 500 apps at most per list.

### Local channel (security)

- The companion calls a **content provider** of the agent (`ContentResolver.call`, authority
  `io.github.erwsim.watchpost.notifications`): a synchronous call, which starts the agent's process if it is not
  running (no background service start, hence no Android 12+ restriction), with no binding to manage.
  Cross-package visibility: `<queries>` on the agent's package on the companion side; the agent sees everything
  (`QUERY_ALL_PACKAGES`).
- Protected by the **`io.github.erwsim.watchpost.permission.NOTIFICATION_RELAY`** permission of `signature` level,
  **declared by both APKs** (same key: no conflict, and the installation order or the uninstallation of
  one does not make it disappear). The agent also checks, on each call, that the caller holds the
  permission, that its uid and its attributed package are the companion's and that its signing key is its own.
- In the other direction, the agent only sends an empty "settings changed" broadcast to the companion's receiver
  (protected by the same permission); the companion then re-reads the settings. It also re-reads them at most every
  minute and as soon as the agent answers with another version. As long as it could not read them, it relays nothing.
- Bounded sizes on both sides: title and text 512 code points, category 64, channel 128, package 255
  characters, 32 keys per call; beyond that, the agent refuses the call (nothing is recorded). 300 calls per minute
  at most on the agent side; queue of 256 notifications at most on the companion side.
- Agent absent, stopped, being updated or collector disabled: the companion **drops** the
  notifications of that moment (it does not keep them for later) and counts them ("not delivered"); after a failure
  it does not retry for 10 s. If the agent's process was restarted by the call before its service
  restarts the collectors, the event is written directly into the agent's buffer.

### Removing

- Stop the collection while keeping the companion: disable the "Notifications" collector in Watchpost.
- Withdraw the access: `./scripts/notifier-access.sh --revoke` (`cmd notification disallow_listener …`), or the
  notification access setting.
- Uninstall: `./scripts/uninstall-notifier.sh` (withdraws the access then `adb uninstall`), or from
  Settings. The agent keeps running without it; the lists stay in the agent's settings.

### What is verified, what is not

- **Verified** (JVM tests and build checks, no device): compilation, lint (no warning on the
  companion), debug and release APKs (R8); the companion's manifest only requests the channel permission (no
  `INTERNET`), its release code only contains its own; the agent's APK contains no
  `NotificationListenerService`, declares the signature permission and requires it on its provider; JVM tests
  of masking, lists, truncation, noise reduction, agent-side validation (hostile
  payloads) and `app.notification` conformance; bash scripts tried against a fake `adb` (the `.ps1` files
  were not run).
- **Nothing has been run on a phone.** To verify on the phone, in order of risk:
  1. the reaction of **Play Protect** to the companion's installation (and a possible later scan of the agent);
  2. access granted by `cmd notification allow_listener` on One UI 8/9, and the "restricted
     setting" display in Settings;
  3. **survival of the listener service** (Samsung battery management: if needed, Watchpost Notifications in
     "Never sleeping apps") and reconnection after a reboot, an update or a force stop;
  4. the channel when the agent is killed, being updated or stopped ("not delivered" must increase, no
     error) and the agent's startup by the companion's call;
  5. the agent's reading of `enabled_notification_listeners` (otherwise the collector relies on what the
     companion says); "settings changed" broadcast received by the companion;
  6. the real content of notifications of common apps (messengers, codes received by SMS already masked by
     Android 15+, grouped notifications) and the daily volume.

## Remote commands

Principle 2 (contract §8): the server can send the phone commands from a **closed list**, and nothing else.
No command can change a setting, the policy or the enrollment: an unknown type, an extra parameter or one
out of bounds is **refused**, never interpreted. **Settings › Remote commands** screen (or the "Remote
commands" card on Home).

| Command | Effect on the phone | Requires | Android API |
|---|---|---|---|
| `ring` (`duration_s` 1–300, `vibrate`) | looping alarm ringtone at full volume (alarm stream, volume restored afterwards), optional vibration, notification "Watchpost is making this phone ring" with **Stop** | channel enabled | `MediaPlayer` with `USAGE_ALARM`, `AudioManager.setStreamVolume(STREAM_ALARM)`, `VibrationAttributes.USAGE_ALARM` |
| `vibrate` (`duration_s` 1–60) | vibration only | channel enabled | `VibratorManager` |
| `stop_ring` | stops the ringtone or vibration | channel enabled | — |
| `locate` | immediate position by the `location` collector in **its** mode (up to 60 s), then immediate upload of the buffer | channel enabled, `location` collector active | `LocationManager.getCurrentLocation` |
| `lock` (`message` ≤ 200 characters, optional) | message on the lock screen then immediate lock | **signed**, Device Owner | `setDeviceOwnerLockScreenInfo`, `lockNow` |
| `clear_lock_message` | removes the message | **signed**, Device Owner | `setDeviceOwnerLockScreenInfo(null)` |
| `wipe` | factory reset | **signed**, Device Owner, "Allow remote erase" | `DevicePolicyManager.wipeDevice(0)` |

Each processed command produces `command.result` (`command_id`, `type`, `status` = `executed`/`failed`/`refused`,
`detail`, `signed`), a line in the local history and **a notification on the phone** (a command never
goes unnoticed); the result is also sent to the server (`POST /api/v1/commands/{id}/result`, kept and
resent until acknowledged). The permanent notification and Home say when the channel is active.

### Putting it into service

1. Enroll the device (the passphrase depends on its identifier).
2. **Remote commands** › "Receive remote commands" (**off by default**), mode
   "Permanent connection" (default) or "Periodic polling" (1 to 15 min).
3. **Command passphrase**: 12 characters at least, entered twice. It is known only to the phone and to you;
   the server does not receive it and can neither lock nor erase without it. **This promise has two
   limits** (the screen says them): the server sees the signed commands go by and can therefore try passphrases
   offline — on the order of 15,000 guesses per second per high-end graphics card despite the
   600,000 iterations (order of magnitude taken from public PBKDF2-HMAC-SHA256 benchmarks, not measured here):
   12 digits fall in about two card-years, i.e. a few days of rented hardware, a dictionary word followed by digits in a few hours,
   whereas five randomly drawn words or 16 random characters are out of reach; and the passphrase is entered into
   the console, which this same server serves (a compromised server can modify the page and read it). The app refuses a passphrase with fewer than 6 distinct
   characters, or without a letter and with fewer than 20 digits (`CommandCrypto.isTooWeak`: a floor, not a strength
   measure). **Changing the passphrase invalidates every command already signed**, including those the server might
   still hold. It is entered again in the console for each sensitive command. The phone only keeps the derived key
   `K = PBKDF2-HMAC-SHA256(passphrase, "watchpost-cmd-v1:" + device_id, 600,000, 32 bytes)`, encrypted by a Keystore AES key;
   the passphrase itself is kept nowhere (not even on the screen). After a re-enrollment under another
   identifier, the app asks for it to be entered again. "Delete the passphrase" also sets remote erase
   back to "forbidden".
4. Optional: **Allow remote erase** (off by default; enabling only with a passphrase
   set and after typing ERASE in the confirmation). Each change of these settings emits
   `agent.config_changed` (`commands.enabled`, `commands.mode`, `commands.allow_wipe`, `commands.code` with
   `set`/`changed`/`unset`, never the passphrase).
5. If a lock message has been set, the screen offers "Clear the message" (locally, without a command).

### Verifications (in the order of the contract)

channel enabled (`disabled`) → parsable `payload`, `v` = 1, same `id` (`malformed`) → `device_id` (`wrong_device`)
→ type in the list (`unknown_type`) → for a sensitive type: passphrase set (`no_code_configured`), no
temporary lockout (`locked_out`), HMAC-SHA256 over the **exact UTF-8 bytes** of `payload`, compared in
constant time (`bad_signature`) → `wipe` allowed (`disabled`; the `id` of a signed and still valid `wipe`
refused here is **consumed**: the server keeps the signed command until it expires and could otherwise
deliver it again after the switch is turned on) → not expired, 5 min tolerance (`expired`) →
never seen (`replay`) → parameters within bounds (`bad_params`) → Device Owner for `lock`,
`clear_lock_message`, `wipe` (`not_device_owner`). Before the signature, only `v`, `id`, `device_id` and `type`
are read, in order to refuse; the rest (parameters, dates) is only parsed afterwards. Five `bad_signature` in one hour
block the sensitive commands for an hour (persistent). Persistent anti-replay: last 500 signed `id`s,
last 500 plain `id`s and last 500 sensitive `id`s **consumed without a verifiable signature** (three windows:
a compromised server sending commands in bulk cannot push a verified signed `id` out of its
window). Precisions of contract §8 applied by the agent: `wipe` validity
limited to **24 h** (`expired` beyond, and a 7-day `wipe` refused `disabled` is not consumed: it would be
expired anyway); a sensitive command refused `disabled` (channel off) or `no_code_configured` is
**consumed** ("unverified" window, if its `device_id` is the right one and its dates still valid) and will
never run, even after the channel is enabled or the passphrase is entered; U+2028 and U+2029 refused in the
`lock` message; passphrase floor (6 distinct characters, 20 digits without letters). Precisions retained where the contract is silent: unknown key
at the first level of `payload` or `expires_at` earlier than `issued_at` → `malformed`; validity of more than
30 days (24 h for `wipe`) or `issued_at` more than 5 min in the future → `expired`; `sig` on a plain command →
`malformed`; `payload` with a duplicate key (even hidden behind a `\u` escape) → `malformed`;
`lock` message: 200 UTF-16 units at most, no control character except line feed
(`bad_params`, re-checked by the agent: the server is not trusted). The test vector of §8 is reproduced to the byte
(`CommandVerifierTest`). Any JSON coming from the server (payload, stream event, polling response) is
refused beyond a few levels of nesting **before** being parsed (`JsonNesting`): the parser is
recursive and a stack overflow, which is not an `Exception`, would stop the channel.

What the signature does not cover, by construction: a signed command stays executable until its
`expires_at` (7 days by default in the console), whatever the console displays — a compromised server can
hold it back then deliver it later, or ignore a cancellation (cancellation only exists on the server side). Local
countermeasure: change the command passphrase, or turn off the channel or remote erase.

### Remote erase: safeguards

`wipe` is the app's only irreversible action. It requires **all** these conditions: channel enabled, passphrase
set, valid signature, "Allow remote erase" enabled, command not expired and never seen, and
Watchpost as Device Owner. The agent first emits `command.result` (`executed`, sev. 2), tries to upload the buffer and the
result (10 s at most), **re-checks all the conditions on the current state** (a switch turned off during
those 10 s cancels everything), then calls `wipeDevice(0)`. API choice: `wipeData` throws `IllegalStateException` for
an app targeting API 34+ called on the system user (where a Device Owner lives); `wipeDevice` (API 34)
is the call meant to reset the device and requires the `<wipe-data/>` policy (declared in
`policy/src/main/res/xml/device_admin.xml`, with `<force-lock/>` for `lockNow`). Flags 0: factory reset
protection (Google account) and eSIMs are **kept** — a thief cannot reuse the
phone, and you keep your line. The real call exists in a single place (`AndroidFactoryReset`), built in
a single place (`PolicyModule.registerCommandExecutors`); `RemoteCommandsPolicyTest` checks the 64
combinations of the six conditions (only one erases) and, in the sources, that no other path calls
`wipeDevice`/`wipeData`.

### Real limits

- **"Do not disturb"**: the ringtone uses the alarm stream, which is muted neither by silent mode nor
  by vibrate mode. If the user's "Do not disturb" mode mutes alarms ("Total silence", or
  alarms turned off in the mode), the sound stays muted: an app targeting Android 15+ can no longer turn off the
  user's "Do not disturb" (`setInterruptionFilter` now only drives its own rule), and being
  Device Owner gives no right over this mode. The result says so (`detail` = `dnd_alarms_muted`); the
  vibration and the notification remain.
- **`lock` without a secure lock screen** (no PIN, pattern or fingerprint): `lockNow` only turns the screen
  off. The message is displayed on the lock screen until it is removed (command or app).
- **`locate` in GPS-only mode**: indoors, often no position within 60 s (`failed`, `no_fix`); the
  network/fused modes answer better, at the price of what they send to Google. `location` collector off or
  without permission: `failed`, `location_unavailable` (a command never overrides a local choice).
- **Added admin policies** (`force-lock`, `wipe-data`): they are read when the administrator is
  activated. On a phone where Watchpost was already Device Owner with an earlier version, check that
  `lock` works after the update (otherwise: `SecurityException` → `failed`, `lock_refused`).

### Channel and consumption (to measure on the phone)

- **Permanent connection**: `GET /api/v1/commands/stream` (Server-Sent Events) with the same client-certificate TLS
  client as the upload. No permanent wake lock: a blocking read on an idle TCP connection.
  Read timeout 300 s (2.5 × the server's 120 s keep-alive: one lost keep-alive is tolerated). Timers
  stop when the CPU sleeps: an inexact alarm allowed in deep sleep
  (`setAndAllowWhileIdle`, at most once every 15 min or so; Android spaces its effect by at least
  9 min in Doze) checks that a byte arrived less than 5 min ago, otherwise the connection is reopened. Wake lock
  only while processing a command (≤ 2 min), around a poll (≤ 60 s) and
  after an alarm (≤ 30 s).
- **Expected cost**: each server keep-alive (every 2 min) wakes the modem if it is idle — this is
  the main expense, especially on a mobile network. A foreground service normally keeps network access
  in Doze (to be verified on One UI). If consumption is too high: "Periodic polling" mode.
- **Polling**: `GET /api/v1/commands` at the chosen interval (inexact alarm; in deep sleep
  the real interval lengthens), and at each event upload when the stream is not open (at most once
  a minute; pointless when the stream is open, which already delivers pending commands).
- **No loop**: without network, nothing is tried until the network returns (system callback); failures in
  jittered exponential backoff (5 s → 15 min; `429` and `Retry-After` respected; `404` = server without a channel:
  6 h); a stream that dies as soon as it is opened counts as a failure; a stream that lived is reopened after 2 to 10 s.
  **`401`/`403` stops everything** and the screen shows it ("refused by the server") until a re-enrollment, a
  settings change or "Reconnect". Network change (Wi-Fi ↔ mobile): the stream is reopened at once.
- **Resend** (contract §8): the server delivers again a command whose result has not arrived (after
  5 min, 3 times at most), and the stream then polling can deliver the same one. A command already processed
  is **never re-executed** (neither `wipe`, nor `lock`, nor `ring`): the agent sends back its **original result**,
  kept with the `id` (last 1000), with no new event or history line; it only answers
  `refused`/`replay` for an `id` still in the anti-replay window whose result it no longer has.

### What is verified, what is not

- **Verified (JVM)**: the test vector of §8 (and the PBKDF2 vectors of RFC 7914), **hard cases signed by
  the console's real TypeScript code** (`ConsoleVectorsTest` replays
  `server/console/src/lib/fixtures/command-vectors.json`: accents, emoji, quotes, line breaks, bidirectional
  text, non-ASCII passphrases, decomposed or padded with spaces), each refusal reason and
  the order of the checks, anti-replay after a restart, `wipe` refused with the switch off then replayed
  with the switch on (including after the results memory was saturated by plain commands),
  excessively nested JSON, command passphrase floor, lockout after 5 invalid signatures, matrix
  of the `wipe` safeguards, re-check before the erase, channel client against MockWebServer (SSE stream,
  cut, reconnection, stream monitoring, `401`, no network, switch to polling, result
  resent after a cut, duplicate delivery, resend of the original result without re-execution — `wipe`, `lock`,
  `ring`), conformance of `command.result` to the contract (`CommandResultContractTest`).
- **Cross-check against the real collector** (`CrossCommandsTest`, skipped without the `WATCHPOST_CROSS_*` variables,
  instructions at the top of the file; run against `watchpost-collector serve` over a local `http://`):
  commands created by the console API with a `payload` and a signature built like the console does
  (`ring`, signed `lock` with an accented two-line message, signed `wipe`, signed `lock` with another
  passphrase), delivered by the real SSE stream then by polling, verified by the real client; the server
  recorded `executed` for the legitimate commands and `refused`/`bad_signature` for the fake one. Two further
  checks under the same conditions: the 13 hard cases **signed by the console's real
  code** (`node server/console/scripts/command-vectors.ts <device_id>`) go through the real
  collector and are accepted by the real verifier with their exact message; and the **resend after 5 min by
  the real server**: `lock` and `wipe` (fake reset) whose result had not reached the
  server are delivered again, are not re-executed, and their original result is recorded; a
  `ring` whose result could not be sent is resent in the meantime, is not replayed, and its result
  arrives on resumption.
- **Nothing has been run on a phone.** To verify on the phone, in order of risk:
  1. **`wipe`**: with a test phone or a full backup, check that `wipeDevice(0)` does reset
     (and that nothing happens while the switch is off);
  2. **`lock`**: `lockNow` and the display of the message by One UI on the lock screen
     (`setDeviceOwnerLockScreenInfo`), then `clear_lock_message` and "Clear the message";
  3. **consumption of the permanent channel** over 24 h on Wi-Fi then on a mobile network (Settings › Battery,
     `adb shell dumpsys batterystats`), compared with polling mode; if it is high, try a longer server
     keep-alive (`WATCHPOST_CMD_KEEPALIVE_S`, **240 s at most**: the agent's read timeout is
     300 s, and without exceeding the carrier's NAT timeout) or polling mode;
  4. **reception in Doze**: screen off for more than an hour, send `ring`; note the delay (the connection
     must stay open thanks to the foreground service); `adb shell dumpsys deviceidle force-idle` to force it;
  5. **ringtone** in silent mode, vibrate mode and "Do not disturb" (with and without alarms allowed), alarm
     volume restored afterwards, "Stop" button on the lock screen;
  6. `locate` in the three location modes, indoors and outdoors; reconnection after a Wi-Fi ↔
     mobile switch, airplane mode, server restart; behavior after revocation (`401` displayed, no more attempts).

## Device Owner policy

`:policy` module, **Settings › Device Owner › Policy** screen. **Nothing is applied automatically**: apart from the
base (self-grant of Watchpost's permissions, force-stop protection) and the logs
below, the user chooses a profile, adjusts the items, reads the preview ("What will change")
and applies. Each action emits `security.policy` (`action`, `target`, `profile` = `balanced`/
`strict`, `ok`, `error`) and a line in the screen's local log. The applied state (with the previous state of
each item) is written **before** each change (SharedPreferences `watchpost_policy`, `commit()`), then
confirmed after reading back the effect: it survives app updates and reboots, and "Restore" puts back
exactly the state from before. A failure (exception, Samsung refusal, effect not observed) gives `ok=false` with
the error and does not prevent the other items. No policy comes from the server.

**Applying only a part**: "Uncheck everything" (Profile card) turns off every switch, Private DNS,
lock and backup included; then check only what you want to try (for example Private DNS
alone), "Preview", "Apply". Each section (apps, permissions, restrictions) also has "Uncheck everything
here" and "Check the default choices". What is already applied and no longer checked is restored
at the next application (the preview shows it).

### Logs and posture (collectors, Collectors tab)

| Collector (id) | Emits | Notes |
|---|---|---|
| System security log (`security_log`) | `security.log` | batches delivered by the system (≤ 2 h); `fields` according to the contract table (`argN` otherwise); `app_process_start` aggregated per hour (can be disabled); Wi-Fi/Bluetooth connections can be disabled; pre-reboot logs read once per boot if the device provides them (`pre_reboot: true`) |
| System network log (`network_log`) | `net.dns`, `net.connect` | batches ≤ 1200 entries (≤ 1 h 30); package and uid (shared uids: `android.uid.system`…); identical requests aggregated per window (10 min, adjustable: `count`, `last_event_ts`); emission in groups of 100; a batch notified while the agent was stopped is retrieved at the next start; lost batches reported as `agent.collector_error` |
| Security posture (`posture`) | `security.posture`, `security.posture_change`, `security.ca_cert`, `security.keyguard` | at startup, every day and at each change (settings observers, certificate store, Device Owner, passcode change); an unreadable field is omitted; works partially without Device Owner |

These three collectors are active by default (like any collector). Turning off `network_log` or `security_log`
in the Collectors tab also turns off the system's logging (`security.policy` `network_logging` /
`security_logging`). Network logging makes Android display the "network monitored" mention. The `ts` of a
`net.dns`, `net.connect` or `security.log` is the origin time of the entry (first occurrence if
grouped), not the retrieval time.

### Profiles

| | Balanced (default) | Strict (= balanced + …) |
|---|---|---|
| Packages | 35 (28 checked): Customization Service, Knox Analytics, DSMS, Device Quality Agent, Samsung network diagnostics and logs, Device ID Service (OAID), Google AdServices / On-Device Personalization / Federated Compute, Market Feedback, Partner Setup, preinstalled Meta apps…; optional: Bixby, Samsung Free, Android System Intelligence, Gemini | 22 (8 checked): Samsung account, Samsung Cloud, Experience Service, Samsung Push, Update Center, OMC Agent, KLMS, Google app; optional: Find My Mobile, Samsung Wallet/Pay/Pass, Galaxy Store, Device care, Google Play services, GSF, Play Store |
| Denied permissions | location of the Google app (+ optional: Samsung Internet, Weather) | microphone/camera/contacts of the Google app, Bixby; optional: background location and nearby devices of Google Play services, Samsung Health sensors |
| Restrictions | no adding users, no 2G, no unknown sources, no screen capture or content suggestions | + no adding certificates, no safe mode, no content sent to the assistant, UWB, Thread, Bluetooth sharing; optional: eSIM, USB transfer, NFC |
| Settings | permanent Bluetooth scanning turned off (`ble_scan_always_enabled=0`, if WRITE_SECURE_SETTINGS); Android backup re-enabled | backup left off |
| Private DNS | enforced to the enrollment host (`private_dns_host`), locked | same |

**What strict breaks** (checked by default): Samsung account, Galaxy Store, Samsung Cloud, Find My Mobile
(through the account), Samsung notifications, Google app / Assistant / Circle to Search, voice search,
safe mode, adding certificates (enterprise Wi-Fi). High-risk or critical items (Google
Play services, Play Store, payment, anti-theft, NFC) are **never checked by default**.

Data: `policy/src/main/res/raw/policy_catalog.json` (versioned, readable: package, publisher, role, risk,
known effect, method, profile), drawn from `../docs/research/android-platform.md` §7. An absent package is ignored.
Method: **hide** (`setApplicationHidden`, services stopped) for background agents, **suspend**
(`setPackagesSuspended`, greyed-out icon) for visible apps.

### Safeguards (hard-coded, stronger than the catalogue)

- **Deny list** of packages (`PackageDenyList`): `kgclient` and `sm.policy` (lock until a factory
  reset), OTA packages (`soagent`, `wssyncmldm`…), attestation (`rkpdapp`, `knox.attestation`),
  system modules (permissions, network, WebView, `ext.services`, `configupdater`), `diagmonagent` (restart
  loop), `securitylogagent`, Routines, Samsung keyboard, launcher, phone, SMS, emergency alerts,
  installers, Settings, SystemUI, `com.android.shell` (ADB), content providers, Watchpost; plus, read at
  runtime: launcher(s), dialer, SMS app, enabled keyboards, installers, active administrators, always-on
  VPN. Checked at preview **and** at the moment of applying.
- **Restrictions** (`RestrictionGuard`): only the keys of a **verified list** can be set (2G,
  unknown sources, adding users, content capture, certificates, safe mode, eSIM, UWB,
  Thread, NFC, Bluetooth sharing, USB file transfer, autofill). Any other key is
  refused, even if a catalogue lists it; in addition `no_debugging_features`
  (would cut ADB), `no_share_location`, `no_factory_reset`, accounts, app installation, mobile network,
  Wi-Fi, VPN… are explicitly forbidden. The USB data signal is never cut (no call to
  `setUsbDataSignalingEnabled(false)`).
- **Settings** (`SettingGuard`): `WRITE_SECURE_SETTINGS` allows writing any key
  (`adb_enabled`, `user_setup_complete`, `private_dns_mode`…); only `global:ble_scan_always_enabled` and
  `global:wifi_scan_always_enabled` are admitted.
- An applied item that a newer version of the safeguards refuses (or a package that became a launcher,
  keyboard…) is **undone** at the next application.
- An item already in place without Watchpost (package already hidden, restriction already set, permission already denied)
  is neither touched nor recorded: "Restore everything" therefore does not undo it.

### Enforced Private DNS

1. Watchpost first checks, from the phone, that the host answers: TLS handshake on port 853
   (system CA, name verification) **and** a DNS query within the session. Otherwise nothing is changed
   (`private_dns_set` `ok=false`, "pre-check").
2. `setGlobalPrivateDnsModeSpecifiedHost` (off the main thread); codes `HOST_NOT_SERVING` /
   `FAILURE_SETTING` reported; the mode is read back.
3. Optional lock `disallow_config_private_dns`.
   The lock is **off by default**: enforce the DNS first without the lock, check for a few days
   that the Internet works everywhere (Wi-Fi, mobile, captive portals), then lock.
4. **Fallback** (Settings › Device Owner): if the network is no longer validated **and** the host's DoT check
   (through its last known addresses) fails without interruption for 15 min (5 to 240), the DNS goes back to
   automatic mode to keep Internet access; `security.policy` sev. 2 (Wazuh alert). As soon as the host answers
   again, it is enforced again (adjustable). Trade-off: an attacker who blocks port 853 gets this fallback, but
   never silently; disabling the fallback makes protection take precedence (no more Internet while the server does not
   answer: "Restore everything" or the ADB rescue undoes it).
5. Restoring puts back the previous mode (`off` through `setGlobalSetting(private_dns_mode)`, automatic or the
   previous host).
6. If an unaffiliated user exists (guest, secondary user, Samsung maintenance mode), Android
   refuses the dedicated DNS APIs (`checkAllUsersAreAffiliatedWithDevice`): the fallback and the return to
   automatic mode then go through `setGlobalSetting(private_dns_mode)`, which has no such condition.

The fallback only runs if Watchpost's process is alive (foreground service, or the maintenance pass
every 15 min, without a network constraint). During the fallback delay, the phone has **no Internet**.

Permanent Wi-Fi scanning, Samsung diagnostics and the Google advertising ID have no setting key
whose effect is established (stored outside Settings since Android 11, or specific to Samsung/GMS):
not managed, to be turned off by hand (Settings › Location › Location services; Settings › Google ›
Ads). Always-on VPN: choose an installed VPN app ("block without VPN" option only to be used with
a reliable VPN).

### Undoing everything

- **Restore everything** (Policy screen, confirmation): first turns off the guards (section "Capability
  guards"), then undoes everything Watchpost applied, from the most recent to the oldest; an item that resists stays listed with its error (retry). The logs stay active.
  Each item is handled in isolation: a failure (including being unable to write the state, storage
  full) does not stop the following ones. A permission denied just before a crash, therefore never confirmed
  in the state, is restored too.
- **Unreadable state**: the applied state is read back record by record (a record
  unknown from another version does not make the others lost). If it was unreadable, even partly, "Restore
  everything" adds a **catalogue sweep**: catalogue packages hidden or suspended are shown again,
  catalogue restrictions and the DNS lock lifted, catalogue permissions denied given back to the user,
  Private DNS taken off the enrolled host. Nothing outside the catalogue is touched; a setting whose original
  value is unknown is flagged, to be restored by hand.
- **Remove Device Owner** (confirmation + "I understand" box): restore everything, turn off network
  and security logs, remove force-stop protection, `device_owner_cleared`, then
  `clearDeviceOwnerApp`. Stops before the removal if something could not be restored ("Remove
  anyway" possible). Also works with a non-testOnly APK. The removal is announced to the agent: no
  `agent.tamper` (see "Removing the Device Owner and uninstalling").

### ADB rescue without the interface

```bash
./scripts/rescue-revert.sh          # "Restore everything", Watchpost stays Device Owner (PowerShell: .\scripts\rescue-revert.ps1)
./scripts/rescue-revert.sh --sweep  # + catalogue sweep, if Watchpost's state is doubtful (PowerShell: -Sweep)
./scripts/remove-device-owner.sh    # + remove the Device Owner (= rescue-revert.sh --remove-owner)
```

The script sends an explicit broadcast to `…policy.rescue.RescueReceiver`. This receiver requires the sender to
hold `android.permission.FORCE_STOP_PACKAGES`, of `signature|privileged` level without the `development` flag
nor `appop` (checked in the android-37 framework manifest): no third-party app can obtain it, even through
`pm grant`. It is held by: the ADB shell (AOSP `packages/Shell/AndroidManifest.xml`, for `am force-stop`),
the system, and apps signed with the platform key or privileged and allowed by the manufacturer (so
preinstalled Samsung apps, never an app installed by the user). The receiver can only **undo**. Result returned
to `am broadcast`: 1 everything restored, 2 partial (detail), 3 Watchpost is no longer Device Owner (the script then checks
the state of the packages it had disabled), 4 timed out (the operation continues).
Exit codes of `rescue-revert`: those above, and 5 if Watchpost does not answer. With `remove_owner`, the role
is only given up if everything was undone (`force` to override, offered by the script).

Limits: the app is not "direct boot aware" (its state is in credential-encrypted storage): after
a reboot, the rescue only answers **after the first unlock**. It needs the app's
process to start: `WatchpostApplication` therefore tolerates an agent that does not initialize (the screen
shows the error, the rescue stays usable). If the app no longer starts at all,
`remove-device-owner.sh` offers the `dpm remove-active-admin` fallback (testOnly APK only).

### To verify on the phone before applying a profile

1. `dpm set-device-owner`, then the Policy screen: "Device Owner mode: Yes", logs active.
2. `./scripts/rescue-revert.sh` on an empty state (answer "Everything is restored (reverted=0…)"): the rescue
   works **before** you need it.
3. Private DNS alone (uncheck the rest): application, browsing, then cut the server to see the fallback.
4. A single low-risk package (e.g. Tips), "Restore", then the balanced profile; reboot; test
   push, Play Store, bank, payment; "Restore everything" and compare.
5. Only then the strict profile, item by item.

## Capability guards (contract §11.1)

**Policy › Guards** screen. A guard locks down a capability that malware needs, **whatever the vector** it came
through (for instance an app mass-sending phishing SMS without the SMS app showing anything). All of them are
**off by default**, enabled one by one after a **preview** that says exactly which application loses what, and undone by
"Restore" ("Preview and disable" button), "Restore everything", the Device Owner removal and the ADB rescue. Each
action emits `security.policy` (`profile = "guard:<key>"`, `action` ∈ `guard_enabled`, `guard_disabled`,
`permission_denied`, `permission_restored`/`permission_granted`, `quarantined`, `released`; `target` = package
or key of the guard; `permission` for a permission).

| Key | What it does (API) | Option | List |
|---|---|---|---|
| `sms` | `setPermissionGrantState(DENIED)` on `SEND_SMS` for every app that requests it | + `READ_SMS`, `RECEIVE_SMS`, `RECEIVE_MMS`, `RECEIVE_WAP_PUSH` | allowed apps (pre-filled: default SMS app) |
| `calls` | same on `CALL_PHONE` | + `ANSWER_PHONE_CALLS`, `READ_CALL_LOG`, `WRITE_CALL_LOG` | allowed apps (pre-filled: default dialer) |
| `accessibility` | `setPermittedAccessibilityServices(list)` | — | approved services |
| `input_methods` | `setPermittedInputMethods(list)` | — | approved keyboards |
| `quarantine` | `setPermissionGrantState(DENIED)` on SMS, calls, call log, contacts (`READ/WRITE_CONTACTS`, `GET_ACCOUNTS`), microphone, camera, background location, nearby devices (`BLUETOOTH_SCAN/CONNECT/ADVERTISE`, `NEARBY_WIFI_DEVICES`, `UWB_RANGING`, `RANGING`) for each **non-system app installed after activation** | — | — ("Release" app by app) |

### Real semantics of the APIs (sources: javadoc and AOSP code of `DevicePolicyManager`/`DevicePolicyManagerService`, main branch; SDK android-37 for the signatures)

- **`setPermissionGrantState`**: `DENIED` denies the permission and **locks** it in Settings ("controlled
  by the administrator"); an already granted permission is **removed** (Android then stops the app); the
  app's request fails without a dialog. The javadoc specifies that the user can no longer manage
  **the other permissions of the same group** either (their current state is kept): denying `SEND_SMS`
  also greys out the app's SMS group. `DEFAULT` hands control back without revoking. The system reads the state back and
  returns `false` if it is not reached (Watchpost reads it back too). A Device Owner targeting Q+ can act on all
  apps, system and privileged ones included (research §3.7); Watchpost **forbids itself** system apps. Permissions
  marked `SYSTEM_FIXED` are probably refused (not verified, irrelevant here).
- **`setPermittedAccessibilityServices` / `setPermittedInputMethods`**: list of **package names**; `null` =
  no restriction; empty list = system services only; system services/keyboards
  (`ApplicationInfo.isSystemApp()`) stay **always** permitted and cannot be restricted. A non-system service
  **already enabled** must be in the list, otherwise the call returns `false` and **nothing changes**
  (`checkPackagesInPermittedListOrSystem`): these guards **never disable** an already active service, they
  prevent enabling a new one. Watchpost therefore adds the already enabled services to the list as a matter of course
  and the preview names them ("kept, Android requires it"): to exclude one, disable it first in
  Settings, then re-apply. The Samsung keyboard (`honeyboard`) and the preinstalled Samsung accessibility services
  are system apps: always permitted.
- **Where are these two lists enforced?** (AOSP `android16-release`) In the **Settings screen**,
  not in the system services: the `PERMITTED_INPUT_METHODS` policy has `PolicyEnforcerCallbacks::noOp` as its
  enforcer (`PolicyDefinition.java`), `InputMethodManagerService` never reads it, and
  `AccessibilityManagerService` only consults it for shortcuts (`isAccessibilityTargetAllowed`); it is
  `RestrictedLockUtilsInternal.checkIfInputMethodDisallowed` / `checkIfAccessibilityServiceDisallowed` that greys out
  the switch. Consequences: (1) **no risk of ending up without a keyboard** — an already enabled keyboard
  keeps working whatever the list says, the system keyboard is always offered, including for the
  unlock passcode after a reboot, and if the approved keyboard is uninstalled Android switches back
  by itself to a system keyboard; (2) the guard only stops enabling **through Settings** (the only
  route for an app without `WRITE_SECURE_SETTINGS`), not `adb shell ime enable`; (3) One UI's Settings screen
  is Samsung's: whether it respects these lists is **to be verified on the device**.
- **Role and denied permission** (`Permissions.grantSingleAsUser` of the Permission module): when an app becomes the
  default SMS app or dialer, Android grants it the role's permissions **except those a policy
  has set to "denied"**. An app the guard was denying and that becomes the default SMS app would therefore stay
  without `SEND_SMS` (and, with the option, without `RECEIVE_SMS`: incoming SMS would be lost). Watchpost therefore grants
  these permissions itself by lifting its denial (see "Role that changes").
- **Loss of the Device Owner role** (`clearUserPoliciesLocked`): Android then removes the "set by
  policy" flag from **all** permissions and the two lists disappear with the administrator. Nothing stays
  locked; denied permissions stay ungranted but the user manages them again. Watchpost's
  records, however, stay: if the role is given back later, the guards still noted as active are
  **re-applied** at the first pass (each denial no longer in place is redone, see "Persistence").
- **Other users**: all this only applies to the primary user. An app installed in
  Secure Folder, a cloned profile (Dual Messenger) or a second user is neither denied nor put in
  quarantine (a Device Owner in principle prevents creating these spaces: to be verified).

### Safeguards (hard-coded)

- Never touched, whatever the list: Watchpost and its companion, **any system app** (`FLAG_SYSTEM`:
  emergency SOS, carrier, Samsung) and the policy's deny list. In addition, **only the holder of the
  corresponding role** (contract §11.4): the default SMS app for the `sms` guard, the dialer (default and
  system) for `calls`. A **keyboard or home screen** chosen by the user is spared by
  **no** guard (`sms`, `calls`, `quarantine`): "choose a home app" is a tap that malware
  can ask for, and none of these roles needs SMS or calls. Neither are active administrators,
  nor any app able to be a launcher.
- **Role that changes** (checked at each package broadcast, at a dialer change, when the screen opens,
  every 15 min, and by re-reading the holders **every 10 s**
  while a per-package guard is active and the phone is awake: no broadcast tells a
  third-party app about a change of SMS app, keyboard or home). The new holder has its denials lifted.
  If it is the SMS app (SMS guard) or the dialer (Calls guard), it **enters the list** ("the list follows",
  `agent.config_changed`) and the SMS and call permissions that its role would have given it are
  **granted** (`permission_granted`); microphone, camera and contacts stay on the usual request.
  A guard's list only follows its own role. A **priority notification** (channel "Guards: SMS app or
  dialer changed", shown at the top of the screen and on the lock screen) says so, with the package name.
- **Quarantine and role** (a decided choice): a quarantined app designated default SMS app or dialer
  **stays in quarantine**; only the permissions of that role are given back and granted (without them, incoming SMS
  or calls would be lost silently), contacts, microphone, camera, location and nearby devices
  stay denied, and the priority notification says so. Reason: getting designated default SMS app is
  precisely the route of SMS trojans; an automatic release would also open the address book to them
  (propagation). If it loses the role, the role's permissions are denied again. The
  user releases it when they trust it. A keyboard or a home screen stays in quarantine.
- A failure on a package gives `permission_denied` `ok=false` and does not stop the others; it is not retried at
  each pass (no burst of events), but at the next "Preview and re-apply".
- Two items that deny the same permission (SMS guard and quarantine, or a catalogue permission) share
  it: the one that is undone last restores it, to its original state.
- **Persistence**: the same state as the rest of the policy (`watchpost_policy`, `commit()` before each
  change). `guard:<key>` records (the guard is active, its option, the list in force, the list
  from before Watchpost for accessibility/keyboards, the released apps) and `guard:<key>:<package>` (the
  denied permissions and their previous state). "Restore everything" **first turns off all the guards** (none can
  deny again what has just been given back if the process dies in the middle), then undoes the rest. Unreadable
  state: the sweep gives back to the user any guard permission denied without a record on a
  non-system app (`DEFAULT`: it is not re-granted, the app will ask again) and lifts the accessibility and
  keyboard lists.
- **Reconciliation on each pass** (`CapabilityGuards.settle`): before using a package record,
  Watchpost compares it with the device. (1) A record left "in progress" after a crash: a permission
  denied on the device without having been confirmed is confirmed (its previous state is noted, so it will be
  restored), one that had not been reached is denied now. Without this, an interrupted guard would stay half applied
  (quarantine included) and a re-application would forget the unconfirmed denial: the permission would stay
  denied and locked with neither "Restore" nor "Restore everything" giving it back. (2) A noted denial that is no longer
  in place (app uninstalled then reinstalled between two passes, Device Owner role lost then given back): it is
  redone, with the state from that moment. Without this, the reinstalled app would keep the permission requestable
  while the screen said it was denied or in quarantine.
- Watchpost's screen hides other apps' overlay windows (`setHideOverlayWindows`, normal permission
  `HIDE_OVERLAY_WINDOWS`): an overlay cannot hijack a tap on "Release" or "Disable".
  App names (chosen by the apps) are shown on a bounded line, without control or
  writing-direction characters, always with the package name.
- The list chosen in the screen only takes effect at "Preview and (re-)apply" (the screen flags a
  modified list). The lists are "package list" settings (`policy.guard.<key>.allowed`): each
  modification emits `agent.config_changed`.

### When they apply

At activation (apps present, except quarantine), then at each `PACKAGE_ADDED`/`REPLACED`/`REMOVED` received by
a dynamic receiver of `:policy` (independent of the `apps` collector), at agent start, when the
screen opens and at the maintenance pass (15 min). An update that adds a guarded permission is therefore denied
right away. Quarantine: an app is "new" if its `firstInstallTime` (kept by updates, reset by
a reinstallation) is after the activation; a released app stays so until
it is uninstalled.

### What the guards cannot prevent (frankly)

- **Race window**: between installation and denial, a few seconds if Watchpost is running, **up to 15 min**
  if its process was stopped. A freshly installed app cannot run before being launched
  (Android's "stopped" state), but an app that installs and launches another one can.
- **System apps** and **default SMS app / dialer**: never touched. Malware that gets
  itself chosen as default SMS app (system dialog, **a single tap**) sends SMS: Watchpost
  **flags** it (notification, `app.role` on the collectors side) but does not block it, and adds it to the list. This is the
  classic route of SMS trojans: **the SMS guard only closes the "permission request" route**; for
  the "default app" route, Watchpost **flags** (priority notification) and does not block. A keyboard or home screen
  is no longer spared (contract §11.4).
- **Accessibility service already enabled**: it taps in place of the user, including in Watchpost (turning off
  a guard, releasing a quarantine, "Restore everything") and in the SMS app. Watchpost's screen does not ask for the
  unlock passcode before these actions (a possible future improvement).
- **Frozen permission group**: denying `SEND_SMS` or `CALL_PHONE` to an app also prevents the user from
  granting or removing the other permissions of the same group (SMS; Phone: phone state, numbers);
  they keep their current state. Background location forms a subgroup distinct from "while in use"
  location in AOSP's permission controller (to be verified on One UI).
- **Counting SMS**: no guard limits the *number* of SMS of an allowed app, and without `app.ops`
  (experimental) nothing counts them (see `../server/collector/README.md`, "What the detections do not see").
- **Other routes**: an SMS prepared by an app and sent by the SMS app (you have to tap Send… or an
  accessibility service does it: hence the Accessibility guard); a call through the dialer; VoIP, Internet
  messengers; network exfiltration (see the collector's detections); overlay, notification listening,
  device administrator (app-ops and special access, outside `setPermissionGrantState`).
- **Already acquired**: an accessibility service or keyboard already enabled stays enabled; what was sent
  before activation is gone. Quarantine does not touch apps already present.
- An app on the list, or released, that is compromised afterwards.
- Since Android 13, an app installed outside a store already cannot enable accessibility unless
  the user unlocks "restricted settings": the Accessibility guard also covers store apps and the case where
  the user is being manipulated.

### Order to try on the phone (from least to most risky) and checks

None of this has been run on a device. First of all: `rescue-revert` on an empty state (see "ADB rescue").

1. **Quarantine** (no immediate effect). Install a small test app (APK or store): notification
   "New app in quarantine", Settings › Apps › app › Permissions: SMS, contacts,
   microphone… greyed out "controlled by the administrator"; "Release": the app asks again. Update the
   released app: no new quarantine. Check `quarantined`/`released` in the console.
2. **Keyboards** (empty list): the preview must list the third-party keyboard that may be enabled as "kept".
   Check: normal typing, including the PIN after a reboot (Direct Boot: Samsung keyboard);
   Settings › General management › Keyboard: an unapproved keyboard appears as not enableable.
3. **Accessibility** (empty list): services already enabled kept; Samsung TalkBack/Voice Assistant still
   enableable; a non-enabled third-party service no longer is ("disabled by the administrator").
4. **Calls** without the option: preview (**rarely empty**: `CALL_PHONE` is requested by many apps —
   messengers, banks, maps, watch, car; each app that had obtained it is stopped when the
   denial happens); call from the dialer and from the Samsung address book;
   emergency call (do not actually dial: only check that the dialer opens).
5. **SMS** without the option: preview (third-party apps that request `SEND_SMS`); send an SMS from Samsung
   Messages; emergency SOS intact (system app); change the default SMS app and check the notification
   "Warning: default app changed" and the list.
6. Only then the **options** (SMS reading: autofill of codes received by SMS in third-party
   apps stops; call log).
   With an SMS or Calls guard active: **change the default SMS app** to an app the guard was
   denying, check within 10 to 20 s the notification, that the app sends and receives without asking for anything,
   then go back to the original app. Quarantine guard: pairing a watch or earbuds whose app
   has just been installed fails until it is released.
7. After each step: "Restore everything", check that the previous state comes back (the app's Permissions,
   keyboards, accessibility); then `rescue-revert` with a guard active, and `remove-device-owner` last.

## What is verified, what is not

Verified with JVM tests and build checks on Linux, without an emulator or a device:

- `./gradlew lint test assembleDebug assembleRelease` succeeds (lint: 0 errors, style warnings
  `UseKtx`/versions only).
- 392 JVM tests, 0 failures, 5 skipped (the cross-checks against the real collector, which need environment
  variables: `CrossServerTest`, the three of `CrossCommandsTest` and `CrossDetectionsTest`): `:core` 142,
  `:collectors` 146, `:policy` 93, `:app` 11. What they cover:
  - `:core`: Room buffer on JVM SQLite (sequence after a restart, interrupted transaction, severity/age purge,
    non-monotonic origin timestamp); upload against MockWebServer (all the codes of the contract, gzip,
    batches, 1 MiB, Wi-Fi, resume); exact serialization of §1; `.watchpost` files and mTLS with pinning;
    isolation of collector failures; announcement of the Device Owner removal; package-list settings; the
    remote commands (see "Remote commands"); the test bench.
  - `:collectors`: the logic of each collector and its conformance to the contract, including the robustness of
    the `appops` parser (3,000 mangled or random entries, out-of-range numbers, 100,000 entries), the risk
    scoring and the notification masking.
  - `:policy`: translation of the security log, network logs, posture, the policy engine against a fake
    gateway, the catalogue, DNS; 26 tests for the guards (application, exceptions, newcomer, update, role
    change, partial failure, safeguards, "Restore everything" after the 32 combinations of guards, crash at each
    of the first 8 changes, crash during "Restore everything", unreadable state, quarantine then release, crash
    then re-application then disabling, interrupted guard and quarantine finished at the next pass, denial that is
    effective but reported as a failure, uninstall then reinstall between two passes, home screen spared
    without entering the list, role permissions granted to the new dialer); the remote-command matrix.
  - `:app`: end-to-end contract conformance of the 25 collectors, including `agent.heartbeat.collectors`; hostile
    app names; conformance of `command.result`.
  - Cross-check `CrossDetectionsTest` (skipped without `WATCHPOST_CROSS_ENROLL` and `WATCHPOST_CROSS_URL`): the
    real code of `app_risk`, `app_role`, `app_ops` (parser and differences included), `apps` and `special_access`
    tells an SMS-fraud story to the real collector, which accepts everything and produces
    `detect.new_app_risky` (×2), `detect.sms_abuse` and `detect.sensor_background` (run once against a local
    collector).
- Release APK: signed with scheme v3 (`apksigner verify`); after R8, manifest classes, the Room database
  (`OutboxDatabase_Impl`), workers and generated serializers of all `@Serializable` classes present
  under their name (`apkanalyzer dex packages`); `raw/policy_catalog` catalogue and `xml/device_admin` kept
  by resource shrinking (`aapt2 dump resources`). The R8 code itself has not been run.
- Merged manifest (`aapt2 dump permissions`): no permission or service for notification listening,
  accessibility, SMS, call log or overlay; each declared permission is used
  by a module (the three that can only be granted over ADB: `PACKAGE_USAGE_STATS`, `WRITE_SECURE_SETTINGS`,
  `DUMP`). Also `HIDE_OVERLAY_WINDOWS` (normal), to hide other apps' overlays
  while Watchpost's screen is displayed.
- Bash scripts: syntax checked (`bash -n`), compared with the code (package, components, rescue
  action, `-t` option).

**Not verified** (no device): all the behavior on a phone — Device Owner activation on One UI,
permission self-grant, `setUserControlDisabledPackages`, Device Owner removal and absence of
a false alert, start at boot and 24 h service survival, real import into the Android Keystore and TLS
handshake with a Keystore key (Conscrypt), broadcast reception, real network and security logs, GPS and
significant-motion sensor, battery consumption, interface rendering, CT disabled through
`network_security_config`, policy (profiles, Private DNS, fallback), ADB rescue. The bash rescue,
installation and copy scripts were run against a fake `adb` (never against a phone);
the PowerShell scripts were compared line by line with the `.sh` files but were neither run nor parsed by
PowerShell (not available on the machine used). Robolectric could not be used (its Android jars could not be
reached from the build machine): Android classes are replaced by stubs
in the tests; the types produced only from an Android callback (screen, battery, location…) are
verified by reading, not by test.
