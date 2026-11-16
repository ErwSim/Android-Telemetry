# 05 — Operations

This guide says how to live with Watchpost once it is installed: reading the console (including the Detections,
Tracking and Commands pages), understanding the Wazuh alerts, using AdGuard Home, updating, and knowing when the agent
has stopped sending. It assumes guides 01 to 03 are done. The question "am I protected against software that sends
SMS without my knowledge?" has its own guide: [guide 08](08-sms-and-malware.md).

> **Verification status.** The console, Wazuh and AdGuard were tried with **simulated** data (the collector's
> simulator) and never with a real phone. The "expected false positives" below are **deduced from the logic of the
> rules**, not observed: adapt them to what you actually see (guide 06).

## 1. Recommended rhythm

| When | What |
|---|---|
| Every day (one minute) | console › Overview: last contact, **detections banner** ("Nothing to report" or the number of detections by severity), alerts; without notifications configured (§3), **nothing warns you** |
| Every week | console › Alerts (7 days) and Security › Posture; AdGuard's query log (unexpected blocked domains); the VPS's disk space |
| Every month | `sudo ./backup.sh` + an encrypted copy off the server; VPS system updates; review of the application inventory |
| Every six months | `sudo ./update.sh` (pinned images); a test restore of a backup; check that the keystore backup is readable |
| Before the expiry (2 years) | renew the phone's client certificate (§8); `sudo ./enroll.sh --list` flags "renew" within 30 days |

## 2. The Watchpost console

`https://console.<your domain>`. Session of 12 hours of inactivity; password attempts are rate-limited. At the top:
the **device selector**, a **green/red "last contact" dot** (green if less than 35 minutes: two missed 15-minute
heartbeats plus a margin), the theme, log out. Each page offers a period (selector) and a "Refresh" button.

| Page | What you see there |
|---|---|
| **Overview** | at the top, the **detections banner** (§2.1); "Device state": last contact, battery, buffer waiting, Device Owner, agent version, lost events, state of each collector, state of the command channel; last position; security posture (summary); activity over the last 24 hours; latest events of severity 2 or more; latest Wazuh alerts. A warning banner appears if there has been no contact for more than 35 minutes. |
| **Detections** | the collector's explained verdicts (§2.1): one card per detection |
| **Map** | trace of positions over the period, selected point, summary, and **data gaps** ("phone off" or "no fix": the map cross-references the trace with activity). Positions come from the GPS and the passive provider: indoors, there may be few points. **The base map is loaded from OpenStreetMap tiles by default: OpenStreetMap sees your IP address and the areas you look at** (§9). |
| **Events** | all the events, filterable by severity (0 info to 3 critical), by text (package, domain, SSID…) and by type (prefixes separated by commas, e.g. `net.,security.log`). Tap an event to see all its data. |
| **Network** | "Google / Samsung share" (DNS and applications), most requested DNS names, destinations (connections), most active applications, **data volumes per application**, timeline. The DNS names and connections **per application** come from the Device Owner's network log: they arrive in batches (up to 1 h 30 late) and do not cover UDP/QUIC or hard-coded IPs. |
| **Tracking** | what is blocked or allowed, towards whom, from which application, and what to do (§2.2) |
| **Applications** | tabs **Risk** (§2.4, the first), Inventory (state, installer, dangerous permissions, updates; "Outside a store" = installed from outside the Play Store/Galaxy Store; filters Disabled, Suspended, Hidden), **Sensitive operations** (`app.ops`, experimental: empty as long as that collector does not work), Dangerous permissions, **Special access** (accessibility, notification listeners, administrators, overlay, unknown sources, usage access, VPN, default apps), Notifications (companion), History. An **application sheet** (from the risk tab, the inventory, the detections) gathers profile, roles, detections, permissions, operations, domains contacted and installation history. |
| **Commands** | remote commands (§2.3) |
| **Security** | tabs Posture (current state and history of changes), **Default roles** (SMS app, dialer, keyboard, home, browser: state and history of changes), System log (`security.log`), Camera and microphone, Unlocks (failures), CA certificates (added by the user), Cellular and BLE (2G, trackers), Policy applied (`security.policy`). |
| **Alerts** | Wazuh alerts over the period, filterable by level. "Wazuh not configured" means that the collector cannot reach the indexer (abnormal with this installation: `sudo docker compose logs collector`). |

Limits to keep in mind: the "top" statistics and hourly timelines are aligned on whole UTC hours; a late event
changes counters of hours already past; the console does not display events older than the retention (§7).

### 2.1 The Detections page and the verdict banner

A **detection** is an explained verdict computed by the collector from the data received ("application X did Y, here
is why it is suspicious, what may be innocent about it, what to do"). A card shows: severity, type, application (name
and package), time, a sentence on what was observed, the evidence, then (expandable) why it is suspicious, the
innocent explanations, what to do, links (application sheet, domains in Tracking, traffic in Network, Camera and
microphone) and a reminder of the **guard** that answers the risk: guards are set **only on the phone**. Filters:
type, severity, period. New detections arrive live; one detection **per application, per type and per day** (24 h
after installation for a new application), updated in place.

**The verdict banner tells the truth**: "Nothing to report" is not a guarantee. It always recalls what is monitored
(SMS-sending permission held, change of default SMS app, threat domains, large uploads, connections, new risky
applications), shows "**Not monitored here**" for the sending of SMS themselves and for background microphone and
camera use as long as the experimental "Sensitive operations usage" collector is not "running", and recalls that **the
application's SMS guard is the real protection**. Detections are **hints**, not proof.

| Detection | When | What to do | Predictable false positives |
|---|---|---|---|
| `threat_domain` | an application requested a domain blocked by a **threat** list (phishing, malware, command servers) | identify the application (Network, Tracking pages), uninstall it or quarantine it; browser: phishing link followed, check that no password was typed; **never allow** the domain | a browser that followed a link (reduced severity) |
| `sms_permission` | an application that is neither the SMS app nor a system one **holds** `SEND_SMS` | find out why; otherwise remove the permission or uninstall; SMS guard (guide 08) | **initial review**: visual voicemail, carrier application, connected watch, number verification |
| `default_app_changed` | the default SMS app (3), dialer, keyboard or assistant changed | if it was not you: put your application back, uninstall the intruder (guide 04, case E) | a new messenger or keyboard that **you** chose |
| `new_app_risky` | an application installed less than 24 h ago is high risk or obtains a sensitive capability | check the installation was wanted; otherwise uninstall | **any** new legitimate tool that obtains a tracked capability: VPN, password manager (accessibility), **new watch application** (notifications), new SMS app; parental control, antivirus, automation |
| `sms_abuse` | (with `app_ops`) sending, or a refused attempt, of SMS by an application other than the SMS app, or volume > 200 per day | SMS guard, uninstall, carrier bill | visual voicemail, watch application |
| `sensor_background` | (with `app_ops`) microphone or camera in the background above a threshold | remove microphone and camera, uninstall; if the application is an administrator, remove that right first | a recorder or video-call application left running |
| `upload_spike` | massive upload of data within an hour (> 1 GiB and > 10 × the median) | backup or video: nothing; otherwise (a "vault" gallery, an unknown application) possible exfiltration: uninstall, change the exposed passwords | **first photo backup**, backup to Drive, **an hour-long HD video call** (≈ 1.3 GiB), tethering |
| `fanout` | hundreds of distinct addresses contacted within an hour (300, 100 with the screen off) | relay or proxy (your connection resold): uninstall | podcasts or RSS feeds refreshed at night, a BitTorrent client, very dense browsing |
| `mail_ports` | an application that is not a known mail client connects to ports 25, 465 or 587 | spam sent from the phone: uninstall | **an unlisted mail client** (e.g. Yandex Mail): add it (`WATCHPOST_DETECT_MAIL_CLIENTS`) |
| `dns_bypass` | an application connects to a public DNS resolver (ports 443, 853): it escapes filtering | browser with "secure DNS": turn it off, or exempt the application | **browser with encrypted DNS** (Firefox, Chrome), Telegram, VPN applications, Tailscale: one per application per day, indefinitely |
| `inventory_mismatch` | an application declared "system" while its installer says otherwise (Wazuh alert 100481, level 12) | serious: the agent or the device may be lying; look at the agent's state and the posture | — (cannot be muted) |
| `flood` | more than 200 detections in the day for a device | incoherent data or compromised device: look at the agent and the posture | — (cannot be muted) |

**Muting.** On a detection (or on the application sheet), **"Stop reporting for this application"**, with an optional
reason. The confirmation says it: the detection **stays computed and recorded**, but is **no longer sent to Wazuh nor
notified**, and the console collapses it ("Show muted detections (N)" box); it does not count in the verdict. The
"Current mutes" card lists the mutes with their reason, who and when, and their lifting. **Cannot be muted**:
`sms_abuse`, `default_app_changed`, `inventory_mismatch`, `flood`. Every mute and every lifting is an event
(`detect.muted`, `detect.unmuted`, Wazuh alert): a mute you did not set means that someone used your console (change
the password). Global settings (thresholds, exempted applications, mail clients): `WATCHPOST_DETECT_*` variables in
`infra/.env`, see `infra/README.md` §7.4, then `sudo ./install.sh --yes`.

A **recurring** detection (same application and same type already reported within 30 days) is marked "Already
reported, recurring" and its severity is capped at 1.

### 2.2 The Tracking page

It answers "what is blocked or allowed, towards whom, from which application, and what do we do about it". It shows
whom the phone talks to, how much and from which application, **never the content** (encrypted). Three areas:

- **Summary by publisher** (Google, Samsung, Meta, Microsoft, Amazon, TikTok/ByteDance, advertising and audience
  measurement, others): requests, blocked, allowed, domains, applications, bytes sent and received. **The bytes per
  publisher and the blocked/allowed counts per application are estimates** (distributed in proportion to DNS
  requests).
- **Domains and Applications tabs**: each domain with its status (blocked, allowed, mixed), the reason (responsible list) and
  the applications that request it; **Block**, **Allow** and **Reset to default** buttons (a rule written in AdGuard,
  in a block managed by Watchpost; your manual rules are not touched). Essential domains (connectivity check, push
  notifications, updates) are blocked only after a confirmation that says what the block would break
  (`409 essential_domain`). **Allowing** a domain weakens blocking: every action is an event (`tracking.override`;
  Wazuh alert of level 8 for an allow, 3 for a block).
- **Blocking level**: **Permissive** (threat feeds and obvious telemetry, no general advertising list: to troubleshoot
  a stubborn application), **Balanced** (default), **Strict** (Multi PRO++ and strict lists). Changing the level turns
  on exactly the level's lists in AdGuard; lowering it is a weakening (event `tracking.level_changed`, Wazuh alert of
  level 8). The command-line equivalent: `sudo ./install.sh --profile permissive|balanced|strict --yes`. The level "in
  force" is the actual state of AdGuard's lists; `install.sh` and `update.sh` keep it. **This level is independent of
  the application's profile on the phone.**

If AdGuard is unreachable, the page says so and disables the actions ("adguard: false"); the aggregates already
recorded remain displayed, with a warning.

### 2.3 The Commands page

It drives the remote command channel (guide 03, §15). **Prerequisites on the phone side**: channel on, passphrase set.
The "Command channel" card says whether the phone is connected (permanent mode) or its last contact (polling).

- **Simple actions** (no passphrase, valid for 1 hour): Ring (with or without vibration), Vibrate, Stop ringing,
  **Locate now** (the position arrives through the stream and is shown on the page's map and the Map page).
- **Sensitive actions** (command passphrase, typed every time, **never sent to the server**: the key is derived and the
  signature computed in the browser): Lock with a message (valid for 7 days by default), Clear the message.
- **Danger zone**: Erase the phone, in three steps (an explanation and a reminder that erasing must be allowed in the
  application; the device name to retype; the passphrase). Valid for 15 minutes by default, 24 hours at most.
- **History** (updated live): states pending, delivered, executed, failed, refused, expired, cancelled. A command
  **delivered and then expired with no reply** is shown as "Expired without a response" (it may have been executed); only a
  command never delivered is called "never executed". **Cancel** binds only the server: a signed command already
  delivered remains executable until it expires. The limits are 20 commands per hour and 10 pending per device.

A wrong passphrase is refused by the **phone** (`bad_signature`): the console cannot check it. WebCrypto requires
HTTPS: otherwise the page disables the sensitive commands. If your computer's clock is off by more than 10 minutes,
creation fails ("this computer's clock is off").

**Type the passphrase in a console that you open from a trusted computer.** The page is served by the server: if you
doubt it, do not enter the passphrase (guide 04, case F). A lead outside this repository: sign from a copy of the
console kept off the server.

### 2.4 The Risk tab (Applications)

Every application receives a score from 0 to 100 and a level (low 0-29, medium 30-69, high 70-100) according to its
**declared capabilities** (requested permissions, components, installer, absence of an icon, start at boot…), with
the reasons explained and "often legitimate because…", and the `combo_*` combinations (banking trojan, SMS fraud,
stalkerware) in red and at the top. "Granted" or "requested, not granted" tells intent from state. **It is an
indicator of attention, not a verdict**: a legitimate **parental control, antivirus, automation or caller-identification
application comes out "high"**, and a discreet piece of malware published on a store can come out "low". System
applications and Watchpost are capped at "low". The score stays high when a guard prevents the grant.

## 3. The Wazuh alerts

Interface: `https://siem.<domain>` (two logins, guide 01). Three dashboards are provided: **"Watchpost — phone
security"** (alerts over time, by rule, by ATT&CK Mobile technique, list, map of positions), **"Watchpost — tracking
and DNS"** (applications that contact telemetry, blocked domains, events by type) and **"Watchpost — detections and
apps"**, which shows detections by type and application, medium- or high-risk applications, the denials and the
actions of the guards. The alerts are in the `wazuh-alerts-*` indices (level 3 and above), **all** events in
`wazuh-archives-*`. Useful fields: `rule.level`, `rule.id`, `data.watchpost.type`, `data.watchpost.data.*`. For the
**real** time of an event, use `data.watchpost.ts`: the indexed time (`@timestamp`) is the arrival time, and history
sent late arrives "all at once".

**Notifications (off by default).** As long as you have configured nothing, a serious alert is seen only by opening the
console or Wazuh. To be warned, fill in `infra/.env` with an ntfy-compatible webhook and/or an SMTP relay, then
`sudo ./install.sh --yes`:

| Variable | Purpose |
|---|---|
| `WATCHPOST_NOTIFY_LEVEL` | minimum Wazuh level notified (**10 by default**); the **agent's silence** (rule 100301) and the sequence reset (100305) are always notified |
| `WATCHPOST_NOTIFY_URL` | webhook: `POST` of a JSON `{"title","message","priority","tags"}` |
| `WATCHPOST_NOTIFY_TOPIC` | ntfy topic (with ntfy, `WATCHPOST_NOTIFY_URL` is the root of the server, for example `https://ntfy.sh`) |
| `WATCHPOST_NOTIFY_TOKEN` | optional token (`Authorization: Bearer …`) |
| `WATCHPOST_NOTIFY_SMTP_HOST`, `_PORT` (587), `_TLS` (`starttls`, `tls` or `none`), `_USER`, `_PASSWORD`, `_FROM`, `_TO` | e-mail through your mail provider's SMTP relay |

**Threshold**: 10 by default. The alerts "SMS permission granted" (100161) and "new default SMS app" (100511) are level
8 and are therefore **not notified** by default: lower `WATCHPOST_NOTIFY_LEVEL` to **8** to receive them (at the cost of
a few more alerts; guide 08). At the default threshold the following are notified, among others: threat domains
contacted, SMS fraud (`sms_abuse`), an SMS permission held by another app (`sms_permission`), the change of default SMS
app (`default_app_changed`), microphone or camera in the background, a recent application that obtains serious
capabilities, spam, the detection cap, escalations and correlations (13); lock and erase requested or executed, an
invalid signature, the channel locked; **not** upload spikes, the address fan-out, DNS bypass, detection updates or
traces (`infra/README.md` §8.5). The message contains the rule title, the level, the device name, the event type and
the times: never the raw log, nor the event's data (position, identifiers), nor a secret. **It goes to a third
party**: with ntfy, a public topic is readable by anyone who knows its name, so choose it long and random, or use your
own ntfy server with a token. `install.sh` says on its last line whether notifications are active. Verified with a
local receiver (webhook and plain e-mail); **SMTP with TLS and authentication, and a real ntfy server, have not been
tested**: run a trial (for example by temporarily lowering `WATCHPOST_NOTIFY_LEVEL` to 3, which is a suggestion of this
guide, then putting it back). Device certificate expiries are not notified: `sudo ./enroll.sh --list`.

Rule families (identifiers 100100 to 100549; details in `infra/README.md` §7.2) and first gesture:

| Family | Examples (level) | What to do |
|---|---|---|
| **Agent** | `agent.tamper` tampering (12), collection or upload disabled (5), buffer saturated (6), stop (3) | Did you cause it (switch, removal, update)? If not, look at the detail (`kind`: `force_stop`, `permission_revoked`, `admin_disabled`, `device_owner_lost`…), check the phone, then the system log. |
| **Absence** | no event for 60 min (7), resumption (3), sequence gaps (6, or 3 if explained by a purge), counter gone backwards (8) | Phone off, offline, private DNS unreachable (the agent no longer resolves `ingest.…`), agent stopped? See §5. |
| **Posture** (one alert per field changed) | verified boot degraded (12), encryption lost (10), Device Owner lost (10), private DNS disabled/non-strict or towards an unexpected host (10), wireless ADB (9), lock removed (8), ADB (7), unknown sources (6), Play Protect (5), developer options (4) | A setting change you did not make is the important signal. Reread Security › Posture; put the setting back; for a non-strict private DNS, see whether there was a fallback (severity-2 `security.policy`). Security patch older than 3 months (6) or 6 months (9): update. |
| **Sensors** | microphone or camera used while the device is locked (10), microphone outside a call (6) or camera (8) with the screen off, any use flagged (2) | Who? Watchpost **does not know**: cross-reference with `app.foreground` and the network traffic of the same minute (Applications, Network), look at the dangerous permissions (Applications), revoke or uninstall the suspect application. |
| **Apps** | installed from outside the Play/Galaxy Store (8) or with no installer/ADB (8), new accessibility app (10), device administrator (10), notification listener (8), VPN (7), sensitive permission granted (5) | Do you recognise the application? Applications › Special access; remove the access or uninstall. Accessibility and administrator are the most serious. |
| **Security** | user CA added (10), repeated failed unlocks (10), `security.log`: ADB shell (10), ADB command or transfer (8), logging stopped (12), key integrity violation (12), restriction removed (5)… | A CA you do not know about allows interception of encrypted traffic: remove it (Settings › Security). Unlock failures: someone tried your phone. |
| **Network** | null cellular cipher (12), 2G downgrade (10), BLE tracker following (10), mock location (9), open Wi-Fi (4), network without private DNS (5), time change ≥ 1 h (5), USB with ADB (5) | Tracker: look at the map and the `net.ble_tracker` event (tracker type, duration) and look for it physically. Mock location: a simulation application is installed. |
| **Tracking** | DNS request by an application towards Google/Samsung telemetry (2, **without an alert**, tagged for the dashboards) | Nothing: it is statistics ("tracking and DNS" dashboard). |
| **AdGuard** | threat-feed domain requested (10), repeated (12), burst of blocks (5) | Which application? AdGuard's log shows only the phone: look for this domain in the console's `net.dns` events (Network page, or Events page with the domain in the text search) to find the package. Burst: an application insists (telemetry in a loop); assess it. |
| **Remote commands** | erase requested (12) or executed (12), lock requested (10) or executed (10), invalid signature `bad_signature` (10), channel locked `locked_out` (12), command refused (5), failed (6), burst of 8 commands in 10 min (8) | A command that **you** did not issue is a serious signal: guide 04, case F (change the passphrase **on the phone**, turn off the channel). `bad_signature`: someone is trying to command the phone without the passphrase (or you mistyped yours). |
| **Guards** (`security.policy`, `guard:…`) | guard **disabled** (8), quarantine release (5), activation, quarantine, permission given back (3), permission denied (2), failure (5) | A guard disabled that you did not disable: someone (or an accessibility service) touched Watchpost; look at the Policy screen's action log. |
| **Collector detections** (`detect.*`) | from 3 (trace) to 12; **13 when several detection types target the same application within 24 h**; a detection update: 5; "detection escalated": 12 | See §2.1 for each type. |
| **Risk profile and roles** (`app.risk`, `app.role`) | high risk at installation of an application (9, or 11 with a `combo_*` combination); new default SMS app (8), keyboard (8), dialer (7), assistant or autofill (7); SMS permissions granted (8) | Recognise the application; otherwise guide 08 and guide 04 (case E). |
| **Tracking** (`tracking.*`) | level lowered (8), domain allowed (8), forced block of an essential domain (6), manual block removed (5), other (3) | Check that it was you (the console); otherwise change the console password. |
| **Fallback** | severity 3 or 2 reported by the agent for a type with no dedicated rule (10 / 6) | Read the event. |

### Expected false positives (deduced from the rules, to be confirmed in use)

- **ADB alerts** (shell, command or transfer, USB with ADB, ADB and developer options in the posture): every time you
  use the repository's scripts. This is normal operation.
- **Application "with no installer/ADB"** at every Watchpost update through ADB.
- **Absence**: phone off, empty battery, a long night with no network.
- **Counter gone backwards / sequence gaps** after an unenroll/re-enroll or a reinstall.
- **Loss of the Device Owner and `agent.tamper`** after an emergency removal through `dpm remove-active-admin`
  (expected). A removal through the application or through the normal script is announced and does **not** trigger
  `agent.tamper`.
- **Non-strict private DNS** during a private DNS fallback, or when you change a setting yourself.
- **BLE trackers** on public transport (a neighbour's tracker moves with you), **2G** in a basement or a dead zone (if
  2G is not forbidden), **open Wi-Fi** in a hotel, **microphone outside a call** with a voice assistant or a recorder
  you started.
- Limits of the rules: an event triggers only **one** rule; a microphone used with the screen off during a call
  (source `voice_communication`) does not alert; a defect already present at enrollment produces no alert.

## 4. AdGuard Home

`https://adguard.<domain>` (two logins). At every `install.sh`, Watchpost applies again the configuration it manages
(`admin` account, TLS and DoT, Quad9 and Mullvad upstreams, DNSSEC, the log read by Wazuh, the profile's lists) and
**keeps the rest**: custom rules from the interface, added lists, allowlists, clients, DNS rewrites, rate limiting, log
duration. `sudo ./install.sh --reset-adguard` regenerates everything (the old configuration is kept in
`data/adguard/conf/AdGuardHome.yaml.before-reset-*`). AdGuard is stopped for a few seconds at every `install.sh`: the
phone's DNS is then unavailable for a short moment.

- **See what is blocked**: the console's **Tracking** page (§2.2), AdGuard's query log (filter on blocked requests)
  and the statistics. In the console, Network page: DNS names per application. In Wazuh: the "Watchpost — tracking
  and DNS" dashboard (all requests are archived, 90 days).
- **Unblock a domain that breaks an application**: spot the domain at the moment the application fails. The simplest
  way: console › **Tracking** › Domains › **Allow** (a rule written in a block managed by Watchpost; an essential
  domain asks for confirmation). Other equivalent ways: in AdGuard's interface, "Custom filtering rules" (kept by
  `install.sh`), or by file, on the VPS:

  ```bash
  cd ~/watchpost/infra
  echo '@@||domain.example^$important' | sudo tee -a data/adguard/userfilters/personal-rules.txt
  sudo ./install.sh --yes
  python3 tools/dot-query.py dns.watchpost.example.org domain.example     # must answer a real address
  ```

  `@@||domain^$important` allows the domain and its sub-domains **even if it appears in another list**; each
  exception also weakens threat filtering for that domain: allow only what really breaks. The file is kept by
  `install.sh` and by the backups. To block a domain in addition: `||domain^`. Keep in mind that the
  `@@…$important` exceptions in `watchpost-base.txt` (Android connectivity check, `mtalk*.google.com`, FCM, Play,
  Google accounts, Samsung updates) must **never** be removed: blocking a connectivity-check domain makes the phone
  show "connected, no Internet".
- **Change the DNS blocking level** (server side): console › Tracking › "Blocking level" (permissive, balanced,
  strict), or `sudo ./install.sh --profile permissive|balanced|strict --yes`. The strict level adds HaGeZi Multi PRO++
  and `watchpost-strict.txt` (Firebase Remote Config, Galaxy Store, Samsung push and cloud…). It is **independent** of
  the application's strict profile on the phone: switch to strict on the server only after stabilising the phone's
  profile, and watch for broken applications.
- **If Samsung updates fail**: look at AdGuard's log for blocked `*.samsungdm.com` or `*.samsungapps.com` domains (the
  `ospserver.net` update domains are allowed by default). A reported conflict: the HaGeZi list blocks
  `gld.samsungosp.com`, while the Samsung account goes through `*.samsungosp.com`.
- Part of the Google Play services telemetry goes through shared domains that cannot be blocked without breaking the
  Play Store: see the root README, "limits" section.

## 5. Knowing whether the agent has stopped sending

Without notifications configured (§3), nothing warns you: it is up to you to look. With notifications, the **agent's
silence** is notified whatever the level. Clues, from the quickest to the deepest:

1. **Console, red "last contact" dot** and the "No contact for…" banner (Overview).
2. **Wazuh absence alert**: no event for 60 minutes (level 7, probe run every 10 minutes; `WATCHPOST_WATCH_SILENCE_MIN`
   in `infra/.env`), then "resumption" (3) when the device sends again.
3. **Server**: `sudo ./enroll.sh --list` ("last contact" and certificate expiry columns).
4. **Phone**: the permanent notification "Watchpost is collecting…" (it carries the number of events waiting and the
   time of the last upload) and Watchpost's Home.
5. **Overview › Collectors**: a collector "unavailable" or "disabled" is waiting for a permission or has been turned
   off.

Usual causes: phone off or offline; **private DNS unreachable** (the agent no longer resolves the ingestion address:
it keeps its events in its buffer, up to 200 MB or 30 days, and sends them afterwards); agent killed by Samsung's
battery management (check "Never sleeping apps" and battery optimization, guide 03 §9); **permission removed** in
Settings (the collector becomes "unavailable" and `agent.tamper` `permission_revoked` is emitted: Watchpost does not
take it back by itself, Collectors tab › "Grant permissions", or `grant-adb-permissions`); expired client certificate
(§8); revoked device (the console says so); APK update with another key (impossible).

## 6. Updates

**Server** (`infra` folder):

```bash
sudo ./update.sh            # backup, git pull --ff-only, images, rebuild of the collector, install.sh
sudo ./update.sh --no-pull  # without git pull
```

A backup is made first. The image versions (Wazuh 4.14.10, AdGuard Home v0.107.80, Caddy 2.11.9) are **pinned** in
`docker-compose.yml`: "latest" is never followed. To move up a version, edit that file (the three Wazuh images
together, after reading the release notes) and then run `update.sh`. `git pull` fails if there are local changes in the
repository. After an update, redo the checks of guide 01, section 9. Also update the VPS's system (`apt`) and reboot
from time to time: the containers restart by themselves.

**Application**: the same signing key is **mandatory** and the `versionCode` strictly increasing.

```bash
cd android
./gradlew assembleRelease -Pwatchpost.versionCode=2 -Pwatchpost.versionName=0.2.0
./scripts/install-apk.sh app/build/outputs/apk/release/app-release.apk
./scripts/rescue-revert.sh      # does the rescue still answer? ("reverted=0…")
```

```powershell
cd android
.\gradlew.bat assembleRelease -Pwatchpost.versionCode=2 -Pwatchpost.versionName=0.2.0
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\install-apk.ps1 -Apk app\build\outputs\apk\release\app-release.apk
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\rescue-revert.ps1
```

The **notification companion** is updated the same way (`./gradlew :notifier:assembleRelease`, then
`./scripts/install-notifier.sh notifier/build/outputs/apk/release/notifier-release.apk`), with **the same key** and the
same increasing `versionCode`; the installation order between the agent and the companion does not matter.

The data (buffer, enrollment, settings) is kept and the agent restarts by itself. Check: the version in the console
(Overview › Agent), Device Owner still active, regular uploads. Never tried on a phone: read guide 06 ("APK update").
If installation fails with `INSTALL_FAILED_UPDATE_INCOMPATIBLE`, it is not the same signing key: do not uninstall
Watchpost (it is a Device Owner); find the original key (guide 02).

## 7. Retention (how long data stays)

| Where | Duration | Setting |
|---|---|---|
| Phone (upload buffer) | 200 MB or 30 days; beyond that, the oldest and least severe go first (`agent.buffer_overflow`) | Watchpost settings › Buffer and upload |
| Collector database (console) | **90 days** (on the original time `ts`) | `WATCHPOST_RETENTION_DAYS` |
| Wazuh: alerts | **180 days** | `WAZUH_ALERTS_RETENTION_DAYS` |
| Wazuh: archives (all events, DNS requests included) | **90 days** | `WAZUH_ARCHIVES_RETENTION_DAYS` |
| Archive files on disk (`archives.json`) | 14 days | `WATCHPOST_ARCHIVES_FILE_DAYS` |
| AdGuard query log (interface) | 7 days (`168h`) | template `adguard/AdGuardHome.yaml.tmpl` |
| Backups | until you delete them | `infra/backups/` |

To change a duration: edit the value in `infra/.env`, then `sudo ./install.sh --yes`. An index template applies only to
indices created after it (effect the next day). Watch the disk:

```bash
df -h /var/lib/docker
sudo docker system df
```

An indexer whose disk exceeds 95 % goes read-only: reduce the retention or free up space.

## 8. Renewals to plan

| Deadline | What | How |
|---|---|---|
| **2 years** after enrollment | **the phone's client certificate** | below; the date is shown in Watchpost › Settings › Enrollment ("Certificate valid until", in an alert colour within 30 days) |
| ~60 days | Let's Encrypt certificates (console, ingestion, `dns.…`) | automatic (Caddy); AdGuard reloads the certificate without restarting; **never seen in real conditions** |
| 5 years | Wazuh's internal certificates (CA: 10 years) | `sudo ./install.sh --renew-wazuh-certs` (same CA, the normal case) or `--renew-wazuh-ca` (compromised or expired CA); the expiry is recalled at the end of every `install.sh` (warning within 90 days); old files kept in `secrets/wazuh-certs/old-<date>/`; verified for both on a test stack |
| 20 years | the collector's authority (client certificates) | — |
| as needed | passwords | `sudo ./install.sh --rotate-passwords` (regenerates all the passwords, console included; verified); console only: `docker compose exec collector watchpost-collector user set-password admin` |
| never | signing keystore | **do not** change it (guide 02); test that its backups can be read |

**Renew the phone's certificate** (a month before the expiry, without unenrolling, without splitting the history):

1. On the server (`infra` folder):

   ```bash
   sudo ./enroll.sh --list                 # certificate expiry of each device ("renew" within 30 days)
   sudo ./enroll.sh --renew phone          # or --renew dev_… ; produces ./phone-renewal.watchpost (permissions 600)
   ```

   Same `device_id`, new token and new certificate. **The old pair remains accepted** until the first upload made with
   the new one, then it is refused: if you never import the new file, the old one keeps serving until it expires.
   Verified through Caddy in mTLS: old accepted, new accepted, old refused afterwards.
2. Copy the file to the phone by cable, as in guide 03 (step 10): `scp` to the PC, then `push-enrollment`.
3. In Watchpost › Settings › Enrollment: **"Import a new .watchpost file"** (do **not** unenroll: that would erase the
   key, the token and the pending events). The screen compares with the current enrollment and says what becomes of the
   pending events: "**Renewal: same server, same device. Pending events (N) are kept.**" is the expected message. Tap
   "Enroll this device"; the connection test must succeed and "Certificate valid until" shows the new date.
4. Delete every copy of the file (guide 03, step 10): `shred -u phone-renewal.watchpost` on the server.
5. After a few minutes, `sudo ./enroll.sh --list` shows the new expiry: the switch-over has happened.

If the screen announces "Same server, different device identifier" or "Different server", **stop**: you imported a file
produced by `enroll` (new device) instead of `--renew`, or for another address. The first case keeps the buffer but
splits the history over two identifiers; the second **erases** the buffer. These two behaviours come from the
application and have never been tried on a phone (guide 06).

## 9. Console privacy: the map tiles

By default the map loads `https://tile.openstreetmap.org/{z}/{x}/{y}.png` from **your browser**: OpenStreetMap sees
your IP address and the areas displayed, hence the places the phone frequents. Options: do not open the map, or set
`WATCHPOST_TILE_URL` in `infra/.env` to a provider whose policy suits you (an `https://` URL with `{z}`, `{x}`, `{y}`),
then `sudo ./install.sh --yes` (the console's security policy follows automatically); or self-host tiles (not provided,
see `infra/README.md` §10.2). The Wazuh dashboard's map also loads a third-party base map.

## 10. If the phone is lost or stolen

See [guide 04, case G](04-rollback.md): ring, locate, **lock with a message** (console › Commands, with the command
passphrase), and erase **only** if it had been allowed in advance and tried on a sacrificial device. These commands have
never been tried on a phone, run only if the phone reconnects and the channel is on, and replace neither your carrier
nor the lock and erase features of your Google or Samsung accounts. In all cases, **then revoke the device** to close
ingestion and the channel: `sudo ./enroll.sh --revoke dev_xxx` (or its name). The console keeps the history, including
the last positions received.
