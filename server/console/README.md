# Watchpost web console

The dashboard: location, network per application, tracking (what is blocked or allowed), remote commands, application
inventory and risk profile, detection of abnormal behaviours, security posture, events and Wazuh alerts. React 19, strict
TypeScript, Vite, MapLibre GL JS, uPlot, React Router. English interface, light and dark themes. No external resource at
load time, apart from the map tiles.

The console only talks to the collector's `/api/console/*` API (contract §6, §8 commands, §9 tracking, §10 notifications,
§11 risk, operations and detections of `docs/contract/contract.md`).

## Development

```sh
npm install
npm run mock      # mock server on http://127.0.0.1:8787 (credentials: admin / watchpost)
npm run dev       # Vite on http://localhost:5173, /api proxied to the mock server
```

To target another collector: `WATCHPOST_API_TARGET=http://127.0.0.1:8080 npm run dev`.

The mock server (`mock/`) generates seven days of deterministic telemetry around a city: journeys, data gaps (phone
off, forced stop of the agent, loss of the fix), DNS and connections per Google/Samsung package, volumes, application
inventory, posture with changes, alerts, `sev` 2-3 events, a type outside the catalogue and partial `data`. It also emits
live events on `/stream`. `POST /__mock/control` can simulate `{"wazuh": false}`, `{"expire": true}` (expired session),
`{"fail": ["/stats/top"]}` (500 error) or `{"latency_ms": 800}`.

The mock also simulates (contract §8-§10):

- **commands**: collector validation (type, bounds, validity, `sig` present if and only if the command is sensitive, limits of
  20 per hour and 10 pending, `409` when cancelling a command that was already delivered) and a **simulated agent** that
  fetches the commands, verifies the signature with the key derived from `MOCK_COMMAND_CODE` (default
  `correct horse battery staple`, the passphrase of the contract vector), follows the order of the checks of §8 (`disabled`,
  `malformed`, `bad_signature`, `locked_out` after 5 failures, `replay`, `expired`, `not_device_owner`...), emits
  `command.result` and, for `locate`, a real `location.fix` on the SSE stream. Controls: `{"channel": "stream"|"poll"|"offline"}`,
  `{"agent": {"disabled", "wipe_allowed", "code_configured", "device_owner", "locate_fail", "deliver_ms", "exec_ms"}}`;
  `GET /__mock/requests` returns the bodies of the modifying requests received;
- **tracking**: counts derived from the generated `net.dns`/`net.usage`, policy (level + manual rules) evaluated at the time of
  each query (changing the level produces "mixed" domains), reasons in AdGuard format, `PUT /tracking/override` with `409`
  for essential domains (`force`), `PUT /tracking/level`, and `{"adguard": false}` (DNS-only view, `503` on the `PUT`s);
- **notifications**: `app.notification` with title/text (since D-3), hidden content (`redacted`), hostile text and very long
  text;
- **version 1.2** (`mock/scenario.ts`, `mock/detect.ts`, `mock/risk.ts`): `GET /detections` (cursor, `from`/`to`/`type`
  filters), `GET /apps/risk`, `GET /apps/ops`, computed from `detect.*`, `app.risk`, `app.ops`, `app.role` events added to the
  generated data (so also visible in `/events` and on `/stream`). Three scenarios, chosen at startup with `--scenario` (or
  `MOCK_SCENARIO`): **`mixed`** (default): a fleet of 70 applications with varied profiles, the three `combo_*` combinations,
  the twelve detection types, an unknown type, hostile text, `app.ops` present, role changes including a worrying one;
  **`healthy`**: "healthy phone", no detection, no high-risk application, `app.ops` absent; **`sms-fraud`**: "SMS fraud",
  an application from outside a store, installed 40 h earlier, sends 1,984 SMS over two calendar days (1,790 of them in the
  background), contacts three threat domains, connects to 214 addresses; `app.ops` present. The shapes of the evidence and of
  the responses follow the collector (`server/collector/internal/detect`, `internal/server/detections.go`). Extra controls:
  `{"ops_mode": "normal"|"empty"|"404"}` (`app.ops` absent or unknown route), `{"more_detections": 70}` (pagination),
  `{"emit_detection": {type, package, label, severity, evidence}}` (live arrival); changes of tracking level or rule produce
  `tracking.level_changed` / `tracking.override` like the collector.

## Build, tests, verification

```sh
npm run typecheck   # strict tsc (src + mock)
npm run lint
npm test            # vitest: formatting, aggregations, track gaps, posture, filters, command signature (§8 vector), tracking,
                    # reason codes and detection types (translations, sentences, evidence, empty states), operations, roles...
npm run build       # static output in dist/
npm run verify      # Chromium walkthrough (global Playwright) against the mock server serving dist/
```

`npm run verify` starts the mock server with `--static dist` (which applies the CSP below and the SPA fallback; one instance
per scenario: `mixed` on `PORT`, `healthy` on `PORT+1`, `sms-fraud` on `PORT+2`, stopped by their PID), walks through every
page in light/dark and desktop/phone, and fails on any console error, exception, CSP violation, unexpected HTTP status or
request outside the local host and the tiles. It also replays, against the mock, the end-to-end walkthroughs: simple commands
and live tracking, cancellation, locking with a wrong passphrase (`bad_signature` found by the simulated agent) then the right
one, three-step erase, location that arrives after "Locate now" (live map and track), tracking (filters,
Block/Allow/Reset to default, `409` then `force`, level, `adguard: false`), hostile notifications displayed as text, location
providers; and it **proves that the command passphrase does not leave the page** (no request, no console log, no body received
by the mock server, no storage, cookie or field contains it, neither in clear nor encoded). For version 1.2 it also walks
through (`ONLY=v12` to replay only that): the twelve detection types and an unknown type, filters by type, severity and
period, cursor pagination (70 more detections), live arrival through the SSE stream (Detections page and Overview summary),
hostile text (application name, domain, reason) displayed as text, risk profile (sort by score, three combinations, unknown
code), application detail page (direct opening and reload of a URL whose package contains dots), sensitive operations
present / empty / route absent, roles, tracking events and detections in the event log, erase validity (15 min, 24 h at most),
texts on the limits of the signature, cancellation of a signed command; then the "healthy" and "sms-fraud" scenarios in the
four configurations (light/dark, desktop/phone). Screenshots go to `OUT` (default `verify-out/`). `TILES=real` lets the real
calls to the OSM tiles through (otherwise a synthetic tile is served).

### Against the real collector

`scripts/verify-real.cjs` replays in Chromium the commands walkthroughs (simple, wrong passphrase then right passphrase,
cancellation, location received), tracking, notifications and map against a real collector (`REAL_URL`, `REAL_PASSWORD`,
`REAL_CODE`), with the same checks (console, CSP, third parties, passphrase leak). The version 1.2 walkthroughs against the
real collector are described below. Prerequisites: collector started with `WATCHPOST_CONSOLE_DIR=$PWD/dist`, an enrolled device
fed by `sim --command-code 'correct horse battery staple' --fake-adguard 127.0.0.1:3001 ...` (the simulator's command agent and
fake AdGuard Home: see `server/collector/README.md`). With AdGuard reachable, the script also replays the blocking of a
domain, the `409` of an essential domain and a level change; without AdGuard, it checks the degraded mode.

`scripts/verify-real-v12.cjs` replays version 1.2 against a real collector fed by `sim --scenario all` (or `healthy`):
detections per type (sentences built from the real evidence), filter by type, application detail page opened from a
detection then reloaded, risk profile (sort, combinations, no untranslated reason), sensitive operations, roles, in the four
configurations (`REAL_URL`, `REAL_PASSWORD`, `SCENARIO`, `OUT`).

## Deployment

`dist/` is served at the root of the same host as the API (absolute paths `/assets/...`, API at `/api/console/...`).
The server must return `index.html` for any unknown page URL (client-side routing: `/overview`, `/map`, `/events`,
`/events/:id`, `/network`, `/tracking`, `/detections`, `/apps`, `/apps/detail`, `/security`, `/alerts`, `/commands`, `/login`)
but a 404 for a missing file (`/assets/...`). `.js` files must be served as `text/javascript` (the MapLibre worker is
published as `.js` for this reason).

### Map tiles

By default `https://tile.openstreetmap.org/{z}/{x}/{y}.png`, with the OSM attribution displayed. For another host: edit
`config.json` at the root of `dist/` (`tileUrl`, `tileAttribution`, `tileAttributionUrl`), or set `VITE_TILE_URL` (and
`VITE_TILE_ATTRIBUTION`, `VITE_TILE_ATTRIBUTION_URL`) at build time. The URL must be https and contain `{z}`, `{x}`, `{y}`;
**the CSP must then allow that host** (`img-src` and `connect-src`). If `config.json` is missing or invalid, the default
value is used.

### Content Security Policy (CSP)

The build only needs this (no `'unsafe-inline'`, no `'unsafe-eval'`); each directive was tested in Chromium by removing or
tightening it (`npm run verify` applies this policy):

```
default-src 'none';
script-src 'self';
style-src 'self';
img-src 'self' data:;
connect-src 'self' https://tile.openstreetmap.org;
worker-src 'self';
font-src 'self';
base-uri 'none'; form-action 'self'; frame-ancestors 'none'
```

- `worker-src 'self'`: the MapLibre worker is a file of `dist/assets/`; `worker-src blob:` would not be enough, and `blob:`
  is not needed. Without a `worker-src` directive, the fallback on `script-src 'self'` is also fine.
- `connect-src`: `'self'` covers the API, `config.json` and the SSE stream; the tile host is required because MapLibre loads
  tiles through `fetch` (without it: one violation per tile, map without a background).
- `img-src 'self' data:`: `data:` is required by MapLibre; the tile host does not need to appear there (nor `blob:`).
- `font-src`: no font is loaded; the directive is harmless. `default-src 'none'` is enough otherwise.
- The dynamic styles of React, MapLibre and uPlot go through the CSSOM (`element.style`), which is allowed without
  `'unsafe-inline'`. The style sheets (including those of MapLibre and uPlot) are in the bundle's CSS.
- `script-src 'self'` is enough: `/theme-init.js` is an external file, `index.html` contains no inline script.

## Structure

```
index.html, public/            entry point, config.json (tiles), theme-init.js, favicon
src/api/                       HTTP client, contract types, useApi, cursor pagination, SSE stream
src/lib/                       formatting, periods, track gaps, geo, aggregations, posture, Google/Samsung, detections, risk,
                               operations, roles, guards,
                               commands (ULID, payload, WebCrypto signature), tracking, notifications, providers
src/state/                     session, selected device, theme, application labels
src/components/                layout, map (MapLibre), chart (uPlot), tables, JSON, period picker
src/pages/                     Login, Overview, MapPage, Events, Network, Tracking, Detections, Apps, AppSheet, Security, Alerts, Commands
mock/                          mock server (Node 22, TypeScript without compilation) and data generator
scripts/verify-browser.cjs     browser verification
```

## Remote commands ("Commands" page)

Choice: a **dedicated page** (and not the Overview) because it carries heavy gestures (confirmation dialogs, a history that
updates live); the Overview only shows the channel state and points to it.

- The **browser** generates the ULID, builds `payload` (JSON serialised **once**; this exact string is signed and sent), sets
  the validity (1 h for simple commands; lock 7 days by default and 30 at most; **erase 15 min by default and 24 h at most**,
  contract §8) and signs the sensitive commands:
  `K = PBKDF2-HMAC-SHA256(passphrase, "watchpost-cmd-v1:" + device_id, 600,000, 32 bytes)` then
  `sig = base64(HMAC-SHA256(K, UTF-8(payload)))`, with WebCrypto (`src/lib/commands.ts`). The `commands.test.ts` test
  reproduces the contract §8 vector (K, payload rebuilt identically, signature, em dash in UTF-8).
- The **command passphrase** is entered for each command in an **uncontrolled** field (it does not exist in React state), is
  used to derive the key then to sign, and the field is cleared immediately. No passphrase or key in `localStorage`,
  `sessionStorage`, IndexedDB, cookie, log or request; only `{ device_id, payload, sig }` leaves. The derived key is zeroed
  after being imported into WebCrypto. Accepted limit: a JavaScript string cannot be wiped from memory, it is only left to
  the garbage collector. WebCrypto requires a secure context (HTTPS or localhost): otherwise the interface says so and
  disables the sensitive commands.
- Safeguards: explicit confirmation to lock; erasing the phone in three steps (irreversibility and a reminder that erase must
  be allowed in the app, device name to retype, then passphrase). The interface explains that the server does not know the
  passphrase, cannot verify the signature, and that a wrong passphrase is only detected by the phone (`bad_signature`, a
  warning after each refusal, a reminder of the limit of 5 per hour).
- Contract clarifications applied: `issued_at` within 10 min of the server time. The console compares the `Date` header of the
  responses with its clock and **dates the command at the server's time when the offset is between 30 s and 10 min**
  (`issueTime`): the phone refuses (`expired`) a command issued more than 5 min in its future, whereas the server tolerates
  10 — a computer 5 to 10 min ahead produced commands accepted by the server then refused by the phone. Beyond 10 min the
  offset is never followed (warning, and the `400` is translated into "this computer's clock is off"): the server must not be
  able to get a command dated in the future signed. Lock message ≤ 200 UTF-16 units, without control characters other than
  the line feed nor U+2028/U+2029 separators (refused by the collector), validated before signing; body limited to
  `{ device_id, payload, sig }`; a polling device is judged on `last_contact` (`connected` is only true for an open stream);
  a `delivered` command may stay so for several minutes (the server sends it again after 5 min).
- The history refreshes every 2.5 s while a command is `pending`/`delivered` (and at each `command.result` of the SSE stream);
  cancellation is possible while `pending`. A command **delivered then expired without a result** is displayed "Expired
  without a response": it may have been executed (an erase powers the phone off ten seconds after trying to send its
  report); only a command never delivered is said to "never be executed".
- **What the signature in the browser guarantees, and what it does not.** The passphrase does not leave the page as long as
  the JavaScript served is that of this repository. But it is the server that serves this JavaScript: a compromised server can
  replace it and read the passphrase as it is typed (or ask for it under a false pretext), and the CSP, served by the same
  server, changes nothing. The dialog says so, recalls that cancellation only commits the server and shows the device
  identifier that will be signed. Options outside this repository: sign from a copy of the console kept off the server (`dist/`
  files served locally) or a command-line tool; if in doubt about the server, change the passphrase in the app.
- **Shared hard cases**: `src/lib/commandVectors.ts` builds and signs, with the console's real code, commands with accents,
  emoji, quotes, line feeds, bidirectional text, non-ASCII, decomposed (NFD) or space-padded passphrases. Frozen in
  `src/lib/fixtures/command-vectors.json` (`commandVectors.test.ts`; regeneration:
  `node scripts/command-vectors.ts > src/lib/fixtures/command-vectors.json`), they are replayed by the agent's Kotlin verifier
  (`ConsoleVectorsTest`) and by the Go collector (`internal/command/vectors_test.go`);
  `node scripts/command-vectors.ts <device_id>` produces them for a real device (`CrossCommandsTest` cross-check).
- "Locate now": the SSE stream brings the `location.fix`; the map of the Commands page and the track of the Map page
  ("Follow live") update.

## Detections, risk, operations, roles (version 1.2)

Goal: to see malware coming (for example one that sends thousands of phishing SMS a day without anything being visible)
**whatever its vector**. Contract §11.

**What is where, and why.**

- **Detections: a dedicated `/detections` page** (second entry of the menu), not a rework of the Security page. *Security*
  describes the state of the phone (posture, system log, certificates): readings, without a verdict. A detection is an
  **explained verdict** ("application X did Y, here is why it is suspicious, what it could innocently be, what to do"): it needs
  room and a ten-second read, which the Security page's table does not give. *Alerts* remains the **Wazuh** view (Wazuh rules and
  levels, all topics, absent if Wazuh is not configured): the collector also exports detections to Wazuh, which finds them
  there; to avoid duplication, the Alerts page says so and points to Detections ("See the detection" link on `detect.*` alerts),
  and Detections works without Wazuh.
- **Overview**: at the top, a banner "Nothing to report" (green) or the number of detections of the last 7 days by severity with
  the most worrying application and the three most serious; it updates when a detection arrives on the SSE stream.
- **Applications**: the **Risk** tab (first tab) = `app.risk` profile (sort by score, level, reasons translated with an
  explanation and "often legitimate because...", `combo_*` combinations in red and first, installer and "outside a store"; an
  unknown code is displayed as is, marked "unknown code"); the **Sensitive operations** tab = `app.ops`.
- **Application detail page** `/apps/detail?pkg=<package>` (from risk, inventory, detections, roles): profile and reasons, roles
  (`app.special_access.default_apps` and `app.role` history), information, the application's detections (with live arrival),
  permissions, operations, contacted domains, installation history. **The package is a query parameter and not a path
  segment**: it contains dots, and the server answers 404 to a path whose end looks like a file extension (contract §6).
- **Security > Default roles**: current roles and change history (`app.role`).
- **Event log**: `detect.*`, `app.risk`, `app.role`, `app.ops`, `tracking.level_changed` and `tracking.override` are described
  in plain words.

**Each detection** shows: severity (words and colour), type, application (name and package), time, **a sentence of what was
observed** (built from the evidence, otherwise the collector's `summary`), period, a preview of the evidence, then (expandable;
the first one is open) full evidence, why it is suspicious, innocent explanations, what to do, links (detail page, domains in
Tracking pre-filtered, traffic in Network, Camera and microphone) and a reminder of the app guard that answers the risk.
**Guards can only be set on the phone**: the text says so (the server never commands the phone). Filters: type, severity,
period; cursor pagination ("Load more"); new detections from the SSE stream are added at the top without duplicates (identifier
of the server event).

**Honesty.** "Nothing to report" is not a guarantee and says so; detections are clues, not proof. **`app.ops` is experimental
and may be absent**: the tab then shows an empty state that explains the activation (`DUMP` permission granted through ADB with
`grant-adb-permissions`, experimental collector in the Collectors tab of the app) and recalls that the absence of data is not an
absence of use; never a broken screen (empty response, 404 route and network error are distinguished). All text coming from the
phone or the network is displayed as text (`cleanText`: controls and bidirectional marks removed).

**Tolerant reading of the API** (`src/lib/risk.ts`, `ops.ts`, `detections.ts`): the contract fixes the fields but not the
whole envelope nor the `evidence` keys. `GET /apps/risk`: `{apps:[...]}` (or a bare array); `GET /apps/ops`:
`{apps:[{package, ops:[{op,count,background_count,last_ts}]}]}` (collector format) or flat rows; `GET /detections`:
`{detections, next_cursor}`, `severity` from 0 to 3 (or `low`/`medium`/`high`/`critical`). The evidence keys read are those of the
collector's `internal/detect` (`domain`/`requests`, `tx_bytes`/`median_bytes`, `addresses`, `ports`, `resolvers`/`providers`,
`sent`/`background`/`reason`, `op`/`background_count`, `trigger`/`capability`/`reasons`...), with aliases for other shapes;
unreadable evidence falls back on the collector's `summary`.

**Gaps with contract §11 (to be recorded there)**: (1) the envelope of `/apps/risk` and `/apps/ops` and the `evidence` keys of
each type are not specified; (2) `GET /detections` has no `package` filter: the application detail page sends it (ignored by the
contract) and filters client-side, chaining up to 6 pages; a server-side filter would avoid this sweep; (3)
`window_from`/`window_to` are described as carried by each detection but absent from the list of the API's fields (the collector
returns them: read if present, otherwise "detected on ..."); (4) the `severity` scale (0 to 3 like `sev`) is not written down;
(5) the level of `app.risk` is authoritative; if it is absent or unknown, fall back on the score with the thresholds of contract
§11.2 (< 30 low, < 70 medium, otherwise high); (6) the name of the `app.ops` collector in `agent.heartbeat.collectors` is not
fixed (the console looks for a key containing "ops"); (7) `tracking.level_changed.changes` has no fixed type (a number or a
list: both are read); (8) `/detections` returns one detection per threat domain and per day: the sentence "tried to reach 3
domains" only exists for grouped evidence (`domains`).

**What the verdict does not cover.** `detect.sms_abuse` and `detect.sensor_background` rely only on `app.ops`, an
experimental collector that is off by default: without it, an application that sent thousands of SMS produces no detection,
and "Nothing to report" would be misleading. The verdict banner (Detections page and Overview) therefore shows a "Not
monitored here..." line as long as the phone's last heartbeat does not report this collector as `running` (`opsBlindSpot` in
`src/lib/detections.ts`, tested). "Running" does not prove that data is arriving: check it in Applications › Sensitive
operations. Hostile application and package names: rendered by React as text (no `innerHTML`), API in `application/json` with
`nosniff`; a test with an `<img onerror>` label and fields of the wrong type against the real collector: returned as is in
JSON, no server error (the rendering in a browser was not replayed for that test: the conclusion comes from reading the code).

**Review notes (contract §11.4).**

- **New types**: `detect.sms_permission` (a *review*: "this application can send SMS without going through your messaging app; is
  this intended?", "To check" badge, pointer to the SMS guard), `detect.default_app_changed` (on the `sms` role, the console says
  this is the classic route of SMS trojans), `detect.flood` (cap of 200 detections per day: faulty agent or compromised device)
  and `detect.inventory_mismatch` (application wrongly declared "system"). Evidence read in the collector's format
  (`suppressed`/`limit`, `role`/`old`/`new`/`risk`...).
- **Muting**: on a detection, "Stop reporting for this application" (except `sms_abuse`, `default_app_changed`, `flood`,
  `inventory_mismatch` and detections without an application), with an optional reason (200 characters) and a confirmation that
  says that the detection **stays computed and recorded** but will **no longer be sent to Wazuh or notified**. Muted detections
  are collapsed ("Show muted detections (N)" checkbox), do not count in the verdict, and the "Current mutes" card lists the
  mutes with their reason, who and when, and their lifting. `POST`/`DELETE /detections/mute`, `GET /detections/mutes`; a
  `detect.muted` / `detect.unmuted` on the stream reloads the list; a mute also applies to detections created before it. The
  `detect.muted`/`detect.unmuted` events are described in the event log. Same button on the application detail page.
- **Recurrence**: `recurring: true` is displayed "Already reported, recurring" (severity already capped at 1 by the collector).
  **Updates**: an `update: true` + `detection_id` event replaces the existing card (no duplicate).
- **Declared / granted**: `app.risk` covers the capabilities **requested**; the parallel `granted` list (with or without the
  `:granted` suffix) distinguishes, in the Risk tab and on the detail page, "Granted" from "Requested, not granted" (dashed
  outline) for the reasons that are capabilities; without a `granted` list, no distinction is invented. A note explains that the
  score stays high when a guard prevents granting.
- **The verdict tells the truth** (Detections page and Overview, green included): always what is monitored (SMS sending
  permission held, change of default SMS app, threat domains, large uploads, connections, new risky applications); without a
  running `app_ops` collector (according to the last heartbeat), "Not monitored here: SMS sending itself..."; with it,
  "running" does not prove that data is arriving; and that **the SMS guard of the Watchpost app is the real protection**
  (`monitoringScope`, tested).
- Assumptions made for lack of precision in the contract: shape of `GET /detections/mutes`
  (`{mutes:[{device_id,type,package,reason,created_at,created_by}]}`, confirmed by the collector), `sms_permission` evidence keys
  (none required) and `default_app_changed` keys (`role`, `old`, `new`, profile flattened from `risk` or read as is).

## Tracking ("Tracking" page)

Split with **Network**: *Network* describes the observed traffic (names requested, destinations, volumes, timeline) and works
without AdGuard; *Tracking* answers "what is blocked or allowed, towards whom, and what do we do" (publishers, status, reason,
actions, level). The two pages point to each other (`/network?app=<package>` opens an application's detail). The page always
shows that Watchpost sees who the phone talks to, how many times and from which application, **not the content** (encrypted).
AdGuard unreachable (`adguard: false`): actions and level disabled with an explanation; without blocked/allowed counts the
view is that of the DNS queries alone, with already stored aggregates they stay displayed (warning "recorded before the
outage"). Bytes per publisher and blocked/allowed counts per application are presented as **estimates** (in proportion to DNS
queries). The errors `409 essential_domain` (`breaks` detail, confirmation then `force`), `409 corrupt_rules`, `502
adguard_error`, `503 adguard_unavailable` and `503 levels_not_configured` are translated.

## Known limits related to contract §6

- `/stats/top` does not accept a per-package filter: the "domains of an application" detail reads the `net.dns` /
  `net.connect` events (`q=<package>`, up to 4 pages of 500) and aggregates in the browser; beyond that, a warning flags a
  partial sample.
- `/stats/timeline` has no type filter: the network timeline requests `by=type` and only keeps `net.dns` and `net.connect`.
- `last_heartbeat` has no timestamp of its own: the age of the device is that of `last_seen`.
- To distinguish "phone off" from "no fix" in a track gap, the map cross-checks the track with the activity timeline.
