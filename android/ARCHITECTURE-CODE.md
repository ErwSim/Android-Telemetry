# Watchpost Agent — code architecture and collector conventions

This document is enough to add a collector or a Device Owner feature without reading all the code.
References: `../docs/contract/contract.md` (event format, **specification**), `../docs/ARCHITECTURE.md`
(non-negotiable principles), `../docs/research/android-platform.md` (platform facts).

## 1. Modules

```
:app ──► :collectors ──► :core
  │                        ▲
  └────► :policy ──────────┘
```

| Module | Package | Contents |
|---|---|---|
| `:core` | `io.github.erwsim.watchpost.core` | `Agent` (wiring), remote commands (`command/`: verification, channel, state), event model, `EventSink`, `outbox` buffer (Room), upload (`Uploader`, WorkManager), enrollment, settings, `Collector` interface + `CollectorHost`, `Capabilities`, `IntegrityMonitor` (`agent.tamper`). Shared test bench (testFixtures): `CollectorHarness`, contract reference `Contract`. |
| `:collectors` | `…watchpost.collectors` | 22 collectors **without** Device Owner privilege (including `notifications`, fed by the `:notifier` companion APK). Entry point: `CollectorsModule.all(context)`. |
| `:policy` | `…watchpost.policy` | Everything that requires the Device Owner: `WatchpostAdminReceiver`, `DeviceOwnerManager` (permission self-grant, force-stop protection), the reversible policy engine (`engine/`), the capability guards of contract §11.1 (`engine/CapabilityGuards`), Private DNS and its fallback (`dns/`), 3 collectors (security and network logs, posture), ADB rescue (`rescue/RescueReceiver`), Policy screen state (`ui/PolicyController`), `lock`/`clear_lock_message`/`wipe` executors (`remote/`). Entry point: `PolicyModule`. |
| `:app` | `…watchpost` | `WatchpostApplication`, foreground service `AgentService`, `BootReceiver`, Compose UI (including the Policy screen), end-to-end contract conformance test. |

`WatchpostApplication` does `Agent.init(this) { CollectorsModule.all(it) + PolicyModule.collectors(it) }`.
**Adding a collector only touches its own module**: its class, one line in the entry point, its strings and its
permissions (manifest merging).

## 2. Adding a collector (recipe)

1. Create `collectors/src/main/kotlin/io/github/erwsim/watchpost/collectors/<domain>/<Name>Collector.kt`
   (or in `:policy` if it requires the Device Owner).
2. Add it to the list in `CollectorsModule.all()` (or `PolicyModule.collectors()`). The order of the list is
   the display order.
3. English strings in `<module>/src/main/res/values/strings.xml`, prefixed by the id:
   `collector_<id>_title`, `collector_<id>_desc`, `setting_<id>_…` (the resources of all modules are
   merged: a prefix avoids collisions).
4. Permissions in `<module>/src/main/AndroidManifest.xml`. Forbidden in the APK: notification listening,
   accessibility, SMS, call log, overlay (Play Protect triggers, principle 4).
5. If the collector emits a **type** or **fields** absent from the catalogue (contract §2): do not invent them,
   report it so that the contract is completed first.
6. JVM tests (§9).

```kotlin
class WifiCollector : Collector {
    override val id = "wifi"                                   // [a-z0-9_]+, stable (settings, heartbeat)
    override val titleRes = R.string.collector_wifi_title
    override val descriptionRes = R.string.collector_wifi_desc // what is collected, in plain words
    override val eventTypes = listOf("net.wifi")
    override val requirements = listOf(Requirement.Permission(Manifest.permission.ACCESS_FINE_LOCATION))
    override val settings = listOf(SettingSpec.BoolSpec(SCAN, R.string.setting_wifi_scan))

    override suspend fun start(ctx: CollectorContext) {
        ctx.registerReceiver(IntentFilter(WifiManager.NETWORK_STATE_CHANGED_ACTION)) { intent ->
            ctx.emit("net.wifi") { put("event", "connected"); put("ssid", ssid) }
        }
    }

    companion object { val SCAN = SettingKey.BoolKey("wifi.scan", false) }
}
```

## 3. The `Collector` interface and its lifecycle

| Member | Role |
|---|---|
| `id`, `titleRes`, `descriptionRes`, `eventTypes` | Identity and transparency (shown in the Collectors tab). |
| `defaultEnabled` | `true` by default; `false` for an expensive or intrusive collector (opt-in). |
| `requirements` | `Requirement.Permission(name, optional)`, `Requirement.DeviceOwner`, `Requirement.SystemFeature(name)`. Checked by the host **before** `start`. |
| `checkAvailability(ctx)` | Additional check (hardware, the "usage access" app-op…) → `Availability.Unavailable("reason in English")`. |
| `settings` | Own settings, rendered automatically in the Settings screen. |
| `periodic` | `PeriodicSpec(intervalMinutes ≥ 15, runAtStart)`: `collectOnce` through WorkManager, even with the service stopped. |
| `start(ctx)` / `stop(ctx)` | Real-time subscriptions. **Never** called by the collector itself. |
| `collectOnce(ctx, reason)` | One-off reading (`START`, `PERIODIC`, `MANUAL`). |

The `CollectorHost` (one per process) decides:
- `start` when the agent is running, the collector is enabled (`collector.<id>.enabled`) and its requirements
  are met; it is re-evaluated when the service starts, every time the app comes back to the foreground, every
  15 min (maintenance) and when the Device Owner changes;
- `stop` + `start` when **one of its settings** changes (so new rates apply);
- `stop` when it is disabled, loses a requirement or the agent stops.

Published states (`host.statuses`, copied as is into `agent.heartbeat.collectors`): `running`, `disabled`,
`unavailable` (+ reason in English). The collector instance is reused from one start to the next: reset its
fields at the beginning of `start`.

## 4. Threading

- `start`, `stop`, `collectOnce` and all the callbacks registered through `ctx` run on **the collectors
  thread** (a shared `HandlerThread` named "watchpost-collectors"). They may suspend, **never block**.
- Android callbacks: `ctx.registerReceiver(filter) { intent -> }` (unregistered automatically on stop;
  **`exported = true` is mandatory for broadcasts sent by a system app that does not run under the system
  uid**: Bluetooth, NFC, KeyChain, telephony. A non-exported receiver never receives them.
  Only use it for an action declared `<protected-broadcast>` by the platform),
  `ctx.executor` (for `LocationManager`, `PowerManager`, `TelephonyManager.registerTelephonyCallback`…),
  `ctx.handler` / `ctx.looper` otherwise. A callback delivered on the main thread (e.g. `TriggerEventListener`)
  must go back through `ctx.handler.post { ctx.guard("…") { … } }`.
- Blocking work (I/O, large `PackageManager` queries, `getprop`, log retrieval):
  `withContext(ctx.io) { … }` or `ctx.scope.launch(ctx.io) { … }`. `ctx.io` is `Dispatchers.IO` in
  production; the test bench replaces it with a tracked executor: **never write `Dispatchers.IO`** in a
  collector (the bench would not see that work). `ctx.scope` is cancelled on stop.
- Cleanup: `ctx.onStop { … }` (run on stop, in reverse order, errors isolated).
- Persistent private state (last inventory, last emitted value): `ctx.prefs` (SharedPreferences
  `collector_<id>`), never the user settings.

## 5. Emitting an event

```kotlin
ctx.emit("device.battery", Severity.INFO) {
    put("pct", pct)                 // Int/Long/Double/Float/String/Boolean; null → field absent
    putStrings("functions", list)   // array of strings
    putObject("device") { put("vendor_id", v) }
    putObjects("apps", apps) { app -> put("package", app.pkg) }
    putMap("collectors", mapOf("location" to "running"))  // free keys (ids, packages)
}
```

- The `EventSink` assigns `id` (ULID), `ts` (RFC 3339 UTC ms), `boot_id`, `elapsed_ms` at the call, then `seq`
  at write time, in the **same SQLite transaction** as the insertion and the counter update: no gap and no
  duplicate after a sudden stop. `emit` does not block and can be used from any thread.
- **Origin timestamp** (events read after the fact: `app.foreground`, `net.dns`, `net.connect`,
  `security.log`, contract §2 "Precisions"): pass the time supplied by the system,
  `ctx.emit(type, sev, originTsMs = t) { … }` or `ctx.sink.emit(type, sev, data, originTsMs = t)`. Then:
  - `ts` = that origin time (for a grouping: the **first** occurrence; `count` and
    `last_event_ts` in `data`); there is no `event_ts` field;
  - `elapsed_ms` = `elapsedRealtime` estimated at the origin (`elapsed_now − (now − origin)`),
    so `ts − elapsed_ms` remains the start time as for the other events of the same `boot_id`;
    bounded to `[0, elapsed_now]`: **0** for an origin before the current boot (`pre_reboot` logs,
    usage from before the reboot: no `elapsedRealtime` exists for them on this `boot_id`),
    `elapsed_now` if the origin is "in the future" (clock set back in the meantime);
  - `id` (ULID) and `seq` stay the **emission** order: `ts` is therefore not increasing with `seq`. The
    buffer does not depend on it: upload and size-based purging follow `seq`, age-based purging and
    `agent.buffer_overflow.oldest_ts/newest_ts` compare `ts` (tested in `OriginTimeTest`).
- Grouped writes: events wait in memory for at most 3 s (or 200 events) and are then written
  in one transaction; `sev >= 2` forces the write **and** a quick upload. Accepted consequence: a sudden
  stop can lose the last ≤ 3 seconds of events not yet written (they do not have a `seq` yet, so there is
  no gap on the server side). Before a foreseeable stop: `ctx.flushBlocking()` (e.g. `ACTION_SHUTDOWN`).
- Contract rules, checked at runtime: type `^[a-z0-9_]+(\.[a-z0-9_]+)+$`, `snake_case` keys, fields
  **absent rather than `null`** (the builder ignores `null`, NaN and ∞), durations `*_ms`, sizes
  `*_bytes`, MAC addresses in lowercase with `:`, SHA-256 fingerprints in lowercase hex, timestamps through
  `Rfc3339.format(ms)`. An invalid type or key stops nothing: it becomes an `agent.collector_error`.
- Severity: 0 info, 1 notable, 2 warning, 3 critical. Reserve 2/3 for what deserves an immediate upload
  (they trigger an upload, which is costly in battery if frequent).
- Frugality: only emit **changes** (keep the last value in a field or `ctx.prefs`), cap the rates, prefer
  system broadcasts to polling. A high-volume collector must be disableable and document its expected hourly
  volume in its description.
- Never any private third-party content (SMS, calls, notifications, keystrokes, screen).

## 6. Capabilities and permissions

- `ctx.capabilities`: `isDeviceOwner()`, `hasPermission(p)`, `adminComponent()`, `hasSystemFeature(f)` (false
  if the `PackageManager` does not answer), `isIgnoringBatteryOptimizations()`, `declaredRuntimePermissions()`.
- Runtime permission: declare it in the module's manifest **and** in `requirements`. A permission with
  `optional = true` does not prevent the start (degraded mode; the `missingPermissions` list is displayed).
- As **Device Owner**, `PolicyModule.onAgentStarted` grants itself **all** the runtime permissions
  declared by the merged manifest (foreground location before background), then puts the state back to
  `DEFAULT`: the permission stays granted but the user keeps control. Each permission is
  auto-granted only once per Device Owner activation (`onOwnerEnabled` resets the counter):
  a permission the user removes afterwards is not taken back by the maintenance pass. Each grant emits
  `security.policy` (`permission_granted`, `target` = permission, `ok`), and force-stop protection
  (`setUserControlDisabledPackages`) emits `security.policy` (`force_stop_protection`, `enabled`/`disabled`)
  at each change. Nothing to code for a new collector. Without Device Owner, the Collectors tab
  offers "Grant permissions", and `scripts/grant-adb-permissions.{sh,ps1}` grants them over ADB.
- Permissions that can only be granted over ADB (today `PACKAGE_USAGE_STATS`, `WRITE_SECURE_SETTINGS`,
  `DUMP`): declare them in the module's manifest (with `tools:ignore="ProtectedPermissions"`), test them
  in `checkAvailability` (or degrade), and add them to `scripts/grant-adb-permissions.{sh,ps1}`.
- "Usage access" app-op (`hasUsageAccess()` of `:collectors`):
  `AppOpsManager.unsafeCheckOpNoThrow(OPSTR_GET_USAGE_STATS, uid, package)` (`checkOpNoThrow`, deprecated, has
  the same effect); `MODE_ALLOWED` = granted in Settings, `MODE_DEFAULT` = fall back on the
  `PACKAGE_USAGE_STATS` permission (the `pm grant` case).
- `Requirement.DeviceOwner`: the collector becomes "unavailable" without Device Owner and starts by itself when
  the role is granted (`WatchpostAdminReceiver.onEnabled` → `host.reconcile()`).
- A permission removed by the user is reported by `IntegrityMonitor` as `agent.tamper` (`permission_revoked`);
  the collector becomes "unavailable" at the next `reconcile`.
- Loss of the Device Owner: `agent.tamper` (`device_owner_lost`, and `admin_disabled` from the admin
  receiver), **except** for a voluntary removal announced by `IntegrityMonitor.expectOwnershipLoss()` just
  before `clearDeviceOwnerApp` (5 min window, persisted; `cancelOwnershipLossExpectation()` if the removal
  fails). `PolicyEngine.removeDeviceOwner` does this for the Policy screen and the ADB rescue, which
  emit `security.policy` `device_owner_cleared` instead. The `dpm remove-active-admin` fallback is not
  announced: it is still reported as tampering.

## 7. Settings

- `SettingKey.IntKey("<id>.<name>", default, min, max)`, `SettingKey.BoolKey(...)` or
  `SettingKey.ChoiceKey(name, default, values)` (closed list of strings: a value outside the list is never
  written and reads as the default), exposed through `settings = listOf(SettingSpec.IntSpec(key, titleRes,
  summaryRes, "s"))` or `SettingSpec.ChoiceSpec(key, titleRes, summaryRes, options)` (each option has its label
  and an explanation shown under it, e.g. the location mode). Reading: `ctx.settings[KEY]`.
  They are displayed in the collector's card (Collectors tab). `experimental = true` adds the
  "Experimental" mention (behavior not guaranteed by Android, e.g. attribution through `DUMP`);
  `defaultEnabled = false` makes "Disabled by default" appear, `Requirement.DeviceOwner` "Device Owner
  required".
- Every change goes through `AgentSettings.set`: `agent.config_changed` (`key`, `old`, `new`) is emitted
  automatically and the collector is restarted. No setting comes from the server (one-way flow).
- `SettingKey.PackageListKey(name, default)`: a set of package names (validated, 500 at most, stored sorted one
  line per package; `set` returns `false` and writes nothing for an invalid entry). Exposed through
  `SettingSpec.PackageListSpec(key, titleRes, summaryRes, candidates, locked)`: `SettingRow` shows it (name and
  icon) with a picker among the installed apps (`ui/PackagePicker.kt`: search, `candidates` to
  restrict, "Show all apps", `locked` for the packages that are always spared).
  `agent.config_changed` carries the sorted lists joined by commas. `AgentSettings.isSet(key)` says whether
  the user has already saved the value (pre-filling).
- Policy settings: `PolicyModule.settings` (rendered in the "Device Owner" section of Settings).
- Core settings (buffer, upload): Settings screen.

## 8. Errors and isolation

- Any exception in `start`/`stop`/`collectOnce`, in a `ctx.registerReceiver`/`ctx.executor` callback,
  in `ctx.scope` or in `ctx.guard("where") { … }` is caught and emitted as `agent.collector_error`
  (`collector`, `error`), at most 5 per hour and per collector (the following ones are counted).
- The requirements check (`availability`) never throws: an exception becomes "unavailable"
  ("check failed"). Reconciliation (`startAll`, `reconcile`, settings change) handles
  each collector in isolation: an error on one never interrupts the following ones.
- A failed `start` or 20 errors in one hour → only that collector becomes "unavailable" until it is
  re-enabled or the agent restarts. The others keep running.
- `ctx.reportError(e, "where")` to report an error you caught yourself.
- A callback registered **without** going through `ctx` (e.g. `TriggerEventListener`) must be protected by
  `ctx.guard`: an uncaught exception on an Android thread kills the process.

## 9. Tests

- **Pure JVM** tests (`./gradlew test`), without an emulator or Robolectric (its Android jars could not be
  fetched by the build used for development). The Android stubs return default values
  (`unitTests.isReturnDefaultValues = true`): system services `null`, no broadcast delivered.
- Extract the logic into pure functions/classes and test them directly (`MotionTracker`,
  `DeviceCollector.pluggedName`…).
- Wiring: `CollectorHarness` (testFixtures of `:core`, `testImplementation(testFixtures(project(":core")))`)
  runs real collectors in the real `CollectorHost` and records the events (with their
  `ts`, the origin one if any). The collectors thread and `ctx.io` are tracked executors there:
  `settle()` waits until neither has queued or running work (no race with `ctx.io`);
  a coroutine suspended in `delay` is considered idle: `awaitEvents(type, n)`. The system
  features declared by `Requirement.SystemFeature` are those of `h.features`:

```kotlin
CollectorHarness(MyCollector()).use { h ->
    h.granted += Manifest.permission.ACCESS_FINE_LOCATION
    h.features += PackageManager.FEATURE_WIFI    // Requirement.SystemFeature
    h.deviceOwner = true
    h.startAll()                       // or h.collectOnce("my_id"); settle() included
    assertEquals(CollectorRunState.RUNNING, h.status("my_id").state)
    val e = h.eventsOf("net.wifi").single()
    Contract.check(e.type, e.data)     // single reference of the contract
}
```

- **Contract**: `Contract` (testFixtures of `:core`) is the only test copy of contract §2 and its
  precisions: types, field names, JSON type of each value, closed lists (`sev`, `plugged`,
  `security.policy.action`…), the `fields` table of `security.log`. `Contract.check(type, data)` fails on
  an unknown type or key, a `null`, a wrong value type. Every new field is added there (after the contract).
  `app/src/test/…/ContractConformanceTest` has each collector of the APK produce its
  typical events (public data constructors, log processors, bench) and also checks
  `agent.heartbeat.collectors` (the 25 collectors, state `running`/`disabled`/`unavailable`); a declared type
  that cannot be produced on the JVM must be listed there with its reason. The samples are
  in `ApkSamples`, reused by `CrossServerTest`: upload to the **real collector** (`server/collector`) through
  the real `Uploader`, with a `.watchpost` file from the real `enroll` (skipped without `WATCHPOST_CROSS_ENROLL`; instructions at the
  top of the file).
- Other helpers: `FakeClock`, `MemoryPrefs`, `TestContext`, `openTestDatabase(dir)` (Room on embedded JVM
  SQLite, real schema).
- Before committing: `./gradlew lint test assembleDebug assembleRelease` must be green (the release needs
  the local keystore, see the README).

## 10. Landmarks in `:core`

| Need | Where |
|---|---|
| Event, JSON, ULID, RFC 3339, `boot_id` | `core/event/` |
| Buffer (Room, `seq`, severity/age purge, `dropped_total`) | `core/outbox/Outbox.kt` |
| Age purge horizon (wall-clock jump) | `core/outbox/AgeHorizon.kt` |
| Grouped writes, in-memory local event log | `core/sink/OutboxEventSink.kt` |
| Upload (batches, gzip, HTTP codes including `400` bisection, backoff, Wi-Fi) | `core/upload/Uploader.kt`, `core/work/Workers.kt` |
| mTLS client, CA pinning, ping | `core/upload/IngestApi.kt` |
| `.watchpost` file, Keystore, encrypted token | `core/enroll/` |
| `agent.tamper` (permission removed, force stop, loss of Device Owner), announced voluntary removal | `core/integrity/IntegrityMonitor.kt` |
| Origin timestamp (`OriginTime`) | `core/sink/EventSink.kt` |
| Global wiring, maintenance (15 min), network queue | `core/Agent.kt` |

### Upload: `400` (poisoned batch), `413`, transient errors

`Uploader.runLocked` (contract §3). Only the buffer is durable; nothing else needs to survive a stop.

- Consistent `200`: rows deleted. Inconsistent `200`, `401`/`403`, `429`, `5xx`, network: everything is kept,
  backoff, **never** a split of the batch.
- `413`: the batch is split in two (size remembered in `UploadStatus.batchSize`); a single event is
  deleted.
- `400`: bisection **in memory, within the pass**: `suspects` (stack of the ends of refused ranges, they bound
  `Outbox.batch(..., maxSeq)`) and `bisectLimit` (half of the refused batch). Cost ≈ 2·log2(batch) requests per
  faulty event; at most `MAX_REFUSALS_PER_RUN` (60) `400`/`413` refusals per pass, otherwise `PROTOCOL`
  with backoff. A single event that gets `400` is deleted by `Outbox.drop` (deletion **and** `dropped_total`
  in one transaction) and reported by `onDropped` (`Agent` → `agent.collector_error`).
- **Safeguard**: on the first `400` of a pass, a batch with no event is sent (`probeEnvelope`). Also refused
  (`http_400_envelope`): no event is deleted. Any `200` in the pass counts as proof.
- Sudden stop: a row is only deleted after `200` or on a lone `400`; the next run restarts the
  bisection of what remains (≤ 2·log2(500) more requests), without loss.

### Age purge and wall clock (`AgeHorizon`)

`Outbox.enforceLimits` no longer compares `ts` to `wall_clock − duration` but to `horizon − duration`, with
`horizon = min(wall, previous_horizon + 2 × Δelapsed + 1 min)` (never beyond the wall clock; after a
reboot, `+ 2 days` at most). State: SharedPreferences `watchpost_age_horizon`. A forward jump no longer empties
the buffer; a backward jump brings the horizon back at once (events written afterwards are not purged).

**Known limits** (not covered):
- Forward jump **followed by a reboot**: the horizon advances by at most 2 days per reboot, not zero (the
  downtime is unknown); a phone really switched off for a long time keeps its old events a little
  longer than the configured duration (catch-up at double speed).
- A clock that stays wrong in the forward direction still ages events twice as fast (≈ 15 real days
  for 30 days of retention); a patient attacker can therefore speed up the purge, not trigger it all at once.
- Backward jump: events from before the jump are kept longer than the configured duration
  (the size cap still applies); their `ts` are never corrected.
- **Size-based** purging and `agent.buffer_overflow` do not depend on the clock; the `ts` of events
  emitted during the clock error stay wrong (the server compares them with its own time at reception).
- `400`: if the server refuses the empty envelope AND accepts batches (behavior not foreseen by the
  contract), no event is deleted and the queue stays blocked (backoff). The agent has never been tested
  against a real server returning `400`, nor on a device.

## 11. `:policy` module (landmarks)

- `WatchpostAdminReceiver` (main thread, short callbacks): `onEnabled` → integrity, `PolicyModule.onAgentStarted`
  (self-grant, force-stop protection) and `host.reconcile()`; `onDisableRequested` →
  `agent.tamper`; `onDisabled` → `IntegrityMonitor.onAdminDisabled` (no tampering if the removal was
  announced); network and security logs → `PolicyModule.onNetworkLogsAvailable` / `onSecurityLogsAvailable`,
  which delegate to the `network_log` / `security_log` collectors (retrieval on `ctx.io`); passwords →
  `posture` (`security.keyguard`).
- Logs: pure, tested translation (`logs/SecurityLogTranslator`, `SecurityLogProcessor`,
  `NetworkLogProcessor`, `Aggregation`); each output carries `tsMs` (origin time of the first
  occurrence), passed as `originTsMs`.
- Policy: `engine/PolicyEngine` (preview, apply, rollback, Device Owner removal), on a
  `DevicePolicyGateway` interface (Android implementation `AndroidDevicePolicyGateway`, fake in the
  tests). Each action emits `security.policy` and a line in the local log; the state is written before each
  change. Catalogue: `res/raw/policy_catalog.json`; hard-coded safeguards (`engine/Guards.kt`).
- Policy screen: `app/…/ui/PolicyScreen.kt` (Compose, in `:app`) on `policy/…/ui/PolicyController`.
- ADB rescue: `rescue/RescueReceiver` (`FORCE_STOP_PACKAGES` permission required from the sender;
  extras `sweep`, `remove_owner`, `force`); scripts `rescue-revert.*` and `remove-device-owner.*`. It runs
  in the app's process: nothing launched at startup (`WatchpostApplication`, coroutine scopes of `Agent`
  and `PolicyModule`) may be able to make it crash.
- Safeguards: `PackageDenyList` (deny list), `RestrictionGuard` and `SettingGuard` (**allow** lists:
  any absent key is refused). Adding a restriction or a setting to the catalogue
  requires adding it first to the verified list, backed by the `UserManager`/`Settings` documentation.
- Applied state: written before each change (`PENDING`), read back record by record;
  unreadable → `stateWasUnreadable()` and a catalogue sweep (`sweepCatalog`) at "Restore everything". Undoing
  never stops on one item (`isolated`, `bookkeeping`).
- Blocking calls (`setGlobalPrivateDnsModeSpecifiedHost`, DoT probe) are made off the main thread.
- Never set `DISALLOW_DEBUGGING_FEATURES` nor turn off USB signaling (ADB escape hatch).

### Capability guards (contract §11.1)

| Element | Where |
|---|---|
| Keys, permissions, safeguards, notices, preview, state | `engine/CapabilityGuards.kt`: `GuardKey`, `GuardPermissions`, `GuardSafety`, `GuardNotice`, `GuardPreview`, `GuardStatus` |
| Guard engine | `CapabilityGuards` (instance `PolicyEngine.guards`): `preview`, `set`, `reconcile`, `release`, `quarantined`, `status` |
| Denying and restoring permissions (shared with the catalogue) | `PolicyEngine.denyPermissions` / `revertPermissions(only, keepRecord)` / `claimOf` |
| Gateway | `DevicePolicyGateway.installedApps/appInfo/roles/accessibilityServices/inputMethods/permitted*` (`AndroidDevicePolicyGateway`, `FakeGateway`) |
| Wiring | `PolicyModule`: lists `GUARD_LISTS` (`policy.guard.<key>.allowed`), options `GUARD_EXTENDED`, receiver `PACKAGE_ADDED/REPLACED/REMOVED` + `ACTION_DEFAULT_DIALER_CHANGED`, `requestGuardReconcile()` (merged channel: a burst = one pass), `guardNoticeListener` (set by `WatchpostApplication` → `AgentNotifications.guardNotice`, channel `watchpost_guards`) |
| UI | `ui/PolicyController` (`previewGuard`, `applyGuard`, `release`); `app/…/ui/GuardsUi.kt` (cards, preview, `Screen.Quarantine` screen), `PackagePicker.kt` |
| Tests | `policy/src/test/…/CapabilityGuardsTest` |

Invariants (do not break them):

- Records: `guard:<key>` (`ItemKind.GUARD`: the guard is active; option `guard_extended`, list in
  force `guard_allowed`, `released` for quarantine, `prev_list`/`prev_list_set`/`applied_list` for
  accessibility/keyboards) and `guard:<key>:<package>` (`ItemKind.PERMISSION`, undone like a catalogue
  permission, including the `PENDING` record of a crash). `PolicyEngine.preview/apply` ignore any
  `guard:` identifier (never treated as a catalogue orphan).
- Written before changing (`PENDING`), confirmed after reading back; a failure stays in the record, not
  applied, and is only retried at `set` (`retryFailed`): no burst of events at reconciliation.
- `revertAll`/Device Owner removal: `switchOff` of **all** the per-package guards first (no
  change to the device), then the rest from the most recent to the oldest. Disabling a single guard: its
  record first, then its packages.
- A permission denied by two records is "shared" (`claimOf`): each keeps the original state,
  `revertPermissions` does not touch a permission another one still holds.
- `GuardSafety.exemption`: Watchpost, the companion, `FLAG_SYSTEM`, the static `PackageDenyList`, **current**
  holders of the roles (SMS, dialer, active keyboard, home) — never `protectedPackages()` (too wide: HOME
  candidates, active administrators).
- Sweep (unreadable state): `CapabilityGuards.sweepLocked` (permissions of `GuardPermissions.ALL` denied
  without a record on a non-system app → `DEFAULT`; accessibility and keyboard lists → `null`).
- Accessibility/keyboards: the list set = the chosen list ∪ non-system services already enabled (otherwise the
  platform refuses). Rollback: the list from before (`null` in practice), read back.

Reconciliation additions: `CapabilityGuards.settle` (called by `sync` and `retryFailed`) brings a package
record back in line with the device before using it — unconfirmed entries of a `PENDING` record
(crash), denials that are no longer in place (reinstallation, Device Owner role lost then given back);
`GuardSafety.isOwnRole` (a guard's list only follows **its own** role) and `GuardSafety.roleGrants` (permissions
granted to the new holder of the SMS or dialer role, `grant` parameter of `PolicyEngine.revertPermissions`);
re-reading the roles every 10 s in `PolicyModule.startGuardWatch`; `PolicyStore.state()` keeps the last
decoded state (key: the text itself), because the guards look up a record by package on every pass.


## 12. Remote commands (contract §8)

The only server → phone flow. Closed list, nothing else: no code on this path has write access
to the settings, the policy or the enrollment.

| Element | Where | Role |
|---|---|---|
| Model | `core/command/CommandModel.kt` | `CommandTypes` (closed list, sensitive ones, Device Owner), `Refusal` (reasons of the contract), `CommandParams` (the only fields that reach an executor), `AcceptedCommand` (`internal` constructor: only the verifier creates them), `CommandExecutor`. |
| Cryptography | `CommandCrypto.kt` | PBKDF2-HMAC-SHA256 written on top of `Mac("HmacSHA256")` (the password encoding of `SecretKeyFactory` varies by provider: here always UTF-8, no normalization, like `TextEncoder`), HMAC, comparison with `MessageDigest.isEqual`. `isTooWeak`: floor on the passphrase (6 distinct characters; without letters, 20 digits), because the server can search for the passphrase offline from a signed command. |
| State | `CommandStore.kt` | `CommandKeyStore`: `K` sealed by `SecretBox` (Keystore AES-GCM key, alias `watchpost_command_key`), bound to the `device_id`. `CommandStateStore`: two anti-replay windows of 500 (signed / plain), invalid signatures and lockout, history (50), pending results. All in `commit()`: what guards an execution is on disk before it. |
| Verification | `CommandVerifier.kt` | Exact order of the contract; before the signature, only `v`, `id`, `device_id`, `type` are read. A valid signed `wipe` refused because wiping is not allowed consumes its `id` (it will not run if the server delivers it again after the switch is turned on). `withinValidity` (24 h at most for `wipe`, 30 days otherwise); a sensitive command refused `disabled` (channel) or `no_code_configured` is consumed in a **third window** (`CommandStateStore.consumeUnverified`: its signature cannot be verified, it must not be able to evict a verified signed `id`); U+2028/2029 refused in `message`. `JsonNesting`: JSON depth bounded before any parsing (payload here, events and responses in `CommandChannel`). `WipeGate`: the six conditions of the wipe and their re-check on the current state. |
| Processing | `CommandProcessor.kt` | One at a time: verification → executor → `command.result` (severities of the contract) → history → result to post. A command already processed and delivered again (server resend, stream + polling): never re-executed, its original result (memory of 1000 results, `CommandStateStore.rememberResult`) is sent back. `wipe`: event and upload bounded to 10 s **before** the executor. |
| Channel | `CommandChannel.kt`, `AndroidChannelPlatform.kt` | Loop (one coroutine, `Dispatchers.IO`): disabled / not enrolled / refused (401-403) / no network → wait for a signal; otherwise SSE stream (`SseParser`) or polling; jittered backoff on `elapsedRealtime`; signals: settings, network (`Agent.startNetworkWatch`), batch upload (`Agent.handleUploadOutcome`), alarm (`CommandAlarmReceiver`), maintenance. A queue + a worker process the commands while reading continues. |
| Wiring | `RemoteCommands.kt`, `Agent.commands` | `commands.*` settings, passphrase (`setCode` is slow: off the main thread), registration of the executors by module (`register`). |
| Executors | `LocateExecutor` (`:core`, through `OnDemandLocator` implemented by `LocationCollector`); `RemoteAlerts`/`RingController` (`:app`); `remote/RemoteExecutors.kt` (`:policy`) | `lock`/`clear_lock_message` behind `LockScreenGateway`; `wipe` behind `FactoryReset`, whose only real implementation (`AndroidFactoryReset`, `wipeDevice(0)`) is built in `PolicyModule.registerCommandExecutors`. |
| UI | `app/…/ui/CommandsScreen.kt`, `CommandLabels.kt`, `service/AgentNotifications.kt` | Screen, home, permanent notification ("remote commands: listening"), one notification per command, ringtone with "Stop". |

**Frugality choices** (the point that cannot be measured yet, see the README for the measurements to take):

- no permanent wake lock: reading the stream is a blocking read on an idle connection;
  bounded wake locks during a command (2 min), a poll (60 s), after an alarm (30 s), a ring
  (duration + 10 s);
- read timeout 300 s = 2.5 × the server's 120 s keep-alive (`CommandChannel.STREAM_READ_TIMEOUT_MS`); the
  server must therefore not exceed about 240 s of keep-alive. Timers do not count CPU sleep:
  dead-stream detection also relies on a `setAndAllowWhileIdle` alarm (15 min) and on
  maintenance, which compare the last reception to `elapsedRealtime` (sleep included);
- no attempt without network (wait for `onAvailable`), jittered exponential backoff, a "stillborn" stream counted
  as a failure, `401`/`403` = displayed stop, `404` = 6 h; only one pending alarm at a time;
- polling on each batch upload only happens if the stream is not open, at most once a minute.

**Tests**: `core/src/test/…/command/` (verification, order, vector, precisions of the contract §8
— `CommandReviewPrecisionsTest` —, hard cases signed by the console
— `ConsoleVectorsTest` —, replay, `wipe` refused then replayed, lockout, passphrase floor, channel against
MockWebServer), `policy/src/test/…/RemoteCommandsPolicyTest` (matrix of the 64 `wipe` combinations,
isolation of the real call checked in the sources), `app/src/test/…/CommandResultContractTest` (conformance of
`command.result`). Shared bench: `CommandKit`, `CommandVector`, `RecordingSink`, `PlainSecretBox`
(`core/src/testFixtures/…/CommandFixtures.kt`).

**Adding a command**: first the contract (§8) and the console/the collector; then `CommandTypes`,
`CommandVerifier.parseParams` (closed bounds), an executor registered by the module that owns the platform
call, the labels (`CommandLabels`, `strings_commands.xml`) and `Contract.COMMAND_TYPES`.
