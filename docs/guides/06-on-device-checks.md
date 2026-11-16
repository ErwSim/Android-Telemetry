# 06 — Checks to run on the device

This list gathers **everything that has never been verified on a real Samsung Galaxy phone** (or with a real public
server), drawn from `android/README.md`, the research notes (`docs/research/android-platform.md`,
`docs/research/server-siem-dns.md`), `infra/README.md` and the READMEs of the collector and the console. It is the
roadmap for your **first weeks of trial**, and the material for what you report back so that the project can be
fixed ([guide 07](07-development.md)).

How to use it:

- The boxes are **ordered by decreasing risk**: the first ones can cost you the phone or ADB access, the last ones
  only describe the precision of the data. Follow the order for levels 1 and 2. The phases of guide 03 ("Recommended
  order of trials") refer to these boxes; everything that concerns remote commands, the notification companion, the
  guards, the roles and the counting of operations (versions 1.1 and 1.2) has, like the rest, never been run on a
  phone.
- Each box says **how to test** and **what to note**. Always note: the date and time, the One UI version (Settings ›
  About phone › Software information), the Watchpost version (Settings › About), the **exact** text of messages
  (screenshot), and the result ("it works", "it fails", "different from what is written").
- A failure is not a drama: it is precisely what this list is looking for. After a level 1 failure, **stop** and
  report before going further.
- The identifiers V1, V2… let you cite them.

## Level 1 — Can cost you the phone or ADB access

- [ ] **V1. PowerShell scripts** (checked against the `.sh` ones, never run nor analysed by PowerShell; the bash
  scripts were run against a fake `adb`, never against a phone). *Test*: run each one once on Windows, **in the form
  `powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\<name>.ps1`** (`install-apk`,
  `enable-device-owner`, `grant-adb-permissions`, `battery-exemptions`, `push-enrollment`, `rescue-revert`,
  `remove-device-owner`, `generate-keystore`). *Note*: syntax error, execution policy error, encoding error
  (accents), unexpected message, difference in behaviour from the bash version.
- [ ] **V2. Version and installation.** *Test*: `adb shell getprop ro.build.version.sdk` (36 or more) then
  `install-apk`. *Note*: Android and One UI, installation result, any Play Protect alert (exact text).
- [ ] **V3. Device Owner activation on the Galaxy phone** (`dpm set-device-owner`) after removing the accounts, Secure
  Folder, Dual Messenger. *Test*: `enable-device-owner`. *Note*: the exact `dpm` message (success **or** failure),
  the output of `adb shell pm list users` and `adb shell dumpsys account` beforehand, any "user limit reached" error
  (reported on Samsung by other projects, with no known solution). If `dumpsys account` shows no account any more
  and activation fails anyway: stop, report.
- [ ] **V4. Putting the accounts back under Device Owner.** *Test*: put back Google, then Samsung, then the rest; open
  the Play Store. *Note*: any refusal or "administrator" message, the state of the Play Store, of Samsung Wallet, of
  backups.
- [ ] **V5. The rescue answers "empty".** *Test*: `rescue-revert` with an empty policy, screen on **then** screen off
  and locked; then, after a reboot, **before** the first unlock (the application cannot start at this stage: no
  answer, code 5, is expected) and **after**. *Note*: `Everything is restored (reverted=0…)` and the exit code, the
  response time; otherwise the code (5 = no answer) and the raw output.
- [ ] **V6. The rescue undoes a real policy.** *Test*: apply "Tips" alone (guide 03, stage 2), then `rescue-revert`;
  apply again, then `rescue-revert --sweep` (`-Sweep` in PowerShell: also restores what Watchpost might have lost
  track of). *Note*: `reverted=1`, the Tips icon returns to normal, the Policy screen's log.
- [ ] **V7. Full removal through the script** (`remove-device-owner`), empty policy. *Test*: remove, check
  `adb shell dpm list-owners` (Watchpost absent), then **re-activate** (accounts to be removed again). *Note*: the
  result, the **absence** of an `agent.tamper` alert (the removal is announced) and the presence of the
  `security.policy` event `device_owner_cleared`, Android backup turning back on, what remains (restrictions, DNS).
- [ ] **V8. Last-resort removal** `dpm remove-active-admin` (testOnly APK), empty policy, **before** having applied
  the strict profile. *Test*: run directly `adb shell dpm remove-active-admin --user 0
  io.github.erwsim.watchpost/io.github.erwsim.watchpost.policy.WatchpostAdminReceiver` (this is what the
  `remove-device-owner` script does when Watchpost does not answer), check `adb shell dpm list-owners`, then
  re-activate (accounts to be removed again). *Note*: success or "Attempt to remove non-test admin" (the APK is then
  not testOnly: `adb shell dumpsys package io.github.erwsim.watchpost | grep TEST_ONLY`), `agent.tamper` alerts
  (expected in this case), restrictions and DNS left in place, the application's state afterwards.
- [ ] **V9. Auto Blocker and Advanced Protection.** *Test*: **only after V5 to V8**. (a) Auto Blocker on: does
  `adb devices` see the phone? does `adb install` go through? (b) Device Owner active, **turn on** Auto Blocker:
  `adb shell dpm list-owners`, is Watchpost running, does `rescue-revert` answer? (c) "maximum restrictions" mode:
  does it disable Watchpost? (d) Advanced Protection (Settings › Google › All services › Advanced Protection): same
  questions. *Note*: each result and the texts displayed; if USB is cut, turn the setting off from the phone. When in
  doubt, leave it **off**.
- [ ] **V10. Play Protect.** *Test*: after 24 h, Play Store › profile › Play Protect: is Watchpost scanned, flagged
  "harmful", disabled? *Note*: any message, with the exact text. Behaviour towards a testOnly APK: unknown.
- [ ] **V11. APK update.** *Test*: `install-apk` with the **same** APK (or a new `-Pwatchpost.versionCode=2`), before
  then after applying the balanced policy. *Note*: success, the agent restarts by itself, **Device Owner kept**,
  policy kept, no `agent.tamper` alert or "application with no installer" (expected? see guide 05), `agent.started`
  events (reason `update`).

- [ ] **V12. Remote lock (`lock`) and message.** *Test*: console › Commands › "Lock with a message" (guide 03, §15),
  phone in hand. *Note*: does `lockNow` lock, does One UI show the message on the lock screen
  (`setDeviceOwnerLockScreenInfo`); "Clear the message" (command, then the local button on Watchpost's screen); result
  `lock_refused` if the administration policies were not reloaded after an update; without a secure lock screen, only
  the screen turns off.
- [ ] **V13. Command passphrase and signatures.** *Test*: a wrong passphrase once (`bad_signature` observed **by the
  phone**, Wazuh alert of level 10); a correct passphrase; a passphrase with accents typed identically. **Do not
  provoke five refusals** (one-hour lock-out, `locked_out`). *Note*: the time of "Computing the key…" on the phone,
  the match with the console.
- [ ] **V14. "Restore everything" and rescue with active guards.** *Test*: enable the quarantine then the SMS guard;
  "Restore everything" (they are switched off first) and check Settings › Apps › the app › Permissions, the keyboards
  and accessibility; enable again, then `rescue-revert` (and `--sweep`) **with a guard active**;
  `remove-device-owner` last. *Note*: a permission left locked "controlled by the administrator", a previous state
  that differs.
- [ ] **V15. Remote erase (`wipe`) — ONLY on a test phone or after a complete backup, never on your everyday phone.**
  *Test*: (a) the "Allow remote erase" switch **off**: the command is refused (`disabled`) and nothing happens; (b)
  switch on: does `wipeDevice(0)` really reset, are reset protection (Google account) and eSIMs kept, how long before
  the erase does the result arrive. As long as (b) has not been seen, **never enable** erase on your phone.

## Level 2 — Can break everyday use (policy)

To be done **in the order of guide 03** (section 14 for the policy, section 16 for the guards), one thing at a time, 24
hours minimum between each.

- [ ] **V16. Enforced private DNS** (`setGlobalPrivateDnsModeSpecifiedHost`). *Test*: stage 1 of guide 03, on Wi-Fi
  **and** mobile data, several carriers/networks if possible. *Note*: success of the application (`private_dns_set
  ok=true`), error message (`HOST_NOT_SERVING`…), networks where port 853 is blocked, perceived slowdown, requests
  visible in AdGuard's log.
- [ ] **V17. Private DNS fallback.** *Test*: `sudo docker compose stop adguardhome`; measure the delay before Internet
  returns (15 minutes by default); start AdGuard again; is the host enforced again by itself? *Note*: actual delay,
  severity-2 Wazuh alert received, and whether applying the locked DNS changes the behaviour.
- [ ] **V18. DNS lock** ("Lock the setting"). *Test*: turn it on then open Android's private DNS setting (greyed out?),
  then "Restore". *Note*: effective lifting of the lock.
- [ ] **V19. Hiding and suspending applications.** *Test*: "Tips" (suspension), then each batch (guide 03, batches 3a to
  3c); reboot; compare `adb shell pm list packages` before, after applying, after "Restore everything". *Note*: the
  catalogue packages **absent** from your phone ("absent from this phone"), those whose application fails (log
  `ok=false`), persistence of the hides after a reboot, the exact state found again after "Restore everything".
- [ ] **V20. Hidden system modules (Mainline)**: Android AdServices, On-Device Personalization, Federated Compute
  (effect "to be checked after applying" in the application). *Test*: batch 3b alone, reboot, Settings › Software
  update, Play System Update, Play Store. *Note*: any malfunction or error message.
- [ ] **V21. Push notifications** after each batch. *Test*: message received with the phone locked for more than 10
  minutes, Wi-Fi then data. *Note*: delay or absence; domains blocked in AdGuard.
- [ ] **V22. Play Store** (update, installation) and **app verification**. *Note*: failure, message.
- [ ] **V23. Banking application** (Play Integrity) with the Device Owner active, then with the balanced profile.
  *Test*: opening, login, validation of a transaction. *Note*: refusal to start; do developer options and USB
  debugging being on interfere (temporarily turn off USB debugging if so, then turn it back on); does Play Protect
  being off interfere.
- [ ] **V24. Contactless payment and Wallet** (Google Wallet, Samsung Wallet/Pay/Pass), with the Device Owner alone,
  then after the balanced profile. Effect **unknown** (no source). *Test*: a real small payment, physical card as
  backup; transit card. *Note*: any refusal, the need to register cards again.
- [ ] **V25. Samsung updates (OTA) and Device Owner.** *Test*: Settings › Software update; at the next real update,
  `adb shell dpm list-owners` before and after. *Note*: does the Device Owner survive, does the agent resume, was the
  update possible (`ospserver.net` domains allowed).
- [ ] **V26. Samsung account and services** under the balanced profile (reported conflict: HaGeZi blocks
  `gld.samsungosp.com`). *Note*: Samsung account login failures, Galaxy Store, Samsung Cloud, Find My Mobile.
- [ ] **V27. Restrictions**: "Forbid 2G" (real effect of `DISALLOW_CELLULAR_2G`: the phone no longer uses 2G; check
  `net.cell` over a few days), "Forbid unknown sources" (**does ADB installation go through?** see V11), content
  capture and suggestions. *Note*: observed consequence.
- [ ] **V28. Denied permission** (Google app: location): Settings › Apps › Google app › Permissions (locked?). *Note*:
  the text displayed and the effect on the weather or Discover.
- [ ] **V29. Setting `ble_scan_always_enabled`** (requires `WRITE_SECURE_SETTINGS`). *Test*: after applying,
  `adb shell settings get global ble_scan_always_enabled` (expected `0`). *Note*: value, error.
- [ ] **V30. Android backup re-enabled** by the balanced profile. *Test*: Settings › Accounts and backup;
  `adb shell bmgr enabled`. *Note*: the state before (turned off by the Device Owner) and after.
- [ ] **V31. Strict profile, item by item** (guide 03, stage 4). *Test*: one item at a time, 24 hours. *Note*, per item:
  the observed effect, what really breaks (Samsung account, Galaxy Store, safe mode: is booting into safe mode
  impossible?, adding a certificate, Google app, UWB, Thread…). This list is the main gain in knowledge.
- [ ] **V32. Always-on VPN** (optional, "Always-on VPN" card): consistency with private DNS (the resolver must be
  reachable inside and outside the VPN, according to the research). Not tried; enable the "block without VPN" mode
  only with a reliable VPN.

- [ ] **V33. Quarantine guard** (the least risky). *Test*: guide 03, §16, line 1. *Note*: the "New app in quarantine"
  notification, the greyed-out permissions, "Release" (the app asks again), the absence of a new quarantine at update,
  **pairing a watch, earbuds or a car whose app was just installed** (failure without a message?), the delay between
  installation and denial, `quarantined`/`released` in the console.
- [ ] **V34. Keyboards guard.** *Test*: empty list; does the preview name the enabled third-party keyboard; normal
  typing **and PIN after a reboot**; does One UI's Settings screen respect the list (a non-approved keyboard cannot be
  enabled)? *Note*: the guard is applied only in Settings, `adb shell ime enable` bypasses it.
- [ ] **V35. Accessibility guard.** *Test*: empty list; services already enabled "kept"; TalkBack and Samsung's Voice
  Assistant still enableable; a third-party service that is not enabled can no longer be. *Note*: One UI's behaviour
  ("disabled by the administrator").
- [ ] **V36. Calls guard.** *Test*: the preview (rarely empty), calling from the dialer and Samsung's address book,
  dialer opened for an emergency call (without calling). *Note*: applications stopped at the denial, "Phone" group
  frozen.
- [ ] **V37. SMS guard.** *Test*: the preview; sending an SMS from Samsung Messages; emergency SOS intact; **change the
  default SMS app** and then go back. *Note*: the "Default app changed" notification within 10 to 20 seconds, the list
  that follows, the role's permissions granted to the new holder, the frozen SMS group of the denied applications. See
  guide 08.
- [ ] **V38. Guard options** (reading SMS; answering and call log). *Test*: with an SMS or Calls guard active,
  designate as default SMS app an application the guard was refusing: it sends and receives without asking for
  anything; go back to the original application. *Note*: does automatic entry of codes received by SMS stop ("reading"
  option).

## Level 3 — Does the collection do what it says?

- [ ] **V39. Service survival.** *Test*: 24 hours with the screen off, then a reboot. *Note*: in the console, the
  `agent.heartbeat` events every 15 minutes with no gap (Events › `agent.`), absence alerts, the `agent.started` event
  (reason `boot`), `device.boot` after the first unlock, Watchpost's battery consumption (Settings › Battery).
- [ ] **V40. Nothing before the first unlock** (Direct Boot not used: intended behaviour). *Note*: the interval with no
  event after a reboot.
- [ ] **V41. Automatic permissions and force-stop protection.** *Test*: Settings › Apps › Watchpost › Permissions
  (location "always", notifications, nearby devices, phone); are "Force stop" and "Clear data" greyed out? *Note*:
  missing permissions, effect of `setUserControlDisabledPackages`, is the application uninstallable (expected: no, as
  long as it is Device Owner). Deliberately remove a permission in Settings: does the collector become "unavailable",
  is `agent.tamper` `permission_revoked` emitted, and does the Collectors tab let you give it back (Watchpost does not
  take it back by itself, the application's review having wanted it so)?
- [ ] **V42. Key in the Android Keystore and mTLS.** *Test*: "Test the connection" after enrollment, **after a reboot**
  and after several days. *Note*: "Connection successful" or the exact error message.
- [ ] **V43. System network log.** *Test*: first `net.dns` and `net.connect` with their package (delay up to 1 h 30;
  try `adb shell dpm force-network-logs`); check the original time (`ts`), the `count` values, attribution to real
  packages, lost batches (`agent.collector_error`). *Note*: the real delay, the volume per day, absent applications
  (UDP/QUIC expected).
- [ ] **V44. System security log.** *Test*: `adb shell dpm force-security-logs`; `security.log` events (ADB,
  installations, unlocks); logs from before a reboot (`pre_reboot: true`), **to be compared with what the device
  actually returns** (the function may return `null`). *Note*: tags present and absent, field names that differ from
  the contract.
- [ ] **V45. Android's notifications.** *Test*: exact text of the "device managed" notice and of the "network
  monitored" notification (number of appearances). *Note*: both texts.
- [ ] **V46. Location (GPS + passive).** *Test*: 15 minutes of walking with the phone in the pocket, then a car trip;
  compare with the map; a day spent indoors. *Note*: density of points, accuracy, expected gaps (indoors), battery.
- [ ] **V47. Wi-Fi, cell, Bluetooth, NFC, hotspot.** *Test*: SSID/BSSID present (they require precise location);
  `net.cell` with its fields; Bluetooth connections (car, earbuds); turn on the hotspot. *Note*: absent fields,
  suspicious values.
- [ ] **V48. Camera and microphone.** *Test*: open the camera, record a voice memo, make a call. *Note*:
  `sensor.camera` and `sensor.microphone` events, `screen_on` and `locked`, **no alert during a call**.
  **Experimental attribution** ("Experimental attribution (DUMP)" setting, off by default): turn it on, redo the
  test, note whether `package` is filled in or whether the error indicates a SELinux denial.
- [ ] **V49. Foreground application and volumes** (usage access granted by `grant-adb-permissions`). *Test*:
  `app.foreground` appears (100 to 400 per day); hourly `net.usage` (estimated values, delay of at least 30
  minutes); compare with Settings › Connections › Data usage. *Note*: discrepancies, missing applications.
- [ ] **V50. Inventory and application changes.** *Test*: install then uninstall an application from the Play Store:
  `app.installed`, `app.removed`; revoke/grant a permission: `app.permission_changed`; the Applications › Special access
  page. *Note*: delays, missing fields.
- [ ] **V51. USB and ADB events.** *Test*: plug in the cable, run a script: `device.usb`, `security.log`
  (`adb_shell_cmd`), corresponding Wazuh alerts (expected, guide 05). *Note*: the noise level.
- [ ] **V52. Complete posture.** *Test*: console › Security › Posture. *Note*: fields present and absent
  (`play_protect` is deliberately omitted), wrong values (encryption, verified boot, patch).
- [ ] **V53. Failed unlocks.** *Test*: enter a wrong code once or twice: `security.keyguard`. (The alert rule is at 5
  failures within 10 minutes or 10 consecutive: do not trigger it on purpose on a phone you use.)
- [ ] **V54. Offline mode.** *Test*: airplane mode for an hour, then back: does the buffer go out, with no duplicate or
  sequence gap (no sequence alert)? *Note*: resumption delay.
- [ ] **V55. Certificate renewal and re-enrollment.** *Test*: `sudo ./enroll.sh --renew phone`, import through "Import
  a new .watchpost file" (guide 05 §8); check the message "Renewal: same server, same device", the buffer kept, the new
  expiry, `enroll.sh --list`. Also try (with an `enroll` file of another device) the announcement "Same server,
  different device identifier" and then, without importing it, "Different server" (the buffer is **erased** there).
  *Note*: number of events before and after, sequence or absence alerts, and whether the old pair is indeed refused
  afterwards. Unenrolling (which erases key, token and buffer) is tested separately.
- [ ] **V56. User certificate authority** (optional): install a test certificate then remove it: `security.ca_cert`
  (severity 2) and the expected level-10 alert. *Note*: delay, duplicates between the system log and the posture.
- [ ] **V57. Certificate Transparency disabled by `network_security_config`.** Concerns only `--tls internal` mode
  (the private CA is then pinned). With Let's Encrypt, the success of "Test the connection" is enough.
- [ ] **V58. Bluetooth trackers** (AirTag, SmartTag, Tile, Google's Find Hub): only if you have a tracker available,
  separated from its owner, moved with you for more than 30 minutes over more than 500 m. Otherwise, nothing to check.

- [ ] **V59. Consumption of the permanent command channel.** *Test*: 24 hours on Wi-Fi then on mobile network (Settings
  › Battery; `adb shell dumpsys batterystats`), compared with "Periodic polling" mode. *Note*: Watchpost's share; if
  it is high, try a longer server keep-alive (`WATCHPOST_CMD_KEEPALIVE_S`, **240 s at most**) or polling.
- [ ] **V60. Receiving a command in Doze.** *Test*: screen off for more than an hour (or `adb shell dumpsys deviceidle
  force-idle`), issue `ring`. *Note*: the reception delay (the connection must stay open thanks to the foreground
  service).
- [ ] **V61. Remote ringing.** *Test*: `ring` in silent mode, vibrate mode and "Do Not Disturb" (with and without
  alarms allowed); "Stop" button on the lock screen; alarm volume restored afterwards. *Note*: `dnd_alarms_muted`.
- [ ] **V62. `locate` and channel reconnection.** *Test*: "Locate now" in the three location modes, indoors and
  outside; reconnection after a Wi-Fi ↔ mobile switch, airplane mode, server restart; behaviour after the device is
  revoked ("refused by the server", no more attempts). *Note*: `no_fix`, delays.
- [ ] **V63. Notification companion: Play Protect and installation.** *Test*: `install-notifier` (guide 03, §17).
  *Note*: any Play Protect alert (exact text; is the agent affected?), "Same signing key as the Watchpost agent"
  displayed, `INSTALL_FAILED_DUPLICATE_PERMISSION`.
- [ ] **V64. The companion's notification access.** *Test*: `notifier-access`; does `cmd notification allow_listener`
  work on One UI 8/9; does the "Restricted setting" switch appear. *Note*: the script's output and the real path in
  Settings.
- [ ] **V65. Survival of the companion's listener service.** *Test*: 24 hours, reboot, update, force stop; "Never
  sleeping apps". *Note*: does the companion show "service connected"; the channel when the agent is killed or being
  updated ("not delivered" increases, no error) and the agent being started by the companion's call; the agent's
  reading of `enabled_notification_listeners`; "settings changed" broadcast received.
- [ ] **V66. Real notification content.** *Test*: turn on "Notification content" for a few days. *Note*: content of
  messengers, codes already masked by Android 15+, grouped notifications, daily volume (a few dozen expected);
  wrongly masked items (years, amounts, postal codes); the sensitive applications of **your** phone missing from the
  exclusion list.
- [ ] **V67. Location modes "GPS + network" and "Fused".** *Test*: guide 03, §18; compare with "GPS only" indoors.
  *Note*: `location.fix.provider`, fallback to GPS only if a provider is missing, battery.
- [ ] **V68. Default applications (`app.role`).** *Test*: change browser, keyboard, SMS app; console › Security ›
  Default roles and `app.special_access.default_apps`. *Note*: the roles that can be read (the assistant and autofill
  are **not guaranteed**: an absent value means "unknown"), the absence of an event at the first reading.
- [ ] **V69. Risk profile (`app.risk`).** *Test*: console › Applications › Risk; compare a few scores with reality,
  **especially parental-control, automation, antivirus and caller-identification applications if you have any**
  (expected "high"). *Note*: a legitimate application that is "high", an application that should be and is not, the
  number of events of the first pass (about a hundred expected), "granted" versus "requested".
- [ ] **V70. `app.ops` counters (experimental): to be considered absent until seen.** *Test*: guide 08, §5:
  does `adb shell dumpsys appops --history --op SEND_SMS` produce `[bg-s] = access=N` lines; is `Debug.dumpService`
  refused by SELinux? size of a reading (a few hundred KiB); does sending an SMS from Messages increment `SEND_SMS`
  for *its* package; does a send blocked by the guard appear (`rejected_count`)? *Note*: does the collector declare
  itself "unavailable" (and its reason).
- [ ] **V71. Detections on a real phone.** *Test*: one week. *Note*: the number of `sms_permission` from the **initial
  review** (legitimate applications that hold `SEND_SMS`), the real false positives (browser with encrypted DNS,
  first photo backup, video call, unlisted mail client, new watch application or password manager), the noise per
  day, the effect of muting, the display of "Not monitored here".

### "Plausible to verify on a device" points from the application review

These eight points are assumptions of the code that nothing has confirmed; several overlap with boxes above, the
wording below is that of the review.

- [ ] **V72. Real hiding and suspension on One UI, and what Android undoes when the role is removed.** *Test*: apply a
  hidden package and a suspended package; run `remove-device-owner` **after** "Restore everything" (V7), then, in a
  second empty trial with a package still hidden, removal through `dpm remove-active-admin` (V8): does Android show
  the package again? is `adb shell pm unhide <package>` refused (permission `MANAGE_USERS`)? *Note*: the output of each
  command and `dumpsys package <package>` (line `User 0:`, fields `hidden` and `suspended`).
- [ ] **V73. Shell `am broadcast` to the rescue.** *Test*: V5, screen on, off, then after a reboot before and after
  unlocking. *Note*: the raw output of `am broadcast` (`result=…, data=…`).
- [ ] **V74. Room on the system's SQLite.** *Test*: kill Watchpost's process (Settings › Apps › Watchpost; "Force stop"
  is normally greyed out for a Device Owner), reboot the phone, cut the network for an hour. *Note*: does the buffer
  survive (Local event log › "Pending"), does the `seq` sequence stay continuous (no sequence-gap alert).
- [ ] **V75. Client TLS with an Android Keystore key.** *Test*: V42. *Note*: "Connection successful" before and after a
  reboot; any handshake error.
- [ ] **V76. Service survival for 24 h**: V39.
- [ ] **V77. Does `no_usb_file_transfer` leave ADB alone? and `no_cellular_2g` ticked by default in a 2G-only area.**
  *Test*: apply "Forbid USB file transfer" (strict profile, unticked by default) then `adb devices`, `adb shell` and
  `push-enrollment`; apply "Forbid 2G" (ticked by default in balanced) and go, if possible, to an area with no 4G/5G.
  *Note*: does ADB remain usable, does the phone keep a network for calls (emergency calls remain allowed).
- [ ] **V78. Continuous BLE scanning and GNSS consumption.** *Test*: a full day with the Trackers collector on then
  off; the GNSS falls back to the slow cadence after 5 minutes without a position (indoors). *Note*: Watchpost's share
  of battery (Settings › Battery) in each case.
- [ ] **V79. False `agent.tamper` `force_stop`** if Samsung's "Device care" (optimization, memory cleaning, deep sleep)
  stops the application. *Test*: run Device care's optimization, then look at Security › Log / Alerts. *Note*: alert
  received or not, the agent's state afterwards.

## Level 4 — Server and console with real data

The first five boxes come from guide 01 (section 9).

- [ ] **V80. Real Let's Encrypt** (console, ingestion, `dns.…`): the `curl` and `openssl s_client` commands of guide
  01. *Note*: possible validation failures.
- [ ] **V81. HaGeZi blocking lists** downloaded by AdGuard (non-zero number of rules) and **upstream resolution through
  Quad9**.
- [ ] **V82. Memory with the lists loaded**: `free -h`, `sudo docker stats --no-stream` after 24 hours. *Note*:
  AdGuard's memory (≈ 300 MB expected), swap used, restarted container.
- [ ] **V83. Port 853 from several mobile networks and Wi-Fi networks.** *Note*: which ones block DNS over TLS.
- [ ] **V84. First Let's Encrypt renewal** (about 60 days): certificate dates before and after; AdGuard reloads it
  without restarting.
- [ ] **V85. Restore on a new server** (never tried; only the restore in place was verified): `restore.sh` on a blank
  VPS; the enrolled phone is accepted.
- [ ] **V86. Real map tiles** (OpenStreetMap by default): does the console's map display?
- [ ] **V87. Real volume** after one to two weeks: events per day, disk growth (`df -h /var/lib/docker`), smoothness
  of the console and Wazuh, number of alerts per day (noise).
- [ ] **V88. Wazuh dashboards with real data**: alerts, map of positions (the base map is a third party's).
- [ ] **V89. Options not tried** (optional): ClientID mode with a DNS-01 wildcard, WireGuard.

- [ ] **V90. Real alert notifications.** *Test*: `WATCHPOST_NOTIFY_*` in `infra/.env` (guide 05, §3), then
  `install.sh`; a real ntfy server; an SMTP relay with TLS and authentication; threshold lowered to 8 to receive "SMS
  permission granted". *Note*: reception, absence of notification content in the message, delay.
- [ ] **V91. Tracking page with the real AdGuard and the real lists** (including Multi PRO, not served during the
  trials). *Test*: Block and Allow a domain, change level, `install.sh --profile`. *Note*: the effect on the phone (DoT
  query before/after), the complete blocked/allowed count with a real phone (the collector's reading of AdGuard's log
  was fixed after a trial where it skipped some; `server/collector/README.md`, "Reading"), the consistency of the
  level displayed.
- [ ] **V92. Wazuh dashboard "Watchpost — detections and applications"**: display in a browser (never looked at) and
  correlation rules (13) with real detections.
- [ ] **V93. `update.sh` on a real server** (rebuild from the image registries, never tried).

## Report template

For each box that failed or differs from what was expected, report:

1. the identifier (V16…) and what you expected;
2. what happened: exact message or screenshot, time;
3. the context: Android and One UI version, Watchpost version, mode (Device Owner or not), profile applied and items
   ticked;
4. the traces:
   - **on the phone**: the Policy screen's "Action log" and Watchpost's Local event log tab;
   - **from the PC**: `adb logcat -d | grep -i -E "watchpost|AndroidRuntime"` (PowerShell:
     `adb logcat -d | Select-String -Pattern 'watchpost|AndroidRuntime'`);
   - **in the console**: the JSON detail of the event concerned (Events page, tap the event);
   - **on the server**: `sudo docker compose logs --since 1h collector caddy adguardhome` (`infra` folder).

**Never** attach a `.watchpost` file, the contents of `infra/.env`, `infra/secrets/` or a keystore.
