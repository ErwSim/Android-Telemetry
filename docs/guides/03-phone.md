# 03 — Prepare and configure the phone

This guide installs the Watchpost Agent on your Samsung Galaxy phone, promotes it to **Device Owner**, enrolls it
with your server, and then puts the anti-tracking policy into service **in stages**. This is the guide where a mistake
can be costly: read it all before you start, and keep [guide 04 (rollback)](04-rollback.md) open in another tab.

Prerequisites: the server is running and answers ([guide 01](01-server.md)); you have a **signed release APK** and a
PC with `adb` ([guide 02](02-build-apk.md)). Time: half a day for sections 1 to 12; putting the policy into service
(section 14), the remote commands (15), the guards (16), the notification companion (17) and the location modes (18)
is spread over several weeks, deliberately.

> **Verification status: read this.** Nothing in this guide has ever been run on a phone, and the PowerShell scripts
> have not even been launched once. The commands were checked against the repository's scripts, the expected
> messages come from the scripts and from the research (`docs/research/android-platform.md`), not from an execution.
> When this guide gives a phone menu, it is the usual path on One UI: it may vary with the version. At the slightest
> difference from what is written here, **stop**, note what you see (exact message, screenshot) and refer to
> [guide 06](06-on-device-checks.md). Do not force anything.

## Recommended order of trials (and what not to enable too early)

This is the recommended order. Each phase is judged before the next;
section numbers refer to this guide.

| Phase | What | Recommended duration |
|---|---|---|
| 1 | **Release APK without Device Owner**: installation (§3), ADB permissions (§8, second half) and battery (§9), enrollment (§10) and checking the uploads (§11), in degraded mode | 2 to 3 days |
| 2 | **Device Owner alone** (§4 to §8), then `rescue-revert` **empty** (§12) and a **reboot** (the rescue must still answer after the first unlock) | 1 to 2 days |
| 3 | **Private DNS alone** (§14, stage 1): "Uncheck everything", only the DNS ticked, **lock off**, **fallback active** | one week |
| 4 | **Two or three low-risk packages** (§14, stage 2), then "Restore everything" and a **comparison** | 1 to 2 days |
| 5 | **Balanced profile**, in batches (§14, stage 3) | one week |
| 6 | **Remote command channel** (§15): ring, locate, lock with a message; **never erase** at this point | 2 to 3 days |
| 7 | **Capability guards, one at a time** (§16), from the least risky to the most risky, with "Restore everything" between two | one to two weeks |
| 8 | **Notification companion** (§17), optional, content off at first | a few days |
| 9 | **Location modes** (§18), optional | at your own pace |

**Do not enable until you have seen it work** on your phone: the **strict profile**; the **always-on VPN** with "Block
connections without VPN"; the **DNS lock** ("Lock the setting"); the **ban on safe mode** (an item of the strict
profile); **disabling the DNS fallback** (Settings › Device Owner); **remote erase** (as long as you have not tried it
on a sacrificial or fully backed-up device); the guards' options "also reading SMS" and "also the call log"; the
companion's **notification content**; the location modes "GPS + network" and "Fused" (they send information to
Google).

### Warnings to keep in mind throughout the guide

1. **The APK is a signed release build, with `testOnly` (default variant) and always with the same signing key**
   (guide 02): this is what leaves an exit door (`dpm remove-active-admin`) and allows updates.
2. **Keep USB debugging on and the PC authorised** ("Always allow from this computer"): the rescue goes through
   ADB. Watchpost never turns debugging off; Auto Blocker can (§1.2).
3. **Run `rescue-revert` empty before any policy** (§12), and again after every APK update.
4. **The rescue answers only after the first unlock following a reboot.**
5. **Always "Restore everything" (or `rescue-revert --sweep`) before removing the Device Owner role**: `pm unhide` is
   probably refused to the ADB shell, so a package left hidden can then only be shown again by giving the role back
   to Watchpost.
6. **No guest user, no Samsung maintenance mode** while private DNS is enforced (Android then refuses the dedicated
   DNS APIs; Watchpost falls back to a global setting, not verified on a device).
7. **AdGuard must not block the connectivity-check domains** (`connectivitycheck.gstatic.com`…): the phone would
   show "connected, no Internet". The exceptions in `watchpost-base.txt` protect them: do not remove them.
8. **Allow 15 minutes without Internet before the DNS fallback** if the server goes down (delay adjustable from 5 to
   240 minutes).
9. **If the server is on a private network** (address in 192.168.x, 10.x…), Android 17 requires the
   `ACCESS_LOCAL_NETWORK` permission: `grant-adb-permissions` grants it (with a public VPS, it is not needed).
10. **The command passphrase** (§15): five randomly drawn words, reserved for this use, written down somewhere other
    than on the phone. It is worth only its entropy; changing it on the phone invalidates every command already
    signed.
11. **The notification companion** (§17) must be signed with the **same key** as the agent; a companion signed
    otherwise is refused at installation.

## 0. What changes on your phone

**Device Owner** mode gives Watchpost the powers of a corporate administrator on the phone: system network and
security logs, enforced private DNS, disabling apps, restrictions. It is activated through ADB, without a reset,
**but** only if the phone has no account and no second user. Consequences to accept before starting:

| Effect | Detail | Confidence |
|---|---|---|
| **Secure Folder** unavailable | It must be deleted to activate the Device Owner; it stays impossible to recreate afterwards | restriction set by Android, verified in the AOSP code; Samsung's exact behaviour not verified |
| **Dual Messenger**, **private space**, work profile unavailable | same | same |
| **Accounts to remove and put back** | Google, Samsung, messengers… Removing an account erases from the phone whatever exists only locally for that account (contacts or calendar synchronised with it, for example) | general Android behaviour |
| **"Device managed"** notice | shown in the quick settings and on the lock screen | documented |
| **"Network monitored"** notification | Android shows it at most twice (at most once per 24 h) when network logging is on, then a permanent text in the quick settings | documented |
| **Android backup off** | Android disables it at activation; Watchpost's balanced profile re-enables it | verified in the AOSP code |
| **Samsung Wallet / Pay / Pass** | effect **unknown** (no reliable source) | unverified |
| **Google Wallet, banking apps** | the Device Owner does not by itself affect Play Integrity; the indirect risks (developer options, USB debugging, Play Protect) are to be tested | unverified |
| Samsung updates (OTA) | not blocked by Watchpost; their interaction with the Device Owner is not verified | unverified |

What does **not** change: your apps, photos, files and settings stay in place.

## 1. Before starting: backups and checks

Do this section without shortening it. Allow an hour.

### 1.1 Backups

- **Smart Switch** (Samsung) to the PC, or the Samsung/Google backup of your choice: a recent, complete backup,
  **verified** (know what it contains), before opening anything.
- **Photos and videos**: confirm that they are synchronised or copied to the PC.
- **Contents of Secure Folder and Dual Messenger**: to be taken out before deletion (deleting erases what they
  contain). Check in Secure Folder's settings how to take files out before uninstalling it; for Dual Messenger, the
  data of an app's copy is in principle lost when it is turned off.
- **Messengers**: export or back up your conversations (WhatsApp, Signal, etc.) with each application's backup
  function, **before** removing its account from Android's list.
- **Two-factor authentication**: make sure you can **log back in** to your Google and Samsung accounts when you put
  them back (password, backup codes, a second factor that does not depend on this phone). If your authentication
  app exists only on this phone, know how to restore it.
- **Payment cards and Wallet**: note what Google Wallet and Samsung Wallet contain; know how to register your cards
  again. Keep a physical card on you for the first few days.
- **Factory reset** (last resort, guide 04): know that, on a phone that has a Google account, Android then requires
  that account's credentials (anti-theft protection "FRP"). Know them.

### 1.2 Check the phone

1. **Android version**: Watchpost requires Android 16 or later (`minSdk 36`). Settings › About phone › Software
   information: Android 16 (One UI 8) or 17 (One UI 9). Older: update first (otherwise installation fails with
   `INSTALL_FAILED_OLDER_SDK`). You will confirm it through ADB at step 2.
2. **Auto Blocker**: Settings › Security and privacy › Auto Blocker (usual path). On by default since One UI 6.1.1,
   it **blocks USB commands and installation from outside a store**. Turn it off for steps 3 to 12. One source in
   the research claims that its "maximum restrictions" mode disables device administration apps (which would be
   critical for Watchpost): **unverified**. After the installation, leave it **off for the whole first week** (guide
   06 has you test turning it back on): it could cut ADB access, that is, your rescue.
3. **Advanced Protection** (a Google mode, Android 16): Settings › Google › All services › Advanced Protection
   (path given by the research for One UI 8). If it is on, turn it off: it also blocks USB and 2G, and its effect on
   a third-party Device Owner is not verified.
4. **Secure Folder, Dual Messenger, private space, work profile, guest mode, additional users**: to be deleted
   before activation (usual paths: Secure Folder › Settings › More settings › Uninstall; Settings › Advanced
   features › Dual Messenger; Settings › Security and privacy › Private Space). The script of step 7 detects what
   remains; you can check right now (step 4).
5. **Charge**: battery above 50 %, a good-quality USB cable (a "data" cable, not a charge-only cable).

## 2. Turn on USB debugging

1. Settings › About phone › Software information: tap "Build number" seven times; enter your screen lock.
2. Settings › Developer options › turn on **USB debugging**.
3. Connect the phone to the PC. On the phone, a window "Allow USB debugging?" appears: tick "Always allow from this
   computer" and confirm.

On the PC:

```bash
adb devices
adb shell getprop ro.build.version.sdk      # must print 36 or more
```

```powershell
adb devices
adb shell getprop ro.build.version.sdk
```

Expected: a line `<serial number>    device`. If you see:

| Display | Cause and remedy |
|---|---|
| `unauthorized` | unlock the phone, accept the authorisation window (unplug/replug if it does not appear) |
| empty list | cable without data, USB port, Auto Blocker still on, or, on Windows, Samsung USB driver missing (install the Samsung USB driver from the manufacturer's site); try `adb kill-server` then `adb devices` |
| `no permissions` / `offline` | `adb kill-server`, replug, authorise again |
| several devices | `export ANDROID_SERIAL=<serial>` (bash) or `$env:ANDROID_SERIAL = '<serial>'` (PowerShell) |

**Keep USB debugging on as long as you use Watchpost**: it is the escape hatch. Watchpost never turns it off.

## 3. Install the APK

From the repository's `android/` folder:

```bash
./scripts/install-apk.sh app/build/outputs/apk/release/app-release.apk
```

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\install-apk.ps1 -Apk app\build\outputs\apk\release\app-release.apk
```

Always give the path of the **release** APK (see the pitfall in guide 02: with no argument, the script takes the debug
one if there is no signed release; it then asks for confirmation, answer `no`). A relative path is read from the folder
you launch the script from. Expected: `Success` from `adb`, then `Watchpost installed.` and the `versionName=…` line.

| Failure | Cause and remedy |
|---|---|
| `INSTALL_FAILED_OLDER_SDK` | Android older than 16: update the phone |
| `INSTALL_FAILED_UPDATE_INCOMPATIBLE` | another version, signed differently, is already installed: uninstall it (if it is not Device Owner) or use the original keystore |
| `INSTALL_FAILED_VERSION_DOWNGRADE` | `versionCode` lower than the installed one |
| `INSTALL_FAILED_TEST_ONLY` | installation without `-t`: use the script, not another means |
| installation blocked, or a Play Protect alert appears | Auto Blocker still on; or a Play Protect scan: note the **exact** text of the alert (guide 06) and do not turn off Play Protect without deciding knowingly |

Open the **Watchpost** application on the phone. It shows the Home screen and, as long as it is not Device Owner, a
"Degraded mode…" text: this is expected. Close it. If it shows instead **"Watchpost could not start: …"** (and
"Nothing is being collected"), note the complete message: it is a defect of the application, not of your phone
(guide 06); the rescue remains usable if a policy was applied.

## 4. Starting state (to be noted)

```bash
adb shell pm list users
adb shell dumpsys account | grep "Account {"
adb shell dpm list-owners
```

```powershell
adb shell pm list users
adb shell dumpsys account | Select-String 'Account \{'
adb shell dpm list-owners
```

To activate the Device Owner you need: **a single** `UserInfo{…}` (user 0), **no** `Account {…}` line, and
`dpm list-owners` with no owner. Note what you see now (the list of accounts in particular): you will need it to put
them back.

## 5. Temporarily remove the accounts

Android refuses to name a Device Owner as long as an account exists, **whatever it is** (Google, Samsung, WhatsApp,
Signal, Microsoft…). For each `Account {name=…, type=…}` line listed: Settings › Accounts and backup › Manage
accounts › the account › Remove account. Suggested order: application accounts (messengers…) first, Google and
Samsung last, once your backups are verified (section 1.1).

Run the command of step 4 again: no more `Account {`. If an account remains and you cannot remove it from Settings,
**note its type** (`type=…`) and refer to guide 06; do not try to force it.

> The accounts will be put back right after activation (step 7). The Device Owner does not forbid them (Watchpost
> never sets the corresponding restriction).

## 6. Last check before activation

As long as Watchpost is not Device Owner, everything is undone by uninstalling the application. Reread this list:

- backups made and verified (section 1.1); you know how to log back in to your accounts;
- Auto Blocker and Advanced Protection off; USB debugging authorised (`adb devices` shows `device`);
- step 4 shows a single user and no account;
- the server answers (console reachable) and you have, or can produce, the `.watchpost` file;
- guide 04 is open and the PC stays connected to the phone.

## 7. Activate the Device Owner

```bash
./scripts/enable-device-owner.sh
```

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\enable-device-owner.ps1
```

The script checks, in order: that there is no other owner, a single user, no account, and warns if the APK is not
`testOnly` (in which case it asks for confirmation: type `yes`). Then it runs
`dpm set-device-owner --user 0 io.github.erwsim.watchpost/io.github.erwsim.watchpost.policy.WatchpostAdminReceiver`.

Expected: a `dpm` message of the kind "Success: Device owner set to package…", then `Watchpost is Device Owner. Open the
app: it grants itself its permissions and turns on its protection.` (the exact text of `dpm` is Android's, not
verified here).

| Message | Cause and remedy |
|---|---|
| "Another Device Owner or Profile Owner is already set. Remove it first." | a corporate or management application is already the owner: identify it (`adb shell dpm list-owners`) and remove it first |
| "Several users or profiles exist (…)" | delete what the script lists (Secure Folder, Dual Messenger…) |
| "Android refuses to set a Device Owner while an account exists" | remove the listed accounts (step 5) |
| `already several users` / `already some accounts` / `user limit reached` returned by `dpm` | same causes; the "user limit reached" message is reported on Samsung by other projects **with no known solution**: if it appears while `pm list users` shows only one user, stop and note everything (guide 06) |
| any other `dpm` message | copy it in full; do not insist |

If activation fails: **nothing has changed** on the phone. You can put your accounts back and stop there.

**Immediately after success, put your accounts back** (Google first, then Samsung, then the rest): Settings ›
Accounts and backup › Manage accounts › Add account. Check that the Play Store opens and that you are logged back in.
Samsung now shows "device managed": this is expected.

## 8. First launch and permissions

Open **Watchpost**. As Device Owner, the application grants itself its runtime permissions (location, including in
the background, notifications, Bluetooth, phone…) and turns on force-stop protection.

On the **Home** screen, in the "Device administration" section, you must read:

- **Device Owner mode: Yes**;
- **Force-stop protection**: active.

If "Device Owner mode" is "No" although the script succeeded, close the application and reopen it; otherwise, guide
06.

Runtime permissions are granted automatically only **once** per Device Owner activation: if you remove one afterwards
in Android's Settings, Watchpost does not take it back by itself. The collector concerned becomes "unavailable", an
`agent.tamper` event (`permission_revoked`) is emitted, and the Collectors tab offers to grant it again.

Then the permissions that can only be obtained through ADB (usage access, the policy's secure settings, the
experimental camera/microphone attribution):

```bash
./scripts/grant-adb-permissions.sh
```

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\grant-adb-permissions.ps1
```

Expected: `✔ … — …` lines (PowerShell: `[OK]`) for each permission. A line saying the permission is skipped because this
version of the APK does not declare it is harmless. A "failed" line: note it (guide 06). The script does not grant
`READ_LOGS` (Android 13 and later requires consent at every read: unusable for continuous collection).

## 9. Battery

```bash
./scripts/battery-exemptions.sh
```

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\battery-exemptions.ps1
```

Expected: four success lines (Doze exemption, two background authorisations, standby bucket "active"). Then,
**by hand** (no known command): Settings › Battery › Background usage limits › Never sleeping apps › add
**Watchpost** (usual path, may vary by One UI version). On Watchpost's Home, "Battery optimization" must show
"Disabled for Watchpost". Do not hide the "Device care" application: it hosts this screen (that is an item of the
strict profile, unticked by default).

## 10. Enroll the phone

In the recommended order of trials, this section and the next are done **from phase 1**, before the Device Owner:
enrollment works in degraded mode, and the file is the same afterwards.

1. **On the server**: `sudo ./enroll.sh phone` (in the `infra` folder) produces `phone.watchpost`. Fetch it onto the
   PC: `scp you@vps:~/watchpost/infra/phone.watchpost .` from your repository's `android/` folder (`*.watchpost`
   files are ignored by git there).
2. **Copy to the phone, by cable**:

   ```bash
   ./scripts/push-enrollment.sh phone.watchpost
   ```

   ```powershell
   powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\push-enrollment.ps1 -File .\phone.watchpost
   ```

   Expected: `Copied to /sdcard/Download/phone.watchpost`.
3. **In the application**: Settings › Enrollment › "Import a .watchpost file" › Downloads › `phone.watchpost`.
   Check the summary before confirming: **ingest address** (`https://ingest.…`), name, **server authority**
   ("System public authorities" with Let's Encrypt), **private DNS** (`dns.…`). Tap "Enroll this device".
4. Expected result: the connection test shows "Connection successful (server time: …)" and "Device enrolled. The
   .watchpost file was deleted." The private key is then in the Android Keystore (non-exportable).

| Message | Meaning |
|---|---|
| "File rejected: …" (expired certificate, unreadable key, non-https address…) | the file is invalid: regenerate it on the server |
| "Refused by the server (401/403): invalid token or certificate, or device revoked" | the server does not recognise this device: `sudo ./enroll.sh --list`; regenerate a file |
| "Server unreachable: …" | `ingest.…` DNS not propagated, port 443 closed, invalid server certificate: redo the checks of guide 01 |
| "The server answers, but for a different device identifier" | wrong file: import again the one produced for this phone |
| "invalid device token" or "invalid device identifier" | the file is altered or truncated (transfer, text editor): regenerate it and copy it again by cable without opening it |

5. **Delete every copy of the file** (it contains the private key and the token):

   ```bash
   ./scripts/push-enrollment.sh --remove phone.watchpost
   rm -f phone.watchpost            # on the PC
   ```

   ```powershell
   powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\push-enrollment.ps1 -File .\phone.watchpost -Remove
   Remove-Item .\phone.watchpost
   ```

   and `shred -u phone.watchpost` on the server (guide 01). The removal script deletes the phone's copy if the
   application could not do it by itself.

## 11. Check that events arrive

1. **In the application**, Home tab, "Server" section: "Last successful upload" appears, with no "Last error". The
   "Upload now" button forces an upload. The **Local event log** tab shows what the agent emits.
2. **On the server**: `sudo ./enroll.sh --list` shows a recent "last contact" for `phone`.
3. **In the console** (`https://console.…`): the device selector at the top shows `phone` with a green dot (last
   contact less than 35 minutes ago). Overview: "Last contact", "Device Owner: Active", the list of collectors with
   their state. **Events** page: filter the type by `agent.` and then `security.posture`: you must see at least
   `agent.started`, `agent.heartbeat` (every 15 minutes) and the posture.
4. **Delays to know**: uploads are grouped (every 15 minutes at most). The `net.dns`, `net.connect` and
   `security.log` events are delivered by the system **in batches**, with up to 1 h 30 (network) or 2 h (security)
   of delay: their absence during the first hour is normal. `adb shell dpm force-network-logs` and
   `adb shell dpm force-security-logs` are the test commands cited by the research to force them; they have not
   been verified on a device.
5. **Read the initial posture**: console › Security › Posture. A defect **already present at enrollment**
   (encryption, USB debugging on — you turned it on — etc.) produces **no** Wazuh alert: it is up to you to read it
   here.
6. **In Wazuh** (`https://siem.…`): the "Watchpost — phone security" dashboard starts filling. The alerts expected
   during these first hours are described in [guide 05](05-operations.md) (you just used ADB: the system security log
   reports it).

## 12. Test the rescue **before you need it**

Before any policy, check that the phone answers the "Restore everything" order sent through ADB:

```bash
./scripts/rescue-revert.sh
```

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\rescue-revert.ps1
```

Expected: `Everything is restored (reverted=0…)`. Exit code 0. (This rescue answers only **after the
first unlock that follows a reboot** of the phone.) If you get "No usable answer from Watchpost" (code 5), the rescue
**does not work** on your phone: apply no policy, note the message and go on to guide 06. This test is redone after
every APK update. **Then reboot the phone, unlock it and run `rescue-revert` again**: it must answer again (before the
first unlock, it does not answer).

Also go once through the **Settings › Device Owner › Policy** screen: "Device Owner mode: Yes", "System network log"
and "System security log" active, no error.

## 13. Let it run 24 to 48 hours without a policy

Live normally. Watch: the **battery** (Settings › Battery: Watchpost's share), the **permanent notification** (it must
stay), the **errors** on Watchpost's Home, and the **regularity of the uploads** in the console. A phone that gets hot
or drains abnormally, or an agent that stops, is dealt with **before** adding a policy: see guides 05 and 06.

## 14. Put the policy into service, gradually

### Principles

- Nothing is applied without your agreement. The screen is **Watchpost › Settings › Device Owner › Policy**. There
  you choose a profile (**Balanced** by default or **Strict**), switches per item (apps, permissions, restrictions,
  setting), then "Preview of the changes" (the exact list of what will change) and "Apply". Each applied item has its
  "Restore" button; "Restore everything" undoes everything.
- **The recommended items of the chosen profile are on by default** (35 items for balanced, plus the DNS and the
  backup; the DNS lock is **off** by default). To proceed in stages, use the screen's buttons: **"Uncheck
  everything"** (Profile card: switches off absolutely everything, DNS, lock and backup included), then tick only
  what you want to try; in each card (apps, permissions, restrictions), **"Uncheck everything here"** and **"Check
  the default choices"** act on that section only; **"Profile defaults"** resets the whole selection (and therefore
  switches everything back on).
- **Pitfall: the selection is the wanted state, not a list of additions.** What is already applied and is no longer
  ticked is **restored** at the next application. From one stage to the next, the selection is remembered: **add only
  the new item** and do not press "Uncheck everything" again without ticking again what is already in place (the DNS,
  for example). **Always read the preview before "Apply"**: it lists every change, "apply" or "restore". A line that
  does not belong to the stage: "Close" and correct.
- Between two stages: **24 hours minimum** (this guide's recommendation), with the checks below. One thing at a time:
  if there is a problem, you will know which.
- The application's "profiles" (Balanced/Strict, **on the phone**) and the DNS filtering one (balanced/strict, **on
  the server**, `install.sh --profile`) are **independent**. Keep the server's DNS on balanced as long as the phone's
  profile is not stabilised.
- Keep at hand: a PC with `adb` and [guide 04](04-rollback.md).

### Checks to make after each stage

| Check | How |
|---|---|
| Reboot | reboot the phone; the agent comes back, the Watchpost notification is there |
| **Push notifications** | ask someone to write to you on your messenger, phone locked for more than 10 minutes, first on Wi-Fi and then on mobile data |
| **Play Store** | open it, look for updates, install or update a small application |
| **Banking application** | open it, log in, validate a small transaction (validation by notification included) |
| **Contactless payment** | a real small payment with the application you use (Google Wallet or Samsung Wallet), with a physical card as backup; transit card if you have one |
| Basic functions | calls, SMS, mobile data, Wi-Fi, Bluetooth (car, earbuds, watch), camera, keyboard |
| Samsung update | Settings › Software update › Download and install: must answer normally |
| Watchpost | Home with no error; console: regular uploads; Security › Policy applied page: every line `ok` |
| AdGuard (if DNS active) | query log: look for blocked domains tied to an application that misbehaves |

If something breaks: **note what and since when**, then "Restore" the last applied item; if the symptom disappears,
that is the one. If it persists, "Restore everything": if the symptom disappears, the policy is responsible;
otherwise, the cause is elsewhere. See guide 04 for what to do.

### Stage 1: private DNS alone

Goal: check that the phone can resolve through your AdGuard and that nothing else changes.

Before: from your PC, `python3 infra/tools/dot-query.py dns.watchpost.example.org example.org` must answer (guide 01).

In the Policy screen:

1. **Profile**: Balanced. Tap **"Uncheck everything"**.
2. **Enforced private DNS** card: switch on **"Enforce this DNS"** alone. **"Lock the setting" stays off** (it is off
   by default): the lock forbids changing private DNS in Android's Settings and would take away this exit door as
   long as the server has not proven itself.
3. **Preview of the changes**: a single line must appear, the private DNS. Otherwise "Close" and correct.
4. **Apply**.

Leave the **fallback** active (Settings › Device Owner › "Private DNS automatic fallback", active by default, 15
minutes).

Before applying anything, Watchpost tests from the phone that the host answers (TLS handshake on 853 and a DNS
query); otherwise, nothing changes and the log says "pre-check".

Checks: the DNS card shows the mode and the host; on Wi-Fi **then on mobile data**, browse and open two or three
applications; Settings › Connections › More connection settings › Private DNS (usual path) shows your host; in
AdGuard Home, the query log shows requests from the phone; in the console, Security › Policy applied page:
`private_dns_set` successful. Let it run **several days**: look for applications that complain and for blocked
domains in AdGuard's log (guide 05 for unblocking).

**Fallback test (optional, never run; at home, on Wi-Fi, PC within reach).** Watchpost sets DNS back to automatic mode
when the network is no longer "validated" **and** the host is continuously unreachable for 15 minutes (adjustable
from 5 to 240, Settings › Device Owner), and reports the fallback with a severity-2 `security.policy` (Wazuh alert).
To see it: on the server `sudo docker compose stop adguardhome`; the phone loses Internet; wait (up to 15 minutes by
default) for Internet to return and for the "Fallen back" warning on the DNS card; then
`sudo docker compose start adguardhome`: the host is enforced again as soon as it answers. If Internet does not come
back after 20 minutes: `./scripts/rescue-revert.sh`. The fallback runs only if Watchpost's process is alive
(foreground service, or the maintenance pass every 15 minutes): an agent killed by battery management does not
trigger it.

> The trade-off, stated plainly: with the fallback, someone who blocks port 853 makes you switch to automatic DNS
> (never silently, it is an alert). Without the fallback, protection comes first: no Internet as long as the server
> does not answer.

### Stage 2: two or three low-risk packages

Goal: check the "disable then restore" mechanism on applications you will not miss.

1. Keep the DNS ticked (see the pitfall above) and switch on **"Tips"** (Samsung Tips, "suspended": its icon stays,
   greyed out) and two "no known visible effect" packages of low risk: **Knox Analytics** and **Samsung
   Attribution** ("hidden").
2. Preview: three "apply" lines, nothing else. Apply. The Tips icon is greyed out and no longer opens; the action log
   says "succeeded" three times.
3. Reboot, do the checks of the table, live for a day or two.
4. **"Restore everything"** (bottom of the screen), then **compare**: the applications are back to normal, private DNS
   is also restored ("Restore everything" undoes *everything* Watchpost applied). Then apply the DNS again (stage 1)
   and what you want to keep. This comparison teaches you that "Restore everything" does what it says, before you need
   it.

If this trial fails (log "failed"), go no further: note the error (guide 06).

### Stage 3: the balanced profile, in three batches

The balanced profile cuts Samsung/Google telemetry and advertising that serve no other purpose; Google Play services,
the Play Store, push notifications and banking applications **must** remain functional. You apply it in three
batches, with the checks of the table between each (24 hours minimum). Stay on the Balanced profile and keep ticked
what is already applied (DNS included).

**Batch 3a: Samsung and Meta applications** (Apps card: "Check the default choices", then **switch off** the six Google
applications of batch 3b; 19 Samsung ones: Customization Service, Knox Analytics, DSMS, Device Quality Agent, SVC
Agent, Carrier Log Collector, CcInfo, Log Writer, Samsung Attribution, Device ID Service, SOH Service, Galaxy Widget,
Maps Agent, IPS Geofence, Network Diagnostic, Wi-Fi Network Diagnostics, QoS Indicator, Tips, Smart Suggestions; plus
Meta App Manager, Meta Services, Meta App Installer). Known effects: no more Samsung advertising identifier, no more
personalised suggestions, a less detailed battery diagnostic in Samsung Members. `diagmonagent` is deliberately never
touched (Watchpost's deny list): disabling it causes a restart loop that makes the phone hot; turn off "Send
diagnostic data" in Samsung's settings instead.

**Batch 3b: Google applications** (tick them one at a time; Android AdServices, On-Device Personalization, Federated
Compute, Market Feedback Agent, Google Partner Setup, Location History stub). The first three are **system modules
(Mainline)**: the effect of hiding them is flagged "to be checked after applying". Do this batch **alone**, then
reboot and check **in particular** the Play Store and the system updates (Settings › Software update; Google Play
system update).

**Batch 3c: restrictions, permission, setting** ("Check the default choices" in the Restrictions and Denied
permissions cards, then the setting and the backup)

- Restrictions (5): forbid adding users; **forbid 2G** (no network where only 2G exists; emergency calls remain
  possible); **forbid unknown sources**; turn off content capture; turn off content suggestions.
- Denied permission (1): Google app, location.
- Setting: "Permanent Bluetooth scanning" turned off (requires `WRITE_SECURE_SETTINGS`, granted at step 8;
  `global:ble_scan_always_enabled` is one of the only two settings Watchpost agrees to write).
- Android backup: "Re-enable Android backup" (which the Device Owner had turned off).

**Extra check for "Forbid unknown sources"**: the application's text says that installation through ADB (and so
Watchpost's updates) is "not affected according to the documentation (to be verified)". **Verify it now**, not on
the day of an update: reinstall the same APK
(`./scripts/install-apk.sh app/build/outputs/apk/release/app-release.apk` or, in PowerShell, the form
`powershell … -File .\scripts\install-apk.ps1 -Apk app\build\outputs\apk\release\app-release.apk` of section 3) and
observe success, then that the agent restarts and that the Device Owner is still there. On failure, "Restore" that
restriction.

**After the three batches**, note what works. Later, faced with doubtful behaviour, the comparison "Restore
everything" then reapplying the profile tells you whether the policy is responsible.

### Stage 4: the strict profile, item by item

The strict profile **deliberately breaks** functions: Samsung account, Galaxy Store, Samsung Cloud, Find My Mobile
(through the account), Samsung notifications, the Google app, Assistant and voice search, safe mode, adding
certificates. Choose it only if you have decided to do without them. Switch to the Strict profile in the screen (the
balanced items stay). **At the switch, the strict items recommended by default tick themselves** (8 applications
including the Samsung account, 2 permissions, 6 restrictions): switch them off one by one, then add **only one item
at a time** while keeping ticked what is already applied; the preview must always show **a single** line. In this
order of increasing risk, with the checks of the table between each:

1. Low-risk restrictions: turn off UWB, turn off Thread, forbid Bluetooth sharing, turn off content sent to the
   assistant.
2. Samsung service applications: OMC Agent, Update Center, Samsung Push Service, Samsung Cloud, Experience Service,
   KLMS Agent.
3. **Google app** (suspended) and its permissions (microphone, camera, contacts).
4. "Lost convenience" restrictions: **forbid safe mode** (you lose a recourse if an application locks up the phone),
   **block adding certificates** (corporate Wi-Fi and certificate VPNs to be configured *before*).
5. **Samsung account** (high risk: breaks Galaxy Store, Samsung Cloud, Samsung's Find My Mobile): apply only if you no
   longer depend on it.

**Never tick without a precise plan** (they are unticked by default and marked high or critical risk): Google Play
services, Google Services Framework, Play Store (push notifications, banking applications, Play Store, Wallet),
Samsung Wallet / Pay / Pass, NFC (contactless payment), Find My Mobile (anti-theft), Device care (makes the "never
sleeping" list disappear), eSIM, USB file transfer. The strict profile leaves Android backup off.

## 15. Put the remote command channel into service

Do this **after** phase 5, never before: the channel adds a permanent connection to the server (consumption to be
measured) and commands one of which is irreversible. The principle: the server can send only a closed list of
commands (ring, vibrate, stop ringing, locate, lock with a message, clear that message, erase), never a setting or a
policy. The channel is **off by default**; every command received is shown as a notification and in the history.

**Prerequisites**: enrolled phone; Device Owner to lock, clear the message and erase (ring, vibrate and locate do not
need it).

1. Watchpost › **Settings › Remote commands** (or the "Remote commands" card on Home). Switch on "Receive remote
   commands". Mode **Permanent connection** (default: command received within seconds; each keep-alive message from
   the server, every 2 minutes, wakes the modem) or **Periodic polling** (1 to 15 minutes). Consumption has never been
   measured: after 24 hours, compare Watchpost's share in Settings › Battery, first on Wi-Fi then on mobile network;
   if it is high, switch to polling.
2. **Command passphrase** ("Command passphrase" card): 12 characters at least, entered twice; the application
   refuses a passphrase with fewer than 6 distinct characters, or made of digits only below 20 digits. **Take five
   randomly drawn words** (for example with dice), **reserved for this use**, and write them in your password
   manager: you will be asked for it in the console for every sensitive command. Enter it identically everywhere
   (avoid composed accented characters). The phone keeps only a derived key, encrypted by a Keystore key, after a
   computation of a few seconds ("Computing the key…"); the server never receives it.
3. In the console, **Commands** page: the "Command channel" card must show the phone connected (permanent mode) or a
   recent last contact (polling).
4. **Trials, in order** (phone within reach):
   - **Ring** ("Simple actions" card): the phone rings at full volume even in silent or vibrate mode, a notification
     "Watchpost is making this phone ring" appears with a **Stop** button; the console history goes to "executed". If
     "Do Not Disturb" silences alarms, the sound stays muted and the result says so (`dnd_alarms_muted`): the
     vibration and the notification remain. Try in silent mode, vibrate mode and "Do Not Disturb".
   - **Locate now**: a precise position arrives within a minute at most (GPS; indoors there may be none: result
     "failed", `no_fix`, try outside) and is shown on the page's map. It respects the location collector: if it is
     off or lacks permission, the command fails (`location_unavailable`).
   - **Lock with a message** ("Sensitive actions" card): confirmation, then the command passphrase; the phone locks
     and shows the message on the lock screen. Without a secure lock screen, only the screen turns off. Unlock
     normally, then **Clear the message** (command, or button on Watchpost's screen). If the result is `failed` with
     `lock_refused` (the case after an update from an earlier version), the administration policies were not reloaded:
     note it (guide 06).
   - A wrong passphrase is refused by the **phone** (`bad_signature`, Wazuh alert of level 10); **five refusals within
     an hour block the sensitive commands for an hour** (`locked_out`, level 12). Do not provoke this more than once.
5. Default validities: 1 hour for a simple command, 7 days to lock or clear the message (30 at most), **15 minutes to
   erase** (24 hours at most).

**Remote erase: do not enable it now.** "Allow remote erase" is off by default and turns on only with a passphrase set
and after typing "ERASE". A command signed with your passphrase then resets the phone to zero, **with no other
confirmation**, permanently (reset protection, that is the Google account required at restart, and eSIMs are
kept). Enabling it requires three things you do not yet have: having **tried it on a sacrificial or fully backed-up
device** (never run on a phone), certainty that your passphrase is strong, and the conviction that locking is not
enough. In most cases of loss, **locking with a message is enough** (guide 04, "If the phone is lost").

**What the signature guarantees, and its limits** (contract §8): no sensitive command runs without a valid signature
for the passphrase set on the phone. But the server holds the signed content and can search for your passphrase
offline (hence the five words); the console page where you type it is served by the server (a compromised server can
alter it and read the passphrase the next time you type it); a signed command remains executable until it expires,
whatever the console shows ("cancelled" or "expired" binds only the server). **Only changing the passphrase on the
phone** invalidates a command that was already signed: that is the gesture to make if you doubt the server (guide
04).

## 16. Put the capability guards into service, one by one

The guards lock down the capabilities that malware needs (guide 08 for the SMS case). Screen **Policy › Guards**. They
are **all off by default**, are enabled **one by one** through "Preview and enable" (the preview says which
application loses what), and are undone through "Preview and disable", "Restore everything", the removal of the
Device Owner and the ADB rescue.

**Before**: `rescue-revert` on an empty policy succeeded (§12), phase 5 stabilised. **Method for each guard**: enable,
make the checks below, then **"Restore everything"** and check that the previous state comes back (Settings › Apps ›
the app › Permissions; keyboards; accessibility). "Restore everything" undoes *everything* Watchpost applied (DNS and
packages included) and first switches off all the guards: then apply again what you keep, through "Preview of the
changes" then "Apply" for the policy and "Preview and enable" for the guards (the selection is remembered). Once you
have seen this work twice, you can space out the "Restore everything" steps (this guide's suggestion).

The order suggested by the application itself is: **Quarantine, Keyboards, Accessibility, Calls, SMS, and only then the
"also…" options**, from the least to the most risky.

| # | Guard | Checks after enabling | What can break |
|---|---|---|---|
| 1 | **Quarantine** (no immediate effect) | Install a small test application (APK or store): notification "New app in quarantine"; Settings › Apps › the app › Permissions: SMS, contacts, microphone… greyed out "controlled by the administrator". "**Release**" (Guards › Quarantined apps): the app asks again. Update it: no new quarantine. Console › Security › Policy applied: `quarantined` and `released`. | a brand-new application cannot use the microphone, camera, contacts, SMS, calls, background location before being released; **pairing a watch, earbuds, car or lock whose app was just installed fails without a message** (Bluetooth and nearby devices) |
| 2 | **Keyboards** (empty list) | The preview must name as "guarded" any third-party keyboard that is enabled. Normal typing, **including the PIN after a reboot** (Samsung keyboard). Settings › General management › Keyboard: a non-approved keyboard cannot be enabled. | enabling a new keyboard (Gboard, SwiftKey…) without having added it to the list; no risk of being left without a keyboard (a keyboard already enabled continues, the system one remains offered); the guard is applied only in One UI's Settings screen (**to be verified**) |
| 3 | **Accessibility** (empty list) | Services already enabled are kept (Android requires it); TalkBack and Samsung's Voice Assistant remain enableable; a third-party service that is not enabled can no longer be ("disabled by the administrator"). | a new password manager, Tasker, MacroDroid, a blocker or launcher that uses accessibility, if it is not in the list |
| 4 | **Calls** (no option) | The preview is **rarely empty** (`CALL_PHONE` is requested by messengers, banks, maps, watch, car; every application that had it is stopped at the denial). Call from the dialer and from Samsung's address book. Emergency call: do not actually dial, just check that the dialer opens. | direct calling from a third-party app (home automation, watch, car, taxi); opening the dialer with a prefilled number remains possible; the "Phone" group of the denied applications is frozen |
| 5 | **SMS** (no option) | The preview lists the third-party applications that request `SEND_SMS`. Send an SMS from Samsung Messages; the emergency SOS stays intact (system application). Change the default SMS app and check, within 10 to 20 seconds, the "Default app changed" notification and that the list follows; then go back to the original application. | carrier visual voicemail, watch or car app that replies by SMS, number verification: to be put in the list |
| 6 | **Options** "also…" (reading SMS; answering and call log) | With an SMS or Calls guard active: **change the default SMS app** to an application the guard was refusing, check the notification within 10 to 20 seconds and that the application sends and receives without asking for anything, then go back to the original application. | automatic entry of codes received by SMS stops working in third-party applications |

After the last one: `rescue-revert` **with a guard active** (it must undo them), and only at the very end
`remove-device-owner` (guide 04). A guard's **lists** (allowed applications, approved services) are edited in the
screen; the change takes effect only at "Preview and re-apply". The reasons for the guards' limits (system
application, default app, accessibility service already active, a window of a few seconds to 15 minutes, frozen
permission groups, other users) are in `android/README.md`, "What the guards cannot prevent".

**Default apps and risk profile**: the `app_risk` and `app_role` collectors are on by default (nothing to do); they
feed the console (Applications › Risk, Security › Default roles) and the detections. The experimental `app_ops` counters are
**off by default**: enable them only to check them (guide 08, §5).

## 17. Install the notification companion (optional)

The agent says which applications display notifications; **reading** their title and text requires a second APK,
**Watchpost Notifications** (`io.github.erwsim.watchpost.notifier`), separate so as not to expose the Device Owner APK
to Play Protect. It does not have the `INTERNET` permission, has no sensitive permission, keeps nothing (no history,
no file) and hands notifications to the agent through a local channel protected by a signature-level permission.
**Nothing has ever been tried on a phone**; the first unknown is Play Protect's reaction to its installation.

1. **Build** with the **same key** as the agent (guide 02, §6.1): `notifier/build/outputs/apk/release/notifier-release.apk`.
2. **Install** (from `android/`):

   ```bash
   ./scripts/install-notifier.sh notifier/build/outputs/apk/release/notifier-release.apk
   ```

   ```powershell
   powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\install-notifier.ps1 -Apk notifier\build\outputs\apk\release\notifier-release.apk
   ```

   Expected: "Watchpost Notifications installed.", then "Same signing key as the Watchpost agent." Failures: `INSTALL_FAILED_DUPLICATE_PERMISSION` (another key: install both APKs from the same
   build), a Play Protect alert ("harmful app blocked": note the exact text, the agent is not concerned and continues
   without the companion), Auto Blocker (guide 03 §1.2).
3. **Grant notification access**:

   ```bash
   ./scripts/notifier-access.sh
   ```

   ```powershell
   powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\notifier-access.ps1
   ```

   The script uses `cmd notification allow_listener` (unverified on One UI 8/9) and then checks
   `enabled_notification_listeners`. If it fails: Settings › Notifications › … › "Notification access" › Watchpost
   Notifications (the path varies); if the switch is greyed out ("Restricted setting"): Settings › Apps › Watchpost
   Notifications › ⋮ › "Allow restricted settings", then grant access.
4. Open **Watchpost Notifications**: access granted, listener service connected, agent present (same key), collection
   active. In Watchpost › Collectors › **Notifications**, the collector goes from "unavailable" to "active" (at the
   latest at the 15-minute maintenance pass). Console › Applications › **Notifications**: events arrive, **without title or
   text**.
5. **Adjust**: in Watchpost, "Notification content" is **off by default** (switch it on only after a few days) and
   "Mask numeric codes" is on; in the companion, the two lists (apps excluded from content: banks, payment,
   authenticators, password managers, SMS and phone; ignored apps: nothing is passed on), **to be completed with
   your own sensitive applications**: these are exact package names, so the list is necessarily incomplete. With
   content on, the title and the text (512 characters at most) go to **your** server and are kept 90 days in the Wazuh
   archives; masking replaces any run of 4 to 8 digits with `••••` but also masks years or postal codes, and lets
   through codes of 3 or 9 digits or alphanumeric codes.
6. **Remove**: turn off the "Notifications" collector in Watchpost; `./scripts/notifier-access.sh --revoke`
   (PowerShell: `notifier-access.ps1 -Revoke`); or `./scripts/uninstall-notifier.sh` (PowerShell: same form,
   `uninstall-notifier.ps1`).

To watch: the listener service may be stopped by Samsung's battery management (add Watchpost Notifications to "Never
sleeping apps").

## 18. Choose the location mode (optional)

Watchpost › Collectors › **Location** › "Location mode":

| Mode | What goes to Google | Effect |
|---|---|---|
| **GPS only** (default) | nothing on Watchpost's part (GNSS XTRA/SUPL assistance is set by the system) | often no position indoors |
| **GPS + network** | surrounding Wi-Fi networks and cell towers (the network provider of Google Play services, active if "Google Location Accuracy" is on) | approximate position indoors within seconds |
| **Fused** | same (the fused provider of Google Play services) | fast position, often precise indoors |

`location.fix.provider` gives the actual provider of each fix. If a provider is absent, Watchpost falls back to GPS
only. These modes also improve `locate` (§15) indoors, at the price of what they transmit to Google: it is your
choice. Never tried on a phone.

Once the policy is in place, what follows is in [guide 05](05-operations.md) (operations); in case of problems,
[guide 04](04-rollback.md); and the checks to make during this first week are in
[guide 06](06-on-device-checks.md).
