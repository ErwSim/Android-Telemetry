# 04 — Rollback

Everything Watchpost does is reversible. This guide goes from the gentlest gesture to the most radical: **stop at
the first one that solves your problem**. Breathe: you almost always have a way out without a reset.

Commands are run from the repository's `android/` folder, with the phone plugged in over USB and USB debugging on.
On Windows, each `.ps1` script is run with
`powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\<name>.ps1 [options]` (form given below).

> **Verification status.** None of these gestures has ever been run on a phone; the PowerShell scripts have never been
> launched. The messages quoted come from the scripts. [Guide 06](06-on-device-checks.md) has you test levels 3 to 5
> **empty**, before you need them.

## To have done **before** you need it

1. The installed APK is a **release** build with `testOnly` and the **same signing key** as the updates (guide 02).
2. **USB debugging on**, PC authorised, Auto Blocker off (it can cut USB): without ADB, levels 3 to 5 are out of
   reach.
3. **`rescue-revert` run empty** successfully before any policy (guide 03, §12).
4. Reminder: the rescue answers **only after the first unlock following a reboot**.
5. **Always "Restore everything" (or `rescue-revert --sweep`) before removing the Device Owner role.**
6. No guest user and no Samsung maintenance mode while private DNS is enforced.
7. AdGuard must not block the connectivity-check domains (do not remove the exceptions in `watchpost-base.txt`).
8. With no Internet because of the DNS, the fallback acts only after **15 minutes** (by default).

## Symptom, then gesture

| Symptom | First gesture | If that is not enough |
|---|---|---|
| **No more Internet** (since private DNS) | case A below | level 2, then 3 |
| **An essential application has disappeared or is greyed out** | case B below | level 2 ("Restore everything"), then 3 |
| **No more notifications** (push) | case C below | level 2, then 3 |
| Banking application or contactless payment failing | level 2: "Restore" the last applied item, then "Restore everything" to compare | level 3 |
| No mobile network in an area | "Restore" the "Forbid 2G" restriction | |
| Cannot install or update an APK | "Restore" the "Forbid unknown sources" restriction; failing that, level 3 | |
| The Watchpost application no longer opens, crashes, or shows "Watchpost could not start" | level 3 (rescue; it remains reachable in this case) | level 4 then 5 |
| The phone gets hot or drains | level 1 (turn off collectors) | level 2 |
| **An application no longer gets a permission** (SMS, calls, contacts, microphone, camera; Settings shows "controlled by the administrator") | case D below (guard or quarantine) | level 2, then 3 |
| **A keyboard or an accessibility service will not turn on** ("disabled by the administrator") | case D: add it to the guard's list, or "Preview and disable" | level 2, then 3 |
| **Pairing a watch, earbuds, car or lock fails without a message** | case D: the application is in quarantine, "Release" | level 2 |
| Codes received by SMS no longer fill in by themselves; a direct call from an app no longer goes through | case D: the SMS guard's "also reading" option, the Calls guard | level 2 |
| **An application became the default SMS app without your choosing it** | case E below | |
| **The phone rang or locked without your asking**; unknown remote command | case F below | |
| **Phone lost or stolen** | case G below | |
| I want to stop everything at once | level 4 (remove the Device Owner) | |
| Nothing works and the phone is unusable | levels 3, 4, 5 in order | level 6 (last resort) |

## Case A — No Internet after private DNS

Private DNS is enforced by Watchpost; if your server no longer answers (VPS stopped, AdGuard crashed, port 853
blocked by the network you are on), the phone has no DNS. This is intended (no cleartext leak). In order:

1. **Change network**: Wi-Fi ↔ mobile data. Some networks filter port 853.
2. **In Watchpost** (the application opens without Internet): Settings › Device Owner › Policy › "Enforced private
   DNS" card › **Restore**. The phone gets its previous DNS back.
3. **If the lock was on** ("Lock the setting": it is off by default, and the Android setting is greyed out when it is
   on), solution 2 remains valid: "Restore" also lifts the lock. If the lock is *off*, you can also set private DNS to
   "Automatic" in Settings › Connections › More connection settings › Private DNS (usual path).
4. **From the PC**: level 3 below (`rescue-revert`).
5. **Wait**: if the fallback is active (by default), Watchpost goes back to automatic DNS by itself after 15 minutes
   of unreachability (adjustable from 5 to 240 minutes; severity-2 `security.policy`). Never tested on a device.
6. **Server side** (`infra` folder on the VPS):

   ```bash
   sudo docker compose ps
   sudo docker compose restart adguardhome
   python3 tools/dot-query.py dns.watchpost.example.org example.org
   ```

   The last command must return an address (guide 01).

## Case B — An application has disappeared or is greyed out

A "hidden" application disappears; a "suspended" application stays displayed, greyed out.

1. In Watchpost › Policy: look for it in "Disabled apps" (or read the "Action log") and tap **Restore**.
2. Failing that, level 2 "Restore everything".
3. From the PC: `rescue-revert` and then, if a package remains hidden or suspended, `rescue-revert --sweep` (also
   restores what Watchpost has lost track of). **Do not count on `adb shell pm unhide <package>` /
   `pm unsuspend <package>`**: `pm unhide` requires a permission (`MANAGE_USERS`) that the ADB shell probably does not
   have, and a package suspended by an administrator is not suspended by the shell (flagged by the review, **to be
   verified on the device**). As long as Watchpost is Device Owner, it is the one that can show its packages again.

## Case C — No more notifications

Possible causes: a batch of the policy, a notification domain blocked by AdGuard, the network (some Wi-Fi networks
filter the Google notification port, 5228), or the battery settings of the application concerned.

1. Test on **mobile data** and then on Wi-Fi.
2. Look at AdGuard's query log (`https://adguard.…`): is an `mtalk…google.com` or `fcm…` domain blocked there? By
   default they are allowed by exceptions (guide 05 to add some).
3. "Restore" the last applied item; then "Restore everything" (level 2) to settle it.

## Case D — A guard or the quarantine blocks something

The guards (Policy › Guards) deny permissions or activations; the quarantine denies a set of permissions to the
applications installed after it was turned on. In order:

1. **Quarantine**: Policy › Guards › "Quarantined apps (N)" › **Release** the application: it gets its previous state
   back ("ask": it will ask for the permissions again). This is the usual cause of a watch or earbud pairing that
   fails without a message (Bluetooth and nearby devices denied) or of a video call with no microphone.
2. **A list**: add the application to the guard's list (SMS or Calls: "allowed apps"; Accessibility or Keyboards:
   "services" or "approved keyboards"), then **"Preview and re-apply"**: the change takes effect only then.
3. **Disable the guard**: "**Preview and disable**" under the guard: the denied permissions are given back in their
   previous state. The accessibility and keyboard lists are lifted.
4. **"Restore everything"** (level 2): switches off **all the guards first**, then undoes the rest. The **ADB rescue**
   (level 3) does the same, with `--sweep` if Watchpost's state is doubtful (it also gives back any permission denied
   by the guards without a record). **Removing the Device Owner** (level 4) undoes them along with the rest; if you
   give up the role without "Restore everything" (level 5), Android itself lifts the lists and the locking of
   permissions (claim taken from the AOSP code, **to be verified**), but the denied permissions stay ungranted: the
   applications will ask for them again.

The SMS and Calls guards also freeze the permission group of the denied application in Settings: this is normal and
stops when the guard is disabled.

## Case E — An application became the default SMS app without your choosing it

This is the classic route of SMS trojans: Watchpost does not block it, it warns you (priority notification "Warning:
default app changed", Wazuh alert, `default_app_changed` detection).

1. Settings › Apps › Default apps (usual path): put your SMS application (Messages) back.
2. In Watchpost › Policy › Guards: remove the intruder from the SMS guard's list (Watchpost had added it), then
   "Preview and re-apply".
3. Uninstall it (if it is a device administrator or accessibility service, first remove that right in Settings).
   Check the carrier bill (guide 08).

## Case F — A remote command you did not issue, or a suspect server

The server can send only commands from a closed list, and the sensitive commands (lock, erase) require a signature
that it cannot produce without your command passphrase. **But** this guarantee has limits (guide 03, §15): a
compromised server can make the phone ring or locate it, and read your passphrase the next time it is typed into the
console. A signed command **remains executable until it expires**, whatever the console says.

If you doubt the server, or if an unknown command appears (a "Remote command" notification on the phone, the history
in Watchpost › Settings › Remote commands, a Wazuh alert of level 10 or 12):

1. **Change the command passphrase on the phone**: Settings › Remote commands › "Change the passphrase" (five new
   randomly drawn words). This is **the only gesture that invalidates every command already signed**, including those
   the server may still hold. Never type the old or the new passphrase into a doubtful console.
2. **Turn off the channel**: "Receive remote commands" off (the phone no longer contacts the server for commands), and
   **switch off "Allow remote erase"**.
3. Revoke the device and take back control of the server: `sudo ./enroll.sh --revoke <name>`, change the passwords
   (`sudo ./install.sh --rotate-passwords`, guide 05), then enroll again when the server is healthy.
4. Five invalid signatures within an hour block the sensitive commands for an hour (`locked_out`): this is a
   protection, not a failure.

## Case G — The phone is lost or stolen

Watchpost replaces neither an anti-theft service nor your carrier. In order:

1. **Ring** (console › Commands › "Simple actions") if you are looking for it nearby; **Locate now**: the precise
   position arrives if the phone has network, the command channel is on and the location collector is active. In
   "GPS only", an indoor position may be missing. The channel and these commands have **never been tried on a
   phone**.
2. **Lock with a message** ("Sensitive actions", the command passphrase is needed): a number where you can be
   reached. Valid for 7 days: the command waits for the phone to reconnect. **This is enough in most cases of
   loss.**
3. **Remote erase is to be considered only if**: you had **allowed it in advance** in the application (it is forbidden
   by default), you had **tried it on a sacrificial device**, your phone is **backed up**, you will not see it
   again, and you trust your server and your passphrase. An erase command is valid for only 15 minutes by default:
   the phone must reconnect within that time (otherwise, issue it again). Erasing is **irreversible**; reset
   protection (Google account) and eSIMs are kept.
4. **Whatever happens**: lock and erase through your Google or Samsung accounts, call your **carrier** to block the
   line, change your account passwords, then `sudo ./enroll.sh --revoke <name>` to close ingestion (the console
   keeps the history, last positions included).

## Level 0 — I just want it to stop sending

In Watchpost › Home: the **"Collection active"** switch. Nothing is sent, nothing is collected. Policies already
applied stay in place (level 2 to undo them).

## Level 1 — Switches in the application

- **Collectors tab**: each collector has its switch; turn off the one that heats up or gets in the way. Turning off
  "System network log" or "System security log" also turns off the system's logging. Turning off "Notifications": the
  companion no longer passes anything on.
- **Settings › Remote commands**: "Receive remote commands" turns off the channel; "Allow remote erase" removes it;
  "Delete the passphrase" does too (and sets erase back to "forbidden").
- **Notification companion**: `./scripts/notifier-access.sh --revoke` removes its access;
  `./scripts/uninstall-notifier.sh` uninstalls it (the agent continues without it).
- **Settings › Enrollment › Unenroll**: erases the key, the certificate, the token **and the events still waiting to
  be sent**; collection continues locally. To be avoided if you want to keep what has not left yet (use "Upload now"
  first).

## Level 2 — Policy: Restore and "Restore everything"

In Watchpost › Settings › Device Owner › Policy:

- **Restore** under each applied item (application, permission, restriction, DNS, setting): puts back exactly the
  previous state.
- **Guards** (Policy › Guards): "Preview and disable" undoes a guard; "Release" undoes a quarantine.
- **Restore everything** (bottom of the screen, with confirmation): undoes everything Watchpost applied (guards and
  quarantine included, which it switches off first), from the most recent to the oldest. An item that resists stays
  listed with its error: try again. The system network and security logs stay on; Watchpost remains Device Owner.

The "Action log" of the screen, and the console (Security › Policy applied), say what succeeded or failed.

## Level 3 — The ADB rescue (the application is not usable)

Equivalent of "Restore everything", sent from the PC. Only the ADB shell (or the system) can send this order; no other
application can. It only **undoes**.

```bash
./scripts/rescue-revert.sh
./scripts/rescue-revert.sh --sweep      # in addition: restores everything the catalogue may have changed, even with no trace in Watchpost's state
```

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\rescue-revert.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\rescue-revert.ps1 -Sweep
```

**Limit:** the application cannot start before the first unlock; the rescue therefore answers only **after the phone
has been unlocked at least once since its last reboot**.

| Result | Meaning | What to do |
|---|---|---|
| `Everything is restored (reverted=…)`, code 0 | done | check Internet and the applications |
| code 2, "Partial restore" | an item resists | run again, then `--sweep` (`-Sweep`); otherwise level 4 |
| code 3, "Watchpost is no longer Device Owner" | Watchpost can no longer undo anything itself | the script checks the real state of the packages it had hidden or suspended and tries `pm unhide` / `pm unsuspend` for those that still are (level 5 for what follows) |
| code 4, "did not finish in time" | the operation continues on the phone | run again in a minute |
| code 5, "No usable answer from Watchpost" | phone not unlocked since the reboot, an application that does not start, or a version without a rescue | unlock and run again; otherwise level 4 |

If `adb devices` no longer sees the phone: Auto Blocker turned back on, or the cable; unlock the phone, turn Auto
Blocker off, plug it in again.

## Level 4 — Remove the Device Owner

To be done when you want to stop everything. **First "Restore everything"** (level 2, or `rescue-revert --sweep`) and
check the result. Watchpost undoes its policy, turns off the logs, removes force-stop protection, then gives up the
role. The removal is announced: **no false `agent.tamper` alert**.

- **Through the application** (if it answers): Settings › Device Owner › Policy › **Remove Device Owner**; tick "I
  understand" and confirm. If something could not be restored, the application stops before the removal and offers
  "Remove anyway".
- **Through the script** (no interface):

  ```bash
  ./scripts/remove-device-owner.sh              # add --uninstall to also uninstall Watchpost
  ```

  ```powershell
  powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\remove-device-owner.ps1             # add -Uninstall to also uninstall Watchpost
  ```

  Answer `yes` at the confirmation. Expected: `Watchpost is no longer Device Owner`. Equivalent:
  `rescue-revert.sh --remove-owner` (PowerShell: `rescue-revert.ps1 -RemoveOwner`). **If an item could not be undone,
  Watchpost keeps the role** (only it can try again): the script tells you and offers to **force** the removal.
  Forcing leaves those items in place; depending on the Android version, a package left hidden or suspended can then
  only be restored by a Device Owner. Prefer `rescue-revert` first and then `rescue-revert --sweep`.

Afterwards: Settings › Accounts and backup: turn **Android backup** back on, which Device Owner mode had turned off;
you can uninstall Watchpost normally; on the server side, revoke the device: `sudo ./enroll.sh --revoke dev_xxx`
(`sudo ./enroll.sh --list` gives the identifier). Check: `adb shell dpm list-owners` must no longer mention
Watchpost.

## Level 5 — `dpm remove-active-admin` ("testOnly" APK only)

If the application no longer answers at all (the script printed "No usable answer from Watchpost") **and** the APK is
`testOnly` (the default variant, guide 02), `remove-device-owner` offers this fallback; answer `yes`. Manual
equivalent:

```bash
adb shell dpm remove-active-admin --user 0 io.github.erwsim.watchpost/io.github.erwsim.watchpost.policy.WatchpostAdminReceiver
```

```powershell
adb shell dpm remove-active-admin --user 0 io.github.erwsim.watchpost/io.github.erwsim.watchpost.policy.WatchpostAdminReceiver
```

Warning: in this case **Watchpost undoes nothing itself**. Android in principle lifts a removed Device Owner's
policies by itself, hidden or suspended packages included (claim made by the scripts, **not verified**); the script
checks the real state of every package Watchpost had hidden or suspended and tries `pm unhide` / `pm unsuspend` only
for those that still are. These commands may be **refused** to the ADB shell: the recourse is then to **give the role
back to Watchpost** (`enable-device-owner`, accounts removed, guide 03 step 7) and then run `rescue-revert` (Watchpost
kept the list of what it had applied). Also check private DNS (Settings › Connections › More connection settings ›
Private DNS) and that your applications work. The removal will be reported by `agent.tamper` (`admin_disabled`,
`device_owner_lost`): this is expected. This is why levels 2 to 4 must be tried **before** this one.

With a **non**-testOnly APK, Android refuses this command ("Attempt to remove non-test admin").

To check each step: `adb shell dpm list-owners` (must no longer mention Watchpost).

## Level 6 — Factory reset (last resort)

Only if: the APK is **not** testOnly and the application is unusable, or if none of levels 3 to 5 gives you a usable
phone.

- **Before**, if the phone still starts: back up (Smart Switch, photos). Remove your Google (and Samsung) account from
  the phone before the reset to avoid the anti-theft lock: otherwise Android will then require the credentials of the
  last Google (and possibly Samsung) account registered. Have them.
- **How**: Settings › General management › Reset › Factory data reset (usual path); if the phone no longer starts
  properly, through recovery mode (key combination specific to the model, given by Samsung).
- **Effect**: everything is erased, the Device Owner too. You start again from zero: reinstall, or not, following
  guide 03.

None of these steps is verified on a device; the reset is the only gesture that does not depend on Watchpost.

## After a rollback

- Note what happened (the symptom, the last applied item, the messages) and report it: it is what
  [guide 06](06-on-device-checks.md) and [guide 07](07-development.md) use to fix things.
- To **go back to Device Owner** after a removal: remove your accounts, then `enable-device-owner` (guide 03, step
  7).
