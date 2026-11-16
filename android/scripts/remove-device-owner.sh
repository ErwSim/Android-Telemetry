#!/usr/bin/env bash
# Full removal of the Device Owner over ADB (equivalent to "Remove the Device Owner" on the
# Policy screen, which stays the recommended path when the app is usable).
#
# 1. Normal path: Watchpost's rescue (see common.sh) undoes the whole policy, turns off the network
#    and security logs, removes force-stop protection, emits security.policy "device_owner_cleared"
#    and then calls clearDeviceOwnerApp. As the removal is announced, it is not reported as
#    agent.tamper. Works with any APK (testOnly or not).
#    If an item cannot be undone, Watchpost KEEPS the role (only it can retry) and this script
#    offers to force the removal.
# 2. Fallback, only if Watchpost does not answer (app that no longer starts): "dpm remove-active-admin",
#    possible only with a testOnly APK. Watchpost then undoes nothing itself (hidden packages to
#    unhide, offered afterwards) and the removal is seen as a deactivation (agent.tamper
#    admin_disabled / device_owner_lost at the next start): this is expected.
#
# Usage: ./remove-device-owner.sh [--uninstall]
set -euo pipefail
cd "$(dirname "$0")"
. ./common.sh

uninstall=0
case "${1:-}" in
    "") ;;
    --uninstall) uninstall=1 ;;
    *) die "Unknown option: $1 (only --uninstall exists)." ;;
esac

require_adb
require_installed

if ! is_owner; then
    info "Watchpost is not Device Owner."
else
    cat <<'MSG'
Watchpost will restore everything, turn off its network and security logs, then give up the
Device Owner role. To get it back, you will have to go through enable-device-owner again (with no
accounts on the phone).
MSG
    read -r -p "Continue? (yes/no) " answer
    [ "$answer" = "yes" ] || die "Aborted."

    info "Sending the removal order to Watchpost (up to one minute)…"
    rescue_broadcast remove_owner
    case "$RESCUE_CODE" in
        1) ok "Policy restored ($RESCUE_DATA)." ;;
        2)
            warn "Partial restore: $RESCUE_DATA"
            if is_owner; then
                cat <<'MSG'
Watchpost could not undo everything and therefore kept the Device Owner role: only it can retry
(./rescue-revert.sh, then ./rescue-revert.sh --sweep). Forcing the removal leaves these items as
they are; depending on the Android version, a package left hidden or suspended can then only be
restored by a Device Owner.
MSG
                read -r -p "Force the removal anyway? (yes/no) " answer
                [ "$answer" = "yes" ] || die "Aborted: Watchpost remains Device Owner."
                rescue_broadcast remove_owner force
                [ -n "$RESCUE_CODE" ] || { printf '%s\n' "$RESCUE_OUT" >&2; die "No answer from Watchpost to the forced removal."; }
            fi
            ;;
        3) info "Watchpost was already no longer Device Owner ($RESCUE_DATA)." ;;
        4) warn "Watchpost did not finish in time; checking the role in 30 s…"; sleep 30 ;;
        *)
            printf '%s\n' "$RESCUE_OUT" >&2
            warn "No usable answer from Watchpost (app that no longer starts, or a version without rescue)."
            is_test_only || die "APK is not testOnly: Android refuses 'dpm remove-active-admin'. Repair/update the app (same signing key) then run this script again, or factory-reset the phone."
            cat <<'MSG'
Fallback: 'dpm remove-active-admin' (testOnly APK). Watchpost will not undo its policy itself:
the state of the packages it had hidden or suspended is checked afterwards.
The removal will be reported by agent.tamper (admin_disabled, device_owner_lost): this is expected.
MSG
            read -r -p "Use this fallback? (yes/no) " answer
            [ "$answer" = "yes" ] || die "Aborted."
            ashell dpm remove-active-admin --user 0 "$ADMIN" | sed 's/^/    /'
            ;;
    esac
    if is_owner; then die "Watchpost is still Device Owner ($RESCUE_DATA)."; fi
    ok "Watchpost is no longer Device Owner (Android backup, turned off by Device Owner mode, can be turned back on in Settings)."
    # What Watchpost could not undo itself (fallback, or items that stayed in failure).
    rescue_broadcast
    if [ "$RESCUE_CODE" = 3 ]; then restore_leftovers; fi
fi

if [ "$uninstall" = 1 ]; then
    adb uninstall "$PKG" && ok "Watchpost uninstalled."
fi
