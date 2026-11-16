#!/usr/bin/env bash
# Makes Watchpost the Device Owner of the phone (ADB provisioning, no factory reset).
# Preconditions checked here: no other user/profile, no account, no existing Device Owner or Profile Owner.
# Usage: ./enable-device-owner.sh
set -euo pipefail
cd "$(dirname "$0")"
. ./common.sh

require_adb
require_installed

info "Checking existing Device Owner and Profile Owner…"
owners="$(ashell dpm list-owners 2>/dev/null || true)"
if echo "$owners" | grep -q "$PKG"; then
    ok "Watchpost is already Device Owner."
    exit 0
fi
if echo "$owners" | grep -qiE 'DeviceOwner|ProfileOwner'; then
    echo "$owners"
    die "Another Device Owner or Profile Owner is already set. Remove it first."
fi

info "Checking users and profiles…"
users="$(ashell pm list users)"
user_count=$(echo "$users" | grep -c 'UserInfo{' || true)
if [ "$user_count" -gt 1 ]; then
    echo "$users" | grep 'UserInfo{' | sed 's/^/    /'
    die "Several users or profiles exist ($user_count). Delete Secure Folder, Dual Messenger, Private Space, the work profile and guest users, then run again."
fi

info "Checking accounts…"
accounts="$(ashell dumpsys account | grep -E '^[[:space:]]*Account \{' || true)"
if [ -n "$accounts" ]; then
    echo "Accounts present on the phone:"
    echo "$accounts" | sed -E 's/^[[:space:]]*/    /'
    cat >&2 <<'MSG'
ERROR: Android refuses to set a Device Owner while an account exists.
TEMPORARILY remove every account listed (Settings › Accounts and backup › Manage accounts:
Google, Samsung account, WhatsApp, Signal, Microsoft…), run this script again, then add your accounts
back: Device Owner mode does not forbid them. Check your backups and two-factor authentication
before removing a Google or Samsung account.
MSG
    exit 1
fi

if ashell dumpsys package "$PKG" | grep -q 'TEST_ONLY'; then
    info "testOnly APK: besides removal by the app or by remove-device-owner.sh, 'dpm remove-active-admin' stays available as a last resort."
else
    warn "APK is NOT testOnly: removal has to go through Watchpost (Policy screen or remove-device-owner.sh); if the app no longer starts, only a factory reset will remove it."
    read -r -p "Continue anyway? (yes/no) " answer
    [ "$answer" = "yes" ] || die "Aborted."
fi

info "Enabling: dpm set-device-owner $ADMIN"
result="$(ashell dpm set-device-owner --user 0 "$ADMIN" 2>&1 || true)"
echo "$result" | sed 's/^/    /'
if ashell dpm list-owners | grep -q "$PKG"; then
    ok "Watchpost is Device Owner. Open the app: it grants itself its permissions and turns on its protection."
    info "You can add your Google/Samsung accounts back. Turn Auto Blocker back on if you had turned it off."
else
    die "Activation failed (see the message above)."
fi
