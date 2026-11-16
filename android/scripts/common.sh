#!/usr/bin/env bash
# Shared helpers for the Watchpost ADB scripts (sourced, not executed).
# Device selection: if several devices are connected, export ANDROID_SERIAL=<serial> (see "adb devices").

PKG="${WATCHPOST_PACKAGE:-io.github.erwsim.watchpost}"
ADMIN="$PKG/io.github.erwsim.watchpost.policy.WatchpostAdminReceiver"

die() { echo "ERROR: $*" >&2; exit 1; }
info() { echo "• $*"; }
ok() { echo "✔ $*"; }
warn() { echo "⚠ $*" >&2; }

# adb shell output without the trailing \r some devices add.
ashell() { adb shell "$@" | tr -d '\r'; }

require_adb() {
    command -v adb >/dev/null 2>&1 || die "adb not found. Install 'Android SDK Platform-Tools' and add it to your PATH."
    local count
    count=$(adb devices | tr -d '\r' | awk 'NR>1 && $2=="device"' | wc -l)
    if [ "$count" -eq 0 ]; then
        adb devices | tr -d '\r' | awk 'NR>1 && $2=="unauthorized"' | grep -q . && \
            die "Phone not authorized: unlock it and accept the USB debugging key."
        die "No phone connected over USB debugging (adb devices). On Samsung, temporarily turn off 'Auto Blocker'."
    fi
    if [ "$count" -gt 1 ] && [ -z "${ANDROID_SERIAL:-}" ]; then
        die "Several devices connected: export ANDROID_SERIAL=<serial number> (see adb devices)."
    fi
}

require_installed() {
    ashell pm path "$PKG" | grep -q '^package:' || die "Watchpost ($PKG) is not installed. Run install-apk.sh first."
}

is_owner() { ashell dpm list-owners 2>/dev/null | grep -q "$PKG"; }
is_test_only() { ashell dumpsys package "$PKG" | grep -q 'TEST_ONLY'; }

# ---- ADB rescue: order sent to io.github.erwsim.watchpost.policy.rescue.RescueReceiver ----
# The receiver requires the sender to hold android.permission.FORCE_STOP_PACKAGES
# (signature|privileged, never grantable to a third-party app): only the ADB shell and the system
# can send it. It only UNDOES what Watchpost has applied.
RESCUE_RECEIVER="$PKG/io.github.erwsim.watchpost.policy.rescue.RescueReceiver"
RESCUE_ACTION="io.github.erwsim.watchpost.action.RESCUE_REVERT_ALL"

# rescue_broadcast [remove_owner] [force] [sweep]: sends the order (up to one minute) and sets
# RESCUE_OUT (raw output), RESCUE_CODE (1 everything restored, 2 partial, 3 no longer Device Owner,
# 4 timed out, empty if there was no usable answer) and RESCUE_DATA (summary).
#   remove_owner: then gives up the role, only if everything could be undone;
#   force:        with remove_owner, gives up the role even if an item could not be undone;
#   sweep:        also restores everything the catalogue may have changed (doubtful or lost state).
rescue_broadcast() {
    local extra=() flag
    for flag in "$@"; do
        case "$flag" in
            remove_owner|force|sweep) extra+=(--ez "$flag" true) ;;
            *) die "rescue_broadcast: unknown option $flag" ;;
        esac
    done
    RESCUE_OUT="$(ashell am broadcast --include-stopped-packages -a "$RESCUE_ACTION" -n "$RESCUE_RECEIVER" ${extra[@]+"${extra[@]}"} 2>&1 || true)"
    RESCUE_CODE="$(printf '%s\n' "$RESCUE_OUT" | sed -n 's/.*Broadcast completed: result=\(-\{0,1\}[0-9]*\).*/\1/p' | tail -n 1)"
    RESCUE_DATA="$(printf '%s\n' "$RESCUE_OUT" | sed -n 's/.*Broadcast completed: result=[-0-9]*, data="\(.*\)"$/\1/p' | tail -n 1)"
    case "$RESCUE_CODE" in 1|2|3|4) ;; *) RESCUE_CODE="" ;; esac
}

# Extracts "key=a,b,c" from the summary, as a space-separated list.
rescue_field() { printf '%s\n' "$RESCUE_DATA" | tr ' ' '\n' | sed -n "s/^$1=//p" | tr ',' ' '; }

# State of a package for user 0, read from "dumpsys package" (line "User 0: ... hidden=... suspended=...").
pkg_flag() { ashell dumpsys package "$1" 2>/dev/null | grep -m1 -E '^[[:space:]]*User 0:' | grep -q "$2=true"; }

# Once the role is lost, Watchpost can no longer undo anything. Android normally lifts the removed
# Device Owner's policies itself (hidden or suspended packages included): the real state of each
# package Watchpost had hidden or suspended is checked, and "pm unhide" / "pm unsuspend" is only
# tried for those that still are. These commands may be refused to the ADB shell (MANAGE_USERS
# permission, packages suspended by an administrator): the only way out is then to give the role
# back to Watchpost (enable-device-owner) and run rescue-revert again, the applied state having been kept.
restore_leftovers() {
    local hidden suspended p stuck=""
    hidden="$(rescue_field hidden)"
    suspended="$(rescue_field suspended)"
    if [ -z "$hidden$suspended" ]; then
        info "No hidden or suspended package to restore."
    fi
    for p in $hidden; do
        if ! pkg_flag "$p" hidden; then ok "$p: visible."; continue; fi
        info "pm unhide $p: $(ashell pm unhide "$p" 2>&1 | tr '\n' ' ')"
        if pkg_flag "$p" hidden; then stuck="$stuck $p"; else ok "$p: unhidden."; fi
    done
    for p in $suspended; do
        if ! pkg_flag "$p" suspended; then ok "$p: active."; continue; fi
        info "pm unsuspend $p: $(ashell pm unsuspend "$p" 2>&1 | tr '\n' ' ')"
        if pkg_flag "$p" suspended; then stuck="$stuck $p"; else ok "$p: unsuspended."; fi
    done
    if [ -n "$stuck" ]; then
        warn "Still hidden or suspended:$stuck"
        warn "Android reserves restoring them to the Device Owner. Give the role back to Watchpost (./enable-device-owner.sh, with no accounts on the phone), then run ./rescue-revert.sh: Watchpost kept the list of what it had applied."
    fi
    if [ -n "$(rescue_field other_items)" ]; then
        warn "Restrictions, permissions or Private DNS set by Watchpost are normally lifted by Android when the Device Owner is removed; check Private DNS in Settings > Connections > More connection settings."
    fi
}
