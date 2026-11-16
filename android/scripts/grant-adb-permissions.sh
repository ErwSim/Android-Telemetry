#!/usr/bin/env bash
# Grants over ADB every permission Watchpost may need (inventory taken from the code of the
# :core, :collectors and :policy modules).
# - Runtime permissions: useful in degraded mode (without Device Owner); as Device Owner, the app
#   grants them to itself at startup.
# - Permissions that can only be granted over ADB: needed even as Device Owner.
# "pm grant" only works for a permission declared by the installed APK: the others are
# reported and skipped.
# Usage: ./grant-adb-permissions.sh
set -euo pipefail
cd "$(dirname "$0")"
. ./common.sh

require_adb
require_installed

grant() {
    local perm="$1" why="$2" out
    if out="$(adb shell pm grant "$PKG" "$perm" 2>&1 | tr -d '\r')" && [ -z "$out" ]; then
        ok "$perm — $why"
    elif echo "$out" | grep -qiE 'has not requested|not a changeable|Unknown permission'; then
        info "$perm skipped: not declared by this version of the APK ($why)"
    else
        warn "$perm: failed — $out"
    fi
}

echo "Runtime permissions (Device Owner mode also grants them automatically):"
grant android.permission.ACCESS_FINE_LOCATION "GPS location; Wi-Fi SSID/BSSID, cell identifiers, BLE scanning"
grant android.permission.ACCESS_COARSE_LOCATION "location"
# Always after foreground location.
grant android.permission.ACCESS_BACKGROUND_LOCATION "background location"
grant android.permission.POST_NOTIFICATIONS "persistent notification"
grant android.permission.BLUETOOTH_SCAN "BLE tracker detection (ble_tracker)"
grant android.permission.BLUETOOTH_CONNECT "Bluetooth connections (bluetooth)"
grant android.permission.READ_PHONE_STATE "cell-by-cell tracking and signal (cell, optional)"
grant android.permission.ACCESS_LOCAL_NETWORK "server on a private network (Android 17)"

echo "Permissions that can only be granted over ADB:"
grant android.permission.PACKAGE_USAGE_STATS "usage access: network volumes per app (net_usage), foreground app (foreground)"
if adb shell cmd appops set "$PKG" GET_USAGE_STATS allow >/dev/null 2>&1; then
    ok "appops GET_USAGE_STATS = allow (usage access)"
else
    warn "appops GET_USAGE_STATS: failed (grant it in Settings › Apps › Special access › Usage data access)"
fi
grant android.permission.WRITE_SECURE_SETTINGS "policy: anti-tracking settings outside the Device Owner list (ble_scan_always_enabled)"
grant android.permission.DUMP "experimental camera/microphone attribution and real per-app usage (app_ops, which also requires usage-stats access); off by default in the app"
info "READ_LOGS is not granted: Android 13+ requires consent at each read, which is unusable for continuous collection."
info "Battery exemptions: ./battery-exemptions.sh"
