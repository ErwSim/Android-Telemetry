#!/usr/bin/env bash
# Installs (or updates) the Watchpost APK over ADB.
# Usage: ./install-apk.sh [path/to/app.apk]
# Default: the release APK, else the debug APK, from android/app/build/outputs/apk/.
# "-t" is required for a testOnly APK (default build); "-r" keeps the data on update.
# An update must be signed with the SAME key as the installed app (mandatory for a Device Owner).
set -euo pipefail
# The APK path is the caller's: made absolute BEFORE moving to the scripts directory.
APK="${1:-}"
case "$APK" in ""|/*|[A-Za-z]:[\\/]*) ;; *) APK="$PWD/$APK" ;; esac
cd "$(dirname "$0")"
. ./common.sh

if [ -z "$APK" ]; then
    # An unsigned release APK cannot be installed: say so instead of silently falling back to debug.
    if [ ! -f ../app/build/outputs/apk/release/app-release.apk ] && [ -f ../app/build/outputs/apk/release/app-release-unsigned.apk ]; then
        die "The release APK is not signed (app-release-unsigned.apk). Generate the keystore (./generate-keystore.sh), fill in keystore.properties, then run ./gradlew assembleRelease again."
    fi
    for candidate in ../app/build/outputs/apk/release/app-release.apk ../app/build/outputs/apk/debug/app-debug.apk; do
        if [ -f "$candidate" ]; then APK="$candidate"; break; fi
    done
fi
[ -n "$APK" ] && [ -f "$APK" ] || die "APK not found. Build it (./gradlew assembleRelease) or pass its path as an argument."

case "$APK" in
    *debug*.apk)
        warn "Debug APK: signed with the debug key (an update to the release APK will be refused while Watchpost is Device Owner) and 'debuggable' (adb run-as can read the app's data)."
        warn "On a phone you use every day, install the release APK (./gradlew assembleRelease)."
        read -r -p "Install the debug APK anyway? (yes/no) " answer
        [ "$answer" = "yes" ] || die "Aborted."
        ;;
esac

require_adb
info "Installing $APK"
if ! adb install -r -t "$APK"; then
    cat >&2 <<'MSG'
Installation failed. Frequent causes:
  - INSTALL_FAILED_UPDATE_INCOMPATIBLE: the APK is not signed with the same key as the installed app.
    A Device Owner cannot be updated with another key: use the original keystore.
  - INSTALL_FAILED_VERSION_DOWNGRADE: versionCode lower than the installed one (-Pwatchpost.versionCode=…).
  - Samsung Auto Blocker is on: turn it off for the duration of the installation.
MSG
    exit 1
fi
ok "Watchpost installed."
ashell dumpsys package "$PKG" | grep -m1 -E 'versionName=' | sed 's/^ */  /' || true
