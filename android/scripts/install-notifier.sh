#!/usr/bin/env bash
# Installs (or updates) the optional notification companion "Watchpost Notifications" over ADB.
# Usage: ./install-notifier.sh [path/to/notifier.apk]
# Default: the release APK, else the debug APK, from android/notifier/build/outputs/apk/.
# The companion must be signed with the SAME key as the Watchpost agent (same build, same keystore):
# otherwise Android refuses to install it (INSTALL_FAILED_DUPLICATE_PERMISSION, both APKs declare the
# channel's permission) or, if the agent is absent, it will never be able to talk to it.
# Then: ./notifier-access.sh (grants notification access).
set -euo pipefail
# The APK path is the caller's: made absolute BEFORE moving to the scripts directory.
APK="${1:-}"
case "$APK" in ""|/*|[A-Za-z]:[\\/]*) ;; *) APK="$PWD/$APK" ;; esac
cd "$(dirname "$0")"
. ./common.sh
NOTIFIER_PKG="io.github.erwsim.watchpost.notifier"

if [ -z "$APK" ]; then
    if [ ! -f ../notifier/build/outputs/apk/release/notifier-release.apk ] && [ -f ../notifier/build/outputs/apk/release/notifier-release-unsigned.apk ]; then
        die "The companion's release APK is not signed (notifier-release-unsigned.apk). Generate the keystore (./generate-keystore.sh), fill in keystore.properties, then run ./gradlew :notifier:assembleRelease again."
    fi
    for candidate in ../notifier/build/outputs/apk/release/notifier-release.apk ../notifier/build/outputs/apk/debug/notifier-debug.apk; do
        if [ -f "$candidate" ]; then APK="$candidate"; break; fi
    done
fi
[ -n "$APK" ] && [ -f "$APK" ] || die "Companion APK not found. Build it (./gradlew :notifier:assembleRelease) or pass its path as an argument."

case "$APK" in
    *debug*.apk)
        warn "Debug APK: signed with this computer's debug key. It only works with a debug Watchpost agent built on the same computer; with the release agent, Android will refuse the installation."
        read -r -p "Install the debug APK anyway? (yes/no) " answer
        [ "$answer" = "yes" ] || die "Aborted."
        ;;
esac

require_adb
if ! ashell pm path "$PKG" | grep -q '^package:'; then
    warn "The Watchpost agent ($PKG) is not installed: the companion will install, but will relay nothing until the agent (signed with the same key) is there."
fi

info "Installing $APK"
if ! adb install -r -t "$APK"; then
    cat >&2 <<'MSG'
Installation failed. Frequent causes:
  - INSTALL_FAILED_DUPLICATE_PERMISSION: the companion is not signed with the same key as the installed
    Watchpost agent. Install both APKs from the same build (same keystore; release with release,
    debug with debug).
  - INSTALL_FAILED_UPDATE_INCOMPATIBLE: a companion signed with another key is already installed:
    ./uninstall-notifier.sh, then try again.
  - INSTALL_FAILED_VERSION_DOWNGRADE: versionCode lower than the installed one (-Pwatchpost.versionCode=…).
  - Play Protect blocks the installation ('harmful app blocked'): see the README (Notifications
    section); the agent is not affected, it keeps running without the companion.
  - Samsung Auto Blocker is on: turn it off for the duration of the installation.
MSG
    exit 1
fi
ok "Watchpost Notifications installed."
ashell dumpsys package "$NOTIFIER_PKG" | grep -m1 -E 'versionName=' | sed 's/^ */  /' || true

# Same signing key as the agent? (short digest of the signing certificate shown by dumpsys)
sig() { ashell dumpsys package "$1" 2>/dev/null | grep -m1 -oE 'signatures:\[[^]]*\]' || true; }
agent_sig="$(sig "$PKG")"
notifier_sig="$(sig "$NOTIFIER_PKG")"
if [ -n "$agent_sig" ] && [ -n "$notifier_sig" ]; then
    if [ "$agent_sig" = "$notifier_sig" ]; then
        ok "Same signing key as the Watchpost agent."
    else
        warn "Signing keys differ from the agent's ($agent_sig / $notifier_sig): the companion will not be able to relay anything."
    fi
fi
info "Next step: ./notifier-access.sh (notification access), then open 'Watchpost Notifications' to check its state."
