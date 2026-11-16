#!/usr/bin/env bash
# Withdraws notification access and uninstalls the companion "Watchpost Notifications".
# Usage: ./uninstall-notifier.sh
# The Watchpost agent keeps running; its "Notifications" collector becomes "unavailable". The package
# lists remain stored in the agent (they are used again if the companion is reinstalled).
set -euo pipefail
cd "$(dirname "$0")"
. ./common.sh
NOTIFIER_PKG="io.github.erwsim.watchpost.notifier"
COMPONENT="$NOTIFIER_PKG/io.github.erwsim.watchpost.notifier.NotifierListenerService"

require_adb
if ! ashell pm path "$NOTIFIER_PKG" | grep -q '^package:'; then
    ok "Watchpost Notifications is not installed: nothing to do."
    exit 0
fi
info "Withdrawing notification access"
ashell cmd notification disallow_listener "$COMPONENT" >/dev/null 2>&1 || warn "disallow_listener refused (the access goes away with the app anyway)."
info "Uninstalling $NOTIFIER_PKG"
out="$(adb uninstall "$NOTIFIER_PKG" 2>&1 | tr -d '\r' || true)"
info "$out"
if ashell pm path "$NOTIFIER_PKG" | grep -q '^package:'; then
    die "Watchpost Notifications is still installed. Uninstall it from Settings > Apps > Watchpost Notifications > Uninstall."
fi
ok "Watchpost Notifications uninstalled."
