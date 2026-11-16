#!/usr/bin/env bash
# Withdraws notification access and uninstalls the companion "Vigie Notifications".
# Usage: ./uninstall-notifier.sh
# The Vigie agent keeps running; its "Notifications" collector becomes "indisponible". The package
# lists remain stored in the agent (they are used again if the companion is reinstalled).
set -euo pipefail
cd "$(dirname "$0")"
. ./common.sh
NOTIFIER_PKG="io.github.erwsim.vigie.notifier"
COMPONENT="$NOTIFIER_PKG/io.github.erwsim.vigie.notifier.NotifierListenerService"

require_adb
if ! ashell pm path "$NOTIFIER_PKG" | grep -q '^package:'; then
    ok "Vigie Notifications n'est pas installé : rien à faire."
    exit 0
fi
info "Retrait de l'accès aux notifications"
ashell cmd notification disallow_listener "$COMPONENT" >/dev/null 2>&1 || warn "disallow_listener refusé (l'accès disparaît de toute façon avec l'app)."
info "Désinstallation de $NOTIFIER_PKG"
out="$(adb uninstall "$NOTIFIER_PKG" 2>&1 | tr -d '\r' || true)"
info "$out"
if ashell pm path "$NOTIFIER_PKG" | grep -q '^package:'; then
    die "Vigie Notifications est toujours installé. Désinstallez-le depuis Paramètres > Applications > Vigie Notifications > Désinstaller."
fi
ok "Vigie Notifications désinstallé."
