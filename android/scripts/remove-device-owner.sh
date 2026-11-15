#!/usr/bin/env bash
# Removes Vigie's Device Owner role (only possible over ADB with a testOnly APK).
# Usage: ./remove-device-owner.sh [--uninstall]
set -euo pipefail
cd "$(dirname "$0")"
. ./common.sh

require_adb
require_installed

if ! ashell dpm list-owners | grep -q "$PKG"; then
    info "Vigie n'est pas Device Owner."
else
    ashell dumpsys package "$PKG" | grep -q 'TEST_ONLY' || die "APK non testOnly : Android refuse « remove-active-admin » (Attempt to remove non-test admin). Retirez le rôle depuis l'app, ou réinstallez une version testOnly signée par la même clé."
    cat <<'MSG'
Avant le retrait : les réglages appliqués par la politique de Vigie (paquets désactivés, restrictions,
DNS privé) doivent être défaits depuis l'app (écran Politique), sinon certains restent en place.
MSG
    read -r -p "Retirer le Device Owner maintenant ? (oui/non) " answer
    [ "$answer" = "oui" ] || die "Abandon."
    ashell dpm remove-active-admin --user 0 "$ADMIN"
    if ashell dpm list-owners | grep -q "$PKG"; then die "Le retrait a échoué."; fi
    ok "Vigie n'est plus Device Owner (la sauvegarde Android, coupée par le mode Device Owner, peut être réactivée dans les Paramètres)."
fi

if [ "${1:-}" = "--uninstall" ]; then
    adb uninstall "$PKG" && ok "Vigie désinstallée."
fi
