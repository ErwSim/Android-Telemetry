#!/usr/bin/env bash
# Exempts Vigie from battery restrictions that could stop the collection.
# Usage: ./battery-exemptions.sh
set -euo pipefail
cd "$(dirname "$0")"
. ./common.sh

require_adb
require_installed

run() {
    local label="$1"; shift
    if adb shell "$@" >/dev/null 2>&1; then ok "$label"; else warn "$label : échec (commande : $*)"; fi
}

run "Exemption Doze (liste blanche deviceidle)" dumpsys deviceidle whitelist "+$PKG"
run "Exécution en arrière-plan autorisée (appops RUN_ANY_IN_BACKGROUND)" cmd appops set "$PKG" RUN_ANY_IN_BACKGROUND allow
run "Exécution en arrière-plan autorisée (appops RUN_IN_BACKGROUND)" cmd appops set "$PKG" RUN_IN_BACKGROUND allow
run "Seau de veille « active »" am set-standby-bucket "$PKG" active

cat <<'MSG'

À faire à la main sur Samsung (aucune commande connue) :
  Paramètres › Batterie › Limites d'utilisation en arrière-plan › Applications jamais en veille › ajouter Vigie.
En mode Device Owner, Vigie active aussi « Protection contre l'arrêt forcé », qui l'exempte des seaux de veille.
MSG
