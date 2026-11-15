#!/usr/bin/env bash
# Grants by ADB the permissions listed in docs/research/android-plateforme.md §4.
# "pm grant" only works for permissions the installed APK declares: the others are reported and skipped.
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
        info "$perm ignorée : non déclarée par cette version de l'APK ($why)"
    else
        warn "$perm : échec — $out"
    fi
}

echo "Permissions d'exécution (le mode Device Owner les accorde aussi automatiquement) :"
grant android.permission.ACCESS_FINE_LOCATION "localisation GPS"
grant android.permission.ACCESS_COARSE_LOCATION "localisation"
grant android.permission.ACCESS_BACKGROUND_LOCATION "localisation en arrière-plan"
grant android.permission.POST_NOTIFICATIONS "notification permanente"
grant android.permission.ACCESS_LOCAL_NETWORK "serveur sur réseau privé (Android 17)"

echo "Permissions de développement (accordables uniquement par ADB) :"
grant android.permission.WRITE_SECURE_SETTINGS "écriture des réglages Global/Secure"
grant android.permission.DUMP "Debug.dumpService (historique appops)"
grant android.permission.BATTERY_STATS "statistiques batterie"
grant android.permission.PACKAGE_USAGE_STATS "usage des apps et volumes réseau par app"
if adb shell cmd appops set "$PKG" GET_USAGE_STATS allow >/dev/null 2>&1; then
    ok "appops GET_USAGE_STATS = allow"
fi
info "READ_LOGS n'est pas accordée : Android 13+ exige un consentement à chaque lecture, inutilisable en continu."
