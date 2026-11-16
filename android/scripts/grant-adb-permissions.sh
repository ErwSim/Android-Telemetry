#!/usr/bin/env bash
# Accorde par ADB toutes les permissions dont Vigie peut avoir besoin (inventaire du code des
# modules :core, :collectors et :policy).
# - Permissions d'exécution : utiles en mode dégradé (sans Device Owner) ; en Device Owner, l'app se
#   les accorde elle-même au démarrage.
# - Permissions accordables seulement par ADB : nécessaires même en Device Owner.
# « pm grant » ne marche que pour une permission déclarée par l'APK installé : les autres sont
# signalées et ignorées.
# Usage : ./grant-adb-permissions.sh
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
grant android.permission.ACCESS_FINE_LOCATION "localisation GPS ; SSID/BSSID Wi-Fi, identifiants de cellule, balayage BLE"
grant android.permission.ACCESS_COARSE_LOCATION "localisation"
# Toujours après la localisation d'avant-plan.
grant android.permission.ACCESS_BACKGROUND_LOCATION "localisation en arrière-plan"
grant android.permission.POST_NOTIFICATIONS "notification permanente"
grant android.permission.BLUETOOTH_SCAN "détection des traceurs BLE (ble_tracker)"
grant android.permission.BLUETOOTH_CONNECT "connexions Bluetooth (bluetooth)"
grant android.permission.READ_PHONE_STATE "suivi cellule par cellule et signal (cell, optionnel)"
grant android.permission.ACCESS_LOCAL_NETWORK "serveur sur réseau privé (Android 17)"

echo "Permissions accordables uniquement par ADB :"
grant android.permission.PACKAGE_USAGE_STATS "accès à l'utilisation : volumes réseau par app (net_usage), app au premier plan (foreground)"
if adb shell cmd appops set "$PKG" GET_USAGE_STATS allow >/dev/null 2>&1; then
    ok "appops GET_USAGE_STATS = allow (accès à l'utilisation)"
else
    warn "appops GET_USAGE_STATS : échec (à accorder dans Paramètres › Applications › Accès spéciaux › Accès aux données d'utilisation)"
fi
grant android.permission.WRITE_SECURE_SETTINGS "politique : réglages anti-pistage hors liste Device Owner (ble_scan_always_enabled)"
grant android.permission.DUMP "attribution expérimentale caméra/micro (désactivée par défaut dans l'app)"
info "READ_LOGS n'est pas accordée : Android 13+ exige un consentement à chaque lecture, inutilisable en continu."
info "Exemptions de batterie : ./battery-exemptions.sh"
