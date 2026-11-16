#!/usr/bin/env bash
# Installs (or updates) the Vigie APK over ADB.
# Usage: ./install-apk.sh [chemin/vers/app.apk]
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
        die "L'APK release n'est pas signé (app-release-unsigned.apk). Générez le keystore (./generate-keystore.sh), renseignez keystore.properties, puis relancez ./gradlew assembleRelease."
    fi
    for candidate in ../app/build/outputs/apk/release/app-release.apk ../app/build/outputs/apk/debug/app-debug.apk; do
        if [ -f "$candidate" ]; then APK="$candidate"; break; fi
    done
fi
[ -n "$APK" ] && [ -f "$APK" ] || die "APK introuvable. Construisez-le (./gradlew assembleRelease) ou passez son chemin en argument."

case "$APK" in
    *debug*.apk)
        warn "APK de débogage : signé avec la clé de débogage (une mise à jour vers l'APK release sera refusée tant que Vigie est Device Owner) et « débogable » (adb run-as peut lire les données de l'app)."
        warn "Sur le téléphone de tous les jours, installez l'APK release (./gradlew assembleRelease)."
        read -r -p "Installer quand même l'APK de débogage ? (oui/non) " answer
        [ "$answer" = "oui" ] || die "Abandon."
        ;;
esac

require_adb
info "Installation de $APK"
if ! adb install -r -t "$APK"; then
    cat >&2 <<'MSG'
L'installation a échoué. Causes fréquentes :
  - INSTALL_FAILED_UPDATE_INCOMPATIBLE : l'APK n'est pas signé avec la même clé que l'app installée.
    Un Device Owner ne peut pas être mis à jour avec une autre clé : utilisez le keystore d'origine.
  - INSTALL_FAILED_VERSION_DOWNGRADE : versionCode inférieur à celui installé (-Pvigie.versionCode=…).
  - Blocage automatique (Auto Blocker) Samsung actif : désactivez-le le temps de l'installation.
MSG
    exit 1
fi
ok "Vigie installée."
ashell dumpsys package "$PKG" | grep -m1 -E 'versionName=' | sed 's/^ */  /' || true
