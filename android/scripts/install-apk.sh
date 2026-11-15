#!/usr/bin/env bash
# Installs (or updates) the Vigie APK over ADB.
# Usage: ./install-apk.sh [chemin/vers/app.apk]
# Default: the release APK, else the debug APK, from android/app/build/outputs/apk/.
# "-t" is required for a testOnly APK (default build); "-r" keeps the data on update.
# An update must be signed with the SAME key as the installed app (mandatory for a Device Owner).
set -euo pipefail
cd "$(dirname "$0")"
. ./common.sh

APK="${1:-}"
if [ -z "$APK" ]; then
    for candidate in ../app/build/outputs/apk/release/app-release.apk ../app/build/outputs/apk/debug/app-debug.apk; do
        if [ -f "$candidate" ]; then APK="$candidate"; break; fi
    done
fi
[ -n "$APK" ] && [ -f "$APK" ] || die "APK introuvable. Construisez-le (./gradlew assembleRelease) ou passez son chemin en argument."

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
