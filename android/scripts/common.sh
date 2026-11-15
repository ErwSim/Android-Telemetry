#!/usr/bin/env bash
# Shared helpers for the Vigie ADB scripts (sourced, not executed).
# Device selection: if several devices are connected, export ANDROID_SERIAL=<serial> (see "adb devices").

PKG="${VIGIE_PACKAGE:-io.github.erwsim.vigie}"
ADMIN="$PKG/io.github.erwsim.vigie.policy.VigieAdminReceiver"

die() { echo "ERREUR : $*" >&2; exit 1; }
info() { echo "• $*"; }
ok() { echo "✔ $*"; }
warn() { echo "⚠ $*" >&2; }

# adb shell output without the trailing \r some devices add.
ashell() { adb shell "$@" | tr -d '\r'; }

require_adb() {
    command -v adb >/dev/null 2>&1 || die "adb introuvable. Installez « Android SDK Platform-Tools » et ajoutez-le au PATH."
    local count
    count=$(adb devices | tr -d '\r' | awk 'NR>1 && $2=="device"' | wc -l)
    if [ "$count" -eq 0 ]; then
        adb devices | tr -d '\r' | awk 'NR>1 && $2=="unauthorized"' | grep -q . && \
            die "Téléphone non autorisé : déverrouillez-le et acceptez la clé de débogage USB."
        die "Aucun téléphone connecté en débogage USB (adb devices). Sur Samsung, désactivez temporairement « Blocage automatique » (Auto Blocker)."
    fi
    if [ "$count" -gt 1 ] && [ -z "${ANDROID_SERIAL:-}" ]; then
        die "Plusieurs appareils connectés : export ANDROID_SERIAL=<numéro de série> (voir adb devices)."
    fi
}

require_installed() {
    ashell pm path "$PKG" | grep -q '^package:' || die "Vigie ($PKG) n'est pas installée. Lancez d'abord install-apk.sh."
}
