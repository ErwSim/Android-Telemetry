#!/usr/bin/env bash
# Installs (or updates) the optional notification companion "Vigie Notifications" over ADB.
# Usage: ./install-notifier.sh [chemin/vers/notifier.apk]
# Default: the release APK, else the debug APK, from android/notifier/build/outputs/apk/.
# The companion must be signed with the SAME key as the Vigie agent (same build, same keystore):
# otherwise Android refuses to install it (INSTALL_FAILED_DUPLICATE_PERMISSION, both APKs declare the
# channel's permission) or, if the agent is absent, it will never be able to talk to it.
# Then: ./notifier-access.sh (grants notification access).
set -euo pipefail
# The APK path is the caller's: made absolute BEFORE moving to the scripts directory.
APK="${1:-}"
case "$APK" in ""|/*|[A-Za-z]:[\\/]*) ;; *) APK="$PWD/$APK" ;; esac
cd "$(dirname "$0")"
. ./common.sh
NOTIFIER_PKG="io.github.erwsim.vigie.notifier"

if [ -z "$APK" ]; then
    if [ ! -f ../notifier/build/outputs/apk/release/notifier-release.apk ] && [ -f ../notifier/build/outputs/apk/release/notifier-release-unsigned.apk ]; then
        die "L'APK release du compagnon n'est pas signé (notifier-release-unsigned.apk). Générez le keystore (./generate-keystore.sh), renseignez keystore.properties, puis relancez ./gradlew :notifier:assembleRelease."
    fi
    for candidate in ../notifier/build/outputs/apk/release/notifier-release.apk ../notifier/build/outputs/apk/debug/notifier-debug.apk; do
        if [ -f "$candidate" ]; then APK="$candidate"; break; fi
    done
fi
[ -n "$APK" ] && [ -f "$APK" ] || die "APK du compagnon introuvable. Construisez-le (./gradlew :notifier:assembleRelease) ou passez son chemin en argument."

case "$APK" in
    *debug*.apk)
        warn "APK de débogage : signé avec la clé de débogage de cet ordinateur. Il ne fonctionne qu'avec un agent Vigie de débogage construit sur le même ordinateur ; avec l'agent release, Android refusera l'installation."
        read -r -p "Installer quand même l'APK de débogage ? (oui/non) " answer
        [ "$answer" = "oui" ] || die "Abandon."
        ;;
esac

require_adb
if ! ashell pm path "$PKG" | grep -q '^package:'; then
    warn "L'agent Vigie ($PKG) n'est pas installé : le compagnon s'installe, mais ne transmettra rien tant que l'agent (signé par la même clé) ne sera pas là."
fi

info "Installation de $APK"
if ! adb install -r -t "$APK"; then
    cat >&2 <<'MSG'
L'installation a échoué. Causes fréquentes :
  - INSTALL_FAILED_DUPLICATE_PERMISSION : le compagnon n'est pas signé par la même clé que l'agent Vigie
    installé. Installez les deux APK issus de la même construction (même keystore ; release avec release,
    débogage avec débogage).
  - INSTALL_FAILED_UPDATE_INCOMPATIBLE : un compagnon signé par une autre clé est déjà installé :
    ./uninstall-notifier.sh, puis réessayez.
  - INSTALL_FAILED_VERSION_DOWNGRADE : versionCode inférieur à celui installé (-Pvigie.versionCode=…).
  - Play Protect bloque l'installation (« appli nuisible bloquée ») : voir le README (section
    Notifications) ; l'agent n'est pas concerné, il continue sans le compagnon.
  - Blocage automatique (Auto Blocker) Samsung actif : désactivez-le le temps de l'installation.
MSG
    exit 1
fi
ok "Vigie Notifications installé."
ashell dumpsys package "$NOTIFIER_PKG" | grep -m1 -E 'versionName=' | sed 's/^ */  /' || true

# Same signing key as the agent? (short digest of the signing certificate shown by dumpsys)
sig() { ashell dumpsys package "$1" 2>/dev/null | grep -m1 -oE 'signatures:\[[^]]*\]' || true; }
agent_sig="$(sig "$PKG")"
notifier_sig="$(sig "$NOTIFIER_PKG")"
if [ -n "$agent_sig" ] && [ -n "$notifier_sig" ]; then
    if [ "$agent_sig" = "$notifier_sig" ]; then
        ok "Même clé de signature que l'agent Vigie."
    else
        warn "Clés de signature différentes de l'agent ($agent_sig / $notifier_sig) : le compagnon ne pourra rien transmettre."
    fi
fi
info "Étape suivante : ./notifier-access.sh (accès aux notifications), puis ouvrez « Vigie Notifications » pour vérifier l'état."
