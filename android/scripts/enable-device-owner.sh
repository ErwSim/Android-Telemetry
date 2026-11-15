#!/usr/bin/env bash
# Makes Vigie the Device Owner of the phone (ADB provisioning, no factory reset).
# Preconditions checked here: no other user/profile, no account, no existing owner.
# Usage: ./enable-device-owner.sh
set -euo pipefail
cd "$(dirname "$0")"
. ./common.sh

require_adb
require_installed

info "Vérification des propriétaires existants…"
owners="$(ashell dpm list-owners 2>/dev/null || true)"
if echo "$owners" | grep -q "$PKG"; then
    ok "Vigie est déjà Device Owner."
    exit 0
fi
if echo "$owners" | grep -qiE 'DeviceOwner|ProfileOwner'; then
    echo "$owners"
    die "Un autre Device Owner ou Profile Owner est déjà défini. Retirez-le d'abord."
fi

info "Vérification des utilisateurs et profils…"
users="$(ashell pm list users)"
user_count=$(echo "$users" | grep -c 'UserInfo{' || true)
if [ "$user_count" -gt 1 ]; then
    echo "$users" | grep 'UserInfo{' | sed 's/^/    /'
    die "Plusieurs utilisateurs ou profils existent ($user_count). Supprimez Dossier sécurisé (Secure Folder), Dual Messenger, l'espace privé, le profil professionnel et les invités, puis relancez."
fi

info "Vérification des comptes…"
accounts="$(ashell dumpsys account | grep -E '^[[:space:]]*Account \{' || true)"
if [ -n "$accounts" ]; then
    echo "Comptes présents sur le téléphone :"
    echo "$accounts" | sed -E 's/^[[:space:]]*/    /'
    cat >&2 <<'MSG'
ERREUR : Android refuse de nommer un Device Owner tant qu'un compte existe.
Retirez TEMPORAIREMENT chaque compte listé (Paramètres › Comptes et sauvegarde › Gérer les comptes :
Google, Samsung account, WhatsApp, Signal, Microsoft…), relancez ce script, puis rajoutez vos comptes :
le mode Device Owner ne les interdit pas. Pensez à vérifier vos sauvegardes et la double
authentification avant de retirer un compte Google ou Samsung.
MSG
    exit 1
fi

if ashell dumpsys package "$PKG" | grep -q 'TEST_ONLY'; then
    info "APK testOnly : le Device Owner pourra être retiré par ADB (remove-device-owner.sh)."
else
    warn "APK NON testOnly : le retrait par ADB sera impossible ; seul l'app (ou une réinitialisation) pourra le retirer."
    read -r -p "Continuer quand même ? (oui/non) " answer
    [ "$answer" = "oui" ] || die "Abandon."
fi

info "Activation : dpm set-device-owner $ADMIN"
result="$(ashell dpm set-device-owner --user 0 "$ADMIN" 2>&1 || true)"
echo "$result" | sed 's/^/    /'
if ashell dpm list-owners | grep -q "$PKG"; then
    ok "Vigie est Device Owner. Ouvrez l'app : elle s'accorde ses permissions et active sa protection."
    info "Vous pouvez rajouter vos comptes Google/Samsung. Réactivez le Blocage automatique si vous l'aviez coupé."
else
    die "L'activation a échoué (voir le message ci-dessus)."
fi
