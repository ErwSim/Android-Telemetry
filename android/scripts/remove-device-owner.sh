#!/usr/bin/env bash
# Retrait complet du Device Owner par ADB (équivalent de « Retirer le Device Owner » de l'écran
# Politique, qui reste le chemin recommandé quand l'app est utilisable).
#
# 1. Chemin normal : l'issue de secours de Vigie (voir common.sh) défait toute la politique, coupe
#    les journaux réseau et sécurité, retire la protection contre l'arrêt forcé, émet
#    security.policy « device_owner_cleared » puis appelle clearDeviceOwnerApp. Le retrait étant
#    annoncé, il n'est pas signalé comme agent.tamper. Fonctionne avec tout APK (testOnly ou non).
# 2. Repli, seulement si Vigie ne répond pas (app qui ne démarre plus) : « dpm remove-active-admin »,
#    possible uniquement avec un APK testOnly. Vigie ne défait alors rien elle-même (paquets masqués
#    à réafficher, proposé ensuite) et le retrait est vu comme une désactivation (agent.tamper
#    admin_disabled / device_owner_lost au prochain démarrage) : c'est attendu.
#
# Usage : ./remove-device-owner.sh [--uninstall]
set -euo pipefail
cd "$(dirname "$0")"
. ./common.sh

uninstall=0
case "${1:-}" in
    "") ;;
    --uninstall) uninstall=1 ;;
    *) die "Option inconnue : $1 (seule --uninstall existe)." ;;
esac

require_adb
require_installed

if ! is_owner; then
    info "Vigie n'est pas Device Owner."
else
    cat <<'MSG'
Vigie va tout rétablir, couper ses journaux réseau et de sécurité, puis abandonner le rôle de
Device Owner. Pour le retrouver, il faudra repasser par enable-device-owner (sans comptes sur le
téléphone).
MSG
    read -r -p "Continuer ? (oui/non) " answer
    [ "$answer" = "oui" ] || die "Abandon."

    info "Envoi de l'ordre de retrait à Vigie (jusqu'à une minute)…"
    rescue_broadcast remove_owner
    case "$RESCUE_CODE" in
        1|2) [ "$RESCUE_CODE" = 1 ] && ok "Politique rétablie ($RESCUE_DATA)." || warn "Rétablissement partiel, retrait forcé : $RESCUE_DATA" ;;
        3) info "Vigie n'était déjà plus Device Owner ($RESCUE_DATA)." ;;
        4) warn "Vigie n'a pas fini dans le délai ; vérification du rôle dans 30 s…"; sleep 30 ;;
        *)
            printf '%s\n' "$RESCUE_OUT" >&2
            warn "Pas de réponse exploitable de Vigie (app qui ne démarre plus, ou version sans issue de secours)."
            is_test_only || die "APK non testOnly : Android refuse « dpm remove-active-admin ». Réparez/mettez à jour l'app (même clé de signature) puis relancez ce script, ou réinitialisez le téléphone."
            cat <<'MSG'
Repli : « dpm remove-active-admin » (APK testOnly). Vigie ne défera pas sa politique elle-même :
les paquets qu'elle avait masqués ou suspendus vous seront proposés ensuite (pm unhide / unsuspend).
Le retrait sera signalé par agent.tamper (admin_disabled, device_owner_lost) : c'est attendu.
MSG
            read -r -p "Utiliser ce repli ? (oui/non) " answer
            [ "$answer" = "oui" ] || die "Abandon."
            ashell dpm remove-active-admin --user 0 "$ADMIN" | sed 's/^/    /'
            ;;
    esac
    if is_owner; then die "Vigie est toujours Device Owner ($RESCUE_DATA)."; fi
    ok "Vigie n'est plus Device Owner (la sauvegarde Android, coupée par le mode Device Owner, peut être réactivée dans les Paramètres)."
    # Ce que Vigie n'a pas pu défaire elle-même (repli, ou éléments restés en échec).
    rescue_broadcast
    if [ "$RESCUE_CODE" = 3 ]; then restore_leftovers; fi
fi

if [ "$uninstall" = 1 ]; then
    adb uninstall "$PKG" && ok "Vigie désinstallée."
fi
