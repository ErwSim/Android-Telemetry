#!/usr/bin/env bash
# Issue de secours sans l'interface : demande à Vigie, par ADB, de défaire toute sa politique
# Device Owner (« Tout rétablir » de l'écran Politique). Vigie reste Device Owner et ses journaux
# restent actifs.
#
# Mécanisme : diffusion explicite à io.github.erwsim.vigie/.policy.rescue.RescueReceiver (voir
# common.sh) ; seul le shell ADB ou le système peut l'envoyer, et elle ne peut que défaire.
#
# Usage : ./rescue-revert.sh                 « Tout rétablir »
#         ./rescue-revert.sh --sweep         en plus, rétablit tout ce que le catalogue a pu modifier
#                                            (paquets masqués ou suspendus, restrictions, permissions
#                                            refusées, DNS privé), même sans trace dans l'état de Vigie
#         ./rescue-revert.sh --remove-owner  équivaut à ./remove-device-owner.sh (retrait complet)
# Ne fonctionne qu'après le premier déverrouillage qui suit un redémarrage.
# Codes de sortie : 0 tout rétabli, 2 partiel, 3 Vigie n'est plus Device Owner, 4 délai dépassé,
# 5 aucune réponse exploitable de Vigie, 1 autre erreur.
set -euo pipefail
cd "$(dirname "$0")"
. ./common.sh

flags=()
case "${1:-}" in
    "") ;;
    --remove-owner) exec ./remove-device-owner.sh ;;
    --sweep) flags=(sweep) ;;
    *) die "Option inconnue : $1 (--sweep ou --remove-owner)." ;;
esac

require_adb
require_installed

info "Envoi de l'ordre « Tout rétablir » à Vigie (jusqu'à une minute)…"
rescue_broadcast ${flags[@]+"${flags[@]}"}
case "$RESCUE_CODE" in
    1)
        ok "Tout est rétabli ($RESCUE_DATA)."
        ;;
    2)
        warn "Rétablissement partiel : $RESCUE_DATA"
        warn "Réessayez ; si un élément résiste, consultez le journal de l'écran Politique ou le README (section Politique Device Owner). « ./rescue-revert.sh --sweep » rétablit aussi ce dont Vigie aurait perdu la trace."
        exit 2
        ;;
    3)
        warn "Vigie n'est plus Device Owner : elle ne peut plus rien défaire elle-même ($RESCUE_DATA)."
        restore_leftovers
        exit 3
        ;;
    4)
        warn "Vigie n'a pas fini dans le délai : l'opération continue sur le téléphone. Relancez ce script dans une minute pour voir le résultat."
        exit 4
        ;;
    *)
        printf '%s\n' "$RESCUE_OUT" >&2
        warn "Pas de réponse exploitable de Vigie. Vérifiez que le téléphone a été déverrouillé depuis son dernier démarrage, que l'APK installé contient l'issue de secours et qu'il démarre. Dernier recours si l'app ne démarre plus : ./remove-device-owner.sh (APK testOnly)."
        exit 5
        ;;
esac
