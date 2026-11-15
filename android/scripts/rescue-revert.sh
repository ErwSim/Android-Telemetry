#!/usr/bin/env bash
# Rescue without the app's interface: asks Vigie, over ADB, to undo its whole Device Owner policy
# ("Tout rétablir"), and optionally to give up the Device Owner role (--remove-owner).
#
# Mechanism: an explicit broadcast to io.github.erwsim.vigie/.policy.rescue.RescueReceiver. That
# receiver requires the sender to hold android.permission.FORCE_STOP_PACKAGES (signature|privileged,
# never grantable to a third-party app): only the ADB shell and the system can trigger it. It can
# only UNDO what Vigie applied, never apply anything.
#
# Usage: ./rescue-revert.sh [--remove-owner]
set -euo pipefail
cd "$(dirname "$0")"
. ./common.sh

RECEIVER="$PKG/io.github.erwsim.vigie.policy.rescue.RescueReceiver"
ACTION="io.github.erwsim.vigie.action.RESCUE_REVERT_ALL"

require_adb
require_installed

extra=()
if [ "${1:-}" = "--remove-owner" ]; then
    cat <<'MSG'
Vigie va tout rétablir, couper ses journaux réseau et de sécurité, puis abandonner le rôle de
Device Owner. Pour le retrouver, il faudra repasser par enable-device-owner (sans comptes sur le
téléphone).
MSG
    read -r -p "Continuer ? (oui/non) " answer
    [ "$answer" = "oui" ] || die "Abandon."
    extra=(--ez remove_owner true)
elif [ -n "${1:-}" ]; then
    die "Option inconnue : $1 (seule --remove-owner existe)."
fi

info "Envoi de l'ordre « Tout rétablir » à Vigie (jusqu'à une minute)…"
out="$(ashell am broadcast --include-stopped-packages -a "$ACTION" -n "$RECEIVER" ${extra[@]+"${extra[@]}"} 2>&1 || true)"
code="$(printf '%s\n' "$out" | sed -n 's/.*Broadcast completed: result=\(-\{0,1\}[0-9]*\).*/\1/p' | tail -n 1)"
data="$(printf '%s\n' "$out" | sed -n 's/.*Broadcast completed: result=[-0-9]*, data="\(.*\)"$/\1/p' | tail -n 1)"

# Extracts "key=a,b,c" from the summary as a space-separated list.
field() { printf '%s\n' "$data" | tr ' ' '\n' | sed -n "s/^$1=//p" | tr ',' ' '; }

case "$code" in
    1)
        ok "Tout est rétabli ($data)."
        ;;
    2)
        warn "Rétablissement partiel : $data"
        warn "Réessayez ; si un élément résiste, consultez le journal de l'écran Politique ou le README (section Politique Device Owner)."
        exit 2
        ;;
    3)
        warn "Vigie n'est plus Device Owner : elle ne peut plus rien défaire elle-même ($data)."
        hidden="$(field hidden)"
        suspended="$(field suspended)"
        if [ -z "$hidden$suspended" ]; then
            info "Aucun paquet masqué ou suspendu à rétablir."
        else
            read -r -p "Réafficher/réactiver ces paquets par ADB (pm unhide / pm unsuspend) ? (oui/non) " answer
            if [ "$answer" = "oui" ]; then
                for p in $hidden; do info "pm unhide $p : $(ashell pm unhide "$p" 2>&1 | tr '\n' ' ')"; done
                for p in $suspended; do info "pm unsuspend $p : $(ashell pm unsuspend "$p" 2>&1 | tr '\n' ' ')"; done
                warn "Vérifiez dans Paramètres › Applications que ces apps sont de nouveau utilisables."
            fi
        fi
        if [ -n "$(field other_items)" ]; then
            warn "Restrictions, permissions ou DNS privé posés par Vigie ont normalement été levés par Android au retrait du Device Owner ; vérifiez le DNS privé dans Paramètres › Connexions."
        fi
        exit 3
        ;;
    4)
        warn "Vigie n'a pas fini dans le délai : l'opération continue sur le téléphone. Relancez ce script dans une minute pour voir le résultat."
        exit 4
        ;;
    *)
        printf '%s\n' "$out" >&2
        die "Pas de réponse exploitable de Vigie. Vérifiez que l'APK installé contient l'issue de secours (version avec l'écran Politique)."
        ;;
esac

if [ ${#extra[@]} -gt 0 ]; then
    if ashell dpm list-owners | grep -q "$PKG"; then
        die "Vigie est toujours Device Owner ($data)."
    fi
    ok "Vigie n'est plus Device Owner."
fi
