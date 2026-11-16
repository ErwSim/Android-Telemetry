#!/usr/bin/env bash
# Grants (default) or withdraws (--revoke) notification access for the companion "Vigie Notifications".
# Usage: ./notifier-access.sh [--revoke]
#
# Uses "cmd notification allow_listener / disallow_listener <composant> [user_id]" (NotificationManager
# shell command, AOSP NotificationShellCmd; not verified on One UI 8/9). Granting it by ADB also works
# for an app installed outside an app store, whose access switch Android may show as a "paramètre
# restreint" (restricted setting) in the Settings app.
#
# Without ADB: Paramètres > Notifications > ... > Accès aux notifications > Vigie Notifications (search
# "Accès aux notifications" in Settings: the path depends on the One UI version). If the switch is
# greyed out ("Paramètre restreint"): Paramètres > Applications > Vigie Notifications > menu (⋮) >
# "Autoriser les paramètres restreints", then grant the access.
set -euo pipefail
cd "$(dirname "$0")"
. ./common.sh
NOTIFIER_PKG="io.github.erwsim.vigie.notifier"
COMPONENT="$NOTIFIER_PKG/io.github.erwsim.vigie.notifier.NotifierListenerService"

REVOKE=false
case "${1:-}" in
    "") ;;
    --revoke) REVOKE=true ;;
    *) die "Option inconnue : $1 (seule option : --revoke)" ;;
esac

require_adb
ashell pm path "$NOTIFIER_PKG" | grep -q '^package:' || die "Vigie Notifications ($NOTIFIER_PKG) n'est pas installé. Lancez d'abord ./install-notifier.sh."

enabled() { ashell settings get secure enabled_notification_listeners | tr ':' '\n' | grep -qE "^$NOTIFIER_PKG/"; }

if $REVOKE; then
    out="$(ashell cmd notification disallow_listener "$COMPONENT" 2>&1 || true)"
    [ -n "$out" ] && info "$out"
    if enabled; then
        die "L'accès semble toujours accordé. Retirez-le à la main : Paramètres > Notifications > … > Accès aux notifications > Vigie Notifications."
    fi
    ok "Accès aux notifications retiré : Vigie Notifications ne lit plus rien (le collecteur « Notifications » de l'agent passe « indisponible »)."
    exit 0
fi

out="$(ashell cmd notification allow_listener "$COMPONENT" 2>&1 || true)"
[ -n "$out" ] && info "$out"
if ! enabled; then
    warn "L'accès n'apparaît pas dans enabled_notification_listeners."
    warn "Accordez-le à la main : Paramètres > Notifications > … > Accès aux notifications > Vigie Notifications."
    warn "Interrupteur grisé (« Paramètre restreint ») : Paramètres > Applications > Vigie Notifications > ⋮ > Autoriser les paramètres restreints."
    exit 1
fi
ok "Accès aux notifications accordé à Vigie Notifications."
info "Par défaut seuls l'app, la catégorie, le canal et l'importance sont transmis ; le titre et le texte seulement si vous activez « Contenu des notifications » dans Vigie (Collecteurs > Notifications)."
info "Ouvrez « Vigie Notifications » pour vérifier l'état (service connecté, agent présent, collecte active)."
