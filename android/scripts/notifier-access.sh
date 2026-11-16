#!/usr/bin/env bash
# Grants (default) or withdraws (--revoke) notification access for the companion "Watchpost Notifications".
# Usage: ./notifier-access.sh [--revoke]
#
# Uses "cmd notification allow_listener / disallow_listener <component> [user_id]" (NotificationManager
# shell command, AOSP NotificationShellCmd; not verified on One UI 8/9). Granting it by ADB also works
# for an app installed outside an app store, whose access switch Android may show as a "restricted
# setting" in the Settings app.
#
# Without ADB: Settings > Notifications > ... > Notification access > Watchpost Notifications (search
# "Notification access" in Settings: the path depends on the One UI version). If the switch is
# greyed out ("Restricted setting"): Settings > Apps > Watchpost Notifications > menu (⋮) >
# "Allow restricted settings", then grant the access.
set -euo pipefail
cd "$(dirname "$0")"
. ./common.sh
NOTIFIER_PKG="io.github.erwsim.watchpost.notifier"
COMPONENT="$NOTIFIER_PKG/io.github.erwsim.watchpost.notifier.NotifierListenerService"

REVOKE=false
case "${1:-}" in
    "") ;;
    --revoke) REVOKE=true ;;
    *) die "Unknown option: $1 (the only option is --revoke)" ;;
esac

require_adb
ashell pm path "$NOTIFIER_PKG" | grep -q '^package:' || die "Watchpost Notifications ($NOTIFIER_PKG) is not installed. Run ./install-notifier.sh first."

enabled() { ashell settings get secure enabled_notification_listeners | tr ':' '\n' | grep -qE "^$NOTIFIER_PKG/"; }

if $REVOKE; then
    out="$(ashell cmd notification disallow_listener "$COMPONENT" 2>&1 || true)"
    [ -n "$out" ] && info "$out"
    if enabled; then
        die "Access still seems to be granted. Remove it by hand: Settings > Notifications > … > Notification access > Watchpost Notifications."
    fi
    ok "Notification access withdrawn: Watchpost Notifications no longer reads anything (the agent's 'Notifications' collector becomes 'unavailable')."
    exit 0
fi

out="$(ashell cmd notification allow_listener "$COMPONENT" 2>&1 || true)"
[ -n "$out" ] && info "$out"
if ! enabled; then
    warn "The access does not appear in enabled_notification_listeners."
    warn "Grant it by hand: Settings > Notifications > … > Notification access > Watchpost Notifications."
    warn "Switch greyed out ('Restricted setting'): Settings > Apps > Watchpost Notifications > ⋮ > Allow restricted settings."
    exit 1
fi
ok "Notification access granted to Watchpost Notifications."
info "By default only the app, category, channel and importance are relayed; the title and text only if you turn on 'Notification content' in Watchpost (Collectors > Notifications)."
info "Open 'Watchpost Notifications' to check its state (service connected, agent present, collection active)."
