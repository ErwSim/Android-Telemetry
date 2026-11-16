#!/usr/bin/env bash
# ADB rescue without the interface: asks Watchpost, over ADB, to undo its whole Device Owner
# policy ("Restore everything" on the Policy screen). Watchpost stays Device Owner and its logs
# stay on.
#
# Mechanism: explicit broadcast to io.github.erwsim.watchpost/.policy.rescue.RescueReceiver (see
# common.sh); only the ADB shell or the system can send it, and it can only undo.
#
# Usage: ./rescue-revert.sh                 "Restore everything"
#        ./rescue-revert.sh --sweep         also restores everything the catalogue may have changed
#                                           (hidden or suspended packages, restrictions, denied
#                                           permissions, Private DNS), even with no trace in
#                                           Watchpost's state
#        ./rescue-revert.sh --remove-owner  same as ./remove-device-owner.sh (full removal)
# Only works after the first unlock following a reboot.
# Exit codes: 0 everything restored, 2 partial, 3 Watchpost is no longer Device Owner, 4 timed out,
# 5 no usable answer from Watchpost, 1 other error.
set -euo pipefail
cd "$(dirname "$0")"
. ./common.sh

flags=()
case "${1:-}" in
    "") ;;
    --remove-owner) exec ./remove-device-owner.sh ;;
    --sweep) flags=(sweep) ;;
    *) die "Unknown option: $1 (--sweep or --remove-owner)." ;;
esac

require_adb
require_installed

info "Sending the 'Restore everything' order to Watchpost (up to one minute)…"
rescue_broadcast ${flags[@]+"${flags[@]}"}
case "$RESCUE_CODE" in
    1)
        ok "Everything is restored ($RESCUE_DATA)."
        ;;
    2)
        warn "Partial restore: $RESCUE_DATA"
        warn "Try again; if an item resists, see the log on the Policy screen or the README (Device Owner policy section). './rescue-revert.sh --sweep' also restores what Watchpost may have lost track of."
        exit 2
        ;;
    3)
        warn "Watchpost is no longer Device Owner: it can no longer undo anything itself ($RESCUE_DATA)."
        restore_leftovers
        exit 3
        ;;
    4)
        warn "Watchpost did not finish in time: the operation continues on the phone. Run this script again in a minute to see the result."
        exit 4
        ;;
    *)
        printf '%s\n' "$RESCUE_OUT" >&2
        warn "No usable answer from Watchpost. Check that the phone has been unlocked since its last boot, that the installed APK includes the rescue and that it starts. Last resort if the app no longer starts: ./remove-device-owner.sh (testOnly APK)."
        exit 5
        ;;
esac
