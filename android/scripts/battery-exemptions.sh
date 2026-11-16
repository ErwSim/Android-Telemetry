#!/usr/bin/env bash
# Exempts Watchpost from battery restrictions that could stop the collection.
# Usage: ./battery-exemptions.sh
set -euo pipefail
cd "$(dirname "$0")"
. ./common.sh

require_adb
require_installed

run() {
    local label="$1"; shift
    if adb shell "$@" >/dev/null 2>&1; then ok "$label"; else warn "$label: failed (command: $*)"; fi
}

run "Doze exemption (deviceidle allowlist)" dumpsys deviceidle whitelist "+$PKG"
run "Background execution allowed (appops RUN_ANY_IN_BACKGROUND)" cmd appops set "$PKG" RUN_ANY_IN_BACKGROUND allow
run "Background execution allowed (appops RUN_IN_BACKGROUND)" cmd appops set "$PKG" RUN_IN_BACKGROUND allow
run "Standby bucket 'active'" am set-standby-bucket "$PKG" active

cat <<'MSG'

To do by hand on Samsung (no known command):
  Settings › Battery › Background usage limits › Never sleeping apps › add Watchpost.
In Device Owner mode, Watchpost also turns on 'Force-stop protection', which exempts it from standby buckets.
MSG
