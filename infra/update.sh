#!/usr/bin/env bash
# Update of the Watchpost stack.
#
#   sudo ./update.sh            # backup, git pull, images, collector rebuild, install.sh
#   sudo ./update.sh --no-pull  # without "git pull" (repository already up to date)
#
# The image versions are PINNED in docker-compose.yml: an upgrade of Wazuh, AdGuard Home or
# Caddy is done by changing that file (in the repository), never by following "latest". For
# Wazuh, read the release notes first (same version for the three images, indexer updated
# first; install.sh does it in the right order).
set -Eeuo pipefail
INFRA_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$INFRA_DIR/lib/common.sh"

PULL=1
[[ "${1:-}" == --no-pull ]] && PULL=0
[[ -f "$ENV_FILE" ]] || die "no installation: run ./install.sh"

title "1. Backup first"
"$INFRA_DIR/backup.sh"

if ((PULL)) && git -C "$INFRA_DIR" rev-parse >/dev/null 2>&1; then
  title "2. Repository update"
  git -C "$INFRA_DIR" pull --ff-only
fi

title "3. Images"
dc pull --ignore-buildable --quiet
dc build --pull -q collector

title "4. Applying (install.sh)"
"$INFRA_DIR/install.sh" --yes
# Files mounted one by one (ossec.conf, Caddyfile, adguard/levels.json…) are seen only after the
# containers are recreated.
dc up -d --force-recreate wazuh.manager caddy collector >/dev/null
wait_healthy wazuh.manager 300 || warn "Wazuh manager slow to restart"

title "5. Cleanup"
docker image prune -f >/dev/null
info "Update complete."
