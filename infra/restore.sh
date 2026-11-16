#!/usr/bin/env bash
# Restores a backup produced by backup.sh (same server or new server).
#
#   sudo ./restore.sh backups/watchpost-20261115-220000.tar.gz
#
# Stops the stack, replaces .env, secrets/, data/ and the backed-up volumes, then runs
# install.sh again (which picks up the restored secrets). On a new server: install Docker,
# clone the repository, copy the archive, run this script, then update the DNS records.
# If the Wazuh index was not backed up, the SIEM history starts from scratch (the events
# remain in the collector database and in the console).
set -Eeuo pipefail
INFRA_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$INFRA_DIR/lib/common.sh"

ARCHIVE="${1:?usage: restore.sh <.tar.gz archive>}"
[[ -f "$ARCHIVE" ]] || die "archive not found: $ARCHIVE"
ARCHIVE="$(cd "$(dirname "$ARCHIVE")" && pwd)/$(basename "$ARCHIVE")"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
tar -C "$WORK" -xzf "$ARCHIVE"
[[ -f "$WORK/watchpost/MANIFEST" ]] || die "archive not recognised (MANIFEST missing)"
cat "$WORK/watchpost/MANIFEST"

if [[ -t 0 ]]; then
  read -r -p "Replace the current installation with this backup? (yes/no) " r
  [[ "$r" == yes ]] || die "aborted"
fi

info "Stopping the stack…"
dc down >/dev/null 2>&1 || true

info "Configuration and secrets…"
rm -rf "$INFRA_DIR/secrets" "$INFRA_DIR/data"
tar -C "$INFRA_DIR" -xf "$WORK/watchpost/config.tar"

for f in "$WORK"/watchpost/volumes/*.tar.gz; do
  [[ -e "$f" ]] || continue
  v="$(basename "$f" .tar.gz)"
  info "Volume $v…"
  docker volume rm "watchpost_$v" >/dev/null 2>&1 || true
  docker volume create --label com.docker.compose.project=watchpost --label "com.docker.compose.volume=$v" \
    "watchpost_$v" >/dev/null
  docker run --rm -v "watchpost_$v:/v" -v "$f:/in.tar.gz:ro" --entrypoint tar caddy:2.11.9-alpine \
    -xzpf /in.tar.gz -C /v
done

info "Restarting through install.sh…"
"$INFRA_DIR/install.sh" --yes
