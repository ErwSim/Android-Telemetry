#!/usr/bin/env bash
# Backup of the Watchpost stack into a tar.gz archive that can be encrypted.
#
#   sudo ./backup.sh                       -> backups/watchpost-YYYYMMDD-HHMMSS.tar.gz
#   sudo ./backup.sh --with-siem           -> includes the Wazuh index (large; stops the indexer)
#   sudo ./backup.sh --out /mnt/backups
#
# Default content (a few MB to a few hundred MB):
#   .env, secrets/ (passwords, Wazuh CA), data/ (generated configuration, personal AdGuard rules),
#   volumes: collector_data (SQLite database + device CA: ESSENTIAL, without it every phone
#   would have to be enrolled again), caddy_data (certificates, internal CA), adguard_work
#   (statistics), wazuh_etc and wazuh_api_configuration (manager state).
# The collector is stopped for a few seconds for a consistent SQLite copy; the phones keep
# their events in their buffer and send them again afterwards.
# The archive contains every secret: encrypt it before taking it off the server, for example
#   gpg -c backups/watchpost-….tar.gz   (or age -p)
set -Eeuo pipefail
INFRA_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$INFRA_DIR/lib/common.sh"

OUT_DIR="$INFRA_DIR/backups" WITH_SIEM=0
while (($#)); do
  case "$1" in
    --out) OUT_DIR="$2"; shift 2 ;;
    --with-siem) WITH_SIEM=1; shift ;;
    -h | --help) sed -n '2,17p' "$0"; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done
[[ -f "$ENV_FILE" ]] || die "no installation to back up (.env missing)"

STAMP="$(date +%Y%m%d-%H%M%S)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"; dc start collector >/dev/null 2>&1 || true' EXIT
mkdir -p "$OUT_DIR" "$WORK/watchpost/volumes"
chmod 700 "$OUT_DIR"

VOLUMES=(collector_data caddy_data adguard_work wazuh_etc wazuh_api_configuration)
((WITH_SIEM)) && VOLUMES+=(wazuh_indexer_data)

info "Copying the configuration…"
tar -C "$INFRA_DIR" -cf "$WORK/watchpost/config.tar" .env secrets data

info "Stopping the collector briefly (SQLite consistency)…"
dc stop collector >/dev/null
((WITH_SIEM)) && { info "Stopping the Wazuh indexer…"; dc stop wazuh.dashboard wazuh.manager wazuh.indexer >/dev/null; }
for v in "${VOLUMES[@]}"; do
  docker volume inspect "watchpost_$v" >/dev/null 2>&1 || continue
  info "Volume $v…"
  docker run --rm -v "watchpost_$v:/v:ro" -v "$WORK/watchpost/volumes:/out" --entrypoint tar caddy:2.11.9-alpine \
    -czf "/out/$v.tar.gz" -C /v .
done
dc start collector >/dev/null
((WITH_SIEM)) && dc up -d >/dev/null

printf 'date=%s\ngit_version=%s\nvolumes=%s\n' "$STAMP" \
  "$(git -C "$INFRA_DIR" rev-parse --short HEAD 2>/dev/null || echo unknown)" "${VOLUMES[*]}" >"$WORK/watchpost/MANIFEST"
ARCHIVE="$OUT_DIR/watchpost-$STAMP.tar.gz"
tar -C "$WORK" -czf "$ARCHIVE" watchpost
chmod 600 "$ARCHIVE"
info "Backup: $ARCHIVE ($(du -h "$ARCHIVE" | cut -f1))"
warn "It contains every secret: encrypt it (gpg -c) before copying it anywhere else."
