#!/usr/bin/env bash
# Sauvegarde de la pile Vigie dans une archive tar.gz chiffrable.
#
#   sudo ./backup.sh                       -> backups/vigie-AAAAMMJJ-HHMMSS.tar.gz
#   sudo ./backup.sh --with-siem           -> inclut l'index Wazuh (gros ; arrêt de l'indexeur)
#   sudo ./backup.sh --out /mnt/sauvegardes
#
# Contenu par défaut (quelques Mo à quelques centaines de Mo) :
#   .env, secrets/ (mots de passe, AC Wazuh), data/ (configurations générées, règles AdGuard perso),
#   volumes : collector_data (base SQLite + AC des appareils : INDISPENSABLE, sans elle tous les
#   téléphones devraient être réenrôlés), caddy_data (certificats, AC interne), adguard_work
#   (statistiques), wazuh_etc et wazuh_api_configuration (état du manager).
# Le collecteur est arrêté quelques secondes pour une copie cohérente de SQLite ; les téléphones
# gardent leurs événements en tampon et les renvoient ensuite.
# L'archive contient tous les secrets : chiffrez-la avant de la sortir du serveur, par exemple
#   gpg -c backups/vigie-….tar.gz   (ou age -p)
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
    *) die "option inconnue : $1" ;;
  esac
done
[[ -f "$ENV_FILE" ]] || die "aucune installation à sauvegarder (.env absent)"

STAMP="$(date +%Y%m%d-%H%M%S)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"; dc start collector >/dev/null 2>&1 || true' EXIT
mkdir -p "$OUT_DIR" "$WORK/vigie/volumes"
chmod 700 "$OUT_DIR"

VOLUMES=(collector_data caddy_data adguard_work wazuh_etc wazuh_api_configuration)
((WITH_SIEM)) && VOLUMES+=(wazuh_indexer_data)

info "Copie de la configuration…"
tar -C "$INFRA_DIR" -cf "$WORK/vigie/config.tar" .env secrets data

info "Arrêt bref du collecteur (cohérence SQLite)…"
dc stop collector >/dev/null
((WITH_SIEM)) && { info "Arrêt de l'indexeur Wazuh…"; dc stop wazuh.dashboard wazuh.manager wazuh.indexer >/dev/null; }
for v in "${VOLUMES[@]}"; do
  docker volume inspect "vigie_$v" >/dev/null 2>&1 || continue
  info "Volume $v…"
  docker run --rm -v "vigie_$v:/v:ro" -v "$WORK/vigie/volumes:/out" --entrypoint tar caddy:2.11.9-alpine \
    -czf "/out/$v.tar.gz" -C /v .
done
dc start collector >/dev/null
((WITH_SIEM)) && dc up -d >/dev/null

printf 'date=%s\nversion_git=%s\nvolumes=%s\n' "$STAMP" \
  "$(git -C "$INFRA_DIR" rev-parse --short HEAD 2>/dev/null || echo inconnue)" "${VOLUMES[*]}" >"$WORK/vigie/MANIFEST"
ARCHIVE="$OUT_DIR/vigie-$STAMP.tar.gz"
tar -C "$WORK" -czf "$ARCHIVE" vigie
chmod 600 "$ARCHIVE"
info "Sauvegarde : $ARCHIVE ($(du -h "$ARCHIVE" | cut -f1))"
warn "Elle contient tous les secrets : chiffrez-la (gpg -c) avant de la copier ailleurs."
