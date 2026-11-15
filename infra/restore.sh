#!/usr/bin/env bash
# Restauration d'une sauvegarde produite par backup.sh (même serveur ou nouveau serveur).
#
#   sudo ./restore.sh backups/vigie-20261115-220000.tar.gz
#
# Arrête la pile, remplace .env, secrets/, data/ et les volumes sauvegardés, puis relance
# install.sh (qui reprend les secrets restaurés). Sur un nouveau serveur : installez Docker,
# clonez le dépôt, copiez l'archive, lancez ce script, puis mettez à jour les enregistrements DNS.
# Si l'index Wazuh n'était pas sauvegardé, l'historique SIEM repart de zéro (les événements
# restent dans la base du collecteur et la console).
set -Eeuo pipefail
INFRA_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$INFRA_DIR/lib/common.sh"

ARCHIVE="${1:?usage : restore.sh <archive .tar.gz>}"
[[ -f "$ARCHIVE" ]] || die "archive introuvable : $ARCHIVE"
ARCHIVE="$(cd "$(dirname "$ARCHIVE")" && pwd)/$(basename "$ARCHIVE")"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
tar -C "$WORK" -xzf "$ARCHIVE"
[[ -f "$WORK/vigie/MANIFEST" ]] || die "archive non reconnue (MANIFEST absent)"
cat "$WORK/vigie/MANIFEST"

if [[ -t 0 ]]; then
  read -r -p "Remplacer l'installation actuelle par cette sauvegarde ? (oui/non) " r
  [[ "$r" == oui ]] || die "abandon"
fi

info "Arrêt de la pile…"
dc down >/dev/null 2>&1 || true

info "Configuration et secrets…"
rm -rf "$INFRA_DIR/secrets" "$INFRA_DIR/data"
tar -C "$INFRA_DIR" -xf "$WORK/vigie/config.tar"

for f in "$WORK"/vigie/volumes/*.tar.gz; do
  [[ -e "$f" ]] || continue
  v="$(basename "$f" .tar.gz)"
  info "Volume $v…"
  docker volume rm "vigie_$v" >/dev/null 2>&1 || true
  docker volume create --label com.docker.compose.project=vigie --label "com.docker.compose.volume=$v" \
    "vigie_$v" >/dev/null
  docker run --rm -v "vigie_$v:/v" -v "$f:/in.tar.gz:ro" --entrypoint tar caddy:2.11.9-alpine \
    -xzpf /in.tar.gz -C /v
done

info "Redémarrage par install.sh…"
"$INFRA_DIR/install.sh" --yes
