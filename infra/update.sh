#!/usr/bin/env bash
# Mise à jour de la pile Vigie.
#
#   sudo ./update.sh            # sauvegarde, git pull, images, reconstruction du collecteur, install.sh
#   sudo ./update.sh --no-pull  # sans « git pull » (dépôt déjà à jour)
#
# Les versions des images sont ÉPINGLÉES dans docker-compose.yml : une montée de version de Wazuh,
# AdGuard Home ou Caddy se fait en modifiant ce fichier (dans le dépôt), jamais en suivant
# « latest ». Pour Wazuh, lisez les notes de version avant (mêmes versions pour les trois images,
# indexeur mis à jour d'abord ; install.sh le fait dans le bon ordre).
set -Eeuo pipefail
INFRA_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$INFRA_DIR/lib/common.sh"

PULL=1
[[ "${1:-}" == --no-pull ]] && PULL=0
[[ -f "$ENV_FILE" ]] || die "installation absente : lancez ./install.sh"

title "1. Sauvegarde préalable"
"$INFRA_DIR/backup.sh"

if ((PULL)) && git -C "$INFRA_DIR" rev-parse >/dev/null 2>&1; then
  title "2. Mise à jour du dépôt"
  git -C "$INFRA_DIR" pull --ff-only
fi

title "3. Images"
dc pull --ignore-buildable --quiet
dc build --pull -q collector

title "4. Application (install.sh)"
"$INFRA_DIR/install.sh" --yes
# Les fichiers montés un par un (ossec.conf, Caddyfile…) ne sont vus qu'après recréation.
dc up -d --force-recreate wazuh.manager caddy >/dev/null
wait_healthy wazuh.manager 300 || warn "manager Wazuh lent à redémarrer"

title "5. Nettoyage"
docker image prune -f >/dev/null
info "Mise à jour terminée."
