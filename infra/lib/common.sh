# shellcheck shell=bash
# Fonctions communes aux scripts d'exploitation Vigie (install, enroll, backup, update).
# À sourcer depuis un script lancé avec « set -Eeuo pipefail ».

INFRA_DIR="${INFRA_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
SECRETS_DIR="$INFRA_DIR/secrets"
DATA_DIR="$INFRA_DIR/data"
ENV_FILE="$INFRA_DIR/.env"

if [[ -t 1 ]]; then
  C_RED=$'\e[31m'; C_GRN=$'\e[32m'; C_YEL=$'\e[33m'; C_BLD=$'\e[1m'; C_RST=$'\e[0m'
else
  C_RED=""; C_GRN=""; C_YEL=""; C_BLD=""; C_RST=""
fi

info()  { printf '%s==>%s %s\n' "$C_GRN" "$C_RST" "$*"; }
warn()  { printf '%s[attention]%s %s\n' "$C_YEL" "$C_RST" "$*" >&2; }
die()   { printf '%s[erreur]%s %s\n' "$C_RED" "$C_RST" "$*" >&2; exit 1; }
title() { printf '\n%s%s%s\n' "$C_BLD" "$*" "$C_RST"; }

# docker compose avec le bon répertoire de projet et le fichier .env
# VIGIE_COMPOSE_EXTRA : fichier compose supplémentaire (tests ; ex. collecteur factice).
dc() {
  docker compose --project-directory "$INFRA_DIR" -f "$INFRA_DIR/docker-compose.yml" \
    ${VIGIE_COMPOSE_EXTRA:+-f "$VIGIE_COMPOSE_EXTRA"} "$@"
}

# Mot de passe aléatoire : lettres et chiffres, plus un symbole sûr pour YAML/shell/sed
# (« . » et « - »), ce qui satisfait la politique de l'API Wazuh (maj., min., chiffre, symbole).
gen_password() {
  local len="${1:-24}" p
  p="$(openssl rand -base64 96 | LC_ALL=C tr -dc 'A-Za-z0-9')"
  p="${p:0:$len}"
  # garantit chaque classe de caractères
  printf '%sAa1.-%s' "${p:0:$((len / 2))}" "${p:$((len / 2))}"
}

gen_hex() { local h; h="$(openssl rand -hex 32)"; printf '%s' "${h:0:${1:-16}}"; }

# Lecture d'une variable du fichier .env (sans l'exécuter)
env_get() {
  local key="$1"
  [[ -f "$ENV_FILE" ]] || return 0
  local line
  line="$(grep -E "^${key}=" "$ENV_FILE" | tail -n1 || true)"
  line="${line#*=}"
  line="${line#\'}"; line="${line%\'}"
  printf '%s' "$line"
}

# Écrit ou remplace KEY=VALUE dans .env (valeur entre apostrophes : aucune interpolation compose)
env_set() {
  local key="$1" value="$2" tmp
  touch "$ENV_FILE"; chmod 600 "$ENV_FILE"
  tmp="$(mktemp "$ENV_FILE.XXXXXX")"
  grep -vE "^${key}=" "$ENV_FILE" >"$tmp" || true
  printf "%s='%s'\n" "$key" "$value" >>"$tmp"
  mv "$tmp" "$ENV_FILE"; chmod 600 "$ENV_FILE"
}

# Rendu de gabarit : remplace @@NOM@@ par la valeur de la variable shell NOM.
render() {
  local src="$1" dst="$2" content name
  shopt -u patsub_replacement 2>/dev/null || true # bash ≥ 5.2 : « & » littéral
  content="$(<"$src")"
  for name in $(grep -oE '@@[A-Z0-9_]+@@' "$src" | sort -u | tr -d '@'); do
    [[ -v $name ]] || die "render $src : variable $name non définie"
    content="${content//@@${name}@@/${!name}}"
  done
  # Écriture en place (même inode) : un fichier monté seul dans un conteneur voit la mise à jour.
  printf '%s\n' "$content" >"$dst"
}

# Attend qu'un service compose soit « healthy »
wait_healthy() {
  local svc="$1" timeout="${2:-300}" t=0 cid st
  while :; do
    cid="$(dc ps -q "$svc" 2>/dev/null || true)"
    if [[ -n "$cid" ]]; then
      st="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$cid" 2>/dev/null || true)"
      [[ "$st" == healthy ]] && return 0
    fi
    ((t += 5)); ((t > timeout)) && { warn "$svc pas prêt après ${timeout}s (état : ${st:-absent})"; return 1; }
    sleep 5
  done
}

# Hachage bcrypt (coût 12) via l'outil de l'indexeur Wazuh : aucun paquet à installer sur l'hôte.
# Cache dans secrets/ pour ne pas relancer une JVM à chaque exécution.
bcrypt_hash() {
  local pw="$1" cache="$SECRETS_DIR/.bcrypt-cache" key h
  key="$(printf '%s' "$pw" | sha256sum | cut -c1-32)"
  touch "$cache"; chmod 600 "$cache"
  h="$(grep -E "^$key " "$cache" | cut -d' ' -f2- || true)"
  if [[ -z "$h" ]]; then
    h="$(docker run --rm -e "PW=$pw" --entrypoint bash "${WAZUH_INDEXER_IMAGE:-wazuh/wazuh-indexer:4.14.10}" -c \
      'JAVA_HOME=/usr/share/wazuh-indexer/jdk /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh -p "$PW" 2>/dev/null' | grep -E '^\$2' | tail -n1)"
    [[ "$h" == \$2* ]] || die "échec du calcul du hachage bcrypt"
    printf '%s %s\n' "$key" "$h" >>"$cache"
  fi
  printf '%s' "$h"
}
