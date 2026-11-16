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

# Seuils et réglages des détections du collecteur (v1.2), transmis tels quels par docker-compose.yml ;
# vides dans .env = défauts du collecteur (server/collector/README.md, « Détections »).
VIGIE_DETECT_VARS="VIGIE_DETECT_ENABLED VIGIE_DETECT_DISABLE VIGIE_DETECT_INTERVAL_S \
VIGIE_DETECT_UPLOAD_FLOOR_MB VIGIE_DETECT_UPLOAD_FACTOR VIGIE_DETECT_UPLOAD_LEARN_DAYS \
VIGIE_DETECT_FANOUT VIGIE_DETECT_FANOUT_SCREEN_OFF VIGIE_DETECT_MAIL_MIN VIGIE_DETECT_MAIL_CLIENTS \
VIGIE_DETECT_DNS_BYPASS_MIN VIGIE_DETECT_DNS_BYPASS_PORTS VIGIE_DETECT_DNS_BYPASS_EXEMPT \
VIGIE_DETECT_SMS_OTHER_MIN VIGIE_DETECT_SMS_DAILY_MAX VIGIE_DETECT_MIC_BG_MIN VIGIE_DETECT_CAMERA_BG_MIN"

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
  # Remplacement en place (ordre conservé : un .env inchangé reste identique octet pour octet)
  KEY="$key" LINE="$key='$value'" awk '
    BEGIN { k = ENVIRON["KEY"] "="; done = 0 }
    index($0, k) == 1 { if (!done) print ENVIRON["LINE"]; done = 1; next }
    { print }
    END { if (!done) print ENVIRON["LINE"] }
  ' "$ENV_FILE" >"$tmp"
  mv "$tmp" "$ENV_FILE"; chmod 600 "$ENV_FILE"
}

# Retire KEY de .env (sans effet si absente)
env_del() {
  local key="$1" tmp
  [[ -f "$ENV_FILE" ]] && grep -qE "^${key}=" "$ENV_FILE" || return 0
  tmp="$(mktemp "$ENV_FILE.XXXXXX")"
  grep -vE "^${key}=" "$ENV_FILE" >"$tmp" || true
  mv "$tmp" "$ENV_FILE"; chmod 600 "$ENV_FILE"
}

# Mode ClientID : VIGIE_ADGUARD_CLIENTS = « device_id=ClientID » pour chaque appareil actif, afin que
# la vue « pistage » du collecteur n'attribue au téléphone que les requêtes DoT de son ClientID
# (et pas celles d'inconnus refusées). Vide hors mode ClientID (adresse IP mobile variable : tout le
# journal d'AdGuard est alors attribué à l'appareil consulté). Le collecteur doit être démarré ;
# il faut ensuite « dc up -d collector » pour qu'il voie la nouvelle valeur.
adguard_clients_sync() {
  local v="" cid id
  if [[ "$(env_get VIGIE_DNS_CLIENTID_MODE)" == true ]]; then
    cid="$(env_get VIGIE_DNS_CLIENTID)"
    for id in $(dc exec -T collector vigie-collector devices | awk 'NR > 1 && $1 ~ /^dev_/ && $0 !~ /révoqué/ { print $1 }'); do
      v="${v:+$v,}$id=$cid"
    done
  fi
  [[ "$(env_get VIGIE_ADGUARD_CLIENTS)" == "$v" ]] && grep -qE '^VIGIE_ADGUARD_CLIENTS=' "$ENV_FILE" && return 0
  env_set VIGIE_ADGUARD_CLIENTS "$v"
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

# Requête REST à l'indexeur Wazuh avec le certificat admin (super-administrateur), depuis le
# conteneur : es_admin <méthode> <chemin> [body] (corps JSON sur l'entrée standard si « body »).
es_admin() {
  dc exec -T wazuh.indexer curl -sS --cacert config/certs/root-ca.pem \
    --cert config/certs/admin.pem --key config/certs/admin-key.pem \
    -X "$1" -H 'Content-Type: application/json' "https://localhost:9200$2" ${3:+--data-binary @-}
}
