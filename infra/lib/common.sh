# shellcheck shell=bash
# Functions shared by the Watchpost operations scripts (install, enroll, backup, update).
# To be sourced from a script run with "set -Eeuo pipefail".

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
warn()  { printf '%s[warning]%s %s\n' "$C_YEL" "$C_RST" "$*" >&2; }
die()   { printf '%s[error]%s %s\n' "$C_RED" "$C_RST" "$*" >&2; exit 1; }
title() { printf '\n%s%s%s\n' "$C_BLD" "$*" "$C_RST"; }

# docker compose with the right project directory and the .env file
# WATCHPOST_COMPOSE_EXTRA: additional compose file (tests; e.g. a fake collector).
dc() {
  docker compose --project-directory "$INFRA_DIR" -f "$INFRA_DIR/docker-compose.yml" \
    ${WATCHPOST_COMPOSE_EXTRA:+-f "$WATCHPOST_COMPOSE_EXTRA"} "$@"
}

# Random password: letters and digits, plus symbols that are safe for YAML/shell/sed
# ("." and "-"), which satisfies the Wazuh API policy (upper case, lower case, digit, symbol).
gen_password() {
  local len="${1:-24}" p
  p="$(openssl rand -base64 96 | LC_ALL=C tr -dc 'A-Za-z0-9')"
  p="${p:0:$len}"
  # guarantees every character class
  printf '%sAa1.-%s' "${p:0:$((len / 2))}" "${p:$((len / 2))}"
}

gen_hex() { local h; h="$(openssl rand -hex 32)"; printf '%s' "${h:0:${1:-16}}"; }

# Thresholds and settings of the collector detections (v1.2), passed as is by docker-compose.yml;
# empty in .env = collector defaults (server/collector/README.md, "Detections").
WATCHPOST_DETECT_VARS="WATCHPOST_DETECT_ENABLED WATCHPOST_DETECT_DISABLE WATCHPOST_DETECT_INTERVAL_S \
WATCHPOST_DETECT_UPLOAD_FLOOR_MB WATCHPOST_DETECT_UPLOAD_FACTOR WATCHPOST_DETECT_UPLOAD_LEARN_DAYS \
WATCHPOST_DETECT_FANOUT WATCHPOST_DETECT_FANOUT_SCREEN_OFF WATCHPOST_DETECT_MAIL_MIN WATCHPOST_DETECT_MAIL_CLIENTS \
WATCHPOST_DETECT_DNS_BYPASS_MIN WATCHPOST_DETECT_DNS_BYPASS_PORTS WATCHPOST_DETECT_DNS_BYPASS_EXEMPT \
WATCHPOST_DETECT_SMS_OTHER_MIN WATCHPOST_DETECT_SMS_DAILY_MAX WATCHPOST_DETECT_MIC_BG_MIN WATCHPOST_DETECT_CAMERA_BG_MIN"

# Reads a variable from the .env file (without executing it)
env_get() {
  local key="$1"
  [[ -f "$ENV_FILE" ]] || return 0
  local line
  line="$(grep -E "^${key}=" "$ENV_FILE" | tail -n1 || true)"
  line="${line#*=}"
  line="${line#\'}"; line="${line%\'}"
  printf '%s' "$line"
}

# Writes or replaces KEY=VALUE in .env (value in single quotes: no compose interpolation)
env_set() {
  local key="$1" value="$2" tmp
  touch "$ENV_FILE"; chmod 600 "$ENV_FILE"
  tmp="$(mktemp "$ENV_FILE.XXXXXX")"
  # In-place replacement (order kept: an unchanged .env stays byte-for-byte identical)
  KEY="$key" LINE="$key='$value'" awk '
    BEGIN { k = ENVIRON["KEY"] "="; done = 0 }
    index($0, k) == 1 { if (!done) print ENVIRON["LINE"]; done = 1; next }
    { print }
    END { if (!done) print ENVIRON["LINE"] }
  ' "$ENV_FILE" >"$tmp"
  mv "$tmp" "$ENV_FILE"; chmod 600 "$ENV_FILE"
}

# Removes KEY from .env (no effect if absent)
env_del() {
  local key="$1" tmp
  [[ -f "$ENV_FILE" ]] && grep -qE "^${key}=" "$ENV_FILE" || return 0
  tmp="$(mktemp "$ENV_FILE.XXXXXX")"
  grep -vE "^${key}=" "$ENV_FILE" >"$tmp" || true
  mv "$tmp" "$ENV_FILE"; chmod 600 "$ENV_FILE"
}

# ClientID mode: WATCHPOST_ADGUARD_CLIENTS = "device_id=ClientID" for each active device, so that
# the collector's Tracking page attributes to the phone only the DoT queries of its ClientID
# (and not the refused ones from strangers). Empty outside ClientID mode (changing mobile IP address:
# the whole AdGuard query log is then attributed to the device being viewed). The collector must be
# running; "dc up -d collector" is then needed for it to see the new value.
adguard_clients_sync() {
  local v="" cid id
  if [[ "$(env_get WATCHPOST_DNS_CLIENTID_MODE)" == true ]]; then
    cid="$(env_get WATCHPOST_DNS_CLIENTID)"
    for id in $(dc exec -T collector watchpost-collector devices | awk 'NR > 1 && $1 ~ /^dev_/ && $0 !~ /revoked/ { print $1 }'); do
      v="${v:+$v,}$id=$cid"
    done
  fi
  [[ "$(env_get WATCHPOST_ADGUARD_CLIENTS)" == "$v" ]] && grep -qE '^WATCHPOST_ADGUARD_CLIENTS=' "$ENV_FILE" && return 0
  env_set WATCHPOST_ADGUARD_CLIENTS "$v"
}

# Template rendering: replaces @@NAME@@ with the value of the shell variable NAME.
render() {
  local src="$1" dst="$2" content name
  shopt -u patsub_replacement 2>/dev/null || true # bash >= 5.2: literal "&"
  content="$(<"$src")"
  for name in $(grep -oE '@@[A-Z0-9_]+@@' "$src" | sort -u | tr -d '@'); do
    [[ -v $name ]] || die "render $src: variable $name is not defined"
    content="${content//@@${name}@@/${!name}}"
  done
  # In-place write (same inode): a file mounted on its own in a container sees the update.
  printf '%s\n' "$content" >"$dst"
}

# Waits until a compose service is "healthy"
wait_healthy() {
  local svc="$1" timeout="${2:-300}" t=0 cid st
  while :; do
    cid="$(dc ps -q "$svc" 2>/dev/null || true)"
    if [[ -n "$cid" ]]; then
      st="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$cid" 2>/dev/null || true)"
      [[ "$st" == healthy ]] && return 0
    fi
    ((t += 5)); ((t > timeout)) && { warn "$svc not ready after ${timeout}s (state: ${st:-absent})"; return 1; }
    sleep 5
  done
}

# bcrypt hash (cost 12) with the Wazuh indexer tool: no package to install on the host.
# Cached in secrets/ so that a JVM is not started on every run.
bcrypt_hash() {
  local pw="$1" cache="$SECRETS_DIR/.bcrypt-cache" key h
  key="$(printf '%s' "$pw" | sha256sum | cut -c1-32)"
  touch "$cache"; chmod 600 "$cache"
  h="$(grep -E "^$key " "$cache" | cut -d' ' -f2- || true)"
  if [[ -z "$h" ]]; then
    h="$(docker run --rm -e "PW=$pw" --entrypoint bash "${WAZUH_INDEXER_IMAGE:-wazuh/wazuh-indexer:4.14.10}" -c \
      'JAVA_HOME=/usr/share/wazuh-indexer/jdk /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh -p "$PW" 2>/dev/null' | grep -E '^\$2' | tail -n1)"
    [[ "$h" == \$2* ]] || die "bcrypt hash computation failed"
    printf '%s %s\n' "$key" "$h" >>"$cache"
  fi
  printf '%s' "$h"
}

# REST request to the Wazuh indexer with the admin certificate (super administrator), from inside
# the container: es_admin <method> <path> [body] (JSON body on standard input if "body").
es_admin() {
  dc exec -T wazuh.indexer curl -sS --cacert config/certs/root-ca.pem \
    --cert config/certs/admin.pem --key config/certs/admin-key.pem \
    -X "$1" -H 'Content-Type: application/json' "https://localhost:9200$2" ${3:+--data-binary @-}
}
