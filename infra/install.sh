#!/usr/bin/env bash
# Installation (and idempotent reinstallation) of the Watchpost server stack.
#
#   sudo ./install.sh                         # interactive questions
#   sudo ./install.sh --domain watchpost.example.org --email me@example.org --tls acme
#   sudo ./install.sh --domain watchpost.lan --tls internal      # local test / local network
#
# Options:
#   --domain D            base domain (console.D, ingest.D, siem.D, adguard.D, dns.D)
#   --email E             e-mail address for Let's Encrypt (acme mode)
#   --tls acme|internal   TLS mode (acme = Let's Encrypt; internal = Caddy's internal CA)
#   --profile permissive|balanced|strict   APPLIES this DNS blocking level (like the console,
#                         Tracking page); without --profile, the level in service is kept
#                         (on the first installation: balanced)
#   --clientid            DoT restricted by ClientID (<id>.dns.D); in acme mode requires
#   --dns-provider P --dns-token T   (P = cloudflare | desec | duckdns) for the DNS-01 challenge
#   --admin-allow "CIDR…" addresses allowed on siem.D and adguard.D (default: all)
#   --yes                 no questions (default values or values from .env)
#   --no-start            generates everything without starting the stack
#   --rotate-passwords    regenerates every password (indexer, API, AdGuard, Caddy, console…)
#   --reset-console-password  sets the console "admin" password from .env again (otherwise: only
#                         when the account is created; a change made with set-password is kept)
#   --reset-adguard       regenerates the AdGuard configuration (otherwise: only the settings managed
#                         by Watchpost are reapplied); console level and rules are kept
#   --renew-wazuh-certs   renews the Wazuh internal certificates (same CA)
#   --renew-wazuh-ca      renews the Wazuh internal CA and all its certificates
#   --build               rebuilds the collector image (otherwise: only if missing)
#
# Safe to rerun: existing secrets (.env, secrets/) are kept; so are the settings made in the
# interfaces (console, including the blocking level and the rules of the Tracking page,
# AdGuard, users created in the Wazuh dashboard).
set -Eeuo pipefail
trap 'echo "[error] line $LINENO: $BASH_COMMAND" >&2' ERR

INFRA_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$INFRA_DIR/lib/common.sh"

WAZUH_INDEXER_IMAGE="wazuh/wazuh-indexer:4.14.10"
CADDY_BASE_IMAGE="caddy:2.11.9-alpine"
CADDY_VERSION="2.11.9"

ARG_DOMAIN="" ARG_EMAIL="" ARG_TLS="" ARG_PROFILE="" ARG_CLIENTID="" ARG_DNS_PROVIDER="" ARG_DNS_TOKEN=""
ARG_ADMIN_ALLOW="" ASSUME_YES=0 NO_START=0 ROTATE=0 BUILD=0 RESET_CONSOLE=0 RESET_ADGUARD=0 RENEW_CERTS=""
while (($#)); do
  case "$1" in
    --domain) ARG_DOMAIN="$2"; shift 2 ;;
    --email) ARG_EMAIL="$2"; shift 2 ;;
    --tls) ARG_TLS="$2"; shift 2 ;;
    --profile) ARG_PROFILE="$2"; shift 2 ;;
    --clientid) ARG_CLIENTID=true; shift ;;
    --no-clientid) ARG_CLIENTID=false; shift ;;
    --dns-provider) ARG_DNS_PROVIDER="$2"; shift 2 ;;
    --dns-token) ARG_DNS_TOKEN="$2"; shift 2 ;;
    --admin-allow) ARG_ADMIN_ALLOW="$2"; shift 2 ;;
    --yes | -y) ASSUME_YES=1; shift ;;
    --no-start) NO_START=1; shift ;;
    --rotate-passwords) ROTATE=1; shift ;;
    --build) BUILD=1; shift ;;
    --reset-console-password) RESET_CONSOLE=1; shift ;;
    --reset-adguard) RESET_ADGUARD=1; shift ;;
    --renew-wazuh-certs) RENEW_CERTS=--renew; shift ;;
    --renew-wazuh-ca) RENEW_CERTS=--renew-ca; shift ;;
    -h | --help) sed -n '2,31p' "$0"; exit 0 ;;
    *) die "unknown option: $1 (see --help)" ;;
  esac
done

ask() { # ask <variable> <question> <default>
  local __var="$1" q="$2" def="${3:-}" ans=""
  if ((ASSUME_YES)) || [[ ! -t 0 ]]; then
    printf -v "$__var" '%s' "$def"; return
  fi
  read -r -p "$q${def:+ [$def]}: " ans || true
  printf -v "$__var" '%s' "${ans:-$def}"
}

# ============================================================================== 1. Prerequisites
title "1. Prerequisites"
command -v docker >/dev/null || die "Docker is not installed (https://docs.docker.com/engine/install/)."
docker info >/dev/null 2>&1 || die "Docker does not answer (permissions? run with sudo)."
docker compose version >/dev/null 2>&1 || die "The \"docker compose\" plugin (v2) is required."
for c in openssl curl sha256sum; do command -v "$c" >/dev/null || die "Required command missing: $c"; done
DOCKER_VER="$(docker version -f '{{.Server.Version}}' 2>/dev/null || echo 0)"
if [[ "${DOCKER_VER%%.*}" -lt 26 ]]; then
  die "Docker Engine >= 26 required (volume subdirectory mounts); current version: $DOCKER_VER"
fi
COMPOSE_VER="$(docker compose version --short 2>/dev/null || echo 0)"
info "Docker $DOCKER_VER, Compose $COMPOSE_VER"

MEM_KB="$(awk '/MemTotal/ {print $2}' /proc/meminfo)"
if ((MEM_KB < 7500000)); then
  warn "Detected RAM: $((MEM_KB / 1024)) MB. Wazuh needs 8 GB; lower WAZUH_INDEXER_HEAP (1g) in .env at your own risk."
fi
DISK_FREE_KB="$(df -Pk /var/lib/docker 2>/dev/null | awk 'NR==2 {print $4}' || echo 0)"
((DISK_FREE_KB > 20000000)) || warn "Less than 20 GB free for /var/lib/docker: plan 50 GB for 90 days of archives."

MAP_COUNT="$(cat /proc/sys/vm/max_map_count 2>/dev/null || echo 0)"
if ((MAP_COUNT < 262144)); then
  if [[ $EUID -eq 0 ]] && sysctl -w vm.max_map_count=262144 >/dev/null 2>&1; then
    echo "vm.max_map_count=262144" >/etc/sysctl.d/99-watchpost-wazuh.conf
    info "vm.max_map_count raised to 262144 (persistent: /etc/sysctl.d/99-watchpost-wazuh.conf)"
  else
    warn "vm.max_map_count = $MAP_COUNT (< 262144) and cannot be changed here. The Wazuh indexer starts"
    warn "in single-node mode but may fail under load: \"sysctl -w vm.max_map_count=262144\"."
  fi
fi

mkdir -p "$SECRETS_DIR" "$DATA_DIR"/{caddy,wazuh,adguard/conf,adguard/userfilters}
chmod 700 "$SECRETS_DIR"

# ============================================================================== 2. Settings
title "2. Settings"
DOMAIN="${ARG_DOMAIN:-$(env_get WATCHPOST_DOMAIN)}"
[[ -n "$DOMAIN" ]] || ask DOMAIN "Base domain (e.g. watchpost.example.org)" ""
[[ "$DOMAIN" =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$ ]] || die "invalid domain: '$DOMAIN'"

TLS_MODE="${ARG_TLS:-$(env_get WATCHPOST_TLS_MODE)}"
[[ -n "$TLS_MODE" ]] || ask TLS_MODE "TLS mode: acme (Let's Encrypt, public VPS) or internal (test/LAN)" "acme"
[[ "$TLS_MODE" == acme || "$TLS_MODE" == internal ]] || die "invalid TLS mode: $TLS_MODE"

EMAIL="${ARG_EMAIL:-$(env_get WATCHPOST_ACME_EMAIL)}"
if [[ "$TLS_MODE" == acme && -z "$EMAIL" ]]; then
  ask EMAIL "E-mail address for Let's Encrypt (expiry notices)" ""
  [[ "$EMAIL" == *@* ]] || die "an e-mail address is required in acme mode"
fi

# DNS blocking level: it lives in the AdGuard Home configuration (enabled lists), which the
# console changes; --profile applies it once, without storing it anywhere else (README §6.2).
# WATCHPOST_DNS_PROFILE (v1) is only used for migration: default level, then removed from .env.
PROFILE="$ARG_PROFILE"
[[ -z "$PROFILE" || "$PROFILE" =~ ^(permissive|balanced|strict)$ ]] || die "invalid blocking level: $PROFILE (permissive, balanced or strict)"
DEFAULT_LEVEL="$(env_get WATCHPOST_DNS_PROFILE)"
[[ "$DEFAULT_LEVEL" =~ ^(permissive|balanced|strict)$ ]] || DEFAULT_LEVEL=balanced

CLIENTID_MODE="${ARG_CLIENTID:-$(env_get WATCHPOST_DNS_CLIENTID_MODE)}"
CLIENTID_MODE="${CLIENTID_MODE:-false}"
DNS_PROVIDER="${ARG_DNS_PROVIDER:-$(env_get WATCHPOST_ACME_DNS_PROVIDER)}"
DNS_TOKEN="${ARG_DNS_TOKEN:-$(env_get WATCHPOST_ACME_DNS_TOKEN)}"
if [[ "$CLIENTID_MODE" == true && "$TLS_MODE" == acme ]]; then
  case "$DNS_PROVIDER" in
    cloudflare | desec | duckdns) ;;
    *) die "--clientid in acme mode requires --dns-provider cloudflare|desec|duckdns and --dns-token (DNS-01 challenge)" ;;
  esac
  [[ -n "$DNS_TOKEN" ]] || die "--dns-token missing for provider $DNS_PROVIDER"
fi

ADMIN_ALLOW="${ARG_ADMIN_ALLOW:-$(env_get WATCHPOST_ADMIN_ALLOW)}"
ADMIN_ALLOW="${ADMIN_ALLOW:-0.0.0.0/0 ::/0}"

info "Domain: $DOMAIN | TLS: $TLS_MODE | DNS level: ${PROFILE:-kept} | ClientID: $CLIENTID_MODE"

# ============================================================================== 3. Secrets
title "3. Secrets (.env, never committed)"
secret() { # secret <KEY> [length]: keeps the existing value unless --rotate-passwords
  local k="$1" v
  v="$(env_get "$k")"
  if [[ -z "$v" || $ROTATE -eq 1 ]]; then v="$(gen_password "${2:-24}")"; fi
  env_set "$k" "$v"
  printf -v "$k" '%s' "$v"
}
secret WAZUH_ADMIN_PASSWORD
secret WAZUH_DASHBOARD_PASSWORD
secret WAZUH_READER_PASSWORD
secret WAZUH_API_PASSWORD
secret ADGUARD_ADMIN_PASSWORD
secret ADGUARD_COLLECTOR_PASSWORD
secret WATCHPOST_ADMIN_PASSWORD
secret WATCHPOST_CONSOLE_PASSWORD
secret WG_ADMIN_PASSWORD
WATCHPOST_DNS_CLIENTID="$(env_get WATCHPOST_DNS_CLIENTID)"
[[ -n "$WATCHPOST_DNS_CLIENTID" ]] || WATCHPOST_DNS_CLIENTID="tel-$(gen_hex 12)"

env_set WATCHPOST_DOMAIN "$DOMAIN"
env_set WATCHPOST_TLS_MODE "$TLS_MODE"
env_set WATCHPOST_ACME_EMAIL "$EMAIL"
env_del WATCHPOST_DNS_PROFILE
env_set WATCHPOST_DNS_CLIENTID_MODE "$CLIENTID_MODE"
env_set WATCHPOST_DNS_CLIENTID "$WATCHPOST_DNS_CLIENTID"
env_set WATCHPOST_ACME_DNS_PROVIDER "$DNS_PROVIDER"
env_set WATCHPOST_ACME_DNS_TOKEN "$DNS_TOKEN"
env_set WATCHPOST_ADMIN_ALLOW "$ADMIN_ALLOW"
for k in WAZUH_INDEXER_HEAP:2g WAZUH_INDEXER_MEM_LIMIT:3g WAZUH_MANAGER_MEM_LIMIT:1536m \
  WAZUH_DASHBOARD_MEM_LIMIT:1g WAZUH_DASHBOARD_NODE_HEAP_MB:640 \
  WAZUH_ALERTS_RETENTION_DAYS:180 WAZUH_ARCHIVES_RETENTION_DAYS:90 WATCHPOST_RETENTION_DAYS:90 \
  WATCHPOST_WATCH_SILENCE_MIN:60 WATCHPOST_ARCHIVES_FILE_DAYS:14 WATCHPOST_CMD_KEEPALIVE_S:120 WATCHPOST_ADGUARD_POLL_S:60 \
  WATCHPOST_SUBNET:172.31.250.0/24 WATCHPOST_CADDY_IP:172.31.250.10 WATCHPOST_ADGUARD_IP:172.31.250.53 WATCHPOST_WG_IP:172.31.250.20 \
  WATCHPOST_NOTIFY_LEVEL:10 WATCHPOST_NOTIFY_SMTP_PORT:587 WATCHPOST_NOTIFY_SMTP_TLS:starttls; do
  [[ -n "$(env_get "${k%%:*}")" ]] || env_set "${k%%:*}" "${k#*:}"
done
# Notifications (disabled while WATCHPOST_NOTIFY_URL and WATCHPOST_NOTIFY_SMTP_HOST are empty):
# the keys are created empty so that they are visible in .env, never overwritten afterwards.
for k in WATCHPOST_NOTIFY_URL WATCHPOST_NOTIFY_TOPIC WATCHPOST_NOTIFY_TOKEN WATCHPOST_NOTIFY_SMTP_HOST \
  WATCHPOST_NOTIFY_SMTP_USER WATCHPOST_NOTIFY_SMTP_PASSWORD WATCHPOST_NOTIFY_SMTP_FROM WATCHPOST_NOTIFY_SMTP_TO; do
  grep -qE "^$k=" "$ENV_FILE" || env_set "$k" ""
done
# Collector detections (v1.2, contract §11.3): keys created empty, never overwritten afterwards. Empty =
# collector default (README §7.4); an invalid value prevents the collector from starting.
if ! grep -qE '^WATCHPOST_DETECT_' "$ENV_FILE"; then
  printf '%s\n' "# Collector detections (WATCHPOST_DETECT_*): empty = collector default, see infra/README.md §7.4" >>"$ENV_FILE"
fi
for k in $WATCHPOST_DETECT_VARS; do
  grep -qE "^$k=" "$ENV_FILE" || env_set "$k" ""
done
NOTIFY_LEVEL="$(env_get WATCHPOST_NOTIFY_LEVEL)"
[[ "$NOTIFY_LEVEL" =~ ^([1-9]|1[0-6])$ ]] || die "WATCHPOST_NOTIFY_LEVEL must be a Wazuh level between 1 and 16"

# Paths of the DNS certificate in Caddy's storage (read by AdGuard Home)
if [[ "$TLS_MODE" == internal ]]; then ISSUER_DIR=local; else ISSUER_DIR=acme-v02.api.letsencrypt.org-directory; fi
if [[ "$CLIENTID_MODE" == true ]]; then
  CERT_NAME="wildcard_.dns.$DOMAIN"
  PRIVATE_DNS_HOST="$WATCHPOST_DNS_CLIENTID.dns.$DOMAIN"
else
  CERT_NAME="dns.$DOMAIN"
  PRIVATE_DNS_HOST="dns.$DOMAIN"
fi
env_set WATCHPOST_AGH_CERT_SUBPATH "caddy/certificates/$ISSUER_DIR/$CERT_NAME"
env_set WATCHPOST_AGH_CERT_PATH "/certs/$CERT_NAME.crt"
env_set WATCHPOST_PRIVATE_DNS_HOST "$PRIVATE_DNS_HOST"
env_set WATCHPOST_PRIVATE_DNS_HOSTS "$PRIVATE_DNS_HOST"
if [[ "$TLS_MODE" == internal ]]; then
  env_set WATCHPOST_SERVER_CA_FILE /etc/watchpost/caddy/server-root-ca.crt
else
  env_set WATCHPOST_SERVER_CA_FILE ""
fi
info "Secrets and settings saved in $ENV_FILE (mode 600)"

# ============================================================================== 4. Wazuh PKI
title "4. Wazuh internal certificates"
if [[ -n "$RENEW_CERTS" && ! -f "$SECRETS_DIR/wazuh-certs/root-ca.pem" ]]; then
  die "$RENEW_CERTS: no existing certificate to renew"
fi
bash "$INFRA_DIR/wazuh/gen-certs.sh" "$SECRETS_DIR/wazuh-certs" $RENEW_CERTS >/dev/null
[[ -n "$RENEW_CERTS" ]] && info "Wazuh certificates regenerated ($RENEW_CERTS); previous set in secrets/wazuh-certs/old-*"
cp "$SECRETS_DIR/wazuh-certs/root-ca.pem" "$DATA_DIR/caddy/wazuh-root-ca.pem"
info "CA and certificates: $SECRETS_DIR/wazuh-certs"

# ============================================================================== 5. Configuration
title "5. Generated configuration files (data/)"
info "Hashing the passwords (bcrypt)…"
export WAZUH_INDEXER_IMAGE
docker image inspect "$WAZUH_INDEXER_IMAGE" >/dev/null 2>&1 || docker pull -q "$WAZUH_INDEXER_IMAGE" >/dev/null
HASH_ADMIN="$(bcrypt_hash "$WAZUH_ADMIN_PASSWORD")"
HASH_KIBANASERVER="$(bcrypt_hash "$WAZUH_DASHBOARD_PASSWORD")"
HASH_READER="$(bcrypt_hash "$WAZUH_READER_PASSWORD")"
ADGUARD_ADMIN_HASH="$(bcrypt_hash "$ADGUARD_ADMIN_PASSWORD")"
ADGUARD_COLLECTOR_HASH="$(bcrypt_hash "$ADGUARD_COLLECTOR_PASSWORD")"
WATCHPOST_ADMIN_HASH="$(bcrypt_hash "$WATCHPOST_ADMIN_PASSWORD")"
render "$INFRA_DIR/wazuh/indexer/internal_users.yml.tmpl" "$DATA_DIR/wazuh/internal_users.yml"
render "$INFRA_DIR/wazuh/dashboard/wazuh.yml.tmpl" "$DATA_DIR/wazuh/wazuh.yml"
chmod 644 "$DATA_DIR/wazuh/internal_users.yml" "$DATA_DIR/wazuh/wazuh.yml"

# --- Caddy
cat >"$DATA_DIR/caddy/admin-auth.caddy" <<EOF
# Generated by install.sh: account protecting the administration interfaces (siem., adguard.).
basic_auth {
	admin $WATCHPOST_ADMIN_HASH
}
EOF
if [[ "$CLIENTID_MODE" == true ]]; then
  cp "$INFRA_DIR/caddy/dns-site-clientid.caddy" "$DATA_DIR/caddy/dns-site.caddy"
else
  cp "$INFRA_DIR/caddy/dns-site-simple.caddy" "$DATA_DIR/caddy/dns-site.caddy"
fi
case "$TLS_MODE:$CLIENTID_MODE:$DNS_PROVIDER" in
  acme:true:desec) printf 'tls {\n\tdns desec {\n\t\ttoken {env.WATCHPOST_ACME_DNS_TOKEN}\n\t}\n}\n' ;;
  acme:true:*) printf 'tls {\n\tdns %s {env.WATCHPOST_ACME_DNS_TOKEN}\n}\n' "$DNS_PROVIDER" ;;
  *) printf '# No DNS-01 challenge (%s mode).\n' "$TLS_MODE" ;;
esac >"$DATA_DIR/caddy/dns-challenge.caddy"
[[ -f "$DATA_DIR/caddy/watchpost-client-ca.crt" ]] || : >"$DATA_DIR/caddy/watchpost-client-ca.crt"
[[ -f "$DATA_DIR/caddy/server-root-ca.crt" ]] || : >"$DATA_DIR/caddy/server-root-ca.crt"

if [[ "$CLIENTID_MODE" == true && "$TLS_MODE" == acme ]]; then
  CADDY_IMAGE="watchpost-caddy-dns-$DNS_PROVIDER:$CADDY_VERSION"
  if ! docker image inspect "$CADDY_IMAGE" >/dev/null 2>&1; then
    info "Building Caddy with the $DNS_PROVIDER DNS module (a few minutes)…"
    docker build -q -t "$CADDY_IMAGE" --build-arg "DNS_MODULE=github.com/caddy-dns/$DNS_PROVIDER" \
      -f "$INFRA_DIR/caddy/Dockerfile.dns" "$INFRA_DIR/caddy" >/dev/null
  fi
  env_set WATCHPOST_CADDY_IMAGE "$CADDY_IMAGE"
else
  env_set WATCHPOST_CADDY_IMAGE "$CADDY_BASE_IMAGE"
fi

# --- AdGuard Home
WATCHPOST_DOMAIN="$DOMAIN"
ADGUARD_CERT_PATH="/certs/$CERT_NAME.crt"
ADGUARD_KEY_PATH="/certs/$CERT_NAME.key"
ADGUARD_UPSTREAMS=$'\n    - https://dns.quad9.net/dns-query\n    - tls://dns.quad9.net'
if [[ "$CLIENTID_MODE" == true ]]; then
  # Never the whole Docker subnet: its gateway (.1) is the address seen for every connection
  # relayed by docker-proxy (IPv6 without ip6tables, local access), which would open the resolver.
  ADGUARD_ALLOWED_CLIENTS=$'\n'"    - $WATCHPOST_DNS_CLIENTID"$'\n'"    - $(env_get WATCHPOST_WG_IP)/32"$'\n'"    - 127.0.0.0/8"
  ADGUARD_CLIENTS="
    - name: Phone (Watchpost)
      ids:
        - $WATCHPOST_DNS_CLIENTID
      use_global_settings: true
      use_global_blocked_services: true
      filtering_enabled: true
      parental_enabled: false
      safebrowsing_enabled: false
      upstreams: []
      tags: []
      ignore_querylog: false
      ignore_statistics: false"
else
  ADGUARD_ALLOWED_CLIENTS=" []"
  ADGUARD_CLIENTS=" []"
fi
# Configuration managed by Watchpost, merged into the one in service: the settings made in the
# AdGuard interface and in the Watchpost console (blocking level = enabled lists, block
# "! watchpost:begin … ! watchpost:end" of the rules) are kept; the lists come from
# adguard/levels.json, the file the collector also reads (rule: merge-config.py, README §6.2).
render "$INFRA_DIR/adguard/AdGuardHome.yaml.tmpl" "$DATA_DIR/adguard/watchpost-managed.yaml"
AGH_CONF="$DATA_DIR/adguard/conf/AdGuardHome.yaml"
AGH_WAS_RUNNING=0
if [[ -n "$(dc ps -q --status running adguardhome 2>/dev/null)" ]]; then
  AGH_WAS_RUNNING=1
  dc stop adguardhome >/dev/null 2>&1 # AdGuard writes its configuration when it stops: read the latest one
fi
if [[ -s "$AGH_CONF" ]]; then CUR=/w/conf/AdGuardHome.yaml; else CUR=-; fi
MERGE_ARGS=(--default-level "$DEFAULT_LEVEL")
[[ -n "$PROFILE" ]] && MERGE_ARGS+=(--level "$PROFILE")
if [[ -s "$AGH_CONF" && $RESET_ADGUARD -eq 1 ]]; then
  cp -p "$AGH_CONF" "$AGH_CONF.before-reset-$(date +%Y%m%d-%H%M%S)"
  MERGE_ARGS+=(--reset)
fi
MERGE_OUT="$(docker run --rm -v "$DATA_DIR/adguard:/w" -v "$INFRA_DIR/adguard/merge-config.py:/merge.py:ro" \
  -v "$INFRA_DIR/adguard/levels.json:/levels.json:ro" \
  --entrypoint /var/ossec/framework/python/bin/python3 wazuh/wazuh-manager:4.14.10 \
  /merge.py /w/watchpost-managed.yaml "$CUR" /w/conf/AdGuardHome.yaml.new /levels.json "${MERGE_ARGS[@]}")" ||
  die "cannot merge the AdGuard configuration"
DNS_LEVEL="$(sed -n 's/^LEVEL=//p' <<<"$MERGE_OUT")"
cat "$AGH_CONF.new" >"$AGH_CONF" # in place (same inode)
rm -f "$AGH_CONF.new"
chmod 600 "$AGH_CONF" "$DATA_DIR/adguard/watchpost-managed.yaml"
if [[ "$CUR" == - ]]; then info "AdGuard configuration generated."
elif ((RESET_ADGUARD)); then info "AdGuard configuration regenerated (console level and rules kept)."
else info "AdGuard configuration: Watchpost settings reapplied, interface and console settings kept."; fi
if [[ -n "$PROFILE" ]]; then info "DNS blocking level applied: $PROFILE"
else info "DNS blocking level in service: ${DNS_LEVEL:-custom (lists changed by hand)}"; fi
if [[ ! -f "$DATA_DIR/adguard/userfilters/personal-rules.txt" ]]; then
  cat >"$DATA_DIR/adguard/userfilters/personal-rules.txt" <<'EOF'
! Personal AdGuard rules (not committed, kept by install.sh and by the backups).
! Examples:
!   ||domain-to-block.example^
!   @@||domain-to-allow.example^$important
EOF
fi

cat >"$SECRETS_DIR/credentials.txt" <<EOF
Watchpost: credentials generated by install.sh ($(date -u +%Y-%m-%dT%H:%M:%SZ))
Confidential file (mode 600). Source of truth: $ENV_FILE

Watchpost console    https://console.$DOMAIN        admin / $WATCHPOST_CONSOLE_PASSWORD  (INITIAL password: if it was changed with "watchpost-collector user set-password", the new one applies)
Administration access siem./adguard. (first barrier, Caddy)  admin / $WATCHPOST_ADMIN_PASSWORD
Wazuh dashboard      https://siem.$DOMAIN           admin / $WAZUH_ADMIN_PASSWORD
AdGuard Home         https://adguard.$DOMAIN        admin / $ADGUARD_ADMIN_PASSWORD
AdGuard Home, collector account (internal; AdGuard only has administrator accounts)  watchpost-collector / $ADGUARD_COLLECTOR_PASSWORD
Wazuh API (internal) wazuh-wui / $WAZUH_API_PASSWORD
Indexer, dashboard account (internal)  kibanaserver / $WAZUH_DASHBOARD_PASSWORD
Indexer, read-only account of the collector (internal)  watchpost_reader / $WAZUH_READER_PASSWORD
WireGuard (optional profile, http://127.0.0.1:51821 through an SSH tunnel)  admin / $WG_ADMIN_PASSWORD
Private DNS of the phone: $PRIVATE_DNS_HOST
EOF
chmod 600 "$SECRETS_DIR/credentials.txt"
info "Configuration generated in $DATA_DIR"

if ((NO_START)); then
  ((AGH_WAS_RUNNING)) && dc start adguardhome >/dev/null
  info "--no-start: stack not started."
  exit 0
fi

# ============================================================================== 6. Start
title "6. Starting the stack"
volume_cat() { # volume_cat <volume> <path>: reads a file from a named volume
  docker run --rm -v "watchpost_$1:/v:ro" --entrypoint cat "$CADDY_BASE_IMAGE" "/v/$2" 2>/dev/null
}

COLLECTOR_IMAGE=watchpost-collector:local
if ((BUILD)) || ! docker image inspect "$COLLECTOR_IMAGE" >/dev/null 2>&1; then
  [[ -f "$INFRA_DIR/../server/Dockerfile" ]] || die "server/Dockerfile not found: clone the whole repository"
  info "Building the collector image (a few minutes)…"
  dc build -q collector
fi

# Renewed certificates: files mounted one by one have a new inode, the containers must be recreated.
RECREATE=()
[[ -n "$RENEW_CERTS" ]] && RECREATE=(--force-recreate)
info "Wazuh indexer…"
dc up -d "${RECREATE[@]}" wazuh.indexer
wait_healthy wazuh.indexer 420 || die "the indexer does not start: docker compose logs wazuh.indexer"

# Indexer accounts managed by Watchpost (admin, kibanaserver, watchpost_reader): on the first start,
# the security index is created from internal_users.yml. Afterwards, only an account whose password
# no longer matches .env is corrected, one by one, through the security REST API (admin
# certificate): users created in the dashboard are kept (securityadmin.sh, on the other hand,
# would replace the whole list).
sync_indexer_user() { # <name> <password> <hash> <backend_roles JSON>
  local name="$1" pw="$2" hash="$3" roles="$4" r
  if dc exec -T wazuh.indexer curl -sf -o /dev/null --cacert config/certs/root-ca.pem -u "$name:$pw" \
    https://localhost:9200/_plugins/_security/authinfo; then
    return 0
  fi
  r="$(es_admin PATCH "/_plugins/_security/api/internalusers/$name" body <<<"[{\"op\":\"add\",\"path\":\"/hash\",\"value\":\"$hash\"}]")"
  if [[ "$r" != *'"status":"OK"'* ]]; then
    r="$(es_admin PUT "/_plugins/_security/api/internalusers/$name" body <<<"{\"hash\":\"$hash\",\"backend_roles\":$roles}")"
  fi
  [[ "$r" == *'"status":"OK"'* || "$r" == *'"status":"CREATED"'* ]] || die "cannot update the indexer account $name: $r"
  info "Indexer account $name aligned with .env."
}
info "Indexer accounts…"
sync_indexer_user admin "$WAZUH_ADMIN_PASSWORD" "$HASH_ADMIN" '["admin"]'
sync_indexer_user kibanaserver "$WAZUH_DASHBOARD_PASSWORD" "$HASH_KIBANASERVER" '[]'
sync_indexer_user watchpost_reader "$WAZUH_READER_PASSWORD" "$HASH_READER" '["readall"]'
dc exec -T wazuh.indexer curl -sf -o /dev/null --cacert config/certs/root-ca.pem -u "admin:$WAZUH_ADMIN_PASSWORD" \
  https://localhost:9200/_plugins/_security/authinfo || die "the indexer admin password does not work"
info "Indexer passwords active (admin checked)."

info "Index templates and retention policy…"
bash "$INFRA_DIR/wazuh/setup/indexer-setup.sh"

info "Collector…"
if [[ "$RENEW_CERTS" == --renew-ca ]]; then dc up -d --force-recreate collector; else dc up -d collector; fi
wait_healthy collector 120 || die "the collector does not start: docker compose logs collector"

# The export file must exist BEFORE the manager watches it (the collector creates it as soon as it
# starts; this covers an older image): a file that appears afterwards is opened at its end by
# wazuh-logcollector (the first lines would be lost).
COLLECTOR_USER="$(docker image inspect -f '{{.Config.User}}' "$COLLECTOR_IMAGE" 2>/dev/null || true)"
docker run --rm --user "${COLLECTOR_USER:-0:0}" -v watchpost_watchpost_export:/e --entrypoint sh "$CADDY_BASE_IMAGE" \
  -c '[ -e /e/events.ndjson ] || { touch /e/events.ndjson && chmod 640 /e/events.ndjson; }'
docker volume inspect watchpost_adguard_querylog >/dev/null 2>&1 ||
  docker volume create --label com.docker.compose.project=watchpost \
    --label com.docker.compose.volume=adguard_querylog watchpost_adguard_querylog >/dev/null
docker run --rm -v watchpost_adguard_querylog:/q --entrypoint sh "$CADDY_BASE_IMAGE" \
  -c '[ -e /q/querylog.json ] || { touch /q/querylog.json && chmod 600 /q/querylog.json; }'

info "Wazuh manager and dashboard…"
dc up -d "${RECREATE[@]}" wazuh.manager wazuh.dashboard

# CA of the client certificates (created by the collector on its first start) -> Caddy (mTLS)
CLIENT_CA="$(volume_cat collector_data pki/ca.crt || true)"
[[ "$CLIENT_CA" == *"BEGIN CERTIFICATE"* ]] || die "client CA of the collector not found (pki/ca.crt)"
if [[ "$CLIENT_CA" != "$(cat "$DATA_DIR/caddy/watchpost-client-ca.crt")" ]]; then
  printf '%s\n' "$CLIENT_CA" >"$DATA_DIR/caddy/watchpost-client-ca.crt"
  CA_CHANGED=1
else
  CA_CHANGED=0
fi

info "Caddy (TLS certificates)…"
dc up -d caddy
wait_healthy caddy 120 || die "Caddy does not start: docker compose logs caddy"
# Always reloaded: the client CA, the administration account or the DNS site may have changed.
dc exec -T caddy caddy reload --config /etc/caddy/Caddyfile >/dev/null 2>&1 || warn "Caddy reload failed"
((CA_CHANGED)) && info "Client certificate CA updated in Caddy."

info "Waiting for the $CERT_NAME certificate (up to 5 min)…"
for _ in $(seq 1 60); do
  volume_cat caddy_data "caddy/certificates/$ISSUER_DIR/$CERT_NAME/$CERT_NAME.crt" >/dev/null && break
  sleep 5
done
volume_cat caddy_data "caddy/certificates/$ISSUER_DIR/$CERT_NAME/$CERT_NAME.crt" >/dev/null ||
  die "Caddy did not obtain the $CERT_NAME certificate: check the DNS records and ports 80/443 (docker compose logs caddy)"

if [[ "$TLS_MODE" == internal ]]; then
  ROOT="$(volume_cat caddy_data caddy/pki/authorities/local/root.crt || true)"
  if [[ "$ROOT" == *"BEGIN CERTIFICATE"* && "$ROOT" != "$(cat "$DATA_DIR/caddy/server-root-ca.crt")" ]]; then
    printf '%s\n' "$ROOT" >"$DATA_DIR/caddy/server-root-ca.crt"
  fi
fi

info "AdGuard Home (DNS-over-TLS)…"
dc up -d adguardhome
dc start adguardhome >/dev/null # stopped above to merge its configuration
wait_healthy adguardhome 180 || die "AdGuard Home does not start: docker compose logs adguardhome"

# ClientID mode: device -> DoT ClientID mapping for the collector's Tracking page.
adguard_clients_sync

# Picks up .env changes (dc up recreates the containers whose configuration changed)
dc up -d
wait_healthy wazuh.manager 300 || die "the Wazuh manager does not start: docker compose logs wazuh.manager"
wait_healthy wazuh.dashboard 420 || warn "the Wazuh dashboard is not ready yet (it can take several minutes)"

# ============================================================================== 7. Accounts
title "7. Watchpost console account"
# The .env password is set only when the account is created (marker data/console-admin.created),
# with --reset-console-password or with --rotate-passwords: a password changed afterwards with
# "watchpost-collector user set-password admin" is never overwritten.
CONSOLE_MARK="$DATA_DIR/console-admin.created"
if [[ ! -f "$CONSOLE_MARK" || $RESET_CONSOLE -eq 1 || $ROTATE -eq 1 ]]; then
  if printf '%s\n' "$WATCHPOST_CONSOLE_PASSWORD" | dc exec -T collector watchpost-collector user set-password admin >/dev/null; then
    date -u +%Y-%m-%dT%H:%M:%SZ >"$CONSOLE_MARK"
    info "Console account \"admin\": password from .env set."
  else
    warn "Cannot create the console account (watchpost-collector user set-password)."
  fi
else
  info "Console account \"admin\" exists: password unchanged (--reset-console-password sets the one from .env again)."
fi

if [[ -f "$INFRA_DIR/wazuh/dashboards/watchpost-saved-objects.ndjson" ]] && wait_healthy wazuh.dashboard 60; then
  if dc exec -T wazuh.dashboard curl -sk -u "admin:$WAZUH_ADMIN_PASSWORD" -H 'osd-xsrf: true' \
    -F "file=@/dev/stdin;filename=watchpost-saved-objects.ndjson" "https://localhost:5601/api/saved_objects/_import?overwrite=true" \
    <"$INFRA_DIR/wazuh/dashboards/watchpost-saved-objects.ndjson" | grep -q '"success":true'; then
    info "Watchpost dashboards imported into the Wazuh dashboard."
  else
    warn "Import of the Watchpost dashboards failed (try again: ./install.sh --yes)."
  fi
fi

# ============================================================================== 8. Summary
title "8. Summary"
PUBLIC_IP="$(curl -s4 --max-time 5 https://api.ipify.org 2>/dev/null || echo '<VPS IP address>')"
cat <<EOF

${C_BLD}Addresses${C_RST}
  Watchpost console https://console.$DOMAIN
  Ingestion (mTLS)  https://ingest.$DOMAIN      (enrolled devices only)
  Wazuh (SIEM)      https://siem.$DOMAIN        (2 logins: Caddy then Wazuh)
  AdGuard Home      https://adguard.$DOMAIN     (2 logins: Caddy then AdGuard)
  Android private DNS $PRIVATE_DNS_HOST        (DNS-over-TLS, port 853)
  Blocking level    ${DNS_LEVEL:-custom}   (console -> Tracking, or ./install.sh --profile …)

${C_BLD}Passwords${C_RST}: $SECRETS_DIR/credentials.txt (and $ENV_FILE), mode 600.

${C_BLD}DNS records to create${C_RST} (type A to $PUBLIC_IP, and AAAA with IPv6):
  console.$DOMAIN  ingest.$DOMAIN  siem.$DOMAIN  adguard.$DOMAIN  dns.$DOMAIN
EOF
if [[ "$CLIENTID_MODE" == true ]]; then
  echo "  *.dns.$DOMAIN   (wildcard, for $PRIVATE_DNS_HOST)"
fi
cat <<EOF

${C_BLD}Ports to open${C_RST} (provider and host firewalls, see firewall/):
  80/tcp (ACME + HTTPS redirect), 443/tcp, 853/tcp (DNS-over-TLS)$( [[ -n "$(dc ps -q wireguard 2>/dev/null)" ]] && echo ", 51820/udp (WireGuard)")

${C_BLD}Next steps${C_RST}
  1. Enroll the phone:  ./enroll.sh phone      (produces phone.watchpost, to transfer over a cable)
  2. On the phone, private DNS: $PRIVATE_DNS_HOST
  3. Backup: ./backup.sh   -   Updates: ./update.sh
EOF
CERT_END="$(openssl x509 -enddate -noout -in "$SECRETS_DIR/wazuh-certs/wazuh.indexer.pem" | cut -d= -f2)"
echo "  Wazuh internal certificates valid until: $CERT_END (renewal: ./install.sh --renew-wazuh-certs)"
if ! openssl x509 -checkend $((90 * 86400)) -noout -in "$SECRETS_DIR/wazuh-certs/wazuh.indexer.pem" >/dev/null; then
  warn "The Wazuh internal certificates expire in less than 90 days: ./install.sh --renew-wazuh-certs"
fi
if [[ -n "$(env_get WATCHPOST_NOTIFY_URL)$(env_get WATCHPOST_NOTIFY_SMTP_HOST)" ]]; then
  echo "  Notifications: active from level $NOTIFY_LEVEL (and agent silence)."
else
  echo "  Notifications: disabled (WATCHPOST_NOTIFY_URL / WATCHPOST_NOTIFY_SMTP_HOST in .env, README §8.5)."
fi
if [[ "$TLS_MODE" == internal ]]; then
  echo
  warn "Internal TLS mode: browsers and Android must trust Caddy's CA:"
  warn "  $DATA_DIR/caddy/server-root-ca.crt (included in the .watchpost files for the agent)."
fi
