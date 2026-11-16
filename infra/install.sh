#!/usr/bin/env bash
# Installation (et réinstallation idempotente) de la pile serveur Vigie.
#
#   sudo ./install.sh                         # questions interactives
#   sudo ./install.sh --domain vigie.exemple.fr --email moi@exemple.fr --tls acme
#   sudo ./install.sh --domain vigie.lan --tls internal      # test local / réseau local
#
# Options :
#   --domain D            domaine de base (console.D, ingest.D, siem.D, adguard.D, dns.D)
#   --email E             e-mail pour Let's Encrypt (mode acme)
#   --tls acme|internal   mode TLS (acme = Let's Encrypt ; internal = AC interne de Caddy)
#   --profile permissif|equilibre|strict   APPLIQUE ce niveau de blocage DNS (comme la console,
#                         vue « pistage ») ; sans --profile, le niveau en service est conservé
#                         (à la première installation : equilibre)
#   --clientid            DoT restreint par ClientID (<id>.dns.D) ; en mode acme exige
#   --dns-provider P --dns-token T   (P = cloudflare | desec | duckdns) pour le défi DNS-01
#   --admin-allow "CIDR…" adresses autorisées sur siem.D et adguard.D (défaut : toutes)
#   --yes                 aucune question (valeurs par défaut ou de .env)
#   --no-start            génère tout sans démarrer la pile
#   --rotate-passwords    régénère tous les mots de passe (indexeur, API, AdGuard, Caddy, console…)
#   --reset-console-password  repose le mot de passe console « admin » de .env (sinon : seulement
#                         à la création du compte ; un changement par set-password est conservé)
#   --reset-adguard       régénère la configuration AdGuard (sinon : seuls les réglages gérés
#                         par Vigie sont réappliqués) ; niveau et règles de la console conservés
#   --renew-wazuh-certs   renouvelle les certificats internes de Wazuh (même AC)
#   --renew-wazuh-ca      renouvelle l'AC interne de Wazuh et tous ses certificats
#   --build               reconstruit l'image du collecteur (sinon : seulement si absente)
#
# Rejouable sans risque : les secrets existants (.env, secrets/) sont conservés ; les réglages
# faits dans les interfaces (console — dont le niveau de blocage et les règles de la vue
# « pistage » —, AdGuard, utilisateurs créés dans le dashboard Wazuh) aussi.
set -Eeuo pipefail
trap 'echo "[erreur] ligne $LINENO : $BASH_COMMAND" >&2' ERR

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
    *) die "option inconnue : $1 (voir --help)" ;;
  esac
done

ask() { # ask <variable> <question> <défaut>
  local __var="$1" q="$2" def="${3:-}" ans=""
  if ((ASSUME_YES)) || [[ ! -t 0 ]]; then
    printf -v "$__var" '%s' "$def"; return
  fi
  read -r -p "$q${def:+ [$def]} : " ans || true
  printf -v "$__var" '%s' "${ans:-$def}"
}

# ============================================================================== 1. Prérequis
title "1. Prérequis"
command -v docker >/dev/null || die "Docker n'est pas installé (https://docs.docker.com/engine/install/)."
docker info >/dev/null 2>&1 || die "Docker ne répond pas (droits ? lancez avec sudo)."
docker compose version >/dev/null 2>&1 || die "Le greffon « docker compose » (v2) est requis."
for c in openssl curl sha256sum; do command -v "$c" >/dev/null || die "Commande requise absente : $c"; done
DOCKER_VER="$(docker version -f '{{.Server.Version}}' 2>/dev/null || echo 0)"
if [[ "${DOCKER_VER%%.*}" -lt 26 ]]; then
  die "Docker Engine >= 26 requis (montage de sous-répertoire de volume) ; version actuelle : $DOCKER_VER"
fi
COMPOSE_VER="$(docker compose version --short 2>/dev/null || echo 0)"
info "Docker $DOCKER_VER, Compose $COMPOSE_VER"

MEM_KB="$(awk '/MemTotal/ {print $2}' /proc/meminfo)"
if ((MEM_KB < 7500000)); then
  warn "RAM détectée : $((MEM_KB / 1024)) Mo. Wazuh demande 8 Go ; réduisez WAZUH_INDEXER_HEAP (1g) dans .env à vos risques."
fi
DISK_FREE_KB="$(df -Pk /var/lib/docker 2>/dev/null | awk 'NR==2 {print $4}' || echo 0)"
((DISK_FREE_KB > 20000000)) || warn "Moins de 20 Go libres pour /var/lib/docker : prévoyez 50 Go pour 90 jours d'archives."

MAP_COUNT="$(cat /proc/sys/vm/max_map_count 2>/dev/null || echo 0)"
if ((MAP_COUNT < 262144)); then
  if [[ $EUID -eq 0 ]] && sysctl -w vm.max_map_count=262144 >/dev/null 2>&1; then
    echo "vm.max_map_count=262144" >/etc/sysctl.d/99-vigie-wazuh.conf
    info "vm.max_map_count porté à 262144 (persistant : /etc/sysctl.d/99-vigie-wazuh.conf)"
  else
    warn "vm.max_map_count = $MAP_COUNT (< 262144) et non modifiable ici. L'indexeur Wazuh démarre"
    warn "en mode nœud unique mais peut échouer sous charge : « sysctl -w vm.max_map_count=262144 »."
  fi
fi

mkdir -p "$SECRETS_DIR" "$DATA_DIR"/{caddy,wazuh,adguard/conf,adguard/userfilters}
chmod 700 "$SECRETS_DIR"

# ============================================================================== 2. Paramètres
title "2. Paramètres"
DOMAIN="${ARG_DOMAIN:-$(env_get VIGIE_DOMAIN)}"
[[ -n "$DOMAIN" ]] || ask DOMAIN "Domaine de base (ex. vigie.exemple.fr)" ""
[[ "$DOMAIN" =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$ ]] || die "domaine invalide : '$DOMAIN'"

TLS_MODE="${ARG_TLS:-$(env_get VIGIE_TLS_MODE)}"
[[ -n "$TLS_MODE" ]] || ask TLS_MODE "Mode TLS : acme (Let's Encrypt, VPS public) ou internal (test/LAN)" "acme"
[[ "$TLS_MODE" == acme || "$TLS_MODE" == internal ]] || die "mode TLS invalide : $TLS_MODE"

EMAIL="${ARG_EMAIL:-$(env_get VIGIE_ACME_EMAIL)}"
if [[ "$TLS_MODE" == acme && -z "$EMAIL" ]]; then
  ask EMAIL "E-mail pour Let's Encrypt (avis d'expiration)" ""
  [[ "$EMAIL" == *@* ]] || die "un e-mail est requis en mode acme"
fi

# Niveau de blocage DNS : il vit dans la configuration d'AdGuard Home (listes activées), que la
# console modifie ; --profile l'applique ponctuellement, sans rien mémoriser ailleurs (README §6.2).
# VIGIE_DNS_PROFILE (v1) ne sert plus qu'à la migration : niveau par défaut, puis retiré de .env.
PROFILE="$ARG_PROFILE"
[[ -z "$PROFILE" || "$PROFILE" =~ ^(permissif|equilibre|strict)$ ]] || die "niveau de blocage invalide : $PROFILE (permissif, equilibre ou strict)"
DEFAULT_LEVEL="$(env_get VIGIE_DNS_PROFILE)"
[[ "$DEFAULT_LEVEL" =~ ^(permissif|equilibre|strict)$ ]] || DEFAULT_LEVEL=equilibre

CLIENTID_MODE="${ARG_CLIENTID:-$(env_get VIGIE_DNS_CLIENTID_MODE)}"
CLIENTID_MODE="${CLIENTID_MODE:-false}"
DNS_PROVIDER="${ARG_DNS_PROVIDER:-$(env_get VIGIE_ACME_DNS_PROVIDER)}"
DNS_TOKEN="${ARG_DNS_TOKEN:-$(env_get VIGIE_ACME_DNS_TOKEN)}"
if [[ "$CLIENTID_MODE" == true && "$TLS_MODE" == acme ]]; then
  case "$DNS_PROVIDER" in
    cloudflare | desec | duckdns) ;;
    *) die "--clientid en mode acme exige --dns-provider cloudflare|desec|duckdns et --dns-token (défi DNS-01)" ;;
  esac
  [[ -n "$DNS_TOKEN" ]] || die "--dns-token manquant pour le fournisseur $DNS_PROVIDER"
fi

ADMIN_ALLOW="${ARG_ADMIN_ALLOW:-$(env_get VIGIE_ADMIN_ALLOW)}"
ADMIN_ALLOW="${ADMIN_ALLOW:-0.0.0.0/0 ::/0}"

info "Domaine : $DOMAIN | TLS : $TLS_MODE | niveau DNS : ${PROFILE:-conservé} | ClientID : $CLIENTID_MODE"

# ============================================================================== 3. Secrets
title "3. Secrets (.env, jamais versionné)"
secret() { # secret <CLÉ> [longueur] : conserve la valeur existante sauf --rotate-passwords
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
secret VIGIE_ADMIN_PASSWORD
secret VIGIE_CONSOLE_PASSWORD
secret WG_ADMIN_PASSWORD
VIGIE_DNS_CLIENTID="$(env_get VIGIE_DNS_CLIENTID)"
[[ -n "$VIGIE_DNS_CLIENTID" ]] || VIGIE_DNS_CLIENTID="tel-$(gen_hex 12)"

env_set VIGIE_DOMAIN "$DOMAIN"
env_set VIGIE_TLS_MODE "$TLS_MODE"
env_set VIGIE_ACME_EMAIL "$EMAIL"
env_del VIGIE_DNS_PROFILE
env_set VIGIE_DNS_CLIENTID_MODE "$CLIENTID_MODE"
env_set VIGIE_DNS_CLIENTID "$VIGIE_DNS_CLIENTID"
env_set VIGIE_ACME_DNS_PROVIDER "$DNS_PROVIDER"
env_set VIGIE_ACME_DNS_TOKEN "$DNS_TOKEN"
env_set VIGIE_ADMIN_ALLOW "$ADMIN_ALLOW"
for k in WAZUH_INDEXER_HEAP:2g WAZUH_INDEXER_MEM_LIMIT:3g WAZUH_MANAGER_MEM_LIMIT:1536m \
  WAZUH_DASHBOARD_MEM_LIMIT:1g WAZUH_DASHBOARD_NODE_HEAP_MB:640 \
  WAZUH_ALERTS_RETENTION_DAYS:180 WAZUH_ARCHIVES_RETENTION_DAYS:90 VIGIE_RETENTION_DAYS:90 \
  VIGIE_WATCH_SILENCE_MIN:60 VIGIE_ARCHIVES_FILE_DAYS:14 VIGIE_CMD_KEEPALIVE_S:120 VIGIE_ADGUARD_POLL_S:60 \
  VIGIE_SUBNET:172.31.250.0/24 VIGIE_CADDY_IP:172.31.250.10 VIGIE_ADGUARD_IP:172.31.250.53 VIGIE_WG_IP:172.31.250.20 \
  VIGIE_NOTIFY_LEVEL:10 VIGIE_NOTIFY_SMTP_PORT:587 VIGIE_NOTIFY_SMTP_TLS:starttls; do
  [[ -n "$(env_get "${k%%:*}")" ]] || env_set "${k%%:*}" "${k#*:}"
done
# Notifications (désactivées tant que VIGIE_NOTIFY_URL et VIGIE_NOTIFY_SMTP_HOST sont vides) :
# les clés sont créées vides pour être visibles dans .env, jamais écrasées ensuite.
for k in VIGIE_NOTIFY_URL VIGIE_NOTIFY_TOPIC VIGIE_NOTIFY_TOKEN VIGIE_NOTIFY_SMTP_HOST \
  VIGIE_NOTIFY_SMTP_USER VIGIE_NOTIFY_SMTP_PASSWORD VIGIE_NOTIFY_SMTP_FROM VIGIE_NOTIFY_SMTP_TO; do
  grep -qE "^$k=" "$ENV_FILE" || env_set "$k" ""
done
# Détections du collecteur (v1.2, contrat §11.3) : clés créées vides, jamais écrasées ensuite. Vide =
# défaut du collecteur (README §7.4) ; une valeur invalide empêche le collecteur de démarrer.
if ! grep -qE '^VIGIE_DETECT_' "$ENV_FILE"; then
  printf '%s\n' "# Détections du collecteur (VIGIE_DETECT_*) : vide = défaut du collecteur, voir infra/README.md §7.4" >>"$ENV_FILE"
fi
for k in $VIGIE_DETECT_VARS; do
  grep -qE "^$k=" "$ENV_FILE" || env_set "$k" ""
done
NOTIFY_LEVEL="$(env_get VIGIE_NOTIFY_LEVEL)"
[[ "$NOTIFY_LEVEL" =~ ^([1-9]|1[0-6])$ ]] || die "VIGIE_NOTIFY_LEVEL doit être un niveau Wazuh entre 1 et 16"

# Chemins du certificat DNS dans le stockage de Caddy (lus par AdGuard Home)
if [[ "$TLS_MODE" == internal ]]; then ISSUER_DIR=local; else ISSUER_DIR=acme-v02.api.letsencrypt.org-directory; fi
if [[ "$CLIENTID_MODE" == true ]]; then
  CERT_NAME="wildcard_.dns.$DOMAIN"
  PRIVATE_DNS_HOST="$VIGIE_DNS_CLIENTID.dns.$DOMAIN"
else
  CERT_NAME="dns.$DOMAIN"
  PRIVATE_DNS_HOST="dns.$DOMAIN"
fi
env_set VIGIE_AGH_CERT_SUBPATH "caddy/certificates/$ISSUER_DIR/$CERT_NAME"
env_set VIGIE_AGH_CERT_PATH "/certs/$CERT_NAME.crt"
env_set VIGIE_PRIVATE_DNS_HOST "$PRIVATE_DNS_HOST"
env_set VIGIE_PRIVATE_DNS_HOSTS "$PRIVATE_DNS_HOST"
if [[ "$TLS_MODE" == internal ]]; then
  env_set VIGIE_SERVER_CA_FILE /etc/vigie/caddy/server-root-ca.crt
else
  env_set VIGIE_SERVER_CA_FILE ""
fi
info "Secrets et paramètres enregistrés dans $ENV_FILE (droits 600)"

# ============================================================================== 4. PKI Wazuh
title "4. Certificats internes Wazuh"
if [[ -n "$RENEW_CERTS" && ! -f "$SECRETS_DIR/wazuh-certs/root-ca.pem" ]]; then
  die "$RENEW_CERTS : aucun certificat existant à renouveler"
fi
bash "$INFRA_DIR/wazuh/gen-certs.sh" "$SECRETS_DIR/wazuh-certs" $RENEW_CERTS >/dev/null
[[ -n "$RENEW_CERTS" ]] && info "Certificats Wazuh régénérés ($RENEW_CERTS) ; ancien jeu dans secrets/wazuh-certs/ancien-*"
cp "$SECRETS_DIR/wazuh-certs/root-ca.pem" "$DATA_DIR/caddy/wazuh-root-ca.pem"
info "AC et certificats : $SECRETS_DIR/wazuh-certs"

# ============================================================================== 5. Configurations
title "5. Fichiers de configuration générés (data/)"
info "Hachage des mots de passe (bcrypt)…"
export WAZUH_INDEXER_IMAGE
docker image inspect "$WAZUH_INDEXER_IMAGE" >/dev/null 2>&1 || docker pull -q "$WAZUH_INDEXER_IMAGE" >/dev/null
HASH_ADMIN="$(bcrypt_hash "$WAZUH_ADMIN_PASSWORD")"
HASH_KIBANASERVER="$(bcrypt_hash "$WAZUH_DASHBOARD_PASSWORD")"
HASH_READER="$(bcrypt_hash "$WAZUH_READER_PASSWORD")"
ADGUARD_ADMIN_HASH="$(bcrypt_hash "$ADGUARD_ADMIN_PASSWORD")"
ADGUARD_COLLECTOR_HASH="$(bcrypt_hash "$ADGUARD_COLLECTOR_PASSWORD")"
VIGIE_ADMIN_HASH="$(bcrypt_hash "$VIGIE_ADMIN_PASSWORD")"
render "$INFRA_DIR/wazuh/indexer/internal_users.yml.tmpl" "$DATA_DIR/wazuh/internal_users.yml"
render "$INFRA_DIR/wazuh/dashboard/wazuh.yml.tmpl" "$DATA_DIR/wazuh/wazuh.yml"
chmod 644 "$DATA_DIR/wazuh/internal_users.yml" "$DATA_DIR/wazuh/wazuh.yml"

# --- Caddy
cat >"$DATA_DIR/caddy/admin-auth.caddy" <<EOF
# Généré par install.sh : compte d'accès aux interfaces d'administration (siem., adguard.).
basic_auth {
	admin $VIGIE_ADMIN_HASH
}
EOF
if [[ "$CLIENTID_MODE" == true ]]; then
  cp "$INFRA_DIR/caddy/dns-site-clientid.caddy" "$DATA_DIR/caddy/dns-site.caddy"
else
  cp "$INFRA_DIR/caddy/dns-site-simple.caddy" "$DATA_DIR/caddy/dns-site.caddy"
fi
case "$TLS_MODE:$CLIENTID_MODE:$DNS_PROVIDER" in
  acme:true:desec) printf 'tls {\n\tdns desec {\n\t\ttoken {env.VIGIE_ACME_DNS_TOKEN}\n\t}\n}\n' ;;
  acme:true:*) printf 'tls {\n\tdns %s {env.VIGIE_ACME_DNS_TOKEN}\n}\n' "$DNS_PROVIDER" ;;
  *) printf '# Pas de défi DNS-01 (mode %s).\n' "$TLS_MODE" ;;
esac >"$DATA_DIR/caddy/dns-challenge.caddy"
[[ -f "$DATA_DIR/caddy/vigie-client-ca.crt" ]] || : >"$DATA_DIR/caddy/vigie-client-ca.crt"
[[ -f "$DATA_DIR/caddy/server-root-ca.crt" ]] || : >"$DATA_DIR/caddy/server-root-ca.crt"

if [[ "$CLIENTID_MODE" == true && "$TLS_MODE" == acme ]]; then
  CADDY_IMAGE="vigie-caddy-dns-$DNS_PROVIDER:$CADDY_VERSION"
  if ! docker image inspect "$CADDY_IMAGE" >/dev/null 2>&1; then
    info "Construction de Caddy avec le module DNS $DNS_PROVIDER (quelques minutes)…"
    docker build -q -t "$CADDY_IMAGE" --build-arg "DNS_MODULE=github.com/caddy-dns/$DNS_PROVIDER" \
      -f "$INFRA_DIR/caddy/Dockerfile.dns" "$INFRA_DIR/caddy" >/dev/null
  fi
  env_set VIGIE_CADDY_IMAGE "$CADDY_IMAGE"
else
  env_set VIGIE_CADDY_IMAGE "$CADDY_BASE_IMAGE"
fi

# --- AdGuard Home
VIGIE_DOMAIN="$DOMAIN"
ADGUARD_CERT_PATH="/certs/$CERT_NAME.crt"
ADGUARD_KEY_PATH="/certs/$CERT_NAME.key"
ADGUARD_UPSTREAMS=$'\n    - https://dns.quad9.net/dns-query\n    - tls://dns.quad9.net'
if [[ "$CLIENTID_MODE" == true ]]; then
  # Jamais le sous-réseau Docker entier : sa passerelle (.1) est l'adresse vue pour toute connexion
  # relayée par docker-proxy (IPv6 sans ip6tables, accès local), ce qui ouvrirait le résolveur.
  ADGUARD_ALLOWED_CLIENTS=$'\n'"    - $VIGIE_DNS_CLIENTID"$'\n'"    - $(env_get VIGIE_WG_IP)/32"$'\n'"    - 127.0.0.0/8"
  ADGUARD_CLIENTS="
    - name: Telephone (Vigie)
      ids:
        - $VIGIE_DNS_CLIENTID
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
# Configuration gérée par Vigie, fusionnée dans celle en service : les réglages faits dans
# l'interface d'AdGuard et dans la console Vigie (niveau de blocage = listes activées, bloc
# « ! vigie:begin … ! vigie:end » des règles) sont conservés ; les listes viennent de
# adguard/niveaux.json, le fichier que lit aussi le collecteur (règle : merge-config.py, README §6.2).
render "$INFRA_DIR/adguard/AdGuardHome.yaml.tmpl" "$DATA_DIR/adguard/vigie-gere.yaml"
AGH_CONF="$DATA_DIR/adguard/conf/AdGuardHome.yaml"
AGH_WAS_RUNNING=0
if [[ -n "$(dc ps -q --status running adguardhome 2>/dev/null)" ]]; then
  AGH_WAS_RUNNING=1
  dc stop adguardhome >/dev/null 2>&1 # AdGuard écrit sa configuration à l'arrêt : lire la dernière
fi
if [[ -s "$AGH_CONF" ]]; then CUR=/w/conf/AdGuardHome.yaml; else CUR=-; fi
MERGE_ARGS=(--default-level "$DEFAULT_LEVEL")
[[ -n "$PROFILE" ]] && MERGE_ARGS+=(--level "$PROFILE")
if [[ -s "$AGH_CONF" && $RESET_ADGUARD -eq 1 ]]; then
  cp -p "$AGH_CONF" "$AGH_CONF.avant-reset-$(date +%Y%m%d-%H%M%S)"
  MERGE_ARGS+=(--reset)
fi
MERGE_OUT="$(docker run --rm -v "$DATA_DIR/adguard:/w" -v "$INFRA_DIR/adguard/merge-config.py:/merge.py:ro" \
  -v "$INFRA_DIR/adguard/niveaux.json:/niveaux.json:ro" \
  --entrypoint /var/ossec/framework/python/bin/python3 wazuh/wazuh-manager:4.14.10 \
  /merge.py /w/vigie-gere.yaml "$CUR" /w/conf/AdGuardHome.yaml.new /niveaux.json "${MERGE_ARGS[@]}")" ||
  die "fusion de la configuration AdGuard impossible"
DNS_LEVEL="$(sed -n 's/^NIVEAU=//p' <<<"$MERGE_OUT")"
cat "$AGH_CONF.new" >"$AGH_CONF" # en place (même inode)
rm -f "$AGH_CONF.new"
chmod 600 "$AGH_CONF" "$DATA_DIR/adguard/vigie-gere.yaml"
if [[ "$CUR" == - ]]; then info "Configuration AdGuard générée."
elif ((RESET_ADGUARD)); then info "Configuration AdGuard régénérée (niveau et règles de la console conservés)."
else info "Configuration AdGuard : réglages Vigie réappliqués, réglages de l'interface et de la console conservés."; fi
if [[ -n "$PROFILE" ]]; then info "Niveau de blocage DNS appliqué : $PROFILE"
else info "Niveau de blocage DNS en service : ${DNS_LEVEL:-personnalisé (listes modifiées à la main)}"; fi
if [[ ! -f "$DATA_DIR/adguard/userfilters/regles-perso.txt" ]]; then
  cat >"$DATA_DIR/adguard/userfilters/regles-perso.txt" <<'EOF'
! Règles AdGuard personnelles (non versionnées, conservées par install.sh et les sauvegardes).
! Exemples :
!   ||domaine-a-bloquer.example^
!   @@||domaine-a-autoriser.example^$important
EOF
fi

cat >"$SECRETS_DIR/identifiants.txt" <<EOF
Vigie — identifiants générés par install.sh ($(date -u +%Y-%m-%dT%H:%M:%SZ))
Fichier confidentiel (droits 600). Source de vérité : $ENV_FILE

Console Vigie        https://console.$DOMAIN        admin / $VIGIE_CONSOLE_PASSWORD  (mot de passe INITIAL : s'il a été changé avec « vigie-collector user set-password », c'est le nouveau qui compte)
Accès administration siem./adguard. (1re barrière, Caddy)  admin / $VIGIE_ADMIN_PASSWORD
Dashboard Wazuh      https://siem.$DOMAIN           admin / $WAZUH_ADMIN_PASSWORD
AdGuard Home         https://adguard.$DOMAIN        admin / $ADGUARD_ADMIN_PASSWORD
AdGuard Home, compte du collecteur (interne ; AdGuard n'a que des comptes administrateurs)  vigie-collecteur / $ADGUARD_COLLECTOR_PASSWORD
API Wazuh (interne)  wazuh-wui / $WAZUH_API_PASSWORD
Indexeur, compte du dashboard (interne)  kibanaserver / $WAZUH_DASHBOARD_PASSWORD
Indexeur, lecture seule du collecteur (interne)  vigie_reader / $WAZUH_READER_PASSWORD
WireGuard (profil optionnel, http://127.0.0.1:51821 via tunnel SSH)  admin / $WG_ADMIN_PASSWORD
DNS privé du téléphone : $PRIVATE_DNS_HOST
EOF
chmod 600 "$SECRETS_DIR/identifiants.txt"
info "Configurations générées dans $DATA_DIR"

if ((NO_START)); then
  ((AGH_WAS_RUNNING)) && dc start adguardhome >/dev/null
  info "--no-start : pile non démarrée."
  exit 0
fi

# ============================================================================== 6. Démarrage
title "6. Démarrage de la pile"
volume_cat() { # volume_cat <volume> <chemin> : lit un fichier dans un volume nommé
  docker run --rm -v "vigie_$1:/v:ro" --entrypoint cat "$CADDY_BASE_IMAGE" "/v/$2" 2>/dev/null
}

COLLECTOR_IMAGE=vigie-collector:local
if ((BUILD)) || ! docker image inspect "$COLLECTOR_IMAGE" >/dev/null 2>&1; then
  [[ -f "$INFRA_DIR/../server/Dockerfile" ]] || die "server/Dockerfile introuvable : clonez le dépôt complet"
  info "Construction de l'image du collecteur (quelques minutes)…"
  dc build -q collector
fi

# Certificats renouvelés : les fichiers montés un par un ont changé d'inode, il faut recréer.
RECREATE=()
[[ -n "$RENEW_CERTS" ]] && RECREATE=(--force-recreate)
info "Indexeur Wazuh…"
dc up -d "${RECREATE[@]}" wazuh.indexer
wait_healthy wazuh.indexer 420 || die "l'indexeur ne démarre pas : docker compose logs wazuh.indexer"

# Comptes de l'indexeur gérés par Vigie (admin, kibanaserver, vigie_reader) : au premier démarrage,
# l'index de sécurité est créé depuis internal_users.yml. Ensuite, seul un compte dont le mot de
# passe ne correspond plus à .env est corrigé, un par un, par l'API REST de sécurité (certificat
# admin) : les utilisateurs créés dans le dashboard sont conservés (securityadmin.sh, lui,
# remplacerait toute la liste).
sync_indexer_user() { # <nom> <mot de passe> <hachage> <backend_roles JSON>
  local name="$1" pw="$2" hash="$3" roles="$4" r
  if dc exec -T wazuh.indexer curl -sf -o /dev/null --cacert config/certs/root-ca.pem -u "$name:$pw" \
    https://localhost:9200/_plugins/_security/authinfo; then
    return 0
  fi
  r="$(es_admin PATCH "/_plugins/_security/api/internalusers/$name" body <<<"[{\"op\":\"add\",\"path\":\"/hash\",\"value\":\"$hash\"}]")"
  if [[ "$r" != *'"status":"OK"'* ]]; then
    r="$(es_admin PUT "/_plugins/_security/api/internalusers/$name" body <<<"{\"hash\":\"$hash\",\"backend_roles\":$roles}")"
  fi
  [[ "$r" == *'"status":"OK"'* || "$r" == *'"status":"CREATED"'* ]] || die "mise à jour du compte $name de l'indexeur impossible : $r"
  info "Compte $name de l'indexeur aligné sur .env."
}
info "Comptes de l'indexeur…"
sync_indexer_user admin "$WAZUH_ADMIN_PASSWORD" "$HASH_ADMIN" '["admin"]'
sync_indexer_user kibanaserver "$WAZUH_DASHBOARD_PASSWORD" "$HASH_KIBANASERVER" '[]'
sync_indexer_user vigie_reader "$WAZUH_READER_PASSWORD" "$HASH_READER" '["readall"]'
dc exec -T wazuh.indexer curl -sf -o /dev/null --cacert config/certs/root-ca.pem -u "admin:$WAZUH_ADMIN_PASSWORD" \
  https://localhost:9200/_plugins/_security/authinfo || die "le mot de passe admin de l'indexeur ne fonctionne pas"
info "Mots de passe de l'indexeur actifs (admin vérifié)."

info "Modèles d'index et politique de rétention…"
bash "$INFRA_DIR/wazuh/setup/indexer-setup.sh"

info "Collecteur…"
if [[ "$RENEW_CERTS" == --renew-ca ]]; then dc up -d --force-recreate collector; else dc up -d collector; fi
wait_healthy collector 120 || die "le collecteur ne démarre pas : docker compose logs collector"

# Le fichier d'export doit exister AVANT que le manager ne le surveille (le collecteur le crée dès
# son démarrage ; ceci couvre une image plus ancienne) : un fichier apparu après
# coup est ouvert en fin de fichier par wazuh-logcollector (les premières lignes seraient perdues).
COLLECTOR_USER="$(docker image inspect -f '{{.Config.User}}' "$COLLECTOR_IMAGE" 2>/dev/null || true)"
docker run --rm --user "${COLLECTOR_USER:-0:0}" -v vigie_vigie_export:/e --entrypoint sh "$CADDY_BASE_IMAGE" \
  -c '[ -e /e/events.ndjson ] || { touch /e/events.ndjson && chmod 640 /e/events.ndjson; }'
docker volume inspect vigie_adguard_querylog >/dev/null 2>&1 ||
  docker volume create --label com.docker.compose.project=vigie \
    --label com.docker.compose.volume=adguard_querylog vigie_adguard_querylog >/dev/null
docker run --rm -v vigie_adguard_querylog:/q --entrypoint sh "$CADDY_BASE_IMAGE" \
  -c '[ -e /q/querylog.json ] || { touch /q/querylog.json && chmod 600 /q/querylog.json; }'

info "Manager et dashboard Wazuh…"
dc up -d "${RECREATE[@]}" wazuh.manager wazuh.dashboard

# AC des certificats clients (créée par le collecteur au premier démarrage) -> Caddy (mTLS)
CLIENT_CA="$(volume_cat collector_data pki/ca.crt || true)"
[[ "$CLIENT_CA" == *"BEGIN CERTIFICATE"* ]] || die "AC cliente du collecteur introuvable (pki/ca.crt)"
if [[ "$CLIENT_CA" != "$(cat "$DATA_DIR/caddy/vigie-client-ca.crt")" ]]; then
  printf '%s\n' "$CLIENT_CA" >"$DATA_DIR/caddy/vigie-client-ca.crt"
  CA_CHANGED=1
else
  CA_CHANGED=0
fi

info "Caddy (certificats TLS)…"
dc up -d caddy
wait_healthy caddy 120 || die "Caddy ne démarre pas : docker compose logs caddy"
# Rechargement systématique : AC cliente, compte d'administration ou site DNS ont pu changer.
dc exec -T caddy caddy reload --config /etc/caddy/Caddyfile >/dev/null 2>&1 || warn "rechargement de Caddy échoué"
((CA_CHANGED)) && info "AC des certificats clients mise à jour dans Caddy."

info "Attente du certificat de $CERT_NAME (jusqu'à 5 min)…"
for _ in $(seq 1 60); do
  volume_cat caddy_data "caddy/certificates/$ISSUER_DIR/$CERT_NAME/$CERT_NAME.crt" >/dev/null && break
  sleep 5
done
volume_cat caddy_data "caddy/certificates/$ISSUER_DIR/$CERT_NAME/$CERT_NAME.crt" >/dev/null ||
  die "Caddy n'a pas obtenu le certificat $CERT_NAME : vérifiez le DNS et les ports 80/443 (docker compose logs caddy)"

if [[ "$TLS_MODE" == internal ]]; then
  ROOT="$(volume_cat caddy_data caddy/pki/authorities/local/root.crt || true)"
  if [[ "$ROOT" == *"BEGIN CERTIFICATE"* && "$ROOT" != "$(cat "$DATA_DIR/caddy/server-root-ca.crt")" ]]; then
    printf '%s\n' "$ROOT" >"$DATA_DIR/caddy/server-root-ca.crt"
  fi
fi

info "AdGuard Home (DNS-over-TLS)…"
dc up -d adguardhome
dc start adguardhome >/dev/null # arrêté plus haut pour la fusion de sa configuration
wait_healthy adguardhome 180 || die "AdGuard Home ne démarre pas : docker compose logs adguardhome"

# Mode ClientID : correspondance appareil -> ClientID DoT pour la vue « pistage » du collecteur.
adguard_clients_sync

# Rattrape les changements de .env (dc up recrée les conteneurs dont la configuration a changé)
dc up -d
wait_healthy wazuh.manager 300 || die "le manager Wazuh ne démarre pas : docker compose logs wazuh.manager"
wait_healthy wazuh.dashboard 420 || warn "le dashboard Wazuh n'est pas encore prêt (il peut mettre plusieurs minutes)"

# ============================================================================== 7. Comptes
title "7. Compte de la console Vigie"
# Le mot de passe de .env n'est posé qu'à la création du compte (témoin data/console-admin.cree),
# avec --reset-console-password ou --rotate-passwords : un mot de passe changé ensuite avec
# « vigie-collector user set-password admin » n'est jamais écrasé.
CONSOLE_MARK="$DATA_DIR/console-admin.cree"
if [[ ! -f "$CONSOLE_MARK" || $RESET_CONSOLE -eq 1 || $ROTATE -eq 1 ]]; then
  if printf '%s\n' "$VIGIE_CONSOLE_PASSWORD" | dc exec -T collector vigie-collector user set-password admin >/dev/null; then
    date -u +%Y-%m-%dT%H:%M:%SZ >"$CONSOLE_MARK"
    info "Compte console « admin » : mot de passe de .env posé."
  else
    warn "Impossible de créer le compte console (vigie-collector user set-password)."
  fi
else
  info "Compte console « admin » existant : mot de passe inchangé (--reset-console-password pour reposer celui de .env)."
fi

if [[ -f "$INFRA_DIR/wazuh/dashboards/vigie-saved-objects.ndjson" ]] && wait_healthy wazuh.dashboard 60; then
  if dc exec -T wazuh.dashboard curl -sk -u "admin:$WAZUH_ADMIN_PASSWORD" -H 'osd-xsrf: true' \
    -F "file=@/dev/stdin;filename=vigie-saved-objects.ndjson" "https://localhost:5601/api/saved_objects/_import?overwrite=true" \
    <"$INFRA_DIR/wazuh/dashboards/vigie-saved-objects.ndjson" | grep -q '"success":true'; then
    info "Tableaux de bord Vigie importés dans le dashboard Wazuh."
  else
    warn "Import des tableaux de bord Vigie échoué (réessayez : ./install.sh --yes)."
  fi
fi

# ============================================================================== 8. Récapitulatif
title "8. Récapitulatif"
PUBLIC_IP="$(curl -s4 --max-time 5 https://api.ipify.org 2>/dev/null || echo '<IP du VPS>')"
cat <<EOF

${C_BLD}Adresses${C_RST}
  Console Vigie     https://console.$DOMAIN
  Ingestion (mTLS)  https://ingest.$DOMAIN      (appareils enrôlés seulement)
  Wazuh (SIEM)      https://siem.$DOMAIN        (2 connexions : Caddy puis Wazuh)
  AdGuard Home      https://adguard.$DOMAIN     (2 connexions : Caddy puis AdGuard)
  DNS privé Android $PRIVATE_DNS_HOST          (DNS-over-TLS, port 853)
  Niveau de blocage ${DNS_LEVEL:-personnalisé}   (console → Pistage, ou ./install.sh --profile …)

${C_BLD}Mots de passe${C_RST} : $SECRETS_DIR/identifiants.txt (et $ENV_FILE), droits 600.

${C_BLD}Enregistrements DNS à créer${C_RST} (type A vers $PUBLIC_IP, et AAAA si IPv6) :
  console.$DOMAIN  ingest.$DOMAIN  siem.$DOMAIN  adguard.$DOMAIN  dns.$DOMAIN
EOF
if [[ "$CLIENTID_MODE" == true ]]; then
  echo "  *.dns.$DOMAIN   (joker, pour $PRIVATE_DNS_HOST)"
fi
cat <<EOF

${C_BLD}Ports à ouvrir${C_RST} (pare-feu du fournisseur et de l'hôte, voir firewall/) :
  80/tcp (ACME + redirection HTTPS), 443/tcp, 853/tcp (DNS-over-TLS)$( [[ -n "$(dc ps -q wireguard 2>/dev/null)" ]] && echo ", 51820/udp (WireGuard)")

${C_BLD}Suite${C_RST}
  1. Enrôler le téléphone :  ./enroll.sh s25      (produit s25.vigie, à transférer par câble)
  2. Sur le téléphone, DNS privé : $PRIVATE_DNS_HOST
  3. Sauvegarde : ./backup.sh   —   Mises à jour : ./update.sh
EOF
CERT_END="$(openssl x509 -enddate -noout -in "$SECRETS_DIR/wazuh-certs/wazuh.indexer.pem" | cut -d= -f2)"
echo "  Certificats internes Wazuh valables jusqu'au : $CERT_END (renouvellement : ./install.sh --renew-wazuh-certs)"
if ! openssl x509 -checkend $((90 * 86400)) -noout -in "$SECRETS_DIR/wazuh-certs/wazuh.indexer.pem" >/dev/null; then
  warn "Les certificats internes Wazuh expirent dans moins de 90 jours : ./install.sh --renew-wazuh-certs"
fi
if [[ -n "$(env_get VIGIE_NOTIFY_URL)$(env_get VIGIE_NOTIFY_SMTP_HOST)" ]]; then
  echo "  Notifications : actives à partir du niveau $NOTIFY_LEVEL (et silence de l'agent)."
else
  echo "  Notifications : désactivées (VIGIE_NOTIFY_URL / VIGIE_NOTIFY_SMTP_HOST dans .env, README §8.5)."
fi
if [[ "$TLS_MODE" == internal ]]; then
  echo
  warn "Mode TLS interne : les navigateurs et Android doivent faire confiance à l'AC de Caddy :"
  warn "  $DATA_DIR/caddy/server-root-ca.crt (incluse dans les fichiers .vigie pour l'agent)."
fi
