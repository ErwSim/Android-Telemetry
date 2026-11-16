#!/usr/bin/env bash
# Enrôlement et cycle de vie des appareils (fichiers .vigie à importer dans l'app Vigie Agent).
#
#   sudo ./enroll.sh s25                    -> ./s25.vigie (droits 600) : nouvel appareil
#   sudo ./enroll.sh s25 /root/s25.vigie
#   sudo ./enroll.sh --list                 -> appareils, dernier contact, EXPIRATION du certificat
#                                              (« à renouveler » sous 30 jours)
#   sudo ./enroll.sh --renew s25            -> ./s25-renouvellement.vigie : nouveau jeton et nouveau
#   sudo ./enroll.sh --renew dev_xxx [fichier]  certificat pour le MÊME appareil (même historique)
#   sudo ./enroll.sh --revoke dev_xxx       -> révoque un appareil (jeton et certificat refusés)
#
# Renouvellement : importer le nouveau fichier dans l'app (Réglages → Enrôlement). L'ancien couple
# jeton/certificat reste accepté jusqu'au premier envoi fait avec le nouveau, puis est refusé (401).
#
# Le fichier contient le jeton et la clé privée de l'appareil : transférez-le par câble
# (adb push s25.vigie /sdcard/Download/) ou par un canal chiffré, importez-le, puis SUPPRIMEZ-LE
# (shred -u s25.vigie) ainsi que la copie sur le téléphone.
set -Eeuo pipefail
INFRA_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$INFRA_DIR/lib/common.sh"

[[ -f "$ENV_FILE" ]] || die "installation absente : lancez d'abord ./install.sh"

# Conteneur éphémère du collecteur (même base, même configuration) qui écrit dans un répertoire
# temporaire privé : le secret ne reste ni dans le conteneur en service ni dans un volume.
TMP=""
trap '[[ -n "$TMP" ]] && rm -rf "$TMP"' EXIT
run_to_file() { # run_to_file <fichier de sortie> <sous-commande et arguments, --out /out/f.vigie ajouté>
  local out="$1"
  shift
  [[ -e "$out" ]] && die "$out existe déjà"
  TMP="$(mktemp -d)"
  local user_spec
  user_spec="$(docker image inspect -f '{{.Config.User}}' vigie-collector:local 2>/dev/null || echo 0:0)"
  chown "${user_spec:-0:0}" "$TMP" 2>/dev/null || chmod 777 "$TMP"
  dc run --rm --no-deps -T -v "$TMP:/out" collector "$@" --out /out/f.vigie
  install -m 600 "$TMP/f.vigie" "$out"
  [[ -n "${SUDO_USER:-}" ]] && chown "$SUDO_USER" "$out" || true
  info "Fichier : $out"
  warn "Contient des secrets : transfert par câble ou canal chiffré, import dans l'app, puis « shred -u $out »."
}

# Nom ou identifiant -> identifiant d'un appareil non révoqué
resolve_device() {
  local ref="$1" ids
  if [[ "$ref" == dev_* ]]; then
    printf '%s' "$ref"
    return
  fi
  ids="$(dc exec -T collector vigie-collector devices |
    awk -v n="$ref" 'NR > 1 && $2 == n && $0 !~ /révoqué/ { print $1 }')"
  case "$(printf '%s' "$ids" | grep -c .)" in
    1) printf '%s' "$ids" ;;
    0) die "aucun appareil actif nommé « $ref » (./enroll.sh --list)" ;;
    *) die "plusieurs appareils actifs nommés « $ref » : donnez l'identifiant dev_… (./enroll.sh --list)" ;;
  esac
}

# Mode ClientID : la correspondance appareil -> ClientID de la vue « pistage » suit les appareils.
sync_clients() {
  [[ "$(env_get VIGIE_DNS_CLIENTID_MODE)" == true ]] || return 0
  local before
  before="$(env_get VIGIE_ADGUARD_CLIENTS)"
  adguard_clients_sync
  [[ "$(env_get VIGIE_ADGUARD_CLIENTS)" == "$before" ]] || { dc up -d collector >/dev/null && info "Vue « pistage » : ClientID DoT associé aux appareils actifs."; }
}

case "${1:-}" in
  "" | -h | --help) sed -n '2,18p' "$0"; exit 0 ;;
  --list) dc exec -T collector vigie-collector devices; exit 0 ;;
  --revoke) dc exec -T collector vigie-collector revoke "$(resolve_device "${2:?identifiant ou nom manquant}")"; sync_clients; exit 0 ;;
  --renew)
    REF="${2:?identifiant ou nom de l appareil manquant}"
    ID="$(resolve_device "$REF")"
    LABEL="$REF"
    [[ "$LABEL" =~ ^[A-Za-z0-9._-]{1,64}$ ]] || LABEL="$ID"
    run_to_file "${3:-$PWD/$LABEL-renouvellement.vigie}" renew "$ID"
    info "Renouvellement préparé pour $ID : l'ancien fichier reste valable jusqu'au premier envoi avec le nouveau."
    exit 0
    ;;
  -*) die "option inconnue : $1 (voir --help)" ;;
esac

NAME="$1"
[[ "$NAME" =~ ^[A-Za-z0-9._-]{1,64}$ ]] || die "nom d'appareil invalide : $NAME"
run_to_file "${2:-$PWD/$NAME.vigie}" enroll --name "$NAME"
sync_clients
