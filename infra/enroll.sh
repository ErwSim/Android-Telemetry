#!/usr/bin/env bash
# Enrôle un appareil et produit son fichier .vigie (à importer dans l'app Vigie Agent).
#
#   sudo ./enroll.sh s25                 -> ./s25.vigie (droits 600)
#   sudo ./enroll.sh s25 /root/s25.vigie
#   sudo ./enroll.sh --list              -> appareils enrôlés
#   sudo ./enroll.sh --revoke dev_xxx    -> révoque un appareil (jeton et certificat refusés)
#
# Le fichier contient le jeton et la clé privée de l'appareil : transférez-le par câble
# (adb push s25.vigie /sdcard/Download/) ou par un canal chiffré, importez-le, puis SUPPRIMEZ-LE
# (shred -u s25.vigie) ainsi que la copie sur le téléphone.
set -Eeuo pipefail
INFRA_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$INFRA_DIR/lib/common.sh"

[[ -f "$ENV_FILE" ]] || die "installation absente : lancez d'abord ./install.sh"
case "${1:-}" in
  "" | -h | --help) sed -n '2,12p' "$0"; exit 0 ;;
  --list) dc exec -T collector vigie-collector devices; exit 0 ;;
  --revoke) dc exec -T collector vigie-collector revoke "${2:?identifiant de l appareil manquant}"; exit 0 ;;
esac

NAME="$1"
[[ "$NAME" =~ ^[A-Za-z0-9._-]{1,64}$ ]] || die "nom d'appareil invalide : $NAME"
OUT="${2:-$PWD/$NAME.vigie}"
[[ -e "$OUT" ]] && die "$OUT existe déjà"

# Conteneur éphémère du collecteur (même base, même configuration) qui écrit dans un répertoire
# temporaire privé : le secret ne reste ni dans le conteneur en service ni dans un volume.
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
USER_SPEC="$(docker image inspect -f '{{.Config.User}}' vigie-collector:local 2>/dev/null || echo 0:0)"
chown "${USER_SPEC:-0:0}" "$TMP" 2>/dev/null || chmod 777 "$TMP"
dc run --rm --no-deps -T -v "$TMP:/out" collector enroll --name "$NAME" --out "/out/$NAME.vigie"

install -m 600 "$TMP/$NAME.vigie" "$OUT"
[[ -n "${SUDO_USER:-}" ]] && chown "$SUDO_USER" "$OUT" || true
info "Fichier d'enrôlement : $OUT"
warn "Contient des secrets : transfert par câble ou canal chiffré, puis « shred -u $OUT »."
