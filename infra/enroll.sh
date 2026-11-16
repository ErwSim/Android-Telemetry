#!/usr/bin/env bash
# Enrollment and life cycle of the devices (.watchpost files to import into the Watchpost Agent app).
#
#   sudo ./enroll.sh phone                  -> ./phone.watchpost (mode 600): new device
#   sudo ./enroll.sh phone /root/phone.watchpost
#   sudo ./enroll.sh --list                 -> devices, last contact, certificate EXPIRY
#                                              ("renew" under 30 days)
#   sudo ./enroll.sh --renew phone          -> ./phone-renewal.watchpost: new token and new
#   sudo ./enroll.sh --renew dev_xxx [file]     certificate for the SAME device (same history)
#   sudo ./enroll.sh --revoke dev_xxx       -> revokes a device (token and certificate refused)
#
# Renewal: import the new file into the app (Settings -> Enrollment). The old token/certificate
# pair stays accepted until the first upload made with the new one, then it is refused (401).
#
# The file contains the token and the private key of the device: transfer it over a cable
# (adb push phone.watchpost /sdcard/Download/) or over an encrypted channel, import it, then DELETE IT
# (shred -u phone.watchpost) as well as the copy on the phone.
set -Eeuo pipefail
INFRA_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$INFRA_DIR/lib/common.sh"

[[ -f "$ENV_FILE" ]] || die "no installation: run ./install.sh first"

# Ephemeral collector container (same base, same configuration) that writes into a private
# temporary directory: the secret stays neither in the running container nor in a volume.
TMP=""
trap '[[ -n "$TMP" ]] && rm -rf "$TMP"' EXIT
run_to_file() { # run_to_file <output file> <subcommand and arguments, --out /out/f.watchpost appended>
  local out="$1"
  shift
  [[ -e "$out" ]] && die "$out already exists"
  TMP="$(mktemp -d)"
  local user_spec
  user_spec="$(docker image inspect -f '{{.Config.User}}' watchpost-collector:local 2>/dev/null || echo 0:0)"
  chown "${user_spec:-0:0}" "$TMP" 2>/dev/null || chmod 777 "$TMP"
  dc run --rm --no-deps -T -v "$TMP:/out" collector "$@" --out /out/f.watchpost
  install -m 600 "$TMP/f.watchpost" "$out"
  [[ -n "${SUDO_USER:-}" ]] && chown "$SUDO_USER" "$out" || true
  info "File: $out"
  warn "Contains secrets: transfer over a cable or an encrypted channel, import into the app, then \"shred -u $out\"."
}

# Name or identifier -> identifier of a device that is not revoked
resolve_device() {
  local ref="$1" ids
  if [[ "$ref" == dev_* ]]; then
    printf '%s' "$ref"
    return
  fi
  ids="$(dc exec -T collector watchpost-collector devices |
    awk -v n="$ref" 'NR > 1 && $2 == n && $0 !~ /revoked/ { print $1 }')"
  case "$(printf '%s' "$ids" | grep -c .)" in
    1) printf '%s' "$ids" ;;
    0) die "no active device named \"$ref\" (./enroll.sh --list)" ;;
    *) die "several active devices named \"$ref\": give the dev_… identifier (./enroll.sh --list)" ;;
  esac
}

# ClientID mode: the device -> ClientID mapping of the Tracking page follows the devices.
sync_clients() {
  [[ "$(env_get WATCHPOST_DNS_CLIENTID_MODE)" == true ]] || return 0
  local before
  before="$(env_get WATCHPOST_ADGUARD_CLIENTS)"
  adguard_clients_sync
  [[ "$(env_get WATCHPOST_ADGUARD_CLIENTS)" == "$before" ]] || { dc up -d collector >/dev/null && info "Tracking page: DoT ClientID mapped to the active devices."; }
}

case "${1:-}" in
  "" | -h | --help) sed -n '2,18p' "$0"; exit 0 ;;
  --list) dc exec -T collector watchpost-collector devices; exit 0 ;;
  --revoke) dc exec -T collector watchpost-collector revoke "$(resolve_device "${2:?identifier or name missing}")"; sync_clients; exit 0 ;;
  --renew)
    REF="${2:?identifier or name of the device missing}"
    ID="$(resolve_device "$REF")"
    LABEL="$REF"
    [[ "$LABEL" =~ ^[A-Za-z0-9._-]{1,64}$ ]] || LABEL="$ID"
    run_to_file "${3:-$PWD/$LABEL-renewal.watchpost}" renew "$ID"
    info "Renewal prepared for $ID: the old file stays valid until the first upload with the new one."
    exit 0
    ;;
  -*) die "unknown option: $1 (see --help)" ;;
esac

NAME="$1"
[[ "$NAME" =~ ^[A-Za-z0-9._-]{1,64}$ ]] || die "invalid device name: $NAME"
run_to_file "${2:-$PWD/$NAME.watchpost}" enroll --name "$NAME"
sync_clients
