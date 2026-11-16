#!/usr/bin/env bash
# Generates the Wazuh internal PKI (CA + certificates for the indexer, manager/Filebeat, dashboard, admin).
# Replaces wazuh-certs-generator, which downloads its tool from the Internet when it starts.
# Usage: gen-certs.sh <output directory> [--renew | --renew-ca]
#   no option:  idempotent, regenerates nothing that exists;
#   --renew:    regenerates the certificates of the nodes and of the admin account (same CA, same names);
#   --renew-ca: also regenerates the CA (every component that trusts it restarts).
# The previous set is kept in <output>/old-<date>/.
set -Eeuo pipefail

OUT="${1:?output directory}"
MODE="${2:-}"
DAYS_CA=3650
DAYS=1825
SUBJ_BASE="/O=Watchpost/OU=Wazuh"

mkdir -p "$OUT"
chmod 700 "$OUT"
cd "$OUT"

command -v openssl >/dev/null || { echo "openssl is required" >&2; exit 1; }

if [[ "$MODE" == --renew || "$MODE" == --renew-ca ]]; then
  OLD="old-$(date +%Y%m%d-%H%M%S)"
  mkdir -p "$OLD"
  for f in admin wazuh.indexer wazuh.manager wazuh.dashboard; do
    [[ -f "$f.pem" ]] && mv "$f.pem" "$f-key.pem" "$OLD/"
  done
  if [[ "$MODE" == --renew-ca ]]; then
    mv root-ca.pem root-ca-key.pem "$OLD/" 2>/dev/null || true
  fi
  chmod 700 "$OLD"
elif [[ -n "$MODE" ]]; then
  echo "unknown option: $MODE" >&2
  exit 2
fi

if [[ ! -f root-ca.pem ]]; then
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out root-ca-key.pem 2>/dev/null
  openssl req -x509 -new -key root-ca-key.pem -sha256 -days "$DAYS_CA" \
    -subj "$SUBJ_BASE/CN=Watchpost Wazuh Root CA" -out root-ca.pem \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign"
fi

# cert <name> <CN> <SAN> <extended key usages>
cert() {
  local name="$1" cn="$2" san="$3" eku="$4"
  [[ -f "$name.pem" ]] && return 0
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$name-key.pem" 2>/dev/null
  openssl req -new -key "$name-key.pem" -subj "$SUBJ_BASE/CN=$cn" -out "$name.csr"
  local ext
  ext="$(mktemp)"
  {
    echo "basicConstraints=critical,CA:FALSE"
    echo "keyUsage=critical,digitalSignature,keyEncipherment"
    echo "extendedKeyUsage=$eku"
    [[ -n "$san" ]] && echo "subjectAltName=$san"
  } >"$ext"
  openssl x509 -req -in "$name.csr" -CA root-ca.pem -CAkey root-ca-key.pem -CAcreateserial \
    -days "$DAYS" -sha256 -extfile "$ext" -out "$name.pem" 2>/dev/null
  rm -f "$name.csr" "$ext"
}

cert admin           admin           ""                                         clientAuth
cert wazuh.indexer   wazuh.indexer   "DNS:wazuh.indexer,DNS:localhost,IP:127.0.0.1" serverAuth,clientAuth
cert wazuh.manager   wazuh.manager   "DNS:wazuh.manager"                        serverAuth,clientAuth
cert wazuh.dashboard wazuh.dashboard "DNS:wazuh.dashboard,DNS:localhost"        serverAuth,clientAuth

# The Wazuh containers run under different UIDs (indexer and dashboard: 1000) and read these
# files through read-only mounts: they are made readable, the parent directory stays 700.
chmod 644 ./*.pem
rm -f root-ca.srl
echo "Wazuh certificates ready in $OUT"
