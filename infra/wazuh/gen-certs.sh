#!/usr/bin/env bash
# Génère la PKI interne de Wazuh (AC + certificats indexeur, manager/Filebeat, dashboard, admin).
# Remplace wazuh-certs-generator, qui télécharge son outil depuis Internet au lancement.
# Usage : gen-certs.sh <répertoire de sortie> [--renew | --renew-ca]
#   sans option : idempotent, ne régénère rien d'existant ;
#   --renew     : régénère les certificats des nœuds et du compte admin (même AC, mêmes noms) ;
#   --renew-ca  : régénère aussi l'AC (tous les composants qui lui font confiance redémarrent).
# L'ancien jeu est conservé dans <sortie>/ancien-<date>/.
set -Eeuo pipefail

OUT="${1:?répertoire de sortie}"
MODE="${2:-}"
DAYS_CA=3650
DAYS=1825
SUBJ_BASE="/C=FR/L=Vigie/O=Vigie/OU=Wazuh"

mkdir -p "$OUT"
chmod 700 "$OUT"
cd "$OUT"

command -v openssl >/dev/null || { echo "openssl est requis" >&2; exit 1; }

if [[ "$MODE" == --renew || "$MODE" == --renew-ca ]]; then
  OLD="ancien-$(date +%Y%m%d-%H%M%S)"
  mkdir -p "$OLD"
  for f in admin wazuh.indexer wazuh.manager wazuh.dashboard; do
    [[ -f "$f.pem" ]] && mv "$f.pem" "$f-key.pem" "$OLD/"
  done
  if [[ "$MODE" == --renew-ca ]]; then
    mv root-ca.pem root-ca-key.pem "$OLD/" 2>/dev/null || true
  fi
  chmod 700 "$OLD"
elif [[ -n "$MODE" ]]; then
  echo "option inconnue : $MODE" >&2
  exit 2
fi

if [[ ! -f root-ca.pem ]]; then
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out root-ca-key.pem 2>/dev/null
  openssl req -x509 -new -key root-ca-key.pem -sha256 -days "$DAYS_CA" \
    -subj "$SUBJ_BASE/CN=Vigie Wazuh Root CA" -out root-ca.pem \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign"
fi

# cert <nom> <CN> <SAN> <usages étendus>
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

# Les conteneurs Wazuh tournent sous des UID différents (indexeur et dashboard : 1000) et lisent ces
# fichiers via des montages en lecture seule : on les rend lisibles, le répertoire parent reste en 700.
chmod 644 ./*.pem
rm -f root-ca.srl
echo "Certificats Wazuh prêts dans $OUT"
