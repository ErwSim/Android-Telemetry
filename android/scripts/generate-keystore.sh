#!/usr/bin/env bash
# Creates the release signing key (once!) and android/keystore.properties (never versioned).
# The SAME key must sign every future update: a Device Owner app cannot be updated with another
# key, and the only way back would be removing the Device Owner (or a factory reset).
# Back up android/keystore/ and android/keystore.properties offline (encrypted).
# Usage: ./generate-keystore.sh            (password from VIGIE_KEYSTORE_PASSWORD, else random)
set -euo pipefail
cd "$(dirname "$0")/.."

STORE="keystore/vigie-release.jks"
PROPS="keystore.properties"
ALIAS="vigie"

[ -e "$STORE" ] && { echo "ERREUR : $STORE existe déjà. Ne le régénérez jamais : les mises à jour seraient impossibles." >&2; exit 1; }
command -v keytool >/dev/null 2>&1 || { echo "ERREUR : keytool introuvable (installez un JDK 17+)." >&2; exit 1; }

PASS="${VIGIE_KEYSTORE_PASSWORD:-}"
if [ -z "$PASS" ]; then
    PASS="$(LC_ALL=C tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 32 || true)"
fi
[ "${#PASS}" -ge 12 ] || { echo "ERREUR : mot de passe trop court (12 caractères minimum)." >&2; exit 1; }

mkdir -p keystore
chmod 700 keystore
# PKCS12: the key password is the store password.
keytool -genkeypair -v \
    -storetype PKCS12 -keystore "$STORE" -storepass "$PASS" \
    -alias "$ALIAS" -keyalg RSA -keysize 4096 -sigalg SHA256withRSA -validity 18250 \
    -dname "CN=Vigie Agent, O=Vigie (personnel)" >/dev/null
chmod 600 "$STORE"

umask 077
cat > "$PROPS" <<PROPS
# Release signing of Vigie. NEVER commit this file. Back it up with keystore/vigie-release.jks.
storeFile=$STORE
storePassword=$PASS
keyAlias=$ALIAS
keyPassword=$PASS
PROPS

echo "✔ Clé de signature créée : android/$STORE"
echo "✔ Paramètres écrits dans : android/$PROPS"
keytool -list -v -keystore "$STORE" -storepass "$PASS" -alias "$ALIAS" 2>/dev/null | grep -E 'SHA256:' | head -1 | sed -E 's/^[[:space:]]*/  Empreinte du certificat : /' || true
echo "Sauvegardez ces deux fichiers hors de l'ordinateur (chiffrés) : sans eux, plus aucune mise à jour de Vigie."
