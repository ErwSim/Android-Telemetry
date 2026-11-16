#!/usr/bin/env bash
# Creates the release signing key (once!) and android/keystore.properties (never versioned).
# The SAME key must sign every future update: a Device Owner app cannot be updated with another
# key, and the only way back would be removing the Device Owner (or a factory reset).
# Back up android/keystore/ and android/keystore.properties offline (encrypted).
# Usage: ./generate-keystore.sh            (password from WATCHPOST_KEYSTORE_PASSWORD, else random)
set -euo pipefail
cd "$(dirname "$0")/.."

STORE="keystore/watchpost-release.jks"
PROPS="keystore.properties"
ALIAS="watchpost"

[ -e "$STORE" ] && { echo "ERROR: $STORE already exists. Never regenerate it: updates would become impossible." >&2; exit 1; }
command -v keytool >/dev/null 2>&1 || { echo "ERROR: keytool not found (install a JDK 17+)." >&2; exit 1; }

PASS="${WATCHPOST_KEYSTORE_PASSWORD:-}"
if [ -z "$PASS" ]; then
    PASS="$(LC_ALL=C tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 32 || true)"
fi
[ "${#PASS}" -ge 12 ] || { echo "ERROR: password too short (12 characters minimum)." >&2; exit 1; }

mkdir -p keystore
chmod 700 keystore
# PKCS12: the key password is the store password.
keytool -genkeypair -v \
    -storetype PKCS12 -keystore "$STORE" -storepass "$PASS" \
    -alias "$ALIAS" -keyalg RSA -keysize 4096 -sigalg SHA256withRSA -validity 18250 \
    -dname "CN=Watchpost Agent, O=Watchpost" >/dev/null
chmod 600 "$STORE"

umask 077
cat > "$PROPS" <<PROPS
# Release signing of Watchpost. NEVER commit this file. Back it up with keystore/watchpost-release.jks.
storeFile=$STORE
storePassword=$PASS
keyAlias=$ALIAS
keyPassword=$PASS
PROPS

echo "✔ Signing key created: android/$STORE"
echo "✔ Settings written to: android/$PROPS"
keytool -list -v -keystore "$STORE" -storepass "$PASS" -alias "$ALIAS" 2>/dev/null | grep -E 'SHA256:' | head -1 | sed -E 's/^[[:space:]]*/  Certificate fingerprint: /' || true
echo "Back up these two files off this computer (encrypted): without them, Watchpost can no longer be updated."
