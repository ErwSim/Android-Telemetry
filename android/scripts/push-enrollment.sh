#!/usr/bin/env bash
# Copies a .vigie enrollment file to the phone's Download folder, over the USB cable.
# Usage: ./push-enrollment.sh fichier.vigie        copy, then import it in the app (Enrôlement)
#        ./push-enrollment.sh --remove fichier.vigie   delete the copy on the phone afterwards
# The file holds secrets (private key, token): delete every copy once imported.
set -euo pipefail
cd "$(dirname "$0")"
. ./common.sh

REMOVE=0
if [ "${1:-}" = "--remove" ]; then REMOVE=1; shift; fi
FILE="${1:-}"
[ -n "$FILE" ] || die "Usage : $0 [--remove] fichier.vigie"
NAME="$(basename "$FILE")"
case "$NAME" in *.vigie) ;; *) die "Le fichier doit avoir l'extension .vigie" ;; esac
DEST="/sdcard/Download/$NAME"

require_adb
if [ "$REMOVE" -eq 1 ]; then
    adb shell rm -f "$DEST" && ok "Copie supprimée du téléphone : $DEST"
    exit 0
fi
[ -f "$FILE" ] || die "Fichier introuvable : $FILE"
adb push "$FILE" "$DEST" >/dev/null
ok "Copié vers $DEST"
cat <<MSG
Ensuite, sur le téléphone : Vigie › Réglages › Enrôlement › « Importer un fichier .vigie » › Téléchargements › $NAME.
L'app tente de supprimer le fichier après l'import ; sinon : $0 --remove "$FILE"
Supprimez aussi la copie sur cet ordinateur (elle contient la clé privée et le jeton).
MSG
