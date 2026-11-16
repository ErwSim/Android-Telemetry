#!/usr/bin/env bash
# Copies a .watchpost enrollment file to the phone's Download folder, over the USB cable.
# Usage: ./push-enrollment.sh file.watchpost            copy, then import it in the app (Enrollment)
#        ./push-enrollment.sh --remove file.watchpost   delete the copy on the phone afterwards
# The file holds secrets (private key, token): delete every copy once imported.
set -euo pipefail
REMOVE=0
if [ "${1:-}" = "--remove" ]; then REMOVE=1; shift; fi
# The file path is the caller's: made absolute BEFORE moving to the scripts directory.
FILE="${1:-}"
case "$FILE" in ""|/*|[A-Za-z]:[\\/]*) ;; *) FILE="$PWD/$FILE" ;; esac
SELF="$0"
cd "$(dirname "$0")"
. ./common.sh

[ -n "$FILE" ] || die "Usage: $SELF [--remove] file.watchpost"
NAME="$(basename "$FILE")"
case "$NAME" in *.watchpost) ;; *) die "The file must have the .watchpost extension" ;; esac
DEST="/sdcard/Download/$NAME"

require_adb
if [ "$REMOVE" -eq 1 ]; then
    adb shell rm -f "$DEST" && ok "Copy deleted from the phone: $DEST"
    exit 0
fi
[ -f "$FILE" ] || die "File not found: $FILE"
adb push "$FILE" "$DEST" >/dev/null
ok "Copied to $DEST"
cat <<MSG
Next, on the phone: Watchpost › Settings › Enrollment › 'Import a .watchpost file' › Downloads › $NAME.
The app tries to delete the file after the import; otherwise: $SELF --remove "$FILE"
Also delete the copy on this computer (it holds the private key and the token).
MSG
