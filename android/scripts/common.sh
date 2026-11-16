#!/usr/bin/env bash
# Shared helpers for the Vigie ADB scripts (sourced, not executed).
# Device selection: if several devices are connected, export ANDROID_SERIAL=<serial> (see "adb devices").

PKG="${VIGIE_PACKAGE:-io.github.erwsim.vigie}"
ADMIN="$PKG/io.github.erwsim.vigie.policy.VigieAdminReceiver"

die() { echo "ERREUR : $*" >&2; exit 1; }
info() { echo "• $*"; }
ok() { echo "✔ $*"; }
warn() { echo "⚠ $*" >&2; }

# adb shell output without the trailing \r some devices add.
ashell() { adb shell "$@" | tr -d '\r'; }

require_adb() {
    command -v adb >/dev/null 2>&1 || die "adb introuvable. Installez « Android SDK Platform-Tools » et ajoutez-le au PATH."
    local count
    count=$(adb devices | tr -d '\r' | awk 'NR>1 && $2=="device"' | wc -l)
    if [ "$count" -eq 0 ]; then
        adb devices | tr -d '\r' | awk 'NR>1 && $2=="unauthorized"' | grep -q . && \
            die "Téléphone non autorisé : déverrouillez-le et acceptez la clé de débogage USB."
        die "Aucun téléphone connecté en débogage USB (adb devices). Sur Samsung, désactivez temporairement « Blocage automatique » (Auto Blocker)."
    fi
    if [ "$count" -gt 1 ] && [ -z "${ANDROID_SERIAL:-}" ]; then
        die "Plusieurs appareils connectés : export ANDROID_SERIAL=<numéro de série> (voir adb devices)."
    fi
}

require_installed() {
    ashell pm path "$PKG" | grep -q '^package:' || die "Vigie ($PKG) n'est pas installée. Lancez d'abord install-apk.sh."
}

is_owner() { ashell dpm list-owners 2>/dev/null | grep -q "$PKG"; }
is_test_only() { ashell dumpsys package "$PKG" | grep -q 'TEST_ONLY'; }

# ---- Issue de secours : ordre envoyé à io.github.erwsim.vigie.policy.rescue.RescueReceiver ----
# Le récepteur exige que l'expéditeur détienne android.permission.FORCE_STOP_PACKAGES
# (signature|privileged, jamais accordable à une app tierce) : seuls le shell ADB et le système
# peuvent l'envoyer. Il ne fait que DÉFAIRE ce que Vigie a appliqué.
RESCUE_RECEIVER="$PKG/io.github.erwsim.vigie.policy.rescue.RescueReceiver"
RESCUE_ACTION="io.github.erwsim.vigie.action.RESCUE_REVERT_ALL"

# rescue_broadcast [remove_owner] [force] [sweep] : envoie l'ordre (jusqu'à une minute) et renseigne
# RESCUE_OUT (sortie brute), RESCUE_CODE (1 tout rétabli, 2 partiel, 3 plus Device Owner,
# 4 délai dépassé, vide si aucune réponse exploitable) et RESCUE_DATA (résumé).
#   remove_owner : abandonne ensuite le rôle, seulement si tout a pu être défait ;
#   force        : avec remove_owner, abandonne le rôle même si un élément n'a pas pu être défait ;
#   sweep        : rétablit en plus tout ce que le catalogue a pu modifier (état douteux ou perdu).
rescue_broadcast() {
    local extra=() flag
    for flag in "$@"; do
        case "$flag" in
            remove_owner|force|sweep) extra+=(--ez "$flag" true) ;;
            *) die "rescue_broadcast : option inconnue $flag" ;;
        esac
    done
    RESCUE_OUT="$(ashell am broadcast --include-stopped-packages -a "$RESCUE_ACTION" -n "$RESCUE_RECEIVER" ${extra[@]+"${extra[@]}"} 2>&1 || true)"
    RESCUE_CODE="$(printf '%s\n' "$RESCUE_OUT" | sed -n 's/.*Broadcast completed: result=\(-\{0,1\}[0-9]*\).*/\1/p' | tail -n 1)"
    RESCUE_DATA="$(printf '%s\n' "$RESCUE_OUT" | sed -n 's/.*Broadcast completed: result=[-0-9]*, data="\(.*\)"$/\1/p' | tail -n 1)"
    case "$RESCUE_CODE" in 1|2|3|4) ;; *) RESCUE_CODE="" ;; esac
}

# Extrait « clé=a,b,c » du résumé, en liste séparée par des espaces.
rescue_field() { printf '%s\n' "$RESCUE_DATA" | tr ' ' '\n' | sed -n "s/^$1=//p" | tr ',' ' '; }

# État d'un paquet pour l'utilisateur 0, lu dans « dumpsys package » (ligne « User 0: … hidden=… suspended=… »).
pkg_flag() { ashell dumpsys package "$1" 2>/dev/null | grep -m1 -E '^[[:space:]]*User 0:' | grep -q "$2=true"; }

# Après la perte du rôle, Vigie ne peut plus rien défaire. Android lève en principe lui-même les
# politiques du Device Owner retiré (paquets masqués ou suspendus compris) : on vérifie l'état réel
# de chaque paquet que Vigie avait masqué ou suspendu, et on ne tente « pm unhide » / « pm unsuspend »
# que pour ceux qui le sont encore. Ces commandes peuvent être refusées au shell ADB (permission
# MANAGE_USERS, paquets suspendus par un administrateur) : le seul recours est alors de redonner le
# rôle à Vigie (enable-device-owner) puis de relancer rescue-revert, l'état appliqué étant conservé.
restore_leftovers() {
    local hidden suspended p stuck=""
    hidden="$(rescue_field hidden)"
    suspended="$(rescue_field suspended)"
    if [ -z "$hidden$suspended" ]; then
        info "Aucun paquet masqué ou suspendu à rétablir."
    fi
    for p in $hidden; do
        if ! pkg_flag "$p" hidden; then ok "$p : visible."; continue; fi
        info "pm unhide $p : $(ashell pm unhide "$p" 2>&1 | tr '\n' ' ')"
        if pkg_flag "$p" hidden; then stuck="$stuck $p"; else ok "$p : réaffiché."; fi
    done
    for p in $suspended; do
        if ! pkg_flag "$p" suspended; then ok "$p : actif."; continue; fi
        info "pm unsuspend $p : $(ashell pm unsuspend "$p" 2>&1 | tr '\n' ' ')"
        if pkg_flag "$p" suspended; then stuck="$stuck $p"; else ok "$p : réactivé."; fi
    done
    if [ -n "$stuck" ]; then
        warn "Toujours masqués ou suspendus :$stuck"
        warn "Android réserve leur rétablissement au Device Owner. Redonnez le rôle à Vigie (./enable-device-owner.sh, sans comptes sur le téléphone), puis lancez ./rescue-revert.sh : Vigie a gardé la liste de ce qu'elle avait appliqué."
    fi
    if [ -n "$(rescue_field other_items)" ]; then
        warn "Restrictions, permissions ou DNS privé posés par Vigie ont normalement été levés par Android au retrait du Device Owner ; vérifiez le DNS privé dans Paramètres › Connexions › Plus de paramètres de connexion."
    fi
}
