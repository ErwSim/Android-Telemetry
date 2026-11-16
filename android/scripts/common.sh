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

# rescue_broadcast [remove_owner] : envoie l'ordre (jusqu'à une minute) et renseigne
# RESCUE_OUT (sortie brute), RESCUE_CODE (1 tout rétabli, 2 partiel, 3 plus Device Owner,
# 4 délai dépassé, vide si aucune réponse exploitable) et RESCUE_DATA (résumé).
rescue_broadcast() {
    local extra=()
    if [ "${1:-}" = "remove_owner" ]; then extra=(--ez remove_owner true); fi
    RESCUE_OUT="$(ashell am broadcast --include-stopped-packages -a "$RESCUE_ACTION" -n "$RESCUE_RECEIVER" ${extra[@]+"${extra[@]}"} 2>&1 || true)"
    RESCUE_CODE="$(printf '%s\n' "$RESCUE_OUT" | sed -n 's/.*Broadcast completed: result=\(-\{0,1\}[0-9]*\).*/\1/p' | tail -n 1)"
    RESCUE_DATA="$(printf '%s\n' "$RESCUE_OUT" | sed -n 's/.*Broadcast completed: result=[-0-9]*, data="\(.*\)"$/\1/p' | tail -n 1)"
    case "$RESCUE_CODE" in 1|2|3|4) ;; *) RESCUE_CODE="" ;; esac
}

# Extrait « clé=a,b,c » du résumé, en liste séparée par des espaces.
rescue_field() { printf '%s\n' "$RESCUE_DATA" | tr ' ' '\n' | sed -n "s/^$1=//p" | tr ',' ' '; }

# Après la perte du rôle, Vigie ne peut plus rien défaire : propose pm unhide / pm unsuspend pour
# les paquets qu'elle avait masqués ou suspendus (liste tirée du résumé de l'issue de secours).
restore_leftovers() {
    local hidden suspended answer p
    hidden="$(rescue_field hidden)"
    suspended="$(rescue_field suspended)"
    if [ -z "$hidden$suspended" ]; then
        info "Aucun paquet masqué ou suspendu à rétablir."
    else
        read -r -p "Réafficher/réactiver ces paquets par ADB (pm unhide / pm unsuspend) ? (oui/non) " answer
        if [ "$answer" = "oui" ]; then
            for p in $hidden; do info "pm unhide $p : $(ashell pm unhide "$p" 2>&1 | tr '\n' ' ')"; done
            for p in $suspended; do info "pm unsuspend $p : $(ashell pm unsuspend "$p" 2>&1 | tr '\n' ' ')"; done
            warn "Vérifiez dans Paramètres › Applications que ces apps sont de nouveau utilisables."
        fi
    fi
    if [ -n "$(rescue_field other_items)" ]; then
        warn "Restrictions, permissions ou DNS privé posés par Vigie ont normalement été levés par Android au retrait du Device Owner ; vérifiez le DNS privé dans Paramètres › Connexions."
    fi
}
