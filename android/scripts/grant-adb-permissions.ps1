# Accorde par ADB toutes les permissions dont Vigie peut avoir besoin (inventaire du code des
# modules :core, :collectors et :policy).
# - Permissions d'exécution : utiles en mode dégradé (sans Device Owner) ; en Device Owner, l'app se
#   les accorde elle-même au démarrage.
# - Permissions accordables seulement par ADB : nécessaires même en Device Owner.
# « pm grant » ne marche que pour une permission déclarée par l'APK installé : les autres sont
# signalées et ignorées.
# Usage : .\grant-adb-permissions.ps1
#
# Lancement (scripts non signés, sans modifier la politique d'exécution de Windows) :
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\grant-adb-permissions.ps1
. "$PSScriptRoot\Common.ps1"

Assert-Adb
Assert-Installed

function Grant-Permission([string]$Permission, [string]$Why) {
    $out = Invoke-AdbShell pm grant $script:Pkg $Permission
    $code = $LASTEXITCODE
    $text = (($out | Where-Object { $_ }) -join ' ').Trim()
    if ($code -eq 0 -and -not $text) {
        Ok "$Permission - $Why"
    } elseif ($text -match 'has not requested|not a changeable|Unknown permission') {
        Info "$Permission ignorée : non déclarée par cette version de l'APK ($Why)"
    } else {
        Warn "$Permission : échec - $text"
    }
}

Write-Host "Permissions d'exécution (le mode Device Owner les accorde aussi automatiquement) :"
Grant-Permission 'android.permission.ACCESS_FINE_LOCATION' 'localisation GPS ; SSID/BSSID Wi-Fi, identifiants de cellule, balayage BLE'
Grant-Permission 'android.permission.ACCESS_COARSE_LOCATION' 'localisation'
# Toujours après la localisation d'avant-plan.
Grant-Permission 'android.permission.ACCESS_BACKGROUND_LOCATION' 'localisation en arrière-plan'
Grant-Permission 'android.permission.POST_NOTIFICATIONS' 'notification permanente'
Grant-Permission 'android.permission.BLUETOOTH_SCAN' 'détection des traceurs BLE (ble_tracker)'
Grant-Permission 'android.permission.BLUETOOTH_CONNECT' 'connexions Bluetooth (bluetooth)'
Grant-Permission 'android.permission.READ_PHONE_STATE' 'suivi cellule par cellule et signal (cell, optionnel)'
Grant-Permission 'android.permission.ACCESS_LOCAL_NETWORK' 'serveur sur réseau privé (Android 17)'

Write-Host 'Permissions accordables uniquement par ADB :'
Grant-Permission 'android.permission.PACKAGE_USAGE_STATS' "accès à l'utilisation : volumes réseau par app (net_usage), app au premier plan (foreground)"
Invoke-AdbShell cmd appops set $script:Pkg GET_USAGE_STATS allow | Out-Null
if ($LASTEXITCODE -eq 0) {
    Ok "appops GET_USAGE_STATS = allow (accès à l'utilisation)"
} else {
    Warn "appops GET_USAGE_STATS : échec (à accorder dans Paramètres > Applications > Accès spéciaux > Accès aux données d'utilisation)"
}
Grant-Permission 'android.permission.WRITE_SECURE_SETTINGS' 'politique : réglages anti-pistage hors liste Device Owner (ble_scan_always_enabled)'
Grant-Permission 'android.permission.DUMP' "attribution expérimentale caméra/micro et usage réel par appli (app_ops, qui exige aussi l'accès aux statistiques d'usage) ; désactivés par défaut dans l'app"
Info "READ_LOGS n'est pas accordée : Android 13+ exige un consentement à chaque lecture, inutilisable en continu."
Info 'Exemptions de batterie : .\battery-exemptions.ps1'
