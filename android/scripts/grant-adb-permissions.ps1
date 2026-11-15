# Grants by ADB the permissions listed in docs\research\android-plateforme.md §4.
# "pm grant" only works for permissions the installed APK declares: the others are reported and skipped.
# Usage: .\grant-adb-permissions.ps1
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
Grant-Permission 'android.permission.ACCESS_FINE_LOCATION' 'localisation GPS'
Grant-Permission 'android.permission.ACCESS_COARSE_LOCATION' 'localisation'
Grant-Permission 'android.permission.ACCESS_BACKGROUND_LOCATION' 'localisation en arrière-plan'
Grant-Permission 'android.permission.POST_NOTIFICATIONS' 'notification permanente'
Grant-Permission 'android.permission.ACCESS_LOCAL_NETWORK' 'serveur sur réseau privé (Android 17)'

Write-Host 'Permissions de développement (accordables uniquement par ADB) :'
Grant-Permission 'android.permission.WRITE_SECURE_SETTINGS' 'écriture des réglages Global/Secure'
Grant-Permission 'android.permission.DUMP' 'Debug.dumpService (historique appops)'
Grant-Permission 'android.permission.BATTERY_STATS' 'statistiques batterie'
Grant-Permission 'android.permission.PACKAGE_USAGE_STATS' 'usage des apps et volumes réseau par app'
Invoke-AdbShell cmd appops set $script:Pkg GET_USAGE_STATS allow | Out-Null
if ($LASTEXITCODE -eq 0) { Ok 'appops GET_USAGE_STATS = allow' }
Info "READ_LOGS n'est pas accordée : Android 13+ exige un consentement à chaque lecture, inutilisable en continu."
