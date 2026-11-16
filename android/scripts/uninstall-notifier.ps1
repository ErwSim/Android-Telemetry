# Withdraws notification access and uninstalls the companion "Vigie Notifications".
# Usage: .\uninstall-notifier.ps1
# The Vigie agent keeps running; its "Notifications" collector becomes "indisponible". The package
# lists remain stored in the agent (they are used again if the companion is reinstalled).
#
# Lancement (scripts non signés, sans modifier la politique d'exécution de Windows) :
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\uninstall-notifier.ps1
. "$PSScriptRoot\Common.ps1"
$NotifierPkg = 'io.github.erwsim.vigie.notifier'
$Component = "$NotifierPkg/io.github.erwsim.vigie.notifier.NotifierListenerService"

Assert-Adb
if (@(Invoke-AdbShell pm path $NotifierPkg | Where-Object { $_ -like 'package:*' }).Count -eq 0) {
    Ok 'Vigie Notifications n''est pas installé : rien à faire.'
    exit 0
}
Info 'Retrait de l''accès aux notifications'
$null = Invoke-AdbShell cmd notification disallow_listener $Component
if ($LASTEXITCODE -ne 0) { Warn 'disallow_listener refusé (l''accès disparaît de toute façon avec l''app).' }
Info "Désinstallation de $NotifierPkg"
(Invoke-Adb uninstall $NotifierPkg) | ForEach-Object { Info $_ }
if (@(Invoke-AdbShell pm path $NotifierPkg | Where-Object { $_ -like 'package:*' }).Count -gt 0) {
    Fail 'Vigie Notifications est toujours installé. Désinstallez-le depuis Paramètres > Applications > Vigie Notifications > Désinstaller.'
}
Ok 'Vigie Notifications désinstallé.'
