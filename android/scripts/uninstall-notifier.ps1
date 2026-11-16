# Withdraws notification access and uninstalls the companion "Watchpost Notifications".
# Usage: .\uninstall-notifier.ps1
# The Watchpost agent keeps running; its "Notifications" collector becomes "unavailable". The package
# lists remain stored in the agent (they are used again if the companion is reinstalled).
#
# Launching (the scripts are not signed; this leaves the Windows execution policy unchanged):
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\uninstall-notifier.ps1
. "$PSScriptRoot\Common.ps1"
$NotifierPkg = 'io.github.erwsim.watchpost.notifier'
$Component = "$NotifierPkg/io.github.erwsim.watchpost.notifier.NotifierListenerService"

Assert-Adb
if (@(Invoke-AdbShell pm path $NotifierPkg | Where-Object { $_ -like 'package:*' }).Count -eq 0) {
    Ok 'Watchpost Notifications is not installed: nothing to do.'
    exit 0
}
Info 'Withdrawing notification access'
$null = Invoke-AdbShell cmd notification disallow_listener $Component
if ($LASTEXITCODE -ne 0) { Warn 'disallow_listener refused (the access goes away with the app anyway).' }
Info "Uninstalling $NotifierPkg"
(Invoke-Adb uninstall $NotifierPkg) | ForEach-Object { Info $_ }
if (@(Invoke-AdbShell pm path $NotifierPkg | Where-Object { $_ -like 'package:*' }).Count -gt 0) {
    Fail 'Watchpost Notifications is still installed. Uninstall it from Settings > Apps > Watchpost Notifications > Uninstall.'
}
Ok 'Watchpost Notifications uninstalled.'
