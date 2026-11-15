# Removes Vigie's Device Owner role (only possible over ADB with a testOnly APK).
# Usage: .\remove-device-owner.ps1 [-Uninstall]
param([switch]$Uninstall)
. "$PSScriptRoot\Common.ps1"

Assert-Adb
Assert-Installed

if (-not (Test-IsOwner)) {
    Info "Vigie n'est pas Device Owner."
} else {
    if (-not (Test-IsTestOnly)) {
        Fail "APK non testOnly : Android refuse « remove-active-admin » (Attempt to remove non-test admin). Retirez le rôle depuis l'app, ou réinstallez une version testOnly signée par la même clé."
    }
    Write-Host @'
Avant le retrait : les réglages appliqués par la politique de Vigie (paquets désactivés, restrictions,
DNS privé) doivent être défaits depuis l'app (écran Politique), sinon certains restent en place.
'@
    $answer = Read-Host 'Retirer le Device Owner maintenant ? (oui/non)'
    if ($answer -ne 'oui') { Fail 'Abandon.' }
    Invoke-AdbShell dpm remove-active-admin --user 0 $script:Admin | ForEach-Object { Write-Host "    $_" }
    if (Test-IsOwner) { Fail 'Le retrait a échoué.' }
    Ok "Vigie n'est plus Device Owner (la sauvegarde Android, coupée par le mode Device Owner, peut être réactivée dans les Paramètres)."
}

if ($Uninstall) {
    Invoke-Adb uninstall $script:Pkg | ForEach-Object { Write-Host "  $_" }
    if ($LASTEXITCODE -eq 0) { Ok 'Vigie désinstallée.' } else { Fail 'Désinstallation impossible.' }
}
