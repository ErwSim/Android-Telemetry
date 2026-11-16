# Exempts Vigie from battery restrictions that could stop the collection.
# Usage: .\battery-exemptions.ps1
#
# Lancement (scripts non signés, sans modifier la politique d'exécution de Windows) :
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\battery-exemptions.ps1
. "$PSScriptRoot\Common.ps1"

Assert-Adb
Assert-Installed

function Invoke-Step([string]$Label, [string[]]$Command) {
    $out = Invoke-AdbShell @Command
    if ($LASTEXITCODE -eq 0) { Ok $Label } else { Warn "$Label : échec ($($Command -join ' ')) $($out -join ' ')" }
}

Invoke-Step 'Exemption Doze (liste blanche deviceidle)' @('dumpsys', 'deviceidle', 'whitelist', "+$($script:Pkg)")
Invoke-Step 'Exécution en arrière-plan autorisée (appops RUN_ANY_IN_BACKGROUND)' @('cmd', 'appops', 'set', $script:Pkg, 'RUN_ANY_IN_BACKGROUND', 'allow')
Invoke-Step 'Exécution en arrière-plan autorisée (appops RUN_IN_BACKGROUND)' @('cmd', 'appops', 'set', $script:Pkg, 'RUN_IN_BACKGROUND', 'allow')
Invoke-Step 'Seau de veille « active »' @('am', 'set-standby-bucket', $script:Pkg, 'active')

Write-Host @'

À faire à la main sur Samsung (aucune commande connue) :
  Paramètres > Batterie > Limites d'utilisation en arrière-plan > Applications jamais en veille > ajouter Vigie.
En mode Device Owner, Vigie active aussi « Protection contre l'arrêt forcé », qui l'exempte des seaux de veille.
'@
