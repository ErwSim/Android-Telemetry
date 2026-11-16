# Exempts Watchpost from battery restrictions that could stop the collection.
# Usage: .\battery-exemptions.ps1
#
# Launching (the scripts are not signed; this leaves the Windows execution policy unchanged):
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\battery-exemptions.ps1
. "$PSScriptRoot\Common.ps1"

Assert-Adb
Assert-Installed

function Invoke-Step([string]$Label, [string[]]$Command) {
    $out = Invoke-AdbShell @Command
    if ($LASTEXITCODE -eq 0) { Ok $Label } else { Warn "${Label}: failed ($($Command -join ' ')) $($out -join ' ')" }
}

Invoke-Step 'Doze exemption (deviceidle allowlist)' @('dumpsys', 'deviceidle', 'whitelist', "+$($script:Pkg)")
Invoke-Step 'Background execution allowed (appops RUN_ANY_IN_BACKGROUND)' @('cmd', 'appops', 'set', $script:Pkg, 'RUN_ANY_IN_BACKGROUND', 'allow')
Invoke-Step 'Background execution allowed (appops RUN_IN_BACKGROUND)' @('cmd', 'appops', 'set', $script:Pkg, 'RUN_IN_BACKGROUND', 'allow')
Invoke-Step 'Standby bucket ''active''' @('am', 'set-standby-bucket', $script:Pkg, 'active')

Write-Host @'

To do by hand on Samsung (no known command):
  Settings > Battery > Background usage limits > Never sleeping apps > add Watchpost.
In Device Owner mode, Watchpost also turns on 'Force-stop protection', which exempts it from standby buckets.
'@
