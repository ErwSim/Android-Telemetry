# Rescue without the app's interface: asks Vigie, over ADB, to undo its whole Device Owner policy
# ("Tout rétablir"), and optionally to give up the Device Owner role (-RemoveOwner).
#
# Mechanism: an explicit broadcast to io.github.erwsim.vigie/.policy.rescue.RescueReceiver. That
# receiver requires the sender to hold android.permission.FORCE_STOP_PACKAGES (signature|privileged,
# never grantable to a third-party app): only the ADB shell and the system can trigger it. It can
# only UNDO what Vigie applied, never apply anything.
#
# Usage: .\rescue-revert.ps1 [-RemoveOwner]
param([switch]$RemoveOwner)
. "$PSScriptRoot\Common.ps1"

$receiver = "$($script:Pkg)/io.github.erwsim.vigie.policy.rescue.RescueReceiver"
$action = 'io.github.erwsim.vigie.action.RESCUE_REVERT_ALL'

Assert-Adb
Assert-Installed

$extra = @()
if ($RemoveOwner) {
    Write-Host @'
Vigie va tout rétablir, couper ses journaux réseau et de sécurité, puis abandonner le rôle de
Device Owner. Pour le retrouver, il faudra repasser par enable-device-owner (sans comptes sur le
téléphone).
'@
    $answer = Read-Host 'Continuer ? (oui/non)'
    if ($answer -ne 'oui') { Fail 'Abandon.' }
    $extra = @('--ez', 'remove_owner', 'true')
}

Info "Envoi de l'ordre « Tout rétablir » à Vigie (jusqu'à une minute)..."
# Native call (not Invoke-AdbShell): "-a"/"-n" must reach adb verbatim, not be parsed as PowerShell parameters.
$previous = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
try {
    $out = @(& adb shell am broadcast --include-stopped-packages -a $action -n $receiver @extra 2>&1 | ForEach-Object { "$_".TrimEnd("`r") })
} finally {
    $ErrorActionPreference = $previous
}
$line = @($out | Where-Object { $_ -match 'Broadcast completed: result=' }) | Select-Object -Last 1
$code = $null
$data = ''
if ($line -match 'result=(-?\d+)') { $code = [int]$Matches[1] }
if ($line -match 'data="(.*)"$') { $data = $Matches[1] }

# Extracts "key=a,b,c" from the summary as an array.
function Get-Field([string]$Key) {
    foreach ($token in $data -split ' ') {
        if ($token.StartsWith("$Key=")) { return @($token.Substring($Key.Length + 1) -split ',' | Where-Object { $_ }) }
    }
    return @()
}

switch ($code) {
    1 { Ok "Tout est rétabli ($data)." }
    2 {
        Warn "Rétablissement partiel : $data"
        Warn "Réessayez ; si un élément résiste, consultez le journal de l'écran Politique ou le README (section Politique Device Owner)."
        exit 2
    }
    3 {
        Warn "Vigie n'est plus Device Owner : elle ne peut plus rien défaire elle-même ($data)."
        $hidden = Get-Field 'hidden'
        $suspended = Get-Field 'suspended'
        if ($hidden.Count + $suspended.Count -eq 0) {
            Info 'Aucun paquet masqué ou suspendu à rétablir.'
        } else {
            $answer = Read-Host 'Réafficher/réactiver ces paquets par ADB (pm unhide / pm unsuspend) ? (oui/non)'
            if ($answer -eq 'oui') {
                foreach ($p in $hidden) { Info "pm unhide $p : $((Invoke-AdbShell pm unhide $p) -join ' ')" }
                foreach ($p in $suspended) { Info "pm unsuspend $p : $((Invoke-AdbShell pm unsuspend $p) -join ' ')" }
                Warn 'Vérifiez dans Paramètres > Applications que ces apps sont de nouveau utilisables.'
            }
        }
        if ((Get-Field 'other_items').Count -gt 0) {
            Warn "Restrictions, permissions ou DNS privé posés par Vigie ont normalement été levés par Android au retrait du Device Owner ; vérifiez le DNS privé dans Paramètres > Connexions."
        }
        exit 3
    }
    4 {
        Warn "Vigie n'a pas fini dans le délai : l'opération continue sur le téléphone. Relancez ce script dans une minute pour voir le résultat."
        exit 4
    }
    default {
        $out | ForEach-Object { Write-Host "    $_" }
        Fail "Pas de réponse exploitable de Vigie. Vérifiez que l'APK installé contient l'issue de secours (version avec l'écran Politique)."
    }
}

if ($RemoveOwner) {
    if (Test-IsOwner) { Fail "Vigie est toujours Device Owner ($data)." }
    Ok "Vigie n'est plus Device Owner."
}
