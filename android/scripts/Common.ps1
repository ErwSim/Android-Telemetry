# Shared helpers for the Vigie ADB scripts (dot-sourced: . "$PSScriptRoot\Common.ps1").
# Device selection: if several devices are connected, set $env:ANDROID_SERIAL = '<serial>' (see "adb devices").
# Encoding: this file is UTF-8 with BOM so that Windows PowerShell 5.1 reads the French text correctly.

$ErrorActionPreference = 'Stop'
$script:Pkg = if ($env:VIGIE_PACKAGE) { $env:VIGIE_PACKAGE } else { 'io.github.erwsim.vigie' }
$script:Admin = "$($script:Pkg)/io.github.erwsim.vigie.policy.VigieAdminReceiver"

function Fail([string]$Message) {
    Write-Host "ERREUR : $Message" -ForegroundColor Red
    exit 1
}
function Info([string]$Message) { Write-Host "- $Message" }
function Ok([string]$Message) { Write-Host "[OK] $Message" -ForegroundColor Green }
function Warn([string]$Message) { Write-Host "[!] $Message" -ForegroundColor Yellow }

# Runs adb and returns its output lines (stdout and stderr) as strings; never throws.
# The exit code stays available in $LASTEXITCODE.
function Invoke-Adb {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$AdbArgs)
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $out = & adb @AdbArgs 2>&1 | ForEach-Object { "$_".TrimEnd("`r") }
    } finally {
        $ErrorActionPreference = $previous
    }
    return @($out)
}

function Invoke-AdbShell {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$ShellArgs)
    return Invoke-Adb shell @ShellArgs
}

function Assert-Adb {
    if (-not (Get-Command adb -ErrorAction SilentlyContinue)) {
        Fail 'adb introuvable. Installez « Android SDK Platform-Tools » et ajoutez son dossier au PATH.'
    }
    $lines = @(Invoke-Adb devices | Select-Object -Skip 1 | Where-Object { $_ -match '\S' })
    $ready = @($lines | Where-Object { $_ -match '\tdevice$' })
    if ($ready.Count -eq 0) {
        if (@($lines | Where-Object { $_ -match '\tunauthorized$' }).Count -gt 0) {
            Fail 'Téléphone non autorisé : déverrouillez-le et acceptez la clé de débogage USB.'
        }
        Fail 'Aucun téléphone connecté en débogage USB (adb devices). Sur Samsung, désactivez temporairement « Blocage automatique » (Auto Blocker).'
    }
    if ($ready.Count -gt 1 -and -not $env:ANDROID_SERIAL) {
        Fail "Plusieurs appareils connectés : `$env:ANDROID_SERIAL = '<numéro de série>' (voir adb devices)."
    }
}

function Assert-Installed {
    $out = Invoke-AdbShell pm path $script:Pkg
    if (@($out | Where-Object { $_ -like 'package:*' }).Count -eq 0) {
        Fail "Vigie ($($script:Pkg)) n'est pas installée. Lancez d'abord install-apk.ps1."
    }
}

function Test-IsOwner {
    $owners = Invoke-AdbShell dpm list-owners
    return (@($owners | Where-Object { $_ -like "*$($script:Pkg)*" }).Count -gt 0)
}

function Test-IsTestOnly {
    $dump = Invoke-AdbShell dumpsys package $script:Pkg
    return (@($dump | Where-Object { $_ -match 'TEST_ONLY' }).Count -gt 0)
}

# ---- Issue de secours : ordre envoyé à io.github.erwsim.vigie.policy.rescue.RescueReceiver ----
# Le récepteur exige que l'expéditeur détienne android.permission.FORCE_STOP_PACKAGES
# (signature|privileged, jamais accordable à une app tierce) : seuls le shell ADB et le système
# peuvent l'envoyer. Il ne fait que DÉFAIRE ce que Vigie a appliqué.
$script:RescueReceiver = "$($script:Pkg)/io.github.erwsim.vigie.policy.rescue.RescueReceiver"
$script:RescueAction = 'io.github.erwsim.vigie.action.RESCUE_REVERT_ALL'

# Envoie l'ordre (jusqu'à une minute) et renvoie Out (sortie brute), Code (1 tout rétabli,
# 2 partiel, 3 plus Device Owner, 4 délai dépassé, $null si aucune réponse exploitable) et Data (résumé).
#   -RemoveOwner : abandonne ensuite le rôle, seulement si tout a pu être défait ;
#   -Force       : avec -RemoveOwner, abandonne le rôle même si un élément n'a pas pu être défait ;
#   -Sweep       : rétablit en plus tout ce que le catalogue a pu modifier (état douteux ou perdu).
function Invoke-Rescue([switch]$RemoveOwner, [switch]$Force, [switch]$Sweep) {
    $extra = @()
    if ($RemoveOwner) { $extra += @('--ez', 'remove_owner', 'true') }
    if ($Force) { $extra += @('--ez', 'force', 'true') }
    if ($Sweep) { $extra += @('--ez', 'sweep', 'true') }
    # Appel natif (pas Invoke-AdbShell) : « -a »/« -n » doivent arriver tels quels à adb.
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $out = @(& adb shell am broadcast --include-stopped-packages -a $script:RescueAction -n $script:RescueReceiver @extra 2>&1 | ForEach-Object { "$_".TrimEnd("`r") })
    } finally {
        $ErrorActionPreference = $previous
    }
    $line = @($out | Where-Object { $_ -match 'Broadcast completed: result=' }) | Select-Object -Last 1
    $code = $null
    $data = ''
    if ($line -match 'result=(-?\d+)') { $code = [int]$Matches[1] }
    if ($line -match 'data="(.*)"$') { $data = $Matches[1] }
    if ($code -notin 1, 2, 3, 4) { $code = $null }
    return [pscustomobject]@{ Out = $out; Code = $code; Data = $data }
}

# Extrait « clé=a,b,c » du résumé, en tableau.
function Get-RescueField([string]$Data, [string]$Key) {
    foreach ($token in $Data -split ' ') {
        if ($token.StartsWith("$Key=")) { return @($token.Substring($Key.Length + 1) -split ',' | Where-Object { $_ }) }
    }
    return @()
}

# État d'un paquet pour l'utilisateur 0, lu dans « dumpsys package » (ligne « User 0: ... hidden=... suspended=... »).
function Test-PackageFlag([string]$Package, [string]$Flag) {
    $line = @(Invoke-AdbShell dumpsys package $Package | Where-Object { $_ -match '^\s*User 0:' }) | Select-Object -First 1
    return ($line -match "$Flag=true")
}

# Après la perte du rôle, Vigie ne peut plus rien défaire. Android lève en principe lui-même les
# politiques du Device Owner retiré (paquets masqués ou suspendus compris) : on vérifie l'état réel
# de chaque paquet que Vigie avait masqué ou suspendu, et on ne tente « pm unhide » / « pm unsuspend »
# que pour ceux qui le sont encore. Ces commandes peuvent être refusées au shell ADB (permission
# MANAGE_USERS, paquets suspendus par un administrateur) : le seul recours est alors de redonner le
# rôle à Vigie (enable-device-owner) puis de relancer rescue-revert, l'état appliqué étant conservé.
function Restore-Leftovers([string]$Data) {
    $hidden = @(Get-RescueField $Data 'hidden')
    $suspended = @(Get-RescueField $Data 'suspended')
    $stuck = @()
    if ($hidden.Count + $suspended.Count -eq 0) {
        Info 'Aucun paquet masqué ou suspendu à rétablir.'
    }
    foreach ($p in $hidden) {
        if (-not (Test-PackageFlag $p 'hidden')) { Ok "$p : visible."; continue }
        Info "pm unhide $p : $((Invoke-AdbShell pm unhide $p) -join ' ')"
        if (Test-PackageFlag $p 'hidden') { $stuck += $p } else { Ok "$p : réaffiché." }
    }
    foreach ($p in $suspended) {
        if (-not (Test-PackageFlag $p 'suspended')) { Ok "$p : actif."; continue }
        Info "pm unsuspend $p : $((Invoke-AdbShell pm unsuspend $p) -join ' ')"
        if (Test-PackageFlag $p 'suspended') { $stuck += $p } else { Ok "$p : réactivé." }
    }
    if ($stuck.Count -gt 0) {
        Warn "Toujours masqués ou suspendus : $($stuck -join ' ')"
        Warn "Android réserve leur rétablissement au Device Owner. Redonnez le rôle à Vigie (.\enable-device-owner.ps1, sans comptes sur le téléphone), puis lancez .\rescue-revert.ps1 : Vigie a gardé la liste de ce qu'elle avait appliqué."
    }
    if (@(Get-RescueField $Data 'other_items').Count -gt 0) {
        Warn "Restrictions, permissions ou DNS privé posés par Vigie ont normalement été levés par Android au retrait du Device Owner ; vérifiez le DNS privé dans Paramètres > Connexions > Plus de paramètres de connexion."
    }
}
