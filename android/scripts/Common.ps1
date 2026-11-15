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
