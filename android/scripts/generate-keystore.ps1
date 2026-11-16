# Creates the release signing key (once!) and android\keystore.properties (never versioned).
# The SAME key must sign every future update: a Device Owner app cannot be updated with another
# key, and the only way back would be removing the Device Owner (or a factory reset).
# Back up android\keystore\ and android\keystore.properties offline (encrypted).
# Usage: .\generate-keystore.ps1        (password from $env:WATCHPOST_KEYSTORE_PASSWORD, else random)
#
# Launching (the scripts are not signed; this leaves the Windows execution policy unchanged):
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\generate-keystore.ps1
$ErrorActionPreference = 'Stop'
$root = Resolve-Path (Join-Path $PSScriptRoot '..')
$store = Join-Path $root 'keystore\watchpost-release.jks'
$props = Join-Path $root 'keystore.properties'
$alias = 'watchpost'

if (Test-Path $store) {
    Write-Host "ERROR: $store already exists. Never regenerate it: updates would become impossible." -ForegroundColor Red
    exit 1
}
if (-not (Get-Command keytool -ErrorAction SilentlyContinue)) {
    Write-Host 'ERROR: keytool not found (install a JDK 17+ and add its bin folder to your PATH).' -ForegroundColor Red
    exit 1
}

$pass = $env:WATCHPOST_KEYSTORE_PASSWORD
if (-not $pass) {
    $alphabet = [char[]]'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
    $bytes = New-Object byte[] 32
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    $pass = -join ($bytes | ForEach-Object { $alphabet[$_ % $alphabet.Length] })
}
if ($pass.Length -lt 12) {
    Write-Host 'ERROR: password too short (12 characters minimum).' -ForegroundColor Red
    exit 1
}

New-Item -ItemType Directory -Force -Path (Split-Path $store) | Out-Null
# PKCS12: the key password is the store password.
& keytool -genkeypair -v -storetype PKCS12 -keystore $store -storepass $pass `
    -alias $alias -keyalg RSA -keysize 4096 -sigalg SHA256withRSA -validity 18250 `
    -dname 'CN=Watchpost Agent, O=Watchpost'
if ($LASTEXITCODE -ne 0) {
    Write-Host 'ERROR: keytool failed.' -ForegroundColor Red
    exit 1
}

# UTF-8 without BOM: read by Gradle as a Java properties file.
$content = @"
# Release signing of Watchpost. NEVER commit this file. Back it up with keystore/watchpost-release.jks.
storeFile=keystore/watchpost-release.jks
storePassword=$pass
keyAlias=$alias
keyPassword=$pass
"@
[System.IO.File]::WriteAllText($props, $content, (New-Object System.Text.UTF8Encoding($false)))

Write-Host "[OK] Signing key created: $store" -ForegroundColor Green
Write-Host "[OK] Settings written to: $props" -ForegroundColor Green
Write-Host 'Back up these two files off this computer (encrypted): without them, Watchpost can no longer be updated.'
