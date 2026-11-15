# Creates the release signing key (once!) and android\keystore.properties (never versioned).
# The SAME key must sign every future update: a Device Owner app cannot be updated with another
# key, and the only way back would be removing the Device Owner (or a factory reset).
# Back up android\keystore\ and android\keystore.properties offline (encrypted).
# Usage: .\generate-keystore.ps1        (password from $env:VIGIE_KEYSTORE_PASSWORD, else random)
$ErrorActionPreference = 'Stop'
$root = Resolve-Path (Join-Path $PSScriptRoot '..')
$store = Join-Path $root 'keystore\vigie-release.jks'
$props = Join-Path $root 'keystore.properties'
$alias = 'vigie'

if (Test-Path $store) {
    Write-Host "ERREUR : $store existe déjà. Ne le régénérez jamais : les mises à jour seraient impossibles." -ForegroundColor Red
    exit 1
}
if (-not (Get-Command keytool -ErrorAction SilentlyContinue)) {
    Write-Host 'ERREUR : keytool introuvable (installez un JDK 17+ et ajoutez son dossier bin au PATH).' -ForegroundColor Red
    exit 1
}

$pass = $env:VIGIE_KEYSTORE_PASSWORD
if (-not $pass) {
    $alphabet = [char[]]'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
    $bytes = New-Object byte[] 32
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    $pass = -join ($bytes | ForEach-Object { $alphabet[$_ % $alphabet.Length] })
}
if ($pass.Length -lt 12) {
    Write-Host 'ERREUR : mot de passe trop court (12 caractères minimum).' -ForegroundColor Red
    exit 1
}

New-Item -ItemType Directory -Force -Path (Split-Path $store) | Out-Null
# PKCS12: the key password is the store password.
& keytool -genkeypair -v -storetype PKCS12 -keystore $store -storepass $pass `
    -alias $alias -keyalg RSA -keysize 4096 -sigalg SHA256withRSA -validity 18250 `
    -dname 'CN=Vigie Agent, O=Vigie (personnel)'
if ($LASTEXITCODE -ne 0) {
    Write-Host 'ERREUR : keytool a échoué.' -ForegroundColor Red
    exit 1
}

# UTF-8 without BOM: read by Gradle as a Java properties file.
$content = @"
# Release signing of Vigie. NEVER commit this file. Back it up with keystore/vigie-release.jks.
storeFile=keystore/vigie-release.jks
storePassword=$pass
keyAlias=$alias
keyPassword=$pass
"@
[System.IO.File]::WriteAllText($props, $content, (New-Object System.Text.UTF8Encoding($false)))

Write-Host "[OK] Clé de signature créée : $store" -ForegroundColor Green
Write-Host "[OK] Paramètres écrits dans : $props" -ForegroundColor Green
Write-Host 'Sauvegardez ces deux fichiers hors de l''ordinateur (chiffrés) : sans eux, plus aucune mise à jour de Vigie.'
