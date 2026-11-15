# Installs (or updates) the Vigie APK over ADB.
# Usage: .\install-apk.ps1 [-Apk chemin\vers\app.apk]
# Default: the release APK, else the debug APK, from android\app\build\outputs\apk\.
# "-t" is required for a testOnly APK (default build); "-r" keeps the data on update.
# An update must be signed with the SAME key as the installed app (mandatory for a Device Owner).
param([string]$Apk)
. "$PSScriptRoot\Common.ps1"

if (-not $Apk) {
    foreach ($candidate in @(
            (Join-Path $PSScriptRoot '..\app\build\outputs\apk\release\app-release.apk'),
            (Join-Path $PSScriptRoot '..\app\build\outputs\apk\debug\app-debug.apk'))) {
        if (Test-Path $candidate) { $Apk = $candidate; break }
    }
}
if (-not $Apk -or -not (Test-Path $Apk)) {
    Fail 'APK introuvable. Construisez-le (.\gradlew.bat assembleRelease) ou passez son chemin avec -Apk.'
}

Assert-Adb
Info "Installation de $Apk"
$out = Invoke-Adb install -r -t $Apk
$code = $LASTEXITCODE
$out | ForEach-Object { Write-Host "  $_" }
if ($code -ne 0 -or @($out | Where-Object { $_ -match 'Failure' }).Count -gt 0) {
    Write-Host @'
L'installation a échoué. Causes fréquentes :
  - INSTALL_FAILED_UPDATE_INCOMPATIBLE : l'APK n'est pas signé avec la même clé que l'app installée.
    Un Device Owner ne peut pas être mis à jour avec une autre clé : utilisez le keystore d'origine.
  - INSTALL_FAILED_VERSION_DOWNGRADE : versionCode inférieur à celui installé (-Pvigie.versionCode=...).
  - Blocage automatique (Auto Blocker) Samsung actif : désactivez-le le temps de l'installation.
'@ -ForegroundColor Red
    exit 1
}
Ok 'Vigie installée.'
