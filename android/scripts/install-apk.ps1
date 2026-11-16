# Installs (or updates) the Watchpost APK over ADB.
# Usage: .\install-apk.ps1 [-Apk path\to\app.apk]
# Default: the release APK, else the debug APK, from android\app\build\outputs\apk\.
# "-t" is required for a testOnly APK (default build); "-r" keeps the data on update.
# An update must be signed with the SAME key as the installed app (mandatory for a Device Owner).
#
# Launching (the scripts are not signed; this leaves the Windows execution policy unchanged):
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\install-apk.ps1 [options]
param([string]$Apk)
. "$PSScriptRoot\Common.ps1"

if (-not $Apk) {
    # An unsigned release APK cannot be installed: say so instead of silently falling back to debug.
    $releaseDir = Join-Path $PSScriptRoot '..\app\build\outputs\apk\release'
    if (-not (Test-Path (Join-Path $releaseDir 'app-release.apk')) -and (Test-Path (Join-Path $releaseDir 'app-release-unsigned.apk'))) {
        Fail 'The release APK is not signed (app-release-unsigned.apk). Generate the keystore (generate-keystore.ps1), fill in keystore.properties, then run .\gradlew.bat assembleRelease again.'
    }
    foreach ($candidate in @(
            (Join-Path $PSScriptRoot '..\app\build\outputs\apk\release\app-release.apk'),
            (Join-Path $PSScriptRoot '..\app\build\outputs\apk\debug\app-debug.apk'))) {
        if (Test-Path $candidate) { $Apk = $candidate; break }
    }
}
if (-not $Apk -or -not (Test-Path -LiteralPath $Apk)) {
    Fail 'APK not found. Build it (.\gradlew.bat assembleRelease) or pass its path with -Apk.'
}
# Absolute path: adb must not depend on the directory it is started from.
$Apk = (Resolve-Path -LiteralPath $Apk).Path

if ((Split-Path -Leaf $Apk) -like '*debug*.apk') {
    Warn "Debug APK: signed with the debug key (an update to the release APK will be refused while Watchpost is Device Owner) and 'debuggable' (adb run-as can read the app's data)."
    Warn 'On a phone you use every day, install the release APK (.\gradlew.bat assembleRelease).'
    $answer = Read-Host 'Install the debug APK anyway? (yes/no)'
    if ($answer -ne 'yes') { Fail 'Aborted.' }
}

Assert-Adb
Info "Installing $Apk"
# Quoted: an unquoted -r/-t would be parsed as a PowerShell parameter of Invoke-Adb, not passed to adb.
$out = Invoke-Adb 'install' '-r' '-t' $Apk
$code = $LASTEXITCODE
$out | ForEach-Object { Write-Host "  $_" }
if ($code -ne 0 -or @($out | Where-Object { $_ -match 'Failure' }).Count -gt 0) {
    Write-Host @'
Installation failed. Frequent causes:
  - INSTALL_FAILED_UPDATE_INCOMPATIBLE: the APK is not signed with the same key as the installed app.
    A Device Owner cannot be updated with another key: use the original keystore.
  - INSTALL_FAILED_VERSION_DOWNGRADE: versionCode lower than the installed one (-Pwatchpost.versionCode=...).
  - Samsung Auto Blocker is on: turn it off for the duration of the installation.
'@ -ForegroundColor Red
    exit 1
}
Ok 'Watchpost installed.'
