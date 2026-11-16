# Installs (or updates) the optional notification companion "Watchpost Notifications" over ADB.
# Usage: .\install-notifier.ps1 [-Apk path\to\notifier.apk]
# Default: the release APK, else the debug APK, from android\notifier\build\outputs\apk\.
# The companion must be signed with the SAME key as the Watchpost agent (same build, same keystore):
# otherwise Android refuses to install it (INSTALL_FAILED_DUPLICATE_PERMISSION, both APKs declare the
# channel's permission) or, if the agent is absent, it will never be able to talk to it.
# Then: .\notifier-access.ps1 (grants notification access).
#
# Launching (the scripts are not signed; this leaves the Windows execution policy unchanged):
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\install-notifier.ps1 [options]
param([string]$Apk)
. "$PSScriptRoot\Common.ps1"
$NotifierPkg = 'io.github.erwsim.watchpost.notifier'

if (-not $Apk) {
    $releaseDir = Join-Path $PSScriptRoot '..\notifier\build\outputs\apk\release'
    if (-not (Test-Path (Join-Path $releaseDir 'notifier-release.apk')) -and (Test-Path (Join-Path $releaseDir 'notifier-release-unsigned.apk'))) {
        Fail 'The companion''s release APK is not signed (notifier-release-unsigned.apk). Generate the keystore (generate-keystore.ps1), fill in keystore.properties, then run .\gradlew.bat :notifier:assembleRelease again.'
    }
    foreach ($candidate in @(
            (Join-Path $PSScriptRoot '..\notifier\build\outputs\apk\release\notifier-release.apk'),
            (Join-Path $PSScriptRoot '..\notifier\build\outputs\apk\debug\notifier-debug.apk'))) {
        if (Test-Path $candidate) { $Apk = $candidate; break }
    }
}
if (-not $Apk -or -not (Test-Path -LiteralPath $Apk)) {
    Fail 'Companion APK not found. Build it (.\gradlew.bat :notifier:assembleRelease) or pass its path with -Apk.'
}
# Absolute path (relative paths are the caller's): adb must not depend on the directory it is started from.
$Apk = (Resolve-Path -LiteralPath $Apk).Path

if ((Split-Path -Leaf $Apk) -like '*debug*.apk') {
    Warn "Debug APK: signed with this computer's debug key. It only works with a debug Watchpost agent built on the same computer; with the release agent, Android will refuse the installation."
    $answer = Read-Host 'Install the debug APK anyway? (yes/no)'
    if ($answer -ne 'yes') { Fail 'Aborted.' }
}

Assert-Adb
if (@(Invoke-AdbShell pm path $script:Pkg | Where-Object { $_ -like 'package:*' }).Count -eq 0) {
    Warn "The Watchpost agent ($($script:Pkg)) is not installed: the companion will install, but will relay nothing until the agent (signed with the same key) is there."
}

Info "Installing $Apk"
# Quoted: an unquoted -r/-t would be parsed as a PowerShell parameter of Invoke-Adb, not passed to adb.
$out = Invoke-Adb 'install' '-r' '-t' $Apk
$code = $LASTEXITCODE
$out | ForEach-Object { Write-Host "  $_" }
if ($code -ne 0 -or @($out | Where-Object { $_ -match 'Failure' }).Count -gt 0) {
    Write-Host @'
Installation failed. Frequent causes:
  - INSTALL_FAILED_DUPLICATE_PERMISSION: the companion is not signed with the same key as the installed
    Watchpost agent. Install both APKs from the same build (same keystore; release with release,
    debug with debug).
  - INSTALL_FAILED_UPDATE_INCOMPATIBLE: a companion signed with another key is already installed:
    .\uninstall-notifier.ps1, then try again.
  - INSTALL_FAILED_VERSION_DOWNGRADE: versionCode lower than the installed one (-Pwatchpost.versionCode=...).
  - Play Protect blocks the installation ('harmful app blocked'): see the README (Notifications
    section); the agent is not affected, it keeps running without the companion.
  - Samsung Auto Blocker is on: turn it off for the duration of the installation.
'@ -ForegroundColor Red
    exit 1
}
Ok 'Watchpost Notifications installed.'

# Same signing key as the agent? (short digest of the signing certificate shown by dumpsys)
function Get-Sig([string]$Package) {
    $line = @(Invoke-AdbShell dumpsys package $Package | Where-Object { $_ -match 'signatures:\[[^\]]*\]' }) | Select-Object -First 1
    if ($line -match '(signatures:\[[^\]]*\])') { return $Matches[1] }
    return ''
}
$agentSig = Get-Sig $script:Pkg
$notifierSig = Get-Sig $NotifierPkg
if ($agentSig -and $notifierSig) {
    if ($agentSig -eq $notifierSig) {
        Ok 'Same signing key as the Watchpost agent.'
    } else {
        Warn "Signing keys differ from the agent's ($agentSig / $notifierSig): the companion will not be able to relay anything."
    }
}
Info 'Next step: .\notifier-access.ps1 (notification access), then open ''Watchpost Notifications'' to check its state.'
