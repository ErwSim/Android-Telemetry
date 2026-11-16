# Installs (or updates) the optional notification companion "Vigie Notifications" over ADB.
# Usage: .\install-notifier.ps1 [-Apk chemin\vers\notifier.apk]
# Default: the release APK, else the debug APK, from android\notifier\build\outputs\apk\.
# The companion must be signed with the SAME key as the Vigie agent (same build, same keystore):
# otherwise Android refuses to install it (INSTALL_FAILED_DUPLICATE_PERMISSION, both APKs declare the
# channel's permission) or, if the agent is absent, it will never be able to talk to it.
# Then: .\notifier-access.ps1 (grants notification access).
#
# Lancement (scripts non signés, sans modifier la politique d'exécution de Windows) :
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\install-notifier.ps1 [options]
param([string]$Apk)
. "$PSScriptRoot\Common.ps1"
$NotifierPkg = 'io.github.erwsim.vigie.notifier'

if (-not $Apk) {
    $releaseDir = Join-Path $PSScriptRoot '..\notifier\build\outputs\apk\release'
    if (-not (Test-Path (Join-Path $releaseDir 'notifier-release.apk')) -and (Test-Path (Join-Path $releaseDir 'notifier-release-unsigned.apk'))) {
        Fail 'L''APK release du compagnon n''est pas signé (notifier-release-unsigned.apk). Générez le keystore (generate-keystore.ps1), renseignez keystore.properties, puis relancez .\gradlew.bat :notifier:assembleRelease.'
    }
    foreach ($candidate in @(
            (Join-Path $PSScriptRoot '..\notifier\build\outputs\apk\release\notifier-release.apk'),
            (Join-Path $PSScriptRoot '..\notifier\build\outputs\apk\debug\notifier-debug.apk'))) {
        if (Test-Path $candidate) { $Apk = $candidate; break }
    }
}
if (-not $Apk -or -not (Test-Path -LiteralPath $Apk)) {
    Fail 'APK du compagnon introuvable. Construisez-le (.\gradlew.bat :notifier:assembleRelease) ou passez son chemin avec -Apk.'
}
# Absolute path (relative paths are the caller's): adb must not depend on the directory it is started from.
$Apk = (Resolve-Path -LiteralPath $Apk).Path

if ((Split-Path -Leaf $Apk) -like '*debug*.apk') {
    Warn "APK de débogage : signé avec la clé de débogage de cet ordinateur. Il ne fonctionne qu'avec un agent Vigie de débogage construit sur le même ordinateur ; avec l'agent release, Android refusera l'installation."
    $answer = Read-Host 'Installer quand même l''APK de débogage ? (oui/non)'
    if ($answer -ne 'oui') { Fail 'Abandon.' }
}

Assert-Adb
if (@(Invoke-AdbShell pm path $script:Pkg | Where-Object { $_ -like 'package:*' }).Count -eq 0) {
    Warn "L'agent Vigie ($($script:Pkg)) n'est pas installé : le compagnon s'installe, mais ne transmettra rien tant que l'agent (signé par la même clé) ne sera pas là."
}

Info "Installation de $Apk"
# Quoted: an unquoted -r/-t would be parsed as a PowerShell parameter of Invoke-Adb, not passed to adb.
$out = Invoke-Adb 'install' '-r' '-t' $Apk
$code = $LASTEXITCODE
$out | ForEach-Object { Write-Host "  $_" }
if ($code -ne 0 -or @($out | Where-Object { $_ -match 'Failure' }).Count -gt 0) {
    Write-Host @'
L'installation a échoué. Causes fréquentes :
  - INSTALL_FAILED_DUPLICATE_PERMISSION : le compagnon n'est pas signé par la même clé que l'agent Vigie
    installé. Installez les deux APK issus de la même construction (même keystore ; release avec release,
    débogage avec débogage).
  - INSTALL_FAILED_UPDATE_INCOMPATIBLE : un compagnon signé par une autre clé est déjà installé :
    .\uninstall-notifier.ps1, puis réessayez.
  - INSTALL_FAILED_VERSION_DOWNGRADE : versionCode inférieur à celui installé (-Pvigie.versionCode=...).
  - Play Protect bloque l'installation (« appli nuisible bloquée ») : voir le README (section
    Notifications) ; l'agent n'est pas concerné, il continue sans le compagnon.
  - Blocage automatique (Auto Blocker) Samsung actif : désactivez-le le temps de l'installation.
'@ -ForegroundColor Red
    exit 1
}
Ok 'Vigie Notifications installé.'

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
        Ok 'Même clé de signature que l''agent Vigie.'
    } else {
        Warn "Clés de signature différentes de l'agent ($agentSig / $notifierSig) : le compagnon ne pourra rien transmettre."
    }
}
Info 'Étape suivante : .\notifier-access.ps1 (accès aux notifications), puis ouvrez « Vigie Notifications » pour vérifier l''état.'
