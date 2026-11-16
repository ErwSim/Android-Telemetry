# Full removal of the Device Owner over ADB (equivalent to "Remove the Device Owner" on the
# Policy screen, which stays the recommended path when the app is usable).
#
# 1. Normal path: Watchpost's rescue (see Common.ps1) undoes the whole policy, turns off the network
#    and security logs, removes force-stop protection, emits security.policy "device_owner_cleared"
#    and then calls clearDeviceOwnerApp. As the removal is announced, it is not reported as
#    agent.tamper. Works with any APK (testOnly or not).
#    If an item cannot be undone, Watchpost KEEPS the role (only it can retry) and this script
#    offers to force the removal.
# 2. Fallback, only if Watchpost does not answer (app that no longer starts): "dpm remove-active-admin",
#    possible only with a testOnly APK. Watchpost then undoes nothing itself (hidden packages to
#    unhide, offered afterwards) and the removal is seen as a deactivation (agent.tamper
#    admin_disabled / device_owner_lost at the next start): this is expected.
#
# Usage: .\remove-device-owner.ps1 [-Uninstall]
#
# Launching (the scripts are not signed; this leaves the Windows execution policy unchanged):
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\remove-device-owner.ps1 [options]
param([switch]$Uninstall)
. "$PSScriptRoot\Common.ps1"

Assert-Adb
Assert-Installed

if (-not (Test-IsOwner)) {
    Info 'Watchpost is not Device Owner.'
} else {
    Write-Host @'
Watchpost will restore everything, turn off its network and security logs, then give up the
Device Owner role. To get it back, you will have to go through enable-device-owner again (with no
accounts on the phone).
'@
    $answer = Read-Host 'Continue? (yes/no)'
    if ($answer -ne 'yes') { Fail 'Aborted.' }

    Info 'Sending the removal order to Watchpost (up to one minute)...'
    $r = Invoke-Rescue -RemoveOwner
    switch ($r.Code) {
        1 { Ok "Policy restored ($($r.Data))." }
        2 {
            Warn "Partial restore: $($r.Data)"
            if (Test-IsOwner) {
                Write-Host @'
Watchpost could not undo everything and therefore kept the Device Owner role: only it can retry
(.\rescue-revert.ps1, then .\rescue-revert.ps1 -Sweep). Forcing the removal leaves these items as
they are; depending on the Android version, a package left hidden or suspended can then only be
restored by a Device Owner.
'@
                $answer = Read-Host 'Force the removal anyway? (yes/no)'
                if ($answer -ne 'yes') { Fail 'Aborted: Watchpost remains Device Owner.' }
                $r = Invoke-Rescue -RemoveOwner -Force
                if ($null -eq $r.Code) {
                    $r.Out | ForEach-Object { Write-Host "    $_" }
                    Fail 'No answer from Watchpost to the forced removal.'
                }
            }
        }
        3 { Info "Watchpost was already no longer Device Owner ($($r.Data))." }
        4 {
            Warn 'Watchpost did not finish in time; checking the role in 30 s...'
            Start-Sleep -Seconds 30
        }
        default {
            $r.Out | ForEach-Object { Write-Host "    $_" }
            Warn 'No usable answer from Watchpost (app that no longer starts, or a version without rescue).'
            if (-not (Test-IsTestOnly)) {
                Fail 'APK is not testOnly: Android refuses ''dpm remove-active-admin''. Repair/update the app (same signing key) then run this script again, or factory-reset the phone.'
            }
            Write-Host @'
Fallback: 'dpm remove-active-admin' (testOnly APK). Watchpost will not undo its policy itself:
the state of the packages it had hidden or suspended is checked afterwards.
The removal will be reported by agent.tamper (admin_disabled, device_owner_lost): this is expected.
'@
            $answer = Read-Host 'Use this fallback? (yes/no)'
            if ($answer -ne 'yes') { Fail 'Aborted.' }
            Invoke-AdbShell dpm remove-active-admin --user 0 $script:Admin | ForEach-Object { Write-Host "    $_" }
        }
    }
    if (Test-IsOwner) { Fail "Watchpost is still Device Owner ($($r.Data))." }
    Ok 'Watchpost is no longer Device Owner (Android backup, turned off by Device Owner mode, can be turned back on in Settings).'
    # What Watchpost could not undo itself (fallback, or items that stayed in failure).
    $after = Invoke-Rescue
    if ($after.Code -eq 3) { Restore-Leftovers $after.Data }
}

if ($Uninstall) {
    Invoke-Adb uninstall $script:Pkg | ForEach-Object { Write-Host "  $_" }
    if ($LASTEXITCODE -eq 0) { Ok 'Watchpost uninstalled.' } else { Fail 'Could not uninstall.' }
}
