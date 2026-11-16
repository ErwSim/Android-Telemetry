# ADB rescue without the interface: asks Watchpost, over ADB, to undo its whole Device Owner
# policy ("Restore everything" on the Policy screen). Watchpost stays Device Owner and its logs
# stay on.
#
# Mechanism: explicit broadcast to io.github.erwsim.watchpost/.policy.rescue.RescueReceiver (see
# Common.ps1); only the ADB shell or the system can send it, and it can only undo.
#
# Usage: .\rescue-revert.ps1                "Restore everything"
#        .\rescue-revert.ps1 -Sweep         also restores everything the catalogue may have changed
#                                           (hidden or suspended packages, restrictions, denied
#                                           permissions, Private DNS), even with no trace in
#                                           Watchpost's state
#        .\rescue-revert.ps1 -RemoveOwner   same as .\remove-device-owner.ps1 (full removal)
# Only works after the first unlock following a reboot.
# Exit codes: 0 everything restored, 2 partial, 3 Watchpost is no longer Device Owner, 4 timed out,
# 5 no usable answer from Watchpost, 1 other error.
#
# Launching (the scripts are not signed; this leaves the Windows execution policy unchanged):
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\rescue-revert.ps1 [options]
param([switch]$RemoveOwner, [switch]$Sweep)
. "$PSScriptRoot\Common.ps1"

if ($RemoveOwner) {
    & "$PSScriptRoot\remove-device-owner.ps1"
    exit $LASTEXITCODE
}

Assert-Adb
Assert-Installed

Info 'Sending the ''Restore everything'' order to Watchpost (up to one minute)...'
$r = Invoke-Rescue -Sweep:$Sweep
switch ($r.Code) {
    1 { Ok "Everything is restored ($($r.Data))." }
    2 {
        Warn "Partial restore: $($r.Data)"
        Warn "Try again; if an item resists, see the log on the Policy screen or the README (Device Owner policy section). '.\rescue-revert.ps1 -Sweep' also restores what Watchpost may have lost track of."
        exit 2
    }
    3 {
        Warn "Watchpost is no longer Device Owner: it can no longer undo anything itself ($($r.Data))."
        Restore-Leftovers $r.Data
        exit 3
    }
    4 {
        Warn 'Watchpost did not finish in time: the operation continues on the phone. Run this script again in a minute to see the result.'
        exit 4
    }
    default {
        $r.Out | ForEach-Object { Write-Host "    $_" }
        Warn 'No usable answer from Watchpost. Check that the phone has been unlocked since its last boot, that the installed APK includes the rescue and that it starts. Last resort if the app no longer starts: .\remove-device-owner.ps1 (testOnly APK).'
        exit 5
    }
}
