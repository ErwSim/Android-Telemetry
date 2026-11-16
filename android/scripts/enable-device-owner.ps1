# Makes Watchpost the Device Owner of the phone (ADB provisioning, no factory reset).
# Preconditions checked here: no other user/profile, no account, no existing owner.
# Usage: .\enable-device-owner.ps1
#
# Launching (the scripts are not signed; this leaves the Windows execution policy unchanged):
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\enable-device-owner.ps1
. "$PSScriptRoot\Common.ps1"

Assert-Adb
Assert-Installed

Info 'Checking existing owners...'
if (Test-IsOwner) {
    Ok 'Watchpost is already Device Owner.'
    exit 0
}
$owners = Invoke-AdbShell dpm list-owners
if (@($owners | Where-Object { $_ -match 'DeviceOwner|ProfileOwner' }).Count -gt 0) {
    $owners | ForEach-Object { Write-Host "    $_" }
    Fail 'Another Device Owner or Profile Owner is already set. Remove it first.'
}

Info 'Checking users and profiles...'
$users = @(Invoke-AdbShell pm list users | Where-Object { $_ -match 'UserInfo\{' })
if ($users.Count -gt 1) {
    $users | ForEach-Object { Write-Host "    $($_.Trim())" }
    Fail "Several users or profiles exist ($($users.Count)). Delete Secure Folder, Dual Messenger, Private Space, the work profile and guest users, then run again."
}

Info 'Checking accounts...'
$accounts = @(Invoke-AdbShell dumpsys account | Where-Object { $_ -match '^\s*Account \{' })
if ($accounts.Count -gt 0) {
    Write-Host 'Accounts present on the phone:'
    $accounts | ForEach-Object { Write-Host "    $($_.Trim())" }
    Write-Host @'
ERROR: Android refuses to set a Device Owner while an account exists.
TEMPORARILY remove every account listed (Settings > Accounts and backup > Manage accounts:
Google, Samsung account, WhatsApp, Signal, Microsoft...), run this script again, then add your accounts
back: Device Owner mode does not forbid them. Check your backups and two-factor authentication
before removing a Google or Samsung account.
'@ -ForegroundColor Red
    exit 1
}

if (Test-IsTestOnly) {
    Info "testOnly APK: besides removal by the app or by remove-device-owner.ps1, 'dpm remove-active-admin' stays available as a last resort."
} else {
    Warn "APK is NOT testOnly: removal has to go through Watchpost (Policy screen or remove-device-owner.ps1); if the app no longer starts, only a factory reset will remove it."
    $answer = Read-Host 'Continue anyway? (yes/no)'
    if ($answer -ne 'yes') { Fail 'Aborted.' }
}

Info "Enabling: dpm set-device-owner $($script:Admin)"
Invoke-AdbShell dpm set-device-owner --user 0 $script:Admin | ForEach-Object { Write-Host "    $_" }
if (Test-IsOwner) {
    Ok 'Watchpost is Device Owner. Open the app: it grants itself its permissions and turns on its protection.'
    Info 'You can add your Google/Samsung accounts back. Turn Auto Blocker back on if you had turned it off.'
} else {
    Fail 'Activation failed (see the message above).'
}
