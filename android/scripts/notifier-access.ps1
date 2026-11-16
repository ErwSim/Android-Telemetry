# Grants (default) or withdraws (-Revoke) notification access for the companion "Watchpost Notifications".
# Usage: .\notifier-access.ps1 [-Revoke]
#
# Uses "cmd notification allow_listener / disallow_listener <component> [user_id]" (NotificationManager
# shell command, AOSP NotificationShellCmd; not verified on One UI 8/9). Granting it by ADB also works
# for an app installed outside an app store, whose access switch Android may show as a "restricted
# setting" in the Settings app.
#
# Without ADB: Settings > Notifications > ... > Notification access > Watchpost Notifications (search
# "Notification access" in Settings: the path depends on the One UI version). If the switch is
# greyed out ("Restricted setting"): Settings > Apps > Watchpost Notifications > menu (⋮) >
# "Allow restricted settings", then grant the access.
#
# Launching (the scripts are not signed; this leaves the Windows execution policy unchanged):
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\notifier-access.ps1 [options]
param([switch]$Revoke)
. "$PSScriptRoot\Common.ps1"
$NotifierPkg = 'io.github.erwsim.watchpost.notifier'
$Component = "$NotifierPkg/io.github.erwsim.watchpost.notifier.NotifierListenerService"

Assert-Adb
if (@(Invoke-AdbShell pm path $NotifierPkg | Where-Object { $_ -like 'package:*' }).Count -eq 0) {
    Fail "Watchpost Notifications ($NotifierPkg) is not installed. Run install-notifier.ps1 first."
}

function Test-Enabled {
    $value = (Invoke-AdbShell settings get secure enabled_notification_listeners) -join ''
    return (@($value -split ':' | Where-Object { $_.StartsWith("$NotifierPkg/") }).Count -gt 0)
}

if ($Revoke) {
    $out = Invoke-AdbShell cmd notification disallow_listener $Component
    $out | Where-Object { $_ } | ForEach-Object { Info $_ }
    if (Test-Enabled) {
        Fail 'Access still seems to be granted. Remove it by hand: Settings > Notifications > ... > Notification access > Watchpost Notifications.'
    }
    Ok 'Notification access withdrawn: Watchpost Notifications no longer reads anything (the agent''s ''Notifications'' collector becomes ''unavailable'').'
    exit 0
}

$out = Invoke-AdbShell cmd notification allow_listener $Component
$out | Where-Object { $_ } | ForEach-Object { Info $_ }
if (-not (Test-Enabled)) {
    Warn 'The access does not appear in enabled_notification_listeners.'
    Warn 'Grant it by hand: Settings > Notifications > ... > Notification access > Watchpost Notifications.'
    Warn 'Switch greyed out (''Restricted setting''): Settings > Apps > Watchpost Notifications > ⋮ > Allow restricted settings.'
    exit 1
}
Ok 'Notification access granted to Watchpost Notifications.'
Info 'By default only the app, category, channel and importance are relayed; the title and text only if you turn on ''Notification content'' in Watchpost (Collectors > Notifications).'
Info 'Open ''Watchpost Notifications'' to check its state (service connected, agent present, collection active).'
