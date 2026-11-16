# Grants over ADB every permission Watchpost may need (inventory taken from the code of the
# :core, :collectors and :policy modules).
# - Runtime permissions: useful in degraded mode (without Device Owner); as Device Owner, the app
#   grants them to itself at startup.
# - Permissions that can only be granted over ADB: needed even as Device Owner.
# "pm grant" only works for a permission declared by the installed APK: the others are
# reported and skipped.
# Usage: .\grant-adb-permissions.ps1
#
# Launching (the scripts are not signed; this leaves the Windows execution policy unchanged):
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\grant-adb-permissions.ps1
. "$PSScriptRoot\Common.ps1"

Assert-Adb
Assert-Installed

function Grant-Permission([string]$Permission, [string]$Why) {
    $out = Invoke-AdbShell pm grant $script:Pkg $Permission
    $code = $LASTEXITCODE
    $text = (($out | Where-Object { $_ }) -join ' ').Trim()
    if ($code -eq 0 -and -not $text) {
        Ok "$Permission - $Why"
    } elseif ($text -match 'has not requested|not a changeable|Unknown permission') {
        Info "$Permission skipped: not declared by this version of the APK ($Why)"
    } else {
        Warn "${Permission}: failed - $text"
    }
}

Write-Host 'Runtime permissions (Device Owner mode also grants them automatically):'
Grant-Permission 'android.permission.ACCESS_FINE_LOCATION' 'GPS location; Wi-Fi SSID/BSSID, cell identifiers, BLE scanning'
Grant-Permission 'android.permission.ACCESS_COARSE_LOCATION' 'location'
# Always after foreground location.
Grant-Permission 'android.permission.ACCESS_BACKGROUND_LOCATION' 'background location'
Grant-Permission 'android.permission.POST_NOTIFICATIONS' 'persistent notification'
Grant-Permission 'android.permission.BLUETOOTH_SCAN' 'BLE tracker detection (ble_tracker)'
Grant-Permission 'android.permission.BLUETOOTH_CONNECT' 'Bluetooth connections (bluetooth)'
Grant-Permission 'android.permission.READ_PHONE_STATE' 'cell-by-cell tracking and signal (cell, optional)'
Grant-Permission 'android.permission.ACCESS_LOCAL_NETWORK' 'server on a private network (Android 17)'

Write-Host 'Permissions that can only be granted over ADB:'
Grant-Permission 'android.permission.PACKAGE_USAGE_STATS' 'usage access: network volumes per app (net_usage), foreground app (foreground)'
Invoke-AdbShell cmd appops set $script:Pkg GET_USAGE_STATS allow | Out-Null
if ($LASTEXITCODE -eq 0) {
    Ok 'appops GET_USAGE_STATS = allow (usage access)'
} else {
    Warn 'appops GET_USAGE_STATS: failed (grant it in Settings > Apps > Special access > Usage data access)'
}
Grant-Permission 'android.permission.WRITE_SECURE_SETTINGS' 'policy: anti-tracking settings outside the Device Owner list (ble_scan_always_enabled)'
Grant-Permission 'android.permission.DUMP' 'experimental camera/microphone attribution and real per-app usage (app_ops, which also requires usage-stats access); off by default in the app'
Info 'READ_LOGS is not granted: Android 13+ requires consent at each read, which is unusable for continuous collection.'
Info 'Battery exemptions: .\battery-exemptions.ps1'
