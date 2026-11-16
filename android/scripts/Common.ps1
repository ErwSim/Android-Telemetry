# Shared helpers for the Watchpost ADB scripts (dot-sourced: . "$PSScriptRoot\Common.ps1").
# The scripts are not signed: Windows refuses them with the default execution policy. Run them with
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\<script>.ps1 [options]
# which changes nothing in the configuration of the machine (the policy only applies to that process).
# Device selection: if several devices are connected, set $env:ANDROID_SERIAL = '<serial>' (see "adb devices").
# Encoding: this file is UTF-8 with BOM so that Windows PowerShell 5.1 reads any non-ASCII text correctly.

$ErrorActionPreference = 'Stop'
$script:Pkg = if ($env:WATCHPOST_PACKAGE) { $env:WATCHPOST_PACKAGE } else { 'io.github.erwsim.watchpost' }
$script:Admin = "$($script:Pkg)/io.github.erwsim.watchpost.policy.WatchpostAdminReceiver"

function Fail([string]$Message) {
    Write-Host "ERROR: $Message" -ForegroundColor Red
    exit 1
}
function Info([string]$Message) { Write-Host "- $Message" }
function Ok([string]$Message) { Write-Host "[OK] $Message" -ForegroundColor Green }
function Warn([string]$Message) { Write-Host "[!] $Message" -ForegroundColor Yellow }

# Runs adb and returns its output lines (stdout and stderr) as strings; never throws.
# The exit code stays available in $LASTEXITCODE.
function Invoke-Adb {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$AdbArgs)
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $out = & adb @AdbArgs 2>&1 | ForEach-Object { "$_".TrimEnd("`r") }
    } finally {
        $ErrorActionPreference = $previous
    }
    return @($out)
}

function Invoke-AdbShell {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$ShellArgs)
    return Invoke-Adb shell @ShellArgs
}

function Assert-Adb {
    if (-not (Get-Command adb -ErrorAction SilentlyContinue)) {
        Fail 'adb not found. Install ''Android SDK Platform-Tools'' and add its folder to your PATH.'
    }
    $lines = @(Invoke-Adb devices | Select-Object -Skip 1 | Where-Object { $_ -match '\S' })
    $ready = @($lines | Where-Object { $_ -match '\tdevice$' })
    if ($ready.Count -eq 0) {
        if (@($lines | Where-Object { $_ -match '\tunauthorized$' }).Count -gt 0) {
            Fail 'Phone not authorized: unlock it and accept the USB debugging key.'
        }
        Fail 'No phone connected over USB debugging (adb devices). On Samsung, temporarily turn off ''Auto Blocker''.'
    }
    if ($ready.Count -gt 1 -and -not $env:ANDROID_SERIAL) {
        Fail "Several devices connected: `$env:ANDROID_SERIAL = '<serial number>' (see adb devices)."
    }
}

function Assert-Installed {
    $out = Invoke-AdbShell pm path $script:Pkg
    if (@($out | Where-Object { $_ -like 'package:*' }).Count -eq 0) {
        Fail "Watchpost ($($script:Pkg)) is not installed. Run install-apk.ps1 first."
    }
}

function Test-IsOwner {
    $owners = Invoke-AdbShell dpm list-owners
    return (@($owners | Where-Object { $_ -like "*$($script:Pkg)*" }).Count -gt 0)
}

function Test-IsTestOnly {
    $dump = Invoke-AdbShell dumpsys package $script:Pkg
    return (@($dump | Where-Object { $_ -match 'TEST_ONLY' }).Count -gt 0)
}

# ---- ADB rescue: order sent to io.github.erwsim.watchpost.policy.rescue.RescueReceiver ----
# The receiver requires the sender to hold android.permission.FORCE_STOP_PACKAGES
# (signature|privileged, never grantable to a third-party app): only the ADB shell and the system
# can send it. It only UNDOES what Watchpost has applied.
$script:RescueReceiver = "$($script:Pkg)/io.github.erwsim.watchpost.policy.rescue.RescueReceiver"
$script:RescueAction = 'io.github.erwsim.watchpost.action.RESCUE_REVERT_ALL'

# Sends the order (up to one minute) and returns Out (raw output), Code (1 everything restored,
# 2 partial, 3 no longer Device Owner, 4 timed out, $null if there was no usable answer) and Data (summary).
#   -RemoveOwner: then gives up the role, only if everything could be undone;
#   -Force:       with -RemoveOwner, gives up the role even if an item could not be undone;
#   -Sweep:       also restores everything the catalogue may have changed (doubtful or lost state).
function Invoke-Rescue([switch]$RemoveOwner, [switch]$Force, [switch]$Sweep) {
    $extra = @()
    if ($RemoveOwner) { $extra += @('--ez', 'remove_owner', 'true') }
    if ($Force) { $extra += @('--ez', 'force', 'true') }
    if ($Sweep) { $extra += @('--ez', 'sweep', 'true') }
    # Native call (not Invoke-AdbShell): "-a" / "-n" must reach adb as they are.
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $out = @(& adb shell am broadcast --include-stopped-packages -a $script:RescueAction -n $script:RescueReceiver @extra 2>&1 | ForEach-Object { "$_".TrimEnd("`r") })
    } finally {
        $ErrorActionPreference = $previous
    }
    $line = @($out | Where-Object { $_ -match 'Broadcast completed: result=' }) | Select-Object -Last 1
    $code = $null
    $data = ''
    if ($line -match 'result=(-?\d+)') { $code = [int]$Matches[1] }
    if ($line -match 'data="(.*)"$') { $data = $Matches[1] }
    if ($code -notin 1, 2, 3, 4) { $code = $null }
    return [pscustomobject]@{ Out = $out; Code = $code; Data = $data }
}

# Extracts "key=a,b,c" from the summary, as an array.
function Get-RescueField([string]$Data, [string]$Key) {
    foreach ($token in $Data -split ' ') {
        if ($token.StartsWith("$Key=")) { return @($token.Substring($Key.Length + 1) -split ',' | Where-Object { $_ }) }
    }
    return @()
}

# State of a package for user 0, read from "dumpsys package" (line "User 0: ... hidden=... suspended=...").
function Test-PackageFlag([string]$Package, [string]$Flag) {
    $line = @(Invoke-AdbShell dumpsys package $Package | Where-Object { $_ -match '^\s*User 0:' }) | Select-Object -First 1
    return ($line -match "$Flag=true")
}

# Once the role is lost, Watchpost can no longer undo anything. Android normally lifts the removed
# Device Owner's policies itself (hidden or suspended packages included): the real state of each
# package Watchpost had hidden or suspended is checked, and "pm unhide" / "pm unsuspend" is only
# tried for those that still are. These commands may be refused to the ADB shell (MANAGE_USERS
# permission, packages suspended by an administrator): the only way out is then to give the role
# back to Watchpost (enable-device-owner) and run rescue-revert again, the applied state having been kept.
function Restore-Leftovers([string]$Data) {
    $hidden = @(Get-RescueField $Data 'hidden')
    $suspended = @(Get-RescueField $Data 'suspended')
    $stuck = @()
    if ($hidden.Count + $suspended.Count -eq 0) {
        Info 'No hidden or suspended package to restore.'
    }
    foreach ($p in $hidden) {
        if (-not (Test-PackageFlag $p 'hidden')) { Ok "${p}: visible."; continue }
        Info "pm unhide ${p}: $((Invoke-AdbShell pm unhide $p) -join ' ')"
        if (Test-PackageFlag $p 'hidden') { $stuck += $p } else { Ok "${p}: unhidden." }
    }
    foreach ($p in $suspended) {
        if (-not (Test-PackageFlag $p 'suspended')) { Ok "${p}: active."; continue }
        Info "pm unsuspend ${p}: $((Invoke-AdbShell pm unsuspend $p) -join ' ')"
        if (Test-PackageFlag $p 'suspended') { $stuck += $p } else { Ok "${p}: unsuspended." }
    }
    if ($stuck.Count -gt 0) {
        Warn "Still hidden or suspended: $($stuck -join ' ')"
        Warn "Android reserves restoring them to the Device Owner. Give the role back to Watchpost (.\enable-device-owner.ps1, with no accounts on the phone), then run .\rescue-revert.ps1: Watchpost kept the list of what it had applied."
    }
    if (@(Get-RescueField $Data 'other_items').Count -gt 0) {
        Warn "Restrictions, permissions or Private DNS set by Watchpost are normally lifted by Android when the Device Owner is removed; check Private DNS in Settings > Connections > More connection settings."
    }
}
