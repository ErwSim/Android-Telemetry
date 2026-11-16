# Copies a .watchpost enrollment file to the phone's Download folder, over the USB cable.
# Usage: .\push-enrollment.ps1 -File file.watchpost            copy, then import it in the app (Enrollment)
#        .\push-enrollment.ps1 -File file.watchpost -Remove    delete the copy on the phone afterwards
# The file holds secrets (private key, token): delete every copy once imported.
#
# Launching (the scripts are not signed; this leaves the Windows execution policy unchanged):
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\push-enrollment.ps1 [options]
param(
    [Parameter(Mandatory = $true)][string]$File,
    [switch]$Remove
)
. "$PSScriptRoot\Common.ps1"

$name = Split-Path -Leaf $File
if ($name -notlike '*.watchpost') { Fail 'The file must have the .watchpost extension' }
$dest = "/sdcard/Download/$name"

Assert-Adb
if ($Remove) {
    # Quoted: an unquoted -f would be parsed as a PowerShell parameter of Invoke-AdbShell.
    Invoke-AdbShell 'rm' '-f' $dest | Out-Null
    if ($LASTEXITCODE -eq 0) { Ok "Copy deleted from the phone: $dest" } else { Fail "Could not delete: $dest" }
    exit 0
}
if (-not (Test-Path -LiteralPath $File)) { Fail "File not found: $File" }
# Absolute path: adb must not depend on the directory it is started from.
$File = (Resolve-Path -LiteralPath $File).Path
$out = Invoke-Adb push $File $dest
if ($LASTEXITCODE -ne 0) { $out | ForEach-Object { Write-Host "  $_" }; Fail 'Copy failed.' }
Ok "Copied to $dest"
Write-Host @"
Next, on the phone: Watchpost > Settings > Enrollment > 'Import a .watchpost file' > Downloads > $name.
The app tries to delete the file after the import; otherwise: .\push-enrollment.ps1 -File "$File" -Remove
Also delete the copy on this computer (it holds the private key and the token).
"@
