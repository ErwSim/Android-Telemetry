# Copies a .vigie enrollment file to the phone's Download folder, over the USB cable.
# Usage: .\push-enrollment.ps1 -File fichier.vigie            copy, then import it in the app (Enrôlement)
#        .\push-enrollment.ps1 -File fichier.vigie -Remove    delete the copy on the phone afterwards
# The file holds secrets (private key, token): delete every copy once imported.
param(
    [Parameter(Mandatory = $true)][string]$File,
    [switch]$Remove
)
. "$PSScriptRoot\Common.ps1"

$name = Split-Path -Leaf $File
if ($name -notlike '*.vigie') { Fail "Le fichier doit avoir l'extension .vigie" }
$dest = "/sdcard/Download/$name"

Assert-Adb
if ($Remove) {
    Invoke-AdbShell rm -f $dest | Out-Null
    if ($LASTEXITCODE -eq 0) { Ok "Copie supprimée du téléphone : $dest" } else { Fail "Suppression impossible : $dest" }
    exit 0
}
if (-not (Test-Path $File)) { Fail "Fichier introuvable : $File" }
$out = Invoke-Adb push $File $dest
if ($LASTEXITCODE -ne 0) { $out | ForEach-Object { Write-Host "  $_" }; Fail 'Copie impossible.' }
Ok "Copié vers $dest"
Write-Host @"
Ensuite, sur le téléphone : Vigie > Réglages > Enrôlement > « Importer un fichier .vigie » > Téléchargements > $name.
L'app tente de supprimer le fichier après l'import ; sinon : .\push-enrollment.ps1 -File "$File" -Remove
Supprimez aussi la copie sur cet ordinateur (elle contient la clé privée et le jeton).
"@
