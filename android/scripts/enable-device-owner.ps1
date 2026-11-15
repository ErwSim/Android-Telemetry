# Makes Vigie the Device Owner of the phone (ADB provisioning, no factory reset).
# Preconditions checked here: no other user/profile, no account, no existing owner.
# Usage: .\enable-device-owner.ps1
. "$PSScriptRoot\Common.ps1"

Assert-Adb
Assert-Installed

Info 'Vérification des propriétaires existants...'
if (Test-IsOwner) {
    Ok 'Vigie est déjà Device Owner.'
    exit 0
}
$owners = Invoke-AdbShell dpm list-owners
if (@($owners | Where-Object { $_ -match 'DeviceOwner|ProfileOwner' }).Count -gt 0) {
    $owners | ForEach-Object { Write-Host "    $_" }
    Fail "Un autre Device Owner ou Profile Owner est déjà défini. Retirez-le d'abord."
}

Info 'Vérification des utilisateurs et profils...'
$users = @(Invoke-AdbShell pm list users | Where-Object { $_ -match 'UserInfo\{' })
if ($users.Count -gt 1) {
    $users | ForEach-Object { Write-Host "    $($_.Trim())" }
    Fail "Plusieurs utilisateurs ou profils existent ($($users.Count)). Supprimez Dossier sécurisé (Secure Folder), Dual Messenger, l'espace privé, le profil professionnel et les invités, puis relancez."
}

Info 'Vérification des comptes...'
$accounts = @(Invoke-AdbShell dumpsys account | Where-Object { $_ -match '^\s*Account \{' })
if ($accounts.Count -gt 0) {
    Write-Host 'Comptes présents sur le téléphone :'
    $accounts | ForEach-Object { Write-Host "    $($_.Trim())" }
    Write-Host @'
ERREUR : Android refuse de nommer un Device Owner tant qu'un compte existe.
Retirez TEMPORAIREMENT chaque compte listé (Paramètres > Comptes et sauvegarde > Gérer les comptes :
Google, Samsung account, WhatsApp, Signal, Microsoft...), relancez ce script, puis rajoutez vos comptes :
le mode Device Owner ne les interdit pas. Pensez à vérifier vos sauvegardes et la double
authentification avant de retirer un compte Google ou Samsung.
'@ -ForegroundColor Red
    exit 1
}

if (Test-IsTestOnly) {
    Info 'APK testOnly : le Device Owner pourra être retiré par ADB (remove-device-owner.ps1).'
} else {
    Warn "APK NON testOnly : le retrait par ADB sera impossible ; seul l'app (ou une réinitialisation) pourra le retirer."
    $answer = Read-Host 'Continuer quand même ? (oui/non)'
    if ($answer -ne 'oui') { Fail 'Abandon.' }
}

Info "Activation : dpm set-device-owner $($script:Admin)"
Invoke-AdbShell dpm set-device-owner --user 0 $script:Admin | ForEach-Object { Write-Host "    $_" }
if (Test-IsOwner) {
    Ok "Vigie est Device Owner. Ouvrez l'app : elle s'accorde ses permissions et active sa protection."
    Info 'Vous pouvez rajouter vos comptes Google/Samsung. Réactivez le Blocage automatique si vous l''aviez coupé.'
} else {
    Fail "L'activation a échoué (voir le message ci-dessus)."
}
