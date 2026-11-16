# Retrait complet du Device Owner par ADB (équivalent de « Retirer le Device Owner » de l'écran
# Politique, qui reste le chemin recommandé quand l'app est utilisable).
#
# 1. Chemin normal : l'issue de secours de Vigie (voir Common.ps1) défait toute la politique, coupe
#    les journaux réseau et sécurité, retire la protection contre l'arrêt forcé, émet
#    security.policy « device_owner_cleared » puis appelle clearDeviceOwnerApp. Le retrait étant
#    annoncé, il n'est pas signalé comme agent.tamper. Fonctionne avec tout APK (testOnly ou non).
#    Si un élément ne peut pas être défait, Vigie GARDE le rôle (elle seule peut réessayer) et ce
#    script propose de forcer le retrait.
# 2. Repli, seulement si Vigie ne répond pas (app qui ne démarre plus) : « dpm remove-active-admin »,
#    possible uniquement avec un APK testOnly. Vigie ne défait alors rien elle-même (paquets masqués
#    à réafficher, proposé ensuite) et le retrait est vu comme une désactivation (agent.tamper
#    admin_disabled / device_owner_lost au prochain démarrage) : c'est attendu.
#
# Usage : .\remove-device-owner.ps1 [-Uninstall]
#
# Lancement (scripts non signés, sans modifier la politique d'exécution de Windows) :
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\remove-device-owner.ps1 [options]
param([switch]$Uninstall)
. "$PSScriptRoot\Common.ps1"

Assert-Adb
Assert-Installed

if (-not (Test-IsOwner)) {
    Info "Vigie n'est pas Device Owner."
} else {
    Write-Host @'
Vigie va tout rétablir, couper ses journaux réseau et de sécurité, puis abandonner le rôle de
Device Owner. Pour le retrouver, il faudra repasser par enable-device-owner (sans comptes sur le
téléphone).
'@
    $answer = Read-Host 'Continuer ? (oui/non)'
    if ($answer -ne 'oui') { Fail 'Abandon.' }

    Info "Envoi de l'ordre de retrait à Vigie (jusqu'à une minute)..."
    $r = Invoke-Rescue -RemoveOwner
    switch ($r.Code) {
        1 { Ok "Politique rétablie ($($r.Data))." }
        2 {
            Warn "Rétablissement partiel : $($r.Data)"
            if (Test-IsOwner) {
                Write-Host @'
Vigie n'a pas pu tout défaire et a donc gardé le rôle de Device Owner : elle seule peut réessayer
(.\rescue-revert.ps1, puis .\rescue-revert.ps1 -Sweep). Forcer le retrait laisse ces éléments en
l'état ; selon la version d'Android, un paquet resté masqué ou suspendu ne peut ensuite plus être
rétabli que par un Device Owner.
'@
                $answer = Read-Host 'Forcer quand même le retrait ? (oui/non)'
                if ($answer -ne 'oui') { Fail 'Abandon : Vigie reste Device Owner.' }
                $r = Invoke-Rescue -RemoveOwner -Force
                if ($null -eq $r.Code) {
                    $r.Out | ForEach-Object { Write-Host "    $_" }
                    Fail 'Pas de réponse de Vigie au retrait forcé.'
                }
            }
        }
        3 { Info "Vigie n'était déjà plus Device Owner ($($r.Data))." }
        4 {
            Warn "Vigie n'a pas fini dans le délai ; vérification du rôle dans 30 s..."
            Start-Sleep -Seconds 30
        }
        default {
            $r.Out | ForEach-Object { Write-Host "    $_" }
            Warn "Pas de réponse exploitable de Vigie (app qui ne démarre plus, ou version sans issue de secours)."
            if (-not (Test-IsTestOnly)) {
                Fail "APK non testOnly : Android refuse « dpm remove-active-admin ». Réparez/mettez à jour l'app (même clé de signature) puis relancez ce script, ou réinitialisez le téléphone."
            }
            Write-Host @'
Repli : « dpm remove-active-admin » (APK testOnly). Vigie ne défera pas sa politique elle-même :
l'état des paquets qu'elle avait masqués ou suspendus est vérifié ensuite.
Le retrait sera signalé par agent.tamper (admin_disabled, device_owner_lost) : c'est attendu.
'@
            $answer = Read-Host 'Utiliser ce repli ? (oui/non)'
            if ($answer -ne 'oui') { Fail 'Abandon.' }
            Invoke-AdbShell dpm remove-active-admin --user 0 $script:Admin | ForEach-Object { Write-Host "    $_" }
        }
    }
    if (Test-IsOwner) { Fail "Vigie est toujours Device Owner ($($r.Data))." }
    Ok "Vigie n'est plus Device Owner (la sauvegarde Android, coupée par le mode Device Owner, peut être réactivée dans les Paramètres)."
    # Ce que Vigie n'a pas pu défaire elle-même (repli, ou éléments restés en échec).
    $after = Invoke-Rescue
    if ($after.Code -eq 3) { Restore-Leftovers $after.Data }
}

if ($Uninstall) {
    Invoke-Adb uninstall $script:Pkg | ForEach-Object { Write-Host "  $_" }
    if ($LASTEXITCODE -eq 0) { Ok 'Vigie désinstallée.' } else { Fail 'Désinstallation impossible.' }
}
