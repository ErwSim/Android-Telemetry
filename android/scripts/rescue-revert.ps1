# Issue de secours sans l'interface : demande à Vigie, par ADB, de défaire toute sa politique
# Device Owner (« Tout rétablir » de l'écran Politique). Vigie reste Device Owner et ses journaux
# restent actifs.
#
# Mécanisme : diffusion explicite à io.github.erwsim.vigie/.policy.rescue.RescueReceiver (voir
# Common.ps1) ; seul le shell ADB ou le système peut l'envoyer, et elle ne peut que défaire.
#
# Usage : .\rescue-revert.ps1                « Tout rétablir »
#         .\rescue-revert.ps1 -RemoveOwner   équivaut à .\remove-device-owner.ps1 (retrait complet)
# Codes de sortie : 0 tout rétabli, 2 partiel, 3 Vigie n'est plus Device Owner, 4 délai dépassé,
# 5 aucune réponse exploitable de Vigie, 1 autre erreur.
param([switch]$RemoveOwner)
. "$PSScriptRoot\Common.ps1"

if ($RemoveOwner) {
    & "$PSScriptRoot\remove-device-owner.ps1"
    exit $LASTEXITCODE
}

Assert-Adb
Assert-Installed

Info "Envoi de l'ordre « Tout rétablir » à Vigie (jusqu'à une minute)..."
$r = Invoke-Rescue
switch ($r.Code) {
    1 { Ok "Tout est rétabli ($($r.Data))." }
    2 {
        Warn "Rétablissement partiel : $($r.Data)"
        Warn "Réessayez ; si un élément résiste, consultez le journal de l'écran Politique ou le README (section Politique Device Owner)."
        exit 2
    }
    3 {
        Warn "Vigie n'est plus Device Owner : elle ne peut plus rien défaire elle-même ($($r.Data))."
        Restore-Leftovers $r.Data
        exit 3
    }
    4 {
        Warn "Vigie n'a pas fini dans le délai : l'opération continue sur le téléphone. Relancez ce script dans une minute pour voir le résultat."
        exit 4
    }
    default {
        $r.Out | ForEach-Object { Write-Host "    $_" }
        Warn "Pas de réponse exploitable de Vigie. Vérifiez que l'APK installé contient l'issue de secours (version avec l'écran Politique) et qu'il démarre."
        exit 5
    }
}
