# Grants (default) or withdraws (-Revoke) notification access for the companion "Vigie Notifications".
# Usage: .\notifier-access.ps1 [-Revoke]
#
# Uses "cmd notification allow_listener / disallow_listener <composant> [user_id]" (NotificationManager
# shell command, AOSP NotificationShellCmd; not verified on One UI 8/9). Granting it by ADB also works
# for an app installed outside an app store, whose access switch Android may show as a "paramètre
# restreint" (restricted setting) in the Settings app.
#
# Without ADB: Paramètres > Notifications > ... > Accès aux notifications > Vigie Notifications (search
# "Accès aux notifications" in Settings: the path depends on the One UI version). If the switch is
# greyed out ("Paramètre restreint"): Paramètres > Applications > Vigie Notifications > menu (⋮) >
# "Autoriser les paramètres restreints", then grant the access.
#
# Lancement (scripts non signés, sans modifier la politique d'exécution de Windows) :
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\notifier-access.ps1 [options]
param([switch]$Revoke)
. "$PSScriptRoot\Common.ps1"
$NotifierPkg = 'io.github.erwsim.vigie.notifier'
$Component = "$NotifierPkg/io.github.erwsim.vigie.notifier.NotifierListenerService"

Assert-Adb
if (@(Invoke-AdbShell pm path $NotifierPkg | Where-Object { $_ -like 'package:*' }).Count -eq 0) {
    Fail "Vigie Notifications ($NotifierPkg) n'est pas installé. Lancez d'abord install-notifier.ps1."
}

function Test-Enabled {
    $value = (Invoke-AdbShell settings get secure enabled_notification_listeners) -join ''
    return (@($value -split ':' | Where-Object { $_.StartsWith("$NotifierPkg/") }).Count -gt 0)
}

if ($Revoke) {
    $out = Invoke-AdbShell cmd notification disallow_listener $Component
    $out | Where-Object { $_ } | ForEach-Object { Info $_ }
    if (Test-Enabled) {
        Fail 'L''accès semble toujours accordé. Retirez-le à la main : Paramètres > Notifications > ... > Accès aux notifications > Vigie Notifications.'
    }
    Ok 'Accès aux notifications retiré : Vigie Notifications ne lit plus rien (le collecteur « Notifications » de l''agent passe « indisponible »).'
    exit 0
}

$out = Invoke-AdbShell cmd notification allow_listener $Component
$out | Where-Object { $_ } | ForEach-Object { Info $_ }
if (-not (Test-Enabled)) {
    Warn 'L''accès n''apparaît pas dans enabled_notification_listeners.'
    Warn 'Accordez-le à la main : Paramètres > Notifications > ... > Accès aux notifications > Vigie Notifications.'
    Warn 'Interrupteur grisé (« Paramètre restreint ») : Paramètres > Applications > Vigie Notifications > ⋮ > Autoriser les paramètres restreints.'
    exit 1
}
Ok 'Accès aux notifications accordé à Vigie Notifications.'
Info 'Par défaut seuls l''app, la catégorie, le canal et l''importance sont transmis ; le titre et le texte seulement si vous activez « Contenu des notifications » dans Vigie (Collecteurs > Notifications).'
Info 'Ouvrez « Vigie Notifications » pour vérifier l''état (service connecté, agent présent, collecte active).'
