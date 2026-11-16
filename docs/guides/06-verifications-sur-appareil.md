# 06 — Vérifications à faire sur l'appareil

Cette liste rassemble **tout ce qui n'a jamais été vérifié sur un vrai Galaxy S25+** (ou avec un vrai serveur public), tiré
de `android/README.md`, des recherches (`docs/research/android-plateforme.md`, `docs/research/serveur-siem-dns.md`),
de `infra/README.md` et des README du collecteur et de la console. C'est la feuille de route de votre **première semaine
d'essai**, et la matière de ce que vous rapporterez à Claude Code ([guide 07](07-reprise-developpement.md)) pour corriger.

Mode d'emploi :

- Les cases sont **ordonnées par risque décroissant** : les premières peuvent vous coûter le téléphone ou l'accès ADB,
  les dernières ne font que décrire la précision des données. Respectez l'ordre pour les niveaux 1 et 2.
- Chaque case dit **comment tester** et **quoi noter**. Notez toujours : la date et l'heure, la version de One UI (Paramètres ›
  À propos du téléphone › Informations sur le logiciel), la version de Vigie (Réglages › À propos), le texte **exact** des messages
  (capture d'écran), et le résultat (« ça marche », « ça échoue », « différent de ce qui est écrit »).
- Un échec n'est pas un drame : c'est précisément ce que cette liste cherche. Après un échec de niveau 1, **arrêtez-vous** et
  rapportez avant d'aller plus loin.
- Les identifiants V1, V2… permettent de les citer.

## Niveau 1 — Peut coûter le téléphone ou l'accès ADB

- [ ] **V1. Scripts PowerShell** (relus contre les `.sh`, jamais exécutés ni analysés par PowerShell ; les scripts bash ont été
  exécutés contre un `adb` factice, jamais contre un téléphone). *Test* : lancer chacun une fois sous Windows, **sous la forme
  `powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\<nom>.ps1`** (`install-apk`,
  `enable-device-owner`, `grant-adb-permissions`, `battery-exemptions`, `push-enrollment`, `rescue-revert`,
  `remove-device-owner`, `generate-keystore`). *Noter* : erreur de syntaxe, de politique d'exécution, d'encodage
  (accents), message inattendu, différence de comportement avec la version bash.
- [ ] **V2. Version et installation.** *Test* : `adb shell getprop ro.build.version.sdk` (36 ou plus) puis `install-apk`.
  *Noter* : Android et One UI, résultat d'installation, toute alerte Play Protect (texte exact).
- [ ] **V3. Activation du Device Owner sur S25+** (`dpm set-device-owner`) après retrait des comptes, du Dossier sécurisé, de
  Dual Messenger. *Test* : `enable-device-owner`. *Noter* : le message exact de `dpm` (succès **ou** échec), la sortie de
  `adb shell pm list users` et `adb shell dumpsys account` avant, toute erreur « user limit reached » (signalée sur Samsung par
  d'autres projets, sans solution connue). Si `dumpsys account` ne montre plus de compte et que l'activation échoue quand
  même : arrêt, rapport.
- [ ] **V4. Remise des comptes sous Device Owner.** *Test* : remettre Google puis Samsung puis le reste ; ouvrir le Play Store.
  *Noter* : tout refus ou message « administrateur », l'état du Play Store, de Samsung Wallet, des sauvegardes.
- [ ] **V5. L'issue de secours répond « à vide ».** *Test* : `rescue-revert` politique vide, écran allumé **puis** écran éteint
  et verrouillé ; puis, après un redémarrage, **avant** le premier déverrouillage (l'application n'est pas démarrable à ce stade :
  l'absence de réponse, code 5, est attendue) et **après**. *Noter* : `Tout est rétabli (reverted=0…)` et le code de sortie, le temps de réponse ; sinon le code
  (5 = aucune réponse) et la sortie brute.
- [ ] **V6. L'issue de secours défait une vraie politique.** *Test* : appliquer « Astuces » seule (guide 03, palier 2), puis
  `rescue-revert` ; réappliquer, puis `rescue-revert --sweep` (`-Sweep` sous PowerShell : rétablit aussi ce dont Vigie
  aurait perdu la trace). *Noter* : `reverted=1`, l'icône d'Astuces redevient normale, le journal de l'écran Politique.
- [ ] **V7. Retrait complet par le script** (`remove-device-owner`), politique vide. *Test* : retirer, vérifier
  `adb shell dpm list-owners` (Vigie absente), puis **réactiver** (comptes à retirer de nouveau). *Noter* : le résultat, la
  **absence** d'alerte `agent.tamper` (le retrait est annoncé) et la présence de l'événement `security.policy`
  `device_owner_cleared`, la sauvegarde Android qui se réactive, ce qui reste (restrictions, DNS).
- [ ] **V8. Retrait de dernier recours** `dpm remove-active-admin` (APK testOnly), politique vide, **avant** d'avoir appliqué le
  profil strict. *Test* : lancer directement `adb shell dpm remove-active-admin --user 0
  io.github.erwsim.vigie/io.github.erwsim.vigie.policy.VigieAdminReceiver` (c'est ce que le script `remove-device-owner` fait
  quand Vigie ne répond pas), vérifier `adb shell dpm list-owners`, puis réactiver (comptes à retirer de nouveau).
  *Noter* : succès ou « Attempt to remove non-test admin » (l'APK n'est alors pas testOnly : `adb shell dumpsys package
  io.github.erwsim.vigie | grep TEST_ONLY`), alertes `agent.tamper` (attendues dans ce cas), restrictions et DNS restés en
  place, l'état de l'application après.
- [ ] **V9. Blocage automatique (Auto Blocker) et Protection avancée.** *Test* : **seulement après V5 à V8**. (a) Auto Blocker
  actif, `adb devices` voit-il le téléphone ? `adb install` passe-t-il ? (b) Device Owner actif, **activer** Auto Blocker :
  `adb shell dpm list-owners`, Vigie tourne-t-elle, `rescue-revert` répond-il ? (c) mode « restrictions maximales » : désactive-t-il
  Vigie ? (d) Protection avancée (Paramètres › Google › Tous les services › Protection avancée) : mêmes questions. *Noter* :
  chaque résultat et les textes affichés ; si l'USB est coupé, désactivez le réglage depuis le téléphone. En cas de doute,
  laissez-le **désactivé**.
- [ ] **V10. Play Protect.** *Test* : après 24 h, Play Store › profil › Play Protect : Vigie est-elle analysée, signalée
  « dangereuse », désactivée ? *Noter* : tout message, avec le texte exact. Comportement d'un APK testOnly : inconnu.
- [ ] **V11. Mise à jour de l'APK.** *Test* : `install-apk` avec le **même** APK (ou un nouveau `-Pvigie.versionCode=2`), avant
  puis après l'application de la politique équilibrée. *Noter* : succès, l'agent redémarre seul, **Device Owner conservé**, politique
  conservée, aucune alerte `agent.tamper` ou « application sans installateur » (attendue ? voir guide 05), événements
  `agent.started` (raison `update`).

## Niveau 2 — Peut casser l'usage quotidien (politique)

À faire **dans l'ordre du guide 03, section 14**, une chose à la fois, 24 heures minimum entre chaque.

- [ ] **V12. DNS privé imposé** (`setGlobalPrivateDnsModeSpecifiedHost`). *Test* : palier 1 du guide 03, sur Wi-Fi **et** en
  données mobiles, plusieurs opérateurs/réseaux si possible. *Noter* : succès de l'application (`private_dns_set ok=true`),
  message d'erreur (`HOST_NOT_SERVING`…), réseaux où le port 853 est bloqué, ralentissement perçu, requêtes visibles dans le
  journal d'AdGuard.
- [ ] **V13. Repli du DNS privé.** *Test* : `sudo docker compose stop adguardhome` ; mesurer le délai avant retour
  d'Internet (15 minutes par défaut) ; relancer AdGuard ; l'hôte est-il réimposé tout seul ? *Noter* : délai réel, alerte
  Wazuh de sévérité 2 reçue, et si l'application du DNS verrouillé change le comportement.
- [ ] **V14. Verrou du DNS** (« Verrouiller le réglage »). *Test* : l'activer puis ouvrir le réglage DNS privé d'Android (grisé ?),
  puis « Rétablir ». *Noter* : levée effective du verrou.
- [ ] **V15. Masquer et suspendre des applications.** *Test* : « Astuces » (suspension), puis chaque lot (guide 03, lots 3a à 3c) ;
  redémarrer ; comparer `adb shell pm list packages` avant, après application, après « Tout rétablir ». *Noter* : les
  paquets du catalogue **absents** de votre S25+ (« absent de ce téléphone »), ceux dont l'application échoue (journal
  `ok=false`), la persistance des masques après redémarrage, l'état exact retrouvé après « Tout rétablir ».
- [ ] **V16. Modules système (Mainline) masqués** : Android AdServices, On-Device Personalization, Federated Compute (effet « à
  vérifier après application » dans l'application). *Test* : lot 3b seul, redémarrer, Paramètres › Mise à jour logicielle,
  Play System Update, Play Store. *Noter* : tout dysfonctionnement ou message d'erreur.
- [ ] **V17. Notifications push** après chaque lot. *Test* : message reçu téléphone verrouillé depuis plus de 10 minutes, Wi-Fi puis
  données. *Noter* : retard ou absence ; domaines bloqués dans AdGuard.
- [ ] **V18. Play Store** (mise à jour, installation) et **vérification des applications**. *Noter* : échec, message.
- [ ] **V19. Application bancaire** (Play Integrity) avec le Device Owner actif, puis avec le profil équilibré. *Test* :
  ouverture, connexion, validation d'une opération. *Noter* : refus de démarrer ; options développeur et débogage USB actifs
  gênent-ils (désactiver temporairement le débogage USB si c'est le cas, puis le réactiver) ; Play Protect désactivé gêne-t-il.
- [ ] **V20. Paiement sans contact et Wallet** (Google Wallet, Samsung Wallet/Pay/Pass), avec le Device Owner seul, puis après le profil
  équilibré. Effet **inconnu** (aucune source). *Test* : un vrai paiement de faible montant, carte physique en secours ; carte de
  transport. *Noter* : tout refus, la nécessité de ré-enregistrer des cartes.
- [ ] **V21. Mises à jour Samsung (OTA) et Device Owner.** *Test* : Paramètres › Mise à jour logicielle ; à la prochaine mise à jour
  réelle, `adb shell dpm list-owners` avant et après. *Noter* : le Device Owner survit-il, l'agent reprend-il, la mise à jour a-t-elle été
  possible (domaines `ospserver.net` autorisés).
- [ ] **V22. Compte Samsung et services** sous le profil équilibré (conflit signalé : HaGeZi bloque `gld.samsungosp.com`). *Noter* :
  échecs de connexion au compte Samsung, Galaxy Store, Samsung Cloud, Find My Mobile.
- [ ] **V23. Restrictions** : « Interdire la 2G » (effet réel de `DISALLOW_CELLULAR_2G` : le téléphone n'utilise plus la 2G ;
  vérifier `net.cell` sur quelques jours), « Interdire les sources inconnues » (**l'installation ADB passe-t-elle ?** voir V11),
  capture et suggestions de contenu. *Noter* : conséquence observée.
- [ ] **V24. Permission refusée** (Appli Google : localisation) : Paramètres › Applications › Appli Google › Autorisations
  (verrouillée ?). *Noter* : le texte affiché et l'effet sur la météo ou Discover.
- [ ] **V25. Réglage `ble_scan_always_enabled`** (nécessite `WRITE_SECURE_SETTINGS`). *Test* : après application, `adb shell settings get
  global ble_scan_always_enabled` (attendu `0`). *Noter* : valeur, erreur.
- [ ] **V26. Sauvegarde Android réactivée** par le profil équilibré. *Test* : Paramètres › Comptes et sauvegarde ; `adb shell bmgr enabled`.
  *Noter* : l'état avant (coupé par le Device Owner) et après.
- [ ] **V27. Profil strict, élément par élément** (guide 03, palier 4). *Test* : un élément à la fois, 24 heures. *Noter*, par
  élément : l'effet observé, ce qui casse réellement (compte Samsung, Galaxy Store, mode sans échec : démarrer en mode sans échec
  est-il impossible ?, ajout de certificat, Appli Google, UWB, Thread…). Cette liste est le principal gain de connaissance.
- [ ] **V28. VPN permanent** (facultatif, carte « VPN permanent ») : cohérence avec le DNS privé (le résolveur doit être joignable
  dans et hors du VPN, selon la recherche). Non essayé ; n'activez le mode « bloquer sans VPN » qu'avec un VPN fiable.

## Niveau 3 — La collecte fait-elle ce qu'elle dit ?

- [ ] **V29. Survie du service.** *Test* : 24 heures écran éteint, puis redémarrage. *Noter* : dans la console, les
  `agent.heartbeat` toutes les 15 minutes sans trou (Événements › `agent.`), les alertes d'absence, l'événement `agent.started`
  (raison `boot`), `device.boot` après le premier déverrouillage, la consommation de batterie de Vigie (Paramètres › Batterie).
- [ ] **V30. Rien avant le premier déverrouillage** (Direct Boot non utilisé : comportement voulu). *Noter* : l'intervalle sans
  événement après un redémarrage.
- [ ] **V31. Permissions automatiques et protection contre l'arrêt forcé.** *Test* : Paramètres › Applications › Vigie ›
  Autorisations (localisation « toujours », notifications, appareils à proximité, téléphone) ; « Forcer l'arrêt » et « Effacer les
  données » sont-ils grisés ? *Noter* : permissions manquantes, effet de `setUserControlDisabledPackages`, l'application est-elle
  désinstallable (attendu : non, tant qu'elle est Device Owner). Retirer volontairement une permission dans les Paramètres :
  le collecteur passe-t-il « indisponible », `agent.tamper` `permission_revoked` est-il émis, et l'onglet Collecteurs
  permet-il de la redonner (Vigie ne la reprend pas d'elle-même, la revue de l'application l'ayant voulu ainsi) ?
- [ ] **V32. Clé dans l'Android Keystore et mTLS.** *Test* : « Tester la connexion » après l'enrôlement, **après redémarrage**
  et après plusieurs jours. *Noter* : « Connexion réussie » ou le message d'erreur exact.
- [ ] **V33. Journal réseau du système.** *Test* : premiers `net.dns` et `net.connect` avec leur paquet (délai jusqu'à 1 h 30 ; essai
  `adb shell dpm force-network-logs`) ; vérifier l'heure d'origine (`ts`), les `count`, l'attribution à des paquets réels, les lots perdus
  (`agent.collector_error`). *Noter* : le délai réel, le volume par jour, les applications absentes (UDP/QUIC attendu).
- [ ] **V34. Journal de sécurité du système.** *Test* : `adb shell dpm force-security-logs` ; événements `security.log` (ADB,
  installations, déverrouillages) ; journaux d'avant redémarrage (`pre_reboot: true`), **à comparer à ce que renvoie réellement l'appareil**
  (la fonction peut renvoyer `null`). *Noter* : tags présents et absents, noms de champs différents du contrat.
- [ ] **V35. Notifications d'Android.** *Test* : texte exact de la mention « appareil géré » et de la notification « réseau
  surveillé » (nombre d'apparitions). *Noter* : les deux textes.
- [ ] **V36. Position (GPS + passif).** *Test* : 15 minutes de marche avec le téléphone en poche, puis trajet en voiture ; comparer à la carte ;
  un jour de séjour en intérieur. *Noter* : densité de points, précision, trous attendus (intérieur), batterie.
- [ ] **V37. Wi-Fi, cellule, Bluetooth, NFC, point d'accès.** *Test* : SSID/BSSID présents (exigent la localisation précise) ; `net.cell`
  avec ses champs ; connexions Bluetooth (voiture, écouteurs) ; activer le point d'accès. *Noter* : champs absents, valeurs
  suspectes.
- [ ] **V38. Caméra et micro.** *Test* : ouvrir l'appareil photo, enregistrer un mémo vocal, passer un appel. *Noter* : événements
  `sensor.camera` et `sensor.microphone`, `screen_on` et `locked`, **pas d'alerte pendant un appel**. **Attribution
  expérimentale** (réglage « Attribution expérimentale (DUMP) », désactivé par défaut) : l'activer, refaire le test, noter si
  `package` est renseigné ou si l'erreur indique un refus SELinux.
- [ ] **V39. Application au premier plan et volumes** (accès à l'utilisation accordé par `grant-adb-permissions`). *Test* :
  `app.foreground` apparaît (100 à 400 par jour) ; `net.usage` horaire (valeurs estimées, retard d'au moins 30 minutes) ; comparer à
  Paramètres › Connexions › Utilisation des données. *Noter* : écarts, applications manquantes.
- [ ] **V40. Inventaire et changements d'applications.** *Test* : installer puis désinstaller une application depuis le Play Store :
  `app.installed`, `app.removed` ; révoquer/accorder une permission : `app.permission_changed` ; la page Applications ›
  Accès spéciaux. *Noter* : délais, champs manquants.
- [ ] **V41. Événements USB et ADB.** *Test* : brancher le câble, lancer un script : `device.usb`, `security.log` (`adb_shell_cmd`),
  alertes Wazuh correspondantes (attendues, guide 05). *Noter* : niveau de bruit.
- [ ] **V42. Posture complète.** *Test* : console › Sécurité › Posture. *Noter* : champs présents et absents (`play_protect` est
  volontairement omis), valeurs fausses (chiffrement, démarrage vérifié, correctif).
- [ ] **V43. Déverrouillages échoués.** *Test* : saisir un mauvais code une ou deux fois : `security.keyguard`. (La règle
  d'alerte est à 5 échecs en 10 minutes ou 10 consécutifs : ne la déclenchez pas exprès sur un téléphone que vous utilisez.)
- [ ] **V44. Mode hors ligne.** *Test* : mode avion une heure, puis retour : le tampon part-il, sans doublon ni trou de séquence
  (pas d'alerte de séquence) ? *Noter* : délai de reprise.
- [ ] **V45. Renouvellement du certificat et réenrôlement.** *Test* : `sudo ./enroll.sh --renew s25`, import par « Importer un
  nouveau fichier .vigie » (guide 05 §8) ; vérifier le message « Renouvellement : même serveur, même appareil », le tampon
  conservé, la nouvelle échéance, `enroll.sh --list`. Essayer aussi (avec un fichier `enroll` d'un autre appareil) l'annonce
  « Même serveur, autre identifiant » puis, sans l'importer, « Autre serveur » (le tampon y est **effacé**). *Noter* : nombre
  d'événements avant et après, alertes de séquence ou d'absence, et si l'ancien couple est bien refusé ensuite. Le désenrôlement
  (qui efface clé, jeton et tampon) se teste à part.
- [ ] **V46. Autorité de certificat utilisateur** (facultatif) : installer un certificat de test puis le retirer : `security.ca_cert`
  (sévérité 2) et l'alerte de niveau 10 attendue. *Noter* : délai, doublons entre journal système et posture.
- [ ] **V47. Certificate Transparency désactivée par `network_security_config`.** Ne concerne que le mode `--tls internal`
  (l'AC privée est alors épinglée). Avec Let's Encrypt, le succès de « Tester la connexion » suffit.
- [ ] **V48. Traceurs Bluetooth** (AirTag, SmartTag, Tile, Localiser de Google) : seulement si vous avez un traceur à
  disposition, séparé de son propriétaire, déplacé avec vous plus de 30 minutes sur plus de 500 m. Sinon, rien à vérifier.

### Points « plausibles à vérifier sur appareil » issus de la revue de l'application

Ces huit points sont des hypothèses du code que rien n'a confirmées ; plusieurs recoupent des cases ci-dessus, la formulation
ci-dessous est celle de la revue.

- [ ] **V59. Masquage et suspension réels sur One UI, et ce qu'Android défait au retrait du rôle.** *Test* : appliquer un paquet masqué
  et un paquet suspendu ; lancer `remove-device-owner` **après** « Tout rétablir » (V7), puis, sur un second essai à vide avec un
  paquet encore masqué, le retrait par `dpm remove-active-admin` (V8) : le paquet est-il réaffiché par Android ? `adb shell pm unhide
  <paquet>` est-il refusé (permission `MANAGE_USERS`) ? *Noter* : la sortie de chaque commande et `dumpsys package <paquet>`
  (ligne `User 0:`, champs `hidden` et `suspended`).
- [ ] **V60. `am broadcast` du shell vers l'issue de secours.** *Test* : V5, écran allumé, éteint, puis après redémarrage avant et
  après déverrouillage. *Noter* : la sortie brute d'`am broadcast` (`result=…, data=…`).
- [ ] **V61. Room sur le SQLite du système.** *Test* : tuer le processus de Vigie (Paramètres › Applications › Vigie ; « Forcer
  l'arrêt » est normalement grisé en Device Owner), redémarrer le téléphone, couper le réseau une heure. *Noter* : le tampon
  survit-il (Journal local › « En attente »), la séquence `seq` reste-t-elle continue (aucune alerte de trou de séquence).
- [ ] **V62. TLS client avec une clé de l'Android Keystore.** *Test* : V32. *Noter* : « Connexion réussie » avant et après
  redémarrage ; toute erreur de poignée de main.
- [ ] **V63. Survie du service 24 h** : V29.
- [ ] **V64. `no_usb_file_transfer` laisse-t-il ADB ? et `no_cellular_2g` coché par défaut en zone 2G seule.** *Test* : appliquer
  « Interdire le transfert de fichiers USB » (profil strict, décoché par défaut) puis `adb devices`, `adb shell` et
  `push-enrollment` ; appliquer « Interdire la 2G » (coché par défaut dans l'équilibré) et se rendre, si possible, dans une zone sans
  4G/5G. *Noter* : ADB reste-t-il utilisable, le téléphone garde-t-il un réseau pour les appels (les urgences restent permises).
- [ ] **V65. Balayage BLE continu et consommation GNSS.** *Test* : une journée complète avec le collecteur Traceurs actif puis
  inactif ; le GNSS retombe à la cadence lente après 5 minutes sans position (intérieur). *Noter* : part de batterie de Vigie
  (Paramètres › Batterie) dans chaque cas.
- [ ] **V66. Faux `agent.tamper` `force_stop`** si « Entretien de l'appareil » Samsung (optimisation, nettoyage de la mémoire,
  mise en veille profonde) arrête l'application. *Test* : lancer l'optimisation de l'Entretien de l'appareil, puis consulter
  Sécurité › Journal / Alertes. *Noter* : alerte reçue ou non, état de l'agent après.

## Niveau 4 — Serveur et console avec de vraies données

Les cinq premières cases viennent du guide 01 (section 9).

- [ ] **V49. Let's Encrypt** réel (console, ingestion, `dns.…`) : `curl` et `openssl s_client` du guide 01. *Noter* : échecs de validation
  éventuels.
- [ ] **V50. Listes de blocage HaGeZi** téléchargées par AdGuard (nombre de règles non nul) et **résolution amont par Quad9**.
- [ ] **V51. Mémoire avec les listes chargées** : `free -h`, `sudo docker stats --no-stream` après 24 heures. *Noter* : mémoire d'AdGuard
  (≈ 300 Mo attendus), swap utilisé, conteneur redémarré.
- [ ] **V52. Port 853 depuis plusieurs réseaux mobiles et Wi-Fi.** *Noter* : lesquels bloquent le DNS sur TLS.
- [ ] **V53. Premier renouvellement Let's Encrypt** (environ 60 jours) : dates du certificat avant et après ; AdGuard le recharge
  sans redémarrer.
- [ ] **V54. Restauration sur un serveur neuf** (jamais essayée ; seule la restauration sur place a été vérifiée) :
  `restore.sh` sur un VPS vierge ; le téléphone enrôlé est accepté.
- [ ] **V55. Tuiles de carte réelles** (OpenStreetMap par défaut) : la carte de la console s'affiche-t-elle ?
- [ ] **V56. Volume réel** après une à deux semaines : événements par jour, croissance du disque (`df -h /var/lib/docker`),
  fluidité de la console et de Wazuh, nombre d'alertes par jour (bruit).
- [ ] **V57. Tableaux de bord Wazuh avec de vraies données** : alertes, carte des positions (le fond de carte est tiers).
- [ ] **V58. Options non essayées** (facultatif) : mode ClientID avec joker DNS-01, WireGuard.

## Fiche de rapport à transmettre à Claude Code

Pour chaque case en échec ou différente de l'attendu, rapportez :

1. l'identifiant (V12…) et ce que vous attendiez ;
2. ce qui s'est passé : message exact ou capture d'écran, heure ;
3. le contexte : version d'Android et de One UI, version de Vigie, mode (Device Owner ou non), profil appliqué et éléments cochés ;
4. les traces :
   - **sur le téléphone** : le « Journal des actions » de l'écran Politique et l'onglet Journal local de Vigie ;
   - **depuis le PC** : `adb logcat -d | grep -i -E "vigie|AndroidRuntime"` (PowerShell : `adb logcat -d | Select-String -Pattern 'vigie|AndroidRuntime'`) ;
   - **dans la console** : le détail JSON de l'événement concerné (page Événements, touchez l'événement) ;
   - **sur le serveur** : `sudo docker compose logs --since 1h collector caddy adguardhome` (dossier `infra`).

Ne joignez **jamais** de fichier `.vigie`, de contenu de `infra/.env`, `infra/secrets/` ou de keystore.
