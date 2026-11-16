# 03 — Préparer et configurer le téléphone

Ce guide installe Vigie Agent sur votre Samsung Galaxy S25+, l'élève au rang de **Device Owner**, l'enrôle auprès
de votre serveur, puis met la politique anti-pistage en service **par paliers**. C'est le guide où une erreur peut
coûter cher : lisez-le en entier avant de commencer, et gardez [le guide 04 (retour en arrière)](04-retour-arriere.md)
ouvert dans un autre onglet.

Prérequis : le serveur tourne et répond ([guide 01](01-serveur.md)) ; vous avez un APK **release signé** et un
PC avec `adb` ([guide 02](02-compiler-apk.md)). Durée : une demi-journée pour les sections 1 à 12 ; la mise en service de
la politique (section 14), des commandes à distance (15), des gardes (16), du compagnon de notifications (17) et des modes de
localisation (18) s'étale sur plusieurs semaines, volontairement.

> **Statut de vérification : lisez ceci.** Rien dans ce guide n'a jamais été exécuté sur un téléphone, et les scripts
> PowerShell n'ont même pas été lancés une fois. Les commandes ont été relues contre les scripts du dépôt, les
> messages attendus viennent des scripts et de la recherche (`docs/research/android-plateforme.md`), pas d'une
> exécution. Quand ce guide donne un menu du téléphone, c'est le chemin habituel sur One UI : il peut varier selon la
> version. Au moindre écart avec ce qui est écrit ici, **arrêtez-vous**, notez ce que vous voyez (message exact,
> capture d'écran) et reportez-vous au [guide 06](06-verifications-sur-appareil.md). Ne forcez rien.

## Ordre d'essai conseillé (et ce qu'il ne faut pas activer trop tôt)

C'est l'ordre recommandé par la revue indépendante de l'application. Chaque phase se juge avant la suivante ; les numéros de
section renvoient à ce guide.

| Phase | Quoi | Durée conseillée |
|---|---|---|
| 1 | **APK release sans Device Owner** : installation (§3), permissions par ADB (§8, deuxième moitié) et batterie (§9), enrôlement (§10) et vérification des envois (§11), en mode dégradé | 2 à 3 jours |
| 2 | **Device Owner seul** (§4 à §8), puis `rescue-revert` **à vide** (§12) et un **redémarrage** (l'issue de secours doit encore répondre après le premier déverrouillage) | 1 à 2 jours |
| 3 | **DNS privé seul** (§14, palier 1) : « Tout décocher », seul le DNS coché, **verrou éteint**, **repli actif** | une semaine |
| 4 | **Deux ou trois paquets à faible risque** (§14, palier 2), puis « Tout rétablir » et **comparaison** | 1 à 2 jours |
| 5 | **Profil équilibré**, par lots (§14, palier 3) | une semaine |
| 6 | **Canal de commandes à distance** (§15) : sonner, localiser, verrouiller avec message ; **jamais l'effacement** à ce stade | 2 à 3 jours |
| 7 | **Gardes de capacités, une à une** (§16), de la moins risquée à la plus risquée, avec « Tout rétablir » entre deux | une à deux semaines |
| 8 | **Compagnon de notifications** (§17), facultatif, contenu éteint d'abord | quelques jours |
| 9 | **Modes de localisation** (§18), facultatif | à votre rythme |

**À ne pas activer tant que ce n'est pas vu fonctionner** sur votre téléphone : le **profil strict** ; le **VPN permanent**
avec « bloquer sans VPN » ; le **verrou du DNS** (« Verrouiller le réglage ») ; l'**interdiction du mode sans échec** (élément du
profil strict) ; la **désactivation du repli DNS** (Réglages › Device Owner) ; l'**effacement à distance** (tant que vous ne
l'avez pas essayé sur un appareil sacrifiable ou entièrement sauvegardé) ; les options « aussi la lecture des SMS » et « aussi le
journal d'appels » des gardes ; le **contenu des notifications** du compagnon ; les modes de localisation « GPS + réseau » et
« fusionné » (ils envoient des informations à Google).

### Avertissements à garder en tête pendant tout le guide

1. **L'APK est un build release signé, avec `testOnly` (variante par défaut) et toujours avec la même clé de signature**
   (guide 02) : c'est ce qui laisse une porte de sortie (`dpm remove-active-admin`) et permet les mises à jour.
2. **Gardez le débogage USB actif et le PC autorisé** (« Toujours autoriser depuis cet ordinateur ») : l'issue de secours passe
   par ADB. Vigie ne coupe jamais le débogage ; Auto Blocker peut le faire (§1.2).
3. **Lancez `rescue-revert` à vide avant toute politique** (§12), et refaites-le après chaque mise à jour de l'APK.
4. **L'issue de secours ne répond qu'après le premier déverrouillage suivant un redémarrage.**
5. **Faites toujours « Tout rétablir » (ou `rescue-revert --sweep`) avant de retirer le rôle de Device Owner** : `pm unhide` est
   probablement refusé au shell ADB, un paquet resté masqué ne se réaffiche alors plus qu'en redonnant le rôle à Vigie.
6. **Pas d'utilisateur invité, pas de mode maintenance Samsung** tant que le DNS privé est imposé (Android refuse alors les API
   DNS dédiées ; Vigie se replie par un réglage global, non vérifié sur appareil).
7. **AdGuard ne doit pas bloquer les domaines de test de connectivité** (`connectivitycheck.gstatic.com`…) : le téléphone
   afficherait « connecté, sans Internet ». Les exceptions de `vigie-base.txt` les protègent : ne les retirez pas.
8. **Comptez 15 minutes sans Internet avant le repli du DNS** si le serveur tombe (délai réglable de 5 à 240 minutes).
9. **Si le serveur est sur un réseau privé** (adresse en 192.168.x, 10.x…), Android 17 exige la permission
   `ACCESS_LOCAL_NETWORK` : `grant-adb-permissions` l'accorde (avec un VPS public, elle ne sert pas).
10. **Le code de commande** (§15) : cinq mots tirés au hasard, réservé à cet usage, noté ailleurs que sur le téléphone. Il ne
    vaut que par son entropie ; le changer sur le téléphone rend caduques toutes les commandes déjà signées.
11. **Le compagnon de notifications** (§17) doit être signé par la **même clé** que l'agent ; un compagnon signé autrement
    est refusé à l'installation.

## 0. Ce qui change sur votre téléphone

Le mode **Device Owner** donne à Vigie les pouvoirs d'un administrateur d'entreprise sur le téléphone : journaux réseau
et de sécurité du système, DNS privé imposé, désactivation d'applications, restrictions. Il s'active par ADB, sans
réinitialisation, **mais** à condition que le téléphone n'ait ni compte, ni deuxième utilisateur. Conséquences à
accepter avant de commencer :

| Effet | Détail | Confiance |
|---|---|---|
| **Dossier sécurisé** indisponible | Il faut le supprimer pour activer le Device Owner ; il reste impossible à recréer ensuite | restriction posée par Android, vérifiée dans le code AOSP ; comportement exact de Samsung non vérifié |
| **Dual Messenger**, **espace privé**, profil professionnel indisponibles | idem | idem |
| **Comptes à retirer puis remettre** | Google, Samsung, messageries… Retirer un compte efface du téléphone ce qui n'y existe que localement pour ce compte (contacts ou agenda synchronisés avec lui, par exemple) | comportement général d'Android |
| Mention **« appareil géré »** | affichée dans les réglages rapides et sur l'écran de verrouillage | documentée |
| Notification **« réseau surveillé »** | Android l'affiche au plus deux fois (au plus une par 24 h) quand le journal réseau est actif, puis un texte permanent dans les réglages rapides | documentée |
| **Sauvegarde Android coupée** | Android la désactive à l'activation ; le profil équilibré de Vigie la réactive | vérifié dans le code AOSP |
| **Samsung Wallet / Pay / Pass** | effet **inconnu** (aucune source fiable) | non vérifié |
| **Google Wallet, applications bancaires** | le Device Owner n'affecte pas en soi Play Integrity ; les risques indirects (options développeur, débogage USB, Play Protect) sont à tester | non vérifié |
| Mises à jour Samsung (OTA) | non bloquées par Vigie ; leur interaction avec le Device Owner n'est pas vérifiée | non vérifié |

Ce qui **ne change pas** : vos applications, photos, fichiers et réglages restent en place.

## 1. Avant de commencer : sauvegardes et vérifications

Faites cette section sans la raccourcir. Prévoyez une heure.

### 1.1 Sauvegardes

- **Smart Switch** (Samsung) vers le PC, ou la sauvegarde Samsung/Google de votre choix : une sauvegarde complète
  récente, **vérifiée** (en connaître le contenu), avant d'ouvrir quoi que ce soit.
- **Photos et vidéos** : confirmez qu'elles sont synchronisées ou copiées sur le PC.
- **Contenu du Dossier sécurisé et de Dual Messenger** : à sortir avant suppression (la suppression efface ce qu'ils
  contiennent). Vérifiez dans les réglages du Dossier sécurisé comment en sortir les fichiers avant de le désinstaller ;
  pour Dual Messenger, les données de la copie d'une application sont en principe perdues à la désactivation.
- **Messageries** : exportez ou sauvegardez vos conversations (WhatsApp, Signal, etc.) avec la fonction de sauvegarde de
  chaque application, **avant** de retirer son compte de la liste d'Android.
- **Authentification à deux facteurs** : assurez-vous de pouvoir **vous reconnecter** à vos comptes Google et Samsung
  quand vous les remettrez (mot de passe, codes de secours, second facteur qui ne dépend pas de ce téléphone). Si
  votre application d'authentification n'existe que sur ce téléphone, sachez la restaurer.
- **Cartes de paiement et Wallet** : notez ce que contiennent Google Wallet et Samsung Wallet ; sachez
  ré-enregistrer vos cartes. Gardez une carte physique sur vous pendant les premiers jours.
- **Réinitialisation d'usine** (dernier recours, guide 04) : sachez que, sur un téléphone qui a un compte Google, Android
  exige ensuite les identifiants de ce compte (protection antivol « FRP »). Connaissez-les.

### 1.2 Vérifier le téléphone

1. **Version d'Android** : Vigie exige Android 16 ou plus (`minSdk 36`). Paramètres › À propos du téléphone ›
   Informations sur le logiciel : Android 16 (One UI 8) ou 17 (One UI 9). Plus ancien : mettez à jour d'abord
   (sinon l'installation échoue avec `INSTALL_FAILED_OLDER_SDK`). Vous le confirmerez par ADB à l'étape 2.
2. **Blocage automatique (Auto Blocker)** : Paramètres › Sécurité et confidentialité › Auto Blocker (chemin habituel).
   Actif par défaut depuis One UI 6.1.1, il **bloque les commandes USB et l'installation hors boutique**. Désactivez-le
   pour les étapes 3 à 12. Une source de la recherche affirme que son mode « restrictions maximales » désactive les
   applications d'administration de l'appareil (ce qui serait critique pour Vigie) : **non vérifié**. Après
   l'installation, laissez-le **désactivé pendant toute la première semaine** (c'est le guide 06 qui vous fait tester sa
   réactivation) : il pourrait couper l'accès ADB, c'est-à-dire votre issue de secours.
3. **Protection avancée** (mode de Google, Android 16) : Paramètres › Google › Tous les services › Protection avancée
   (chemin donné par la recherche pour One UI 8). Si elle est active, désactivez-la : elle bloque aussi l'USB et la 2G
   et son effet sur un Device Owner tiers n'est pas vérifié.
4. **Dossier sécurisé, Dual Messenger, espace privé, profil professionnel, mode invité, utilisateurs
   supplémentaires** : à supprimer avant l'activation (chemins habituels : Dossier sécurisé › Paramètres › Plus de
   paramètres › Désinstaller ; Paramètres › Fonctions avancées › Dual Messenger ; Paramètres › Sécurité et
   confidentialité › Espace privé). Le script de l'étape 7 détecte ce qui reste ; vous pouvez le vérifier dès maintenant
   (étape 4).
5. **Charge** : batterie à plus de 50 %, câble USB de bonne qualité (câble « données », pas un câble de charge seule).

## 2. Activer le débogage USB

1. Paramètres › À propos du téléphone › Informations sur le logiciel : touchez sept fois « Numéro de build » ; saisissez
   votre code d'écran.
2. Paramètres › Options pour les développeurs › activez **Débogage USB**.
3. Branchez le téléphone au PC. Sur le téléphone, une fenêtre « Autoriser le débogage USB ? » apparaît : cochez
   « Toujours autoriser depuis cet ordinateur » et validez.

Sur le PC :

```bash
adb devices
adb shell getprop ro.build.version.sdk      # doit afficher 36 ou plus
```

```powershell
adb devices
adb shell getprop ro.build.version.sdk
```

Attendu : une ligne `<numéro de série>    device`. Si vous voyez :

| Affichage | Cause et remède |
|---|---|
| `unauthorized` | déverrouillez le téléphone, acceptez la fenêtre d'autorisation (débranchez/rebranchez si elle ne s'affiche pas) |
| liste vide | câble sans données, port USB, Auto Blocker encore actif, ou, sous Windows, pilote USB Samsung manquant (installez le pilote USB Samsung depuis le site du constructeur) ; essayez `adb kill-server` puis `adb devices` |
| `no permissions` / `offline` | `adb kill-server`, rebrancher, réautoriser |
| plusieurs appareils | `export ANDROID_SERIAL=<série>` (bash) ou `$env:ANDROID_SERIAL = '<série>'` (PowerShell) |

**Gardez le débogage USB actif tant que vous utilisez Vigie** : c'est la porte de secours. Vigie ne le coupe jamais.

## 3. Installer l'APK

Depuis le dossier `android/` du dépôt :

```bash
./scripts/install-apk.sh app/build/outputs/apk/release/app-release.apk
```

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\install-apk.ps1 -Apk app\build\outputs\apk\release\app-release.apk
```

Donnez toujours le chemin de l'APK **release** (voir le piège du guide 02 : sans argument, le script prend le debug
s'il n'y a pas de release signé ; il vous demande alors confirmation, répondez `non`). Un chemin relatif est lu depuis le dossier
d'où vous lancez le script. Attendu : `Success` d'`adb`, puis `Vigie installée.` et la ligne `versionName=…`.

| Échec | Cause et remède |
|---|---|
| `INSTALL_FAILED_OLDER_SDK` | Android inférieur à 16 : mettre à jour le téléphone |
| `INSTALL_FAILED_UPDATE_INCOMPATIBLE` | une autre version, signée autrement, est déjà installée : la désinstaller (si elle n'est pas Device Owner) ou reprendre le keystore d'origine |
| `INSTALL_FAILED_VERSION_DOWNGRADE` | `versionCode` plus petit que celui installé |
| `INSTALL_FAILED_TEST_ONLY` | l'installation sans `-t` : utilisez le script, pas un autre moyen |
| installation bloquée, ou une alerte Play Protect s'affiche | Auto Blocker encore actif ; ou une analyse Play Protect : notez le texte **exact** de l'alerte (guide 06) et ne désactivez pas Play Protect sans décider en connaissance de cause |

Ouvrez l'application **Vigie** sur le téléphone. Elle affiche l'écran d'accueil et, tant qu'elle n'est pas Device
Owner, un texte « Mode dégradé… » : c'est attendu. Fermez-la. Si elle affiche à la place **« Vigie n'a pas pu démarrer : … »**
(et « Rien n'est collecté »), notez le message complet : c'est un défaut de l'application, pas de votre téléphone (guide 06) ;
l'issue de secours reste utilisable si une politique était appliquée.

## 4. État de départ (à noter)

```bash
adb shell pm list users
adb shell dumpsys account | grep "Account {"
adb shell dpm list-owners
```

```powershell
adb shell pm list users
adb shell dumpsys account | Select-String 'Account \{'
adb shell dpm list-owners
```

À activer le Device Owner il faut : **un seul** `UserInfo{…}` (l'utilisateur 0), **aucune** ligne `Account {…}`, et
`dpm list-owners` sans propriétaire. Notez ce que vous voyez maintenant (la liste des comptes en particulier) : vous
en aurez besoin pour les remettre.

## 5. Retirer temporairement les comptes

Android refuse de nommer un Device Owner tant qu'un compte existe, **quel qu'il soit** (Google, Samsung, WhatsApp,
Signal, Microsoft…). Pour chaque ligne `Account {name=…, type=…}` listée : Paramètres › Comptes et sauvegarde › Gérer
les comptes › le compte › Supprimer le compte. Ordre suggéré : les comptes d'applications (messageries…) d'abord,
Google et Samsung en dernier, une fois vos sauvegardes vérifiées (section 1.1).

Relancez la commande de l'étape 4 : plus aucun `Account {`. Si un compte reste et que vous ne pouvez pas le
supprimer depuis les Paramètres, **notez son type** (`type=…`) et reportez-vous au guide 06 ; n'essayez pas de le forcer.

> Les comptes seront remis juste après l'activation (étape 7). Le Device Owner ne les interdit pas (la restriction
> correspondante n'est jamais posée par Vigie).

## 6. Dernier contrôle avant l'activation

Tant que Vigie n'est pas Device Owner, tout se défait en désinstallant l'application. Relisez cette liste :

- sauvegardes faites et vérifiées (section 1.1) ; vous savez vous reconnecter à vos comptes ;
- Auto Blocker et Protection avancée désactivés ; débogage USB autorisé (`adb devices` montre `device`) ;
- l'étape 4 montre un seul utilisateur et aucun compte ;
- le serveur répond (console accessible) et vous avez, ou pouvez produire, le fichier `.vigie` ;
- le guide 04 est ouvert et le PC reste branché au téléphone.

## 7. Activer le Device Owner

```bash
./scripts/enable-device-owner.sh
```

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\enable-device-owner.ps1
```

Le script vérifie, dans l'ordre : l'absence d'un autre propriétaire, un seul utilisateur, aucun compte, et signale si
l'APK n'est pas `testOnly` (auquel cas il demande confirmation : tapez `oui`). Puis il exécute
`dpm set-device-owner --user 0 io.github.erwsim.vigie/io.github.erwsim.vigie.policy.VigieAdminReceiver`.

Attendu : un message de `dpm` du type « Success: Device owner set to package… », puis
`Vigie est Device Owner. Ouvrez l'app : elle s'accorde ses permissions et active sa protection.` (le texte exact de
`dpm` est celui d'Android, non vérifié ici).

| Message | Cause et remède |
|---|---|
| « Un autre Device Owner ou Profile Owner est déjà défini » | une application d'entreprise ou de gestion est déjà propriétaire : identifiez-la (`adb shell dpm list-owners`) et retirez-la d'abord |
| « Plusieurs utilisateurs ou profils existent » | supprimez ce que le script liste (Dossier sécurisé, Dual Messenger…) |
| « Android refuse… tant qu'un compte existe » | retirez les comptes listés (étape 5) |
| `already several users` / `already some accounts` / `user limit reached` renvoyés par `dpm` | mêmes causes ; la mention « user limit reached » est signalée sur Samsung par d'autres projets **sans solution connue** : si elle apparaît alors que `pm list users` ne montre qu'un utilisateur, arrêtez-vous et notez tout (guide 06) |
| tout autre message de `dpm` | copiez-le intégralement ; n'insistez pas |

Si l'activation échoue : **rien n'a changé** sur le téléphone. Vous pouvez remettre vos comptes et en rester là.

**Immédiatement après le succès, remettez vos comptes** (Google d'abord, puis Samsung, puis le reste) : Paramètres ›
Comptes et sauvegarde › Gérer les comptes › Ajouter un compte. Vérifiez que le Play Store s'ouvre et que vous êtes
reconnecté. Samsung affiche désormais « appareil géré » : c'est attendu.

## 8. Premier lancement et permissions

Ouvrez **Vigie**. En Device Owner, l'application s'accorde elle-même ses permissions d'exécution (localisation, y
compris en arrière-plan, notifications, Bluetooth, téléphone…) et active la protection contre l'arrêt forcé.

Sur l'écran **Accueil**, section « Administration de l'appareil », vous devez lire :

- **Mode Device Owner : Oui** ;
- **Protection contre l'arrêt forcé** : active.

Si « Mode Device Owner » est « Non » alors que le script a réussi, fermez l'application, rouvrez-la ; sinon, guide 06.

Les permissions d'exécution ne sont accordées automatiquement qu'**une seule fois** par activation du Device Owner : si vous en
retirez une ensuite dans les Paramètres d'Android, Vigie ne la reprend pas d'elle-même. Le collecteur concerné passe
« indisponible », un événement `agent.tamper` (`permission_revoked`) est émis, et l'onglet Collecteurs propose de la redonner.

Puis les permissions qui ne s'obtiennent que par ADB (accès à l'utilisation, réglages sécurisés de la politique, attribution
expérimentale caméra/micro) :

```bash
./scripts/grant-adb-permissions.sh
```

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\grant-adb-permissions.ps1
```

Attendu : des lignes `✔ … — …` (PowerShell : `[OK]`) pour chaque permission. Une ligne « ignorée : non déclarée par
cette version de l'APK » est sans gravité. Une ligne « échec » : notez-la (guide 06). Le script n'accorde pas
`READ_LOGS` (Android 13 et plus exige un consentement à chaque lecture : inutilisable en continu).

## 9. Batterie

```bash
./scripts/battery-exemptions.sh
```

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\battery-exemptions.ps1
```

Attendu : quatre lignes de succès (exemption Doze, deux autorisations d'arrière-plan, seau de veille « active »). Puis,
**à la main** (aucune commande connue) : Paramètres › Batterie › Limites d'utilisation en arrière-plan › Applications
jamais en veille › ajoutez **Vigie** (chemin habituel, peut varier selon One UI). Sur l'Accueil de Vigie, « Optimisation de la
batterie » doit afficher « Désactivée pour Vigie ». Ne masquez pas l'application « Entretien de l'appareil » : elle
héberge cet écran (c'est un élément du profil strict, décoché par défaut).

## 10. Enrôler le téléphone

Dans l'ordre d'essai conseillé, cette section et la suivante se font **dès la phase 1**, avant le Device Owner : l'enrôlement
fonctionne en mode dégradé, et le fichier est le même après.

1. **Sur le serveur** : `sudo ./enroll.sh s25` (dossier `infra`) produit `s25.vigie`. Récupérez-le sur le PC :
   `scp vous@vps:~/vigie/infra/s25.vigie .` depuis le dossier `android/` de votre dépôt (les fichiers `*.vigie` y sont
   ignorés par git).
2. **Copier sur le téléphone, par câble** :

   ```bash
   ./scripts/push-enrollment.sh s25.vigie
   ```

   ```powershell
   powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\push-enrollment.ps1 -File .\s25.vigie
   ```

   Attendu : `Copié vers /sdcard/Download/s25.vigie`.
3. **Dans l'application** : Réglages › Enrôlement › « Importer un fichier .vigie » › Téléchargements › `s25.vigie`.
   Vérifiez le résumé avant de valider : **adresse d'ingestion** (`https://ingest.…`), nom, **autorité du serveur**
   (« Autorités publiques du système » avec Let's Encrypt), **DNS privé** (`dns.…`). Touchez « Enrôler cet appareil ».
4. Résultat attendu : le test de connexion affiche « Connexion réussie (heure du serveur : …) » et « Appareil enrôlé. Le
   fichier .vigie a été supprimé. » La clé privée est alors dans l'Android Keystore (non exportable).

| Message | Signification |
|---|---|
| « Fichier refusé : … » (certificat expiré, clé illisible, adresse non https…) | le fichier est invalide : régénérez-le sur le serveur |
| « Refusé par le serveur (401/403) : jeton ou certificat invalide, ou appareil révoqué » | le serveur ne reconnaît pas cet appareil : `sudo ./enroll.sh --list` ; régénérez un fichier |
| « Serveur injoignable : … » | DNS de `ingest.…` pas propagé, port 443 fermé, certificat serveur non valide : refaites les contrôles du guide 01 |
| « Le serveur répond, mais pour un autre identifiant d'appareil » | mauvais fichier : réimportez celui produit pour ce téléphone |
| « jeton d'appareil invalide » ou « identifiant d'appareil invalide » | le fichier est altéré ou tronqué (transfert, éditeur de texte) : régénérez-le et recopiez-le par câble sans l'ouvrir |

5. **Supprimez toutes les copies du fichier** (il contient la clé privée et le jeton) :

   ```bash
   ./scripts/push-enrollment.sh --remove s25.vigie
   rm -f s25.vigie            # sur le PC
   ```

   ```powershell
   powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\push-enrollment.ps1 -File .\s25.vigie -Remove
   Remove-Item .\s25.vigie
   ```

   et `shred -u s25.vigie` sur le serveur (guide 01). Le script de suppression retire la copie du téléphone si
   l'application n'a pas pu le faire elle-même.

## 11. Vérifier que les événements arrivent

1. **Dans l'application**, onglet Accueil, section « Serveur » : « Dernier envoi réussi » apparaît, sans « Dernière erreur ».
   Le bouton « Envoyer maintenant » force un envoi. L'onglet **Journal local** montre ce que l'agent émet.
2. **Sur le serveur** : `sudo ./enroll.sh --list` affiche un « dernier contact » récent pour `s25`.
3. **Dans la console** (`https://console.…`) : le sélecteur d'appareil en haut affiche `s25` avec un point vert
   (dernier contact de moins de 35 minutes). Vue d'ensemble : « Dernier contact », « Device Owner : Actif », la liste
   des collecteurs avec leur état. Page **Événements** : filtrez le type par `agent.` puis `security.posture` : vous
   devez voir au moins `agent.started`, `agent.heartbeat` (toutes les 15 minutes) et la posture.
4. **Délais à connaître** : les envois sont groupés (toutes les 15 minutes au plus). Les événements `net.dns`,
   `net.connect` et `security.log` sont livrés par le système **par lots**, avec jusqu'à 1 h 30 (réseau) ou 2 h
   (sécurité) de retard : leur absence dans la première heure est normale. `adb shell dpm force-network-logs` et
   `adb shell dpm force-security-logs` sont les commandes de test citées par la recherche pour les forcer ; elles
   n'ont pas été vérifiées sur le S25+.
5. **Lisez la posture initiale** : console › Sécurité › Posture. Un défaut **déjà présent à l'enrôlement** (chiffrement,
   débogage USB activé — vous l'avez activé — etc.) ne produit **pas d'alerte** Wazuh : c'est à vous de le lire ici.
6. **Dans Wazuh** (`https://siem.…`) : le tableau de bord « Vigie — sécurité du téléphone » commence à se remplir. Les alertes
   attendues pendant ces premières heures sont décrites au [guide 05](05-exploitation.md) (vous venez d'utiliser
   ADB : le journal de sécurité du système le signale).

## 12. Tester l'issue de secours **avant d'en avoir besoin**

Avant toute politique, vérifiez que le téléphone répond à l'ordre « Tout rétablir » envoyé par ADB :

```bash
./scripts/rescue-revert.sh
```

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\rescue-revert.ps1
```

Attendu : `Tout est rétabli (reverted=0…)`. Code de sortie 0. (Cette issue de secours ne répond qu'**après le premier
déverrouillage qui suit un redémarrage** du téléphone.) Si vous obtenez « Pas de réponse exploitable de Vigie » (code
5), l'issue de secours **ne fonctionne pas** sur votre téléphone : n'appliquez aucune politique, notez le message et
passez au guide 06. Ce test se refait après chaque mise à jour de l'APK. **Ensuite, redémarrez le téléphone, déverrouillez-le
et relancez `rescue-revert`** : il doit répondre de nouveau (avant le premier déverrouillage, il ne répond pas).

Faites aussi, une fois, le tour de l'écran **Réglages › Device Owner › Politique** : « Mode Device Owner : Oui »,
« Journal réseau » et « Journal de sécurité » actifs, aucune erreur.

## 13. Laisser tourner 24 à 48 heures sans politique

Vivez normalement. Surveillez : la **batterie** (Paramètres › Batterie : la part de Vigie), la **notification
permanente** (elle doit rester), les **erreurs** sur l'Accueil de Vigie, et la **régularité des envois** dans la
console. Un téléphone qui chauffe ou se vide anormalement, ou un agent qui s'arrête, se règle **avant** d'ajouter
une politique : voir guides 05 et 06.

## 14. Mettre la politique en service, progressivement

### Principes

- Rien n'est appliqué sans votre accord. L'écran est **Vigie › Réglages › Device Owner › Politique**. Vous y choisissez un
  profil (**Équilibré** par défaut ou **Strict**), des interrupteurs par élément (applications, permissions,
  restrictions, réglage), puis « Aperçu des changements » (la liste exacte de ce qui va changer) et « Appliquer ».
  Chaque élément appliqué a son bouton « Rétablir » ; « Tout rétablir » défait tout.
- **Les éléments recommandés du profil choisi sont allumés par défaut** (35 éléments pour l'équilibré, plus le DNS et
  la sauvegarde ; le verrou du DNS est **éteint** par défaut). Pour avancer par paliers, utilisez les boutons de l'écran :
  **« Tout décocher »** (carte Profil : éteint absolument tout, DNS, verrou et sauvegarde compris), puis cochez seulement
  ce que vous voulez essayer ; dans chaque carte (applications, permissions, restrictions), **« Tout décocher ici »** et
  **« Cocher les choix par défaut »** agissent sur la seule section ; **« Valeurs par défaut du profil »** réinitialise toute
  la sélection (et rallume donc tout).
- **Piège : la sélection est l'état voulu, pas une liste d'ajouts.** Ce qui est déjà appliqué et n'est plus coché est
  **rétabli** à l'application suivante. D'un palier au suivant, la sélection est mémorisée : **n'ajoutez que le nouvel élément**
  et ne rappuyez pas sur « Tout décocher » sans recocher ce qui est déjà en place (par exemple le DNS). **Lisez toujours
  l'aperçu avant « Appliquer »** : il liste chaque changement, « appliquer » ou « rétablir ». Une ligne qui n'est pas du palier :
  « Fermer » et corrigez.
- Entre deux paliers : **24 heures minimum** (recommandation de ce guide), avec les contrôles ci-dessous. Une seule
  chose à la fois : en cas de problème, vous saurez laquelle.
- Les « profils » de l'application (Équilibré/Strict, **sur le téléphone**) et celui du filtrage DNS (équilibre/strict,
  **sur le serveur**, `install.sh --profile`) sont **indépendants**. Gardez le DNS du serveur en équilibre tant que le
  profil du téléphone n'est pas stabilisé.
- Gardez sous la main : un PC avec `adb` et le [guide 04](04-retour-arriere.md).

### Contrôles à faire après chaque palier

| Contrôle | Comment |
|---|---|
| Redémarrage | redémarrez le téléphone ; l'agent revient, la notification Vigie est là |
| **Notifications push** | demandez à quelqu'un de vous écrire sur votre messagerie, téléphone verrouillé depuis plus de 10 minutes, d'abord sur Wi-Fi puis en données mobiles |
| **Play Store** | ouvrez-le, cherchez des mises à jour, installez ou mettez à jour une petite application |
| **Application bancaire** | ouvrez-la, connectez-vous, validez une opération de faible montant (validation par notification incluse) |
| **Paiement sans contact** | un vrai paiement de faible montant avec l'application que vous utilisez (Google Wallet ou Samsung Wallet), avec une carte physique en secours ; carte de transport si vous en avez une |
| Fonctions de base | appels, SMS, données mobiles, Wi-Fi, Bluetooth (voiture, écouteurs, montre), appareil photo, clavier |
| Mise à jour Samsung | Paramètres › Mise à jour logicielle › Télécharger et installer : doit répondre normalement |
| Vigie | Accueil sans erreur ; console : envois réguliers ; page Sécurité › Politique appliquée : chaque ligne `ok` |
| AdGuard (si DNS actif) | journal des requêtes : repérez des domaines bloqués liés à une application qui dysfonctionne |

Si quelque chose casse : **notez quoi et à partir de quand**, puis « Rétablir » le dernier élément appliqué ; si le
symptôme disparaît, c'est lui. S'il persiste, « Tout rétablir » : si le symptôme disparaît, la politique est en
cause ; sinon, la cause est ailleurs. Voir le guide 04 pour la marche à suivre.

### Palier 1 : le DNS privé seul

Objectif : vérifier que le téléphone sait résoudre par votre AdGuard et que rien d'autre ne change.

Avant : depuis votre PC, `python3 infra/tools/dot-query.py dns.vigie.exemple.fr example.org` doit répondre (guide 01).

Dans l'écran Politique :

1. **Profil** : Équilibré. Touchez **« Tout décocher »**.
2. Carte **DNS privé imposé** : allumez **« Imposer ce DNS »** seul. **« Verrouiller le réglage » reste éteint** (il l'est par
   défaut) : le verrou interdit de changer le DNS privé dans les Paramètres d'Android et vous ôterait cette porte de sortie
   tant que le serveur n'est pas éprouvé.
3. **Aperçu des changements** : une seule ligne doit apparaître, le DNS privé. Sinon « Fermer » et corrigez.
4. **Appliquer**.

Laissez le **repli** actif (Réglages › Device Owner › « Repli automatique du DNS privé », actif par défaut, 15 minutes).

Avant d'appliquer quoi que ce soit, Vigie teste depuis le téléphone que l'hôte répond (poignée de main TLS sur 853 et une
requête DNS) ; sinon, rien ne change et le journal indique « vérification préalable ».

Contrôles : la carte DNS affiche le mode et l'hôte ; sur Wi-Fi **puis en données mobiles**, naviguez et ouvrez deux
ou trois applications ; Paramètres › Connexions › Plus de paramètres de connexion › DNS privé (chemin habituel) affiche
votre hôte ; dans AdGuard Home, le journal des requêtes montre des requêtes du téléphone ; dans la console, page Sécurité ›
Politique appliquée : `private_dns_set` en réussite. Laissez tourner **plusieurs jours** : repérez les applications
qui se plaignent et les domaines bloqués dans le journal d'AdGuard (guide 05 pour débloquer).

**Test du repli (facultatif, jamais exécuté ; chez vous, sur Wi-Fi, PC à portée).** Vigie repasse le DNS en mode
automatique quand le réseau n'est plus « validé » **et** que l'hôte est injoignable en continu pendant 15 minutes (réglable
de 5 à 240, Réglages › Device Owner), et signale le repli par un `security.policy` de sévérité 2 (alerte Wazuh). Pour le
voir : sur le serveur `sudo docker compose stop adguardhome` ; le téléphone perd Internet ; patientez (jusqu'à 15 minutes
par défaut) jusqu'au retour d'Internet et à l'avertissement « En repli » de la carte DNS ; puis
`sudo docker compose start adguardhome` : l'hôte est réimposé dès qu'il répond. Si Internet ne revient pas après
20 minutes : `./scripts/rescue-revert.sh`. Le repli ne tourne que si le processus de Vigie est vivant (service de premier
plan, ou passage de maintenance toutes les 15 minutes) : un agent tué par la gestion de batterie ne le déclenche pas.

> Le compromis, dit plainement : avec le repli, quelqu'un qui bloque le port 853 vous fait basculer en DNS automatique
> (jamais en silence, c'est une alerte). Sans le repli, la protection prime : plus d'Internet tant que le serveur ne
> répond pas.

### Palier 2 : deux ou trois paquets à faible risque

Objectif : vérifier le mécanisme « désactiver puis rétablir » sur des applications que vous ne regretterez pas.

1. Gardez le DNS coché (voir le piège ci-dessus) et allumez **« Astuces »** (Samsung Tips, « suspendue » : son icône reste,
   grisée) et deux paquets « aucun effet visible connu » de risque faible : **Knox Analytics** et **Samsung Attribution**
   (« masqués »).
2. Aperçu : trois lignes « appliquer », rien d'autre. Appliquer. L'icône d'Astuces est grisée et ne s'ouvre plus ; le journal
   d'actions dit « réussi » trois fois.
3. Redémarrez, faites les contrôles du tableau, vivez un jour ou deux.
4. **« Tout rétablir »** (bas de l'écran), puis **comparez** : les applications sont redevenues normales, le DNS privé est aussi
   rétabli (« Tout rétablir » défait *tout* ce que Vigie a appliqué). Réappliquez ensuite le DNS (palier 1) et ce que vous voulez
   garder. Cette comparaison vous apprend que « Tout rétablir » fait bien ce qu'il dit, avant d'en avoir besoin.

Si cet essai échoue (journal « échec »), n'allez pas plus loin : notez l'erreur (guide 06).

### Palier 3 : le profil équilibré, en trois lots

Le profil équilibré coupe la télémétrie et la publicité Samsung/Google qui ne servent à rien d'autre ; les Services Google
Play, le Play Store, les notifications push et les applications bancaires **doivent** rester fonctionnels. Vous l'appliquez en
trois lots, avec les contrôles du tableau entre chacun (24 heures minimum). Restez sur le profil Équilibré et gardez coché
ce qui est déjà appliqué (DNS compris).

**Lot 3a : applications Samsung et Meta** (carte Applications : « Cocher les choix par défaut », puis **éteignez** les six
applications Google du lot 3b ; 19 de Samsung : Customization Service, Knox Analytics, DSMS, Device Quality
Agent, SVC Agent, Carrier Log Collector, CcInfo, Log Writer, Samsung Attribution, Device ID Service, SOH Service,
Galaxy Widget, Maps Agent, IPS Geofence, Network Diagnostic, Wi-Fi Network Diagnostics, QoS Indicator, Astuces,
Smart Suggestions ; plus Meta App Manager, Meta Services, Meta App Installer). Effets connus : plus
d'identifiant publicitaire Samsung, plus de suggestions personnalisées, diagnostic batterie de Samsung Members moins
détaillé. `diagmonagent` n'est volontairement jamais touché (liste de refus de Vigie) : le désactiver provoque une boucle de
relance qui fait chauffer le téléphone ; coupez plutôt « Envoyer les données de diagnostic » dans les réglages Samsung.

**Lot 3b : applications Google** (cochez-les une à une ; Android AdServices, On-Device Personalization, Federated Compute, Market Feedback Agent,
Google Partner Setup, Location History stub). Les trois premières sont des **modules système (Mainline)** : l'effet de leur
masquage est signalé « à vérifier après application ». Faites ce lot **seul**, puis redémarrez et vérifiez
**particulièrement** le Play Store et les mises à jour système (Paramètres › Mise à jour logicielle ; Google Play system
update).

**Lot 3c : restrictions, permission, réglage** (« Cocher les choix par défaut » dans les cartes Restrictions et Permissions
refusées, puis le réglage et la sauvegarde)

- Restrictions (5) : interdire l'ajout d'utilisateurs ; **interdire la 2G** (plus de réseau là où seule la 2G existe ; les appels
  d'urgence restent possibles) ; **interdire les sources inconnues** ; couper la capture de contenu ; couper les suggestions de
  contenu.
- Permission refusée (1) : Appli Google, localisation.
- Réglage : « Recherche Bluetooth permanente » coupée (exige `WRITE_SECURE_SETTINGS`, accordée à l'étape 8 ; `global:ble_scan_always_enabled` est l'un des deux seuls réglages que Vigie accepte d'écrire).
- Sauvegarde Android : « Réactiver la sauvegarde Android » (que le Device Owner avait coupée).

**Contrôle supplémentaire pour « Interdire les sources inconnues »** : le texte de l'application dit que l'installation par
ADB (donc les mises à jour de Vigie) n'est « pas concernée d'après la documentation (à vérifier) ». **Vérifiez-le
maintenant**, pas le jour d'une mise à jour : réinstallez le même APK
(`./scripts/install-apk.sh app/build/outputs/apk/release/app-release.apk` ou, sous PowerShell, la forme `powershell … -File .\scripts\install-apk.ps1 -Apk app\build\outputs\apk\release\app-release.apk` de la section 3) et constatez le succès, puis que
l'agent redémarre et que le Device Owner est toujours là. En cas d'échec, « Rétablir » cette restriction.

**Après les trois lots**, notez ce qui fonctionne. Plus tard, devant un comportement douteux, la comparaison « Tout
rétablir » puis réapplication du profil vous dit si la politique en est responsable.

### Palier 4 : le profil strict, élément par élément

Le profil strict **casse volontairement** des fonctions : compte Samsung, Galaxy Store, Samsung Cloud, Find My Mobile (par le
compte), notifications Samsung, Appli Google, Assistant et recherche vocale, mode sans échec, ajout de certificats. Ne le
choisissez que si vous avez décidé de vous en passer. Passez au profil Strict dans l'écran (les éléments de l'équilibré
restent). **À la bascule, les éléments du strict recommandés par défaut se cochent d'eux-mêmes** (8 applications dont le compte
Samsung, 2 permissions, 6 restrictions) : éteignez-les un par un, puis n'ajoutez **qu'un élément à la fois** en gardant coché ce
qui est déjà appliqué ; l'aperçu doit toujours montrer **une seule** ligne. Dans cet ordre de risque croissant, avec les
contrôles du tableau entre chaque :

1. Restrictions peu risquées : couper l'UWB, couper Thread, interdire le partage Bluetooth, couper le contenu envoyé à
   l'assistant.
2. Applications Samsung de services : OMC Agent, Update Center, Samsung Push Service, Samsung Cloud, Experience Service,
   KLMS Agent.
3. **Appli Google** (suspendue) et ses permissions (micro, caméra, contacts).
4. Restrictions « de confort perdu » : **interdire le mode sans échec** (vous perdez un recours si une application bloque le
   téléphone), **bloquer l'ajout de certificats** (Wi-Fi d'entreprise et VPN à certificat à configurer *avant*).
5. **Compte Samsung** (risque élevé : casse Galaxy Store, Samsung Cloud, Localiser mon appareil Samsung) : à n'appliquer que si
   vous n'en dépendez plus.

**Ne cochez jamais sans un plan précis** (ils sont décochés par défaut et marqués risque élevé ou critique) : Services
Google Play, Google Services Framework, Play Store (notifications push, applications bancaires, Play Store, Wallet),
Samsung Wallet / Pay / Pass, NFC (paiement sans contact), Find My Mobile (antivol), Entretien de l'appareil (fait
disparaître la liste « jamais en veille »), eSIM, transfert de fichiers USB. Le profil strict laisse la sauvegarde Android
coupée.

## 15. Mettre en service le canal de commandes à distance

À faire **après** la phase 5, jamais avant : le canal ajoute une connexion permanente au serveur (consommation à mesurer) et
des commandes dont l'une est irréversible. Le principe : le serveur ne peut transmettre qu'une liste fermée de commandes
(sonner, vibrer, arrêter la sonnerie, localiser, verrouiller avec un message, retirer ce message, effacer), jamais un réglage
ni une politique. Le canal est **coupé par défaut** ; chaque commande reçue s'affiche en notification et dans l'historique.

**Prérequis** : téléphone enrôlé ; Device Owner pour verrouiller, retirer le message et effacer (sonner, vibrer et localiser n'en
ont pas besoin).

1. Vigie › **Réglages › Commandes à distance** (ou la carte « Commandes à distance » de l'accueil). Allumez « Recevoir les
   commandes à distance ». Mode **Connexion permanente** (par défaut : commande reçue en quelques secondes ; chaque message de
   maintien du serveur, toutes les 2 minutes, réveille le modem) ou **Interrogation périodique** (1 à 15 minutes). La
   consommation n'a jamais été mesurée : après 24 heures, comparez la part de Vigie dans Paramètres › Batterie, d'abord en
   Wi-Fi puis en réseau mobile ; si elle est forte, passez en interrogation.
2. **Code de commande** (carte « Code de commande ») : 12 caractères au moins, saisi deux fois ; l'application refuse un code de
   moins de 6 caractères différents, ou fait de chiffres seulement en dessous de 20 chiffres. **Prenez cinq mots tirés au
   hasard** (par exemple avec des dés), **réservés à cet usage**, et notez-les dans votre gestionnaire de mots de passe : il
   vous sera demandé dans la console à chaque commande sensible. Saisissez-le à l'identique partout (évitez les caractères
   accentués composés). Le téléphone n'en garde qu'une clé dérivée, chiffrée par une clé du Keystore, après un calcul de quelques
   secondes (« Calcul de la clé… ») ; le serveur ne le reçoit jamais.
3. Dans la console, page **Commandes** : la carte « Canal de commandes » doit indiquer le téléphone connecté (mode permanent) ou
   un dernier contact récent (interrogation).
4. **Essais, dans l'ordre** (téléphone à portée de main) :
   - **Sonner** (carte « Actions simples ») : le téléphone sonne à plein volume même en silencieux ou en vibreur, une
     notification « Vigie fait sonner ce téléphone » apparaît avec un bouton **Arrêter** ; l'historique de la console passe à
     « exécutée ». Si « Ne pas déranger » coupe les alarmes, le son reste muet et le résultat le dit
     (`dnd_alarms_muted`) : la vibration et la notification restent. Essayez en mode silencieux, vibreur et « Ne pas déranger ».
   - **Localiser maintenant** : une position précise arrive sous une minute au plus (GPS ; en intérieur, il peut n'y en avoir
     aucune : résultat « échouée », `no_fix`, essayez dehors) et s'affiche sur la carte de la page. Elle respecte le collecteur
     de localisation : s'il est coupé ou sans permission, la commande échoue (`location_unavailable`).
   - **Verrouiller avec message** (carte « Actions sensibles ») : confirmation, puis le code de commande ; le téléphone se
     verrouille et affiche le message sur l'écran de verrouillage. Sans écran de verrouillage sécurisé, seul l'écran s'éteint.
     Déverrouillez normalement, puis **Effacer le message** (commande, ou bouton de l'écran de Vigie). Si le résultat est
     `failed` avec `lock_refused` (cas d'une mise à jour depuis une version antérieure), les politiques d'administration n'ont
     pas été rechargées : notez-le (guide 06).
   - Un code faux est refusé par le **téléphone** (`bad_signature`, alerte Wazuh de niveau 10) ; **cinq refus en une heure
     bloquent les commandes sensibles pendant une heure** (`locked_out`, niveau 12). Ne provoquez pas ce cas plus d'une fois.
5. Les validités par défaut : 1 heure pour une commande simple, 7 jours pour verrouiller ou retirer le message (30 au plus),
   **15 minutes pour effacer** (24 heures au plus).

**L'effacement à distance : ne l'activez pas maintenant.** « Autoriser l'effacement à distance » est éteint par défaut et ne
s'allume qu'avec un code défini et après avoir tapé « EFFACER ». Une commande signée avec votre code remet alors le téléphone à
zéro, **sans autre confirmation**, définitivement (la protection contre la réinitialisation, c'est-à-dire le compte Google
exigé au redémarrage, et les eSIM sont conservées). Son activation exige trois choses que vous n'avez pas encore :
l'avoir **essayé sur un appareil sacrifiable ou entièrement sauvegardé** (jamais exécuté sur un téléphone), la certitude que
votre code est fort, et la conviction que le verrouillage ne suffit pas. Dans la plupart des cas de perte, **verrouiller avec un
message suffit** (guide 04, « Si le téléphone est perdu »).

**Ce que la signature garantit, et ses limites** (contrat §8) : aucune commande sensible ne s'exécute sans une signature valide
pour le code défini sur le téléphone. Mais le serveur détient le contenu signé et peut chercher votre code hors ligne (d'où
les cinq mots) ; la page de la console où vous le tapez est servie par le serveur (un serveur compromis peut la modifier et le
lire à la saisie suivante) ; une commande signée reste exécutable jusqu'à son expiration, quoi qu'affiche la console (« annulée »
ou « expirée » n'engage que le serveur). **Seul le changement du code sur le téléphone** rend caduque une commande déjà signée :
c'est le geste à faire si vous doutez du serveur (guide 04).

## 16. Mettre en service les gardes de capacités, une par une

Les gardes verrouillent les capacités dont un logiciel malveillant a besoin (guide 08 pour le cas des SMS). Écran **Politique ›
Gardes**. Elles sont **toutes éteintes par défaut**, s'activent **une par une** par « Aperçu et activation » (l'aperçu dit quelle
application perd quoi), et se défont par « Aperçu et désactivation », « Tout rétablir », le retrait du Device Owner et
l'issue de secours ADB.

**Avant** : `rescue-revert` à vide réussi (§12), phase 5 stabilisée. **Méthode pour chaque garde** : activer, faire les
contrôles ci-dessous, puis **« Tout rétablir »** et vérifier que l'état d'avant revient (Paramètres › Applications › l'appli ›
Autorisations ; claviers ; accessibilité). « Tout rétablir » défait *tout* ce que Vigie a appliqué (DNS et paquets compris) et
éteint d'abord toutes les gardes : réappliquez ensuite ce que vous gardez, par « Aperçu » puis « Appliquer » pour la politique
et « Aperçu et activation » pour les gardes (la sélection est mémorisée). Quand vous avez vu cela fonctionner deux fois, vous
pouvez espacer les « Tout rétablir » (suggestion de ce guide).

L'ordre conseillé par l'application elle-même est : **Quarantaine, Claviers, Accessibilité, Appels, SMS, puis seulement les
options « aussi… »**, du moins au plus risqué.

| # | Garde | Contrôles après activation | Ce qui peut casser |
|---|---|---|---|
| 1 | **Quarantaine** (aucun effet immédiat) | Installez une petite application de test (APK ou boutique) : notification « Nouvelle application en quarantaine » ; Paramètres › Applications › l'appli › Autorisations : SMS, contacts, micro… grisés « contrôlé par l'administrateur ». « **Libérer** » (Gardes › Applications en quarantaine) : l'appli redemande. Mettez-la à jour : pas de nouvelle quarantaine. Console › Sécurité › Politique appliquée : `quarantined` et `released`. | une application toute neuve ne peut pas utiliser micro, caméra, contacts, SMS, appels, position en arrière-plan avant d'être libérée ; **l'appairage d'une montre, d'écouteurs, d'une voiture ou d'une serrure dont l'appli vient d'être installée échoue sans message** (Bluetooth et appareils à proximité) |
| 2 | **Claviers** (liste vide) | L'aperçu doit nommer comme « gardé » le clavier tiers éventuellement activé. Saisie normale, **y compris le code PIN après un redémarrage** (clavier Samsung). Paramètres › Gestion globale › Clavier : un clavier non approuvé n'est pas activable. | activer un nouveau clavier (Gboard, SwiftKey…) sans l'avoir ajouté à la liste ; aucun risque de rester sans clavier (un clavier déjà activé continue, celui du système reste proposé) ; la garde n'est appliquée que dans l'écran des Paramètres de One UI (**à vérifier**) |
| 3 | **Accessibilité** (liste vide) | Les services déjà activés sont gardés (Android l'exige) ; TalkBack et le Voice Assistant Samsung restent activables ; un service tiers non activé ne l'est plus (« désactivé par l'administrateur »). | nouveau gestionnaire de mots de passe, Tasker, MacroDroid, bloqueur ou lanceur qui utilise l'accessibilité, s'il n'est pas dans la liste |
| 4 | **Appels** (sans option) | L'aperçu est **rarement vide** (`CALL_PHONE` est demandée par messageries, banques, cartes, montre, voiture ; chaque application qui l'avait est arrêtée au refus). Appelez depuis le composeur et depuis le carnet d'adresses Samsung. Appel d'urgence : ne composez pas réellement, vérifiez seulement que le composeur s'ouvre. | appel direct depuis une appli tierce (domotique, montre, voiture, taxi) ; ouvrir le composeur avec un numéro prérempli reste possible ; le groupe « Téléphone » des applications refusées est gelé |
| 5 | **SMS** (sans option) | L'aperçu liste les applications tierces qui demandent `SEND_SMS`. Envoyez un SMS depuis Samsung Messages ; le SOS d'urgence reste intact (application du système). Changez d'appli SMS par défaut et vérifiez, en 10 à 20 secondes, la notification « Appli par défaut changée » et que la liste suit ; revenez ensuite à l'application d'origine. | messagerie vocale visuelle de l'opérateur, application de montre ou de voiture qui répond par SMS, vérification de numéro : à mettre dans la liste |
| 6 | **Options** « aussi… » (lecture des SMS ; décrocher et journal d'appels) | Avec une garde SMS ou Appels active : **changez d'appli SMS par défaut** pour une application que la garde refusait, vérifiez la notification dans les 10 à 20 secondes et que l'application envoie et reçoit sans rien redemander, puis revenez à l'application d'origine. | la saisie automatique des codes reçus par SMS cesse dans les applications tierces |

Après la dernière : `rescue-revert` **avec une garde active** (il doit les défaire), puis seulement en tout dernier
`remove-device-owner` (guide 04). Les **listes** d'une garde (applications autorisées, services approuvés) se modifient dans
l'écran ; la modification n'entre en vigueur qu'à « Aperçu et réapplication ». Les raisons des limites des gardes (application du
système, appli par défaut, service d'accessibilité déjà actif, fenêtre de quelques secondes à 15 minutes, groupes de permissions
gelés, autres utilisateurs) sont dans `android/README.md`, « Ce que les gardes ne peuvent pas empêcher ».

**Applications par défaut et profil de risque** : les collecteurs `app_risk` et `app_role` sont actifs par défaut (rien à
faire) ; ils alimentent la console (Applications › Risque, Sécurité › Rôles par défaut) et les détections. Le comptage
expérimental `app_ops` est **éteint par défaut** : ne l'activez que pour le vérifier (guide 08, §5).

## 17. Installer le compagnon de notifications (facultatif)

L'agent dit quelles applications affichent des notifications ; **lire** leur titre et leur texte demande un second APK,
**Vigie Notifications** (`io.github.erwsim.vigie.notifier`), séparé pour ne pas exposer l'APK Device Owner à Play Protect. Il
n'a pas la permission `INTERNET`, n'a aucune permission sensible, ne garde rien (ni historique, ni fichier) et remet les
notifications à l'agent par un canal local protégé par une permission de niveau signature. **Rien n'a jamais été essayé sur un
téléphone** ; la première inconnue est la réaction de Play Protect à son installation.

1. **Construire** avec la **même clé** que l'agent (guide 02, §5) : `notifier/build/outputs/apk/release/notifier-release.apk`.
2. **Installer** (depuis `android/`) :

   ```bash
   ./scripts/install-notifier.sh notifier/build/outputs/apk/release/notifier-release.apk
   ```

   ```powershell
   powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\install-notifier.ps1 -Apk notifier\build\outputs\apk\release\notifier-release.apk
   ```

   Attendu : « Vigie Notifications installé », puis « Même clé de signature que l'agent Vigie ». Échecs : `INSTALL_FAILED_DUPLICATE_PERMISSION`
   (autre clé : installez les deux APK issus de la même construction), alerte Play Protect (« appli nuisible bloquée » : notez le
   texte exact, l'agent n'est pas concerné et continue sans le compagnon), Auto Blocker (guide 03 §1.2).
3. **Accorder l'accès aux notifications** :

   ```bash
   ./scripts/notifier-access.sh
   ```

   ```powershell
   powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\notifier-access.ps1
   ```

   Le script utilise `cmd notification allow_listener` (non vérifié sur One UI 8/9) puis contrôle
   `enabled_notification_listeners`. S'il échoue : Paramètres › Notifications › … › « Accès aux notifications » › Vigie
   Notifications (le chemin varie) ; si l'interrupteur est grisé (« Paramètre restreint ») : Paramètres › Applications › Vigie
   Notifications › ⋮ › « Autoriser les paramètres restreints », puis accorder l'accès.
4. Ouvrez **Vigie Notifications** : accès accordé, service d'écoute connecté, agent présent (même clé), collecte active. Dans
   Vigie › Collecteurs › **Notifications**, le collecteur passe d'« indisponible » à « actif » (au plus tard au passage de
   maintenance de 15 minutes). Console › Applications › **Notifications** : les événements arrivent, **sans titre ni texte**.
5. **Régler** : dans Vigie, « Contenu des notifications » est **éteint par défaut** (ne l'allumez qu'après quelques jours) et
   « Masquer les codes numériques » est allumé ; dans le compagnon, les deux listes (applications exclues du contenu :
   banques, paiement, authentificateurs, gestionnaires de mots de passe, SMS et téléphone ; applications ignorées : rien
   ne part), **à compléter avec vos propres applications sensibles** : ce sont des noms de paquets exacts, la liste est donc
   forcément incomplète. Avec le contenu allumé, le titre et le texte (512 caractères au plus) partent chez **votre** serveur et
   sont conservés 90 jours dans les archives Wazuh ; le masquage remplace toute suite de 4 à 8 chiffres par `••••` mais masque
   aussi des années ou des codes postaux, et laisse passer des codes de 3 ou de 9 chiffres ou alphanumériques.
6. **Retirer** : couper le collecteur « Notifications » dans Vigie ; `./scripts/notifier-access.sh --revoke` (PowerShell : `notifier-access.ps1 -Revoke`) ; ou
   `./scripts/uninstall-notifier.sh` (PowerShell : même forme, `uninstall-notifier.ps1`).

À surveiller : le service d'écoute peut être arrêté par la gestion de batterie Samsung (ajoutez Vigie Notifications à
« Applications jamais en veille »).

## 18. Choisir le mode de localisation (facultatif)

Vigie › Collecteurs › **Localisation** › « Mode de localisation » :

| Mode | Ce qui part chez Google | Effet |
|---|---|---|
| **GPS seul** (défaut) | rien de la part de Vigie (l'assistance GNSS XTRA/SUPL est réglée par le système) | souvent aucune position en intérieur |
| **GPS + réseau** | réseaux Wi-Fi et antennes alentour (fournisseur réseau des Services Google Play, actif si « Précision de la localisation Google » est activée) | position approximative en intérieur en quelques secondes |
| **Fusionné** | idem (fournisseur fusionné des Services Google Play) | position rapide, souvent précise en intérieur |

`location.fix.provider` dit le fournisseur réel de chaque position. Si un fournisseur est absent, Vigie se replie sur le GPS seul.
Ces modes améliorent aussi `locate` (§15) en intérieur, au prix de ce qu'ils transmettent à Google : c'est votre choix.
Jamais essayés sur un téléphone.

Une fois la politique en place, la suite est dans le [guide 05](05-exploitation.md) (exploitation) ; en cas de problème,
[guide 04](04-retour-arriere.md) ; et les vérifications à faire cette première semaine sont dans le
[guide 06](06-verifications-sur-appareil.md).
