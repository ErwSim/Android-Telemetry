# 03 — Préparer et configurer le téléphone

Ce guide installe Vigie Agent sur votre Samsung Galaxy S25+, l'élève au rang de **Device Owner**, l'enrôle auprès
de votre serveur, puis met la politique anti-pistage en service **par paliers**. C'est le guide où une erreur peut
coûter cher : lisez-le en entier avant de commencer, et gardez [le guide 04 (retour en arrière)](04-retour-arriere.md)
ouvert dans un autre onglet.

Prérequis : le serveur tourne et répond ([guide 01](01-serveur.md)) ; vous avez un APK **release signé** et un
PC avec `adb` ([guide 02](02-compiler-apk.md)). Durée : une demi-journée pour les sections 1 à 12 ; la mise en service de
la politique (section 14) s'étale sur plusieurs jours, volontairement.

> **Statut de vérification : lisez ceci.** Rien dans ce guide n'a jamais été exécuté sur un téléphone, et les scripts
> PowerShell n'ont même pas été lancés une fois. Les commandes ont été relues contre les scripts du dépôt, les
> messages attendus viennent des scripts et de la recherche (`docs/research/android-plateforme.md`), pas d'une
> exécution. Quand ce guide donne un menu du téléphone, c'est le chemin habituel sur One UI : il peut varier selon la
> version. Au moindre écart avec ce qui est écrit ici, **arrêtez-vous**, notez ce que vous voyez (message exact,
> capture d'écran) et reportez-vous au [guide 06](06-verifications-sur-appareil.md). Ne forcez rien.

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
./scripts/install-apk.sh "$PWD/app/build/outputs/apk/release/app-release.apk"
```

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass     # une fois par fenêtre PowerShell
.\scripts\install-apk.ps1 -Apk app\build\outputs\apk\release\app-release.apk
```

Donnez toujours le chemin de l'APK **release** (voir le piège du guide 02 : sans argument, le script prend le debug
s'il n'y a pas de release signé ; il vous demande alors confirmation, répondez `non`). Sous bash, donnez un chemin
**absolu** (comme ci-dessus) : le script change de dossier avant de lire l'argument, donc un chemin relatif serait lu depuis
`android/scripts/`. Attendu : `Success` d'`adb`, puis `Vigie installée.` et la ligne `versionName=…`.

| Échec | Cause et remède |
|---|---|
| `INSTALL_FAILED_OLDER_SDK` | Android inférieur à 16 : mettre à jour le téléphone |
| `INSTALL_FAILED_UPDATE_INCOMPATIBLE` | une autre version, signée autrement, est déjà installée : la désinstaller (si elle n'est pas Device Owner) ou reprendre le keystore d'origine |
| `INSTALL_FAILED_VERSION_DOWNGRADE` | `versionCode` plus petit que celui installé |
| `INSTALL_FAILED_TEST_ONLY` | l'installation sans `-t` : utilisez le script, pas un autre moyen |
| installation bloquée, ou une alerte Play Protect s'affiche | Auto Blocker encore actif ; ou une analyse Play Protect : notez le texte **exact** de l'alerte (guide 06) et ne désactivez pas Play Protect sans décider en connaissance de cause |

Ouvrez l'application **Vigie** sur le téléphone. Elle affiche l'écran d'accueil et, tant qu'elle n'est pas Device
Owner, un texte « Mode dégradé… » : c'est attendu. Fermez-la.

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
.\scripts\enable-device-owner.ps1
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
.\scripts\grant-adb-permissions.ps1
```

Attendu : des lignes `✔ … — …` (PowerShell : `[OK]`) pour chaque permission. Une ligne « ignorée : non déclarée par
cette version de l'APK » est sans gravité. Une ligne « échec » : notez-la (guide 06). Le script n'accorde pas
`READ_LOGS` (Android 13 et plus exige un consentement à chaque lecture : inutilisable en continu).

## 9. Batterie

```bash
./scripts/battery-exemptions.sh
```

```powershell
.\scripts\battery-exemptions.ps1
```

Attendu : quatre lignes de succès (exemption Doze, deux autorisations d'arrière-plan, seau de veille « active »). Puis,
**à la main** (aucune commande connue) : Paramètres › Batterie › Limites d'utilisation en arrière-plan › Applications
jamais en veille › ajoutez **Vigie** (chemin habituel, peut varier selon One UI). Sur l'Accueil de Vigie, « Optimisation de la
batterie » doit afficher « Désactivée pour Vigie ». Ne masquez pas l'application « Entretien de l'appareil » : elle
héberge cet écran (c'est un élément du profil strict, décoché par défaut).

## 10. Enrôler le téléphone

1. **Sur le serveur** : `sudo ./enroll.sh s25` (dossier `infra`) produit `s25.vigie`. Récupérez-le sur le PC :
   `scp vous@vps:~/vigie/infra/s25.vigie .` depuis le dossier `android/` de votre dépôt (les fichiers `*.vigie` y sont
   ignorés par git).
2. **Copier sur le téléphone, par câble** :

   ```bash
   ./scripts/push-enrollment.sh "$PWD/s25.vigie"      # chemin absolu : le script change de dossier avant de lire l'argument
   ```

   ```powershell
   .\scripts\push-enrollment.ps1 -File .\s25.vigie
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
   .\scripts\push-enrollment.ps1 -File .\s25.vigie -Remove
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
.\scripts\rescue-revert.ps1
```

Attendu : `Tout est rétabli (reverted=0…)`. Code de sortie 0. (Cette issue de secours ne répond qu'**après le premier
déverrouillage qui suit un redémarrage** du téléphone.) Si vous obtenez « Pas de réponse exploitable de Vigie » (code
5), l'issue de secours **ne fonctionne pas** sur votre téléphone : n'appliquez aucune politique, notez le message et
passez au guide 06. Ce test se refait après chaque mise à jour de l'APK.

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
  son verrou, plus la sauvegarde). **Il n'existe pas de bouton « tout décocher »** : pour avancer par paliers, vous
  éteignez à la main ce qui n'est pas du palier. La sélection est mémorisée ; « Valeurs par défaut du profil » la
  réinitialise (et rallume tout). **Lisez toujours l'aperçu avant « Appliquer »** : si une ligne n'est pas du palier,
  fermez-le et corrigez.
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

1. **Profil** : Équilibré.
2. Carte **DNS privé imposé** : « Imposer ce DNS » **allumé** ; **« Verrouiller le réglage » éteint**. Le verrou interdit de
   changer le DNS privé dans les Paramètres d'Android ; tant que le serveur n'est pas éprouvé, vous voulez garder cette
   porte (il est allumé par défaut).
3. Cartes **Applications désactivées**, **Permissions refusées**, **Restrictions de sécurité** : éteignez **tous** les
   interrupteurs (28 + 1 + 5). Carte **Réglages système** : éteignez « Recherche Bluetooth permanente » et « Réactiver la
   sauvegarde Android ».
4. **Aperçu des changements** : une seule ligne doit apparaître, le DNS privé. Sinon « Fermer » et corrigez.
5. **Appliquer**.

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

### Palier 2 : un paquet sans risque

Objectif : vérifier le mécanisme « désactiver puis rétablir » sur une application que vous ne regretterez pas.

1. Allumez **uniquement « Astuces »** (Samsung Tips, « suspendue » : son icône reste, grisée). Tout le reste éteint.
2. Aperçu : une ligne. Appliquer. L'icône d'Astuces est grisée et ne s'ouvre plus ; le journal d'actions dit « réussi ».
3. **Rétablir** : l'application redevient normale. Réappliquez si vous le souhaitez.

Si cet essai échoue (journal « échec »), n'allez pas plus loin : notez l'erreur (guide 06).

### Palier 3 : le profil équilibré, en trois lots

Le profil équilibré coupe la télémétrie et la publicité Samsung/Google qui ne servent à rien d'autre ; les Services Google
Play, le Play Store, les notifications push et les applications bancaires **doivent** rester fonctionnels. Vous l'appliquez en
trois lots, avec les contrôles du tableau entre chacun (24 heures minimum). Pour chaque lot, éteignez tout le reste.

**Lot 3a : applications Samsung et Meta** (19 de Samsung : Customization Service, Knox Analytics, DSMS, Device Quality
Agent, SVC Agent, Carrier Log Collector, CcInfo, Log Writer, Samsung Attribution, Device ID Service, SOH Service,
Galaxy Widget, Maps Agent, IPS Geofence, Network Diagnostic, Wi-Fi Network Diagnostics, QoS Indicator, Astuces,
Smart Suggestions ; plus Meta App Manager, Meta Services, Meta App Installer). Effets connus : plus
d'identifiant publicitaire Samsung, plus de suggestions personnalisées, diagnostic batterie de Samsung Members moins
détaillé. `diagmonagent` n'est volontairement jamais touché (liste de refus de Vigie) : le désactiver provoque une boucle de
relance qui fait chauffer le téléphone ; coupez plutôt « Envoyer les données de diagnostic » dans les réglages Samsung.

**Lot 3b : applications Google** (Android AdServices, On-Device Personalization, Federated Compute, Market Feedback Agent,
Google Partner Setup, Location History stub). Les trois premières sont des **modules système (Mainline)** : l'effet de leur
masquage est signalé « à vérifier après application ». Faites ce lot **seul**, puis redémarrez et vérifiez
**particulièrement** le Play Store et les mises à jour système (Paramètres › Mise à jour logicielle ; Google Play system
update).

**Lot 3c : restrictions, permission, réglage**

- Restrictions (5) : interdire l'ajout d'utilisateurs ; **interdire la 2G** (plus de réseau là où seule la 2G existe ; les appels
  d'urgence restent possibles) ; **interdire les sources inconnues** ; couper la capture de contenu ; couper les suggestions de
  contenu.
- Permission refusée (1) : Appli Google, localisation.
- Réglage : « Recherche Bluetooth permanente » coupée (exige `WRITE_SECURE_SETTINGS`, accordée à l'étape 8).
- Sauvegarde Android : « Réactiver la sauvegarde Android » (que le Device Owner avait coupée).

**Contrôle supplémentaire pour « Interdire les sources inconnues »** : le texte de l'application dit que l'installation par
ADB (donc les mises à jour de Vigie) n'est « pas concernée d'après la documentation (à vérifier) ». **Vérifiez-le
maintenant**, pas le jour d'une mise à jour : réinstallez le même APK
(`./scripts/install-apk.sh "$PWD/app/build/outputs/apk/release/app-release.apk"` ou `.\scripts\install-apk.ps1 -Apk app\build\outputs\apk\release\app-release.apk`) et constatez le succès, puis que
l'agent redémarre et que le Device Owner est toujours là. En cas d'échec, « Rétablir » cette restriction.

**Après les trois lots**, notez ce qui fonctionne. Plus tard, devant un comportement douteux, la comparaison « Tout
rétablir » puis réapplication du profil vous dit si la politique en est responsable.

### Palier 4 : le profil strict, élément par élément

Le profil strict **casse volontairement** des fonctions : compte Samsung, Galaxy Store, Samsung Cloud, Find My Mobile (par le
compte), notifications Samsung, Appli Google, Assistant et recherche vocale, mode sans échec, ajout de certificats. Ne le
choisissez que si vous avez décidé de vous en passer. Passez au profil Strict dans l'écran (les éléments de l'équilibré
restent), éteignez **tout ce qui n'est pas du palier en cours**, puis avancez **un élément à la fois**, dans cet ordre de risque
croissant, avec les contrôles du tableau entre chaque :

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

Une fois la politique en place, la suite est dans le [guide 05](05-exploitation.md) (exploitation) ; en cas de problème,
[guide 04](04-retour-arriere.md) ; et les vérifications à faire cette première semaine sont dans le
[guide 06](06-verifications-sur-appareil.md).
