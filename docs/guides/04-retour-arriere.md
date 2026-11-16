# 04 — Retour en arrière

Tout ce que Vigie fait est réversible. Ce guide va du geste le plus doux au plus radical : **arrêtez-vous au premier
qui règle votre problème**. Respirez : vous avez presque toujours une issue sans réinitialisation.

Les commandes se lancent depuis le dossier `android/` du dépôt, téléphone branché en USB, débogage USB actif. Sous
Windows, dans PowerShell, une fois par fenêtre : `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`.

> **Statut de vérification.** Aucun de ces gestes n'a jamais été exécuté sur un téléphone ; les scripts PowerShell n'ont
> jamais été lancés. Les messages cités viennent des scripts. Le [guide 06](06-verifications-sur-appareil.md) vous fait
> tester les niveaux 3 à 5 **à vide**, avant d'en avoir besoin.

## Symptôme, puis geste

| Symptôme | Premier geste | Si ça ne suffit pas |
|---|---|---|
| **Plus d'Internet** (depuis le DNS privé) | cas A ci-dessous | niveau 2, puis 3 |
| **Une application indispensable a disparu ou est grisée** | cas B ci-dessous | niveau 2 (« Tout rétablir »), puis 3 |
| **Plus de notifications** (push) | cas C ci-dessous | niveau 2, puis 3 |
| Application bancaire ou paiement sans contact en échec | niveau 2 : « Rétablir » le dernier élément appliqué, puis « Tout rétablir » pour comparer | niveau 3 |
| Plus de réseau mobile dans une zone | « Rétablir » la restriction « Interdire la 2G » | |
| Impossible d'installer ou de mettre à jour un APK | « Rétablir » la restriction « Interdire les sources inconnues » ; à défaut, niveau 3 | |
| L'application Vigie ne s'ouvre plus ou plante | niveau 3 (issue de secours) | niveau 4 puis 5 |
| Le téléphone chauffe ou se vide | niveau 1 (couper des collecteurs) | niveau 2 |
| Je veux tout arrêter d'un coup | niveau 4 (retirer le Device Owner) | |
| Rien ne marche et le téléphone est inutilisable | niveaux 3, 4, 5 dans l'ordre | niveau 6 (dernier recours) |

## Cas A — Plus d'Internet après le DNS privé

Le DNS privé est imposé par Vigie ; si votre serveur ne répond plus (VPS arrêté, AdGuard planté, port 853 bloqué par le
réseau où vous êtes), le téléphone n'a plus de DNS. C'est voulu (pas de fuite en clair). Dans l'ordre :

1. **Changez de réseau** : Wi-Fi ↔ données mobiles. Certains réseaux filtrent le port 853.
2. **Dans Vigie** (l'application s'ouvre sans Internet) : Réglages › Device Owner › Politique › carte « DNS privé imposé »
   › **Rétablir**. Le téléphone retrouve son DNS d'avant.
3. **Si le verrou était actif** (« Verrouiller le réglage » : le réglage Android est grisé), la solution 2 reste valable :
   « Rétablir » lève aussi le verrou. Si le verrou était *éteint*, vous pouvez aussi passer le DNS privé en
   « Automatique » dans Paramètres › Connexions › Plus de paramètres de connexion › DNS privé (chemin habituel).
4. **Depuis le PC** : niveau 3 plus bas (`rescue-revert`).
5. **Attendre** : si le repli est actif (par défaut), Vigie repasse seul en DNS automatique après 15 minutes
   d'injoignabilité (réglable de 5 à 240 minutes ; `security.policy` de sévérité 2). Jamais testé sur appareil.
6. **Côté serveur** (dossier `infra` du VPS) :

   ```bash
   sudo docker compose ps
   sudo docker compose restart adguardhome
   python3 tools/dot-query.py dns.vigie.exemple.fr example.org
   ```

   La dernière commande doit renvoyer une adresse (guide 01).

## Cas B — Une application a disparu ou est grisée

Une application « masquée » disparaît ; une application « suspendue » reste affichée, grisée.

1. Dans Vigie › Politique : cherchez-la dans « Applications désactivées » (ou lisez le « Journal des actions ») et touchez
   **Rétablir**.
2. À défaut, niveau 2 « Tout rétablir ».
3. Depuis le PC, si vous connaissez le nom du paquet (affiché sous chaque application dans l'écran Politique, par exemple
   `com.samsung.android.app.tips`) :

   ```bash
   adb shell pm unhide <paquet>
   adb shell pm unsuspend <paquet>
   ```

   ```powershell
   adb shell pm unhide <paquet>
   adb shell pm unsuspend <paquet>
   ```

   Préférez les niveaux 2 et 3 quand l'application Vigie répond : elle tient la liste de ce qu'elle a changé, `pm` non.

## Cas C — Plus de notifications

Causes possibles : un lot de la politique, un domaine de notification bloqué par AdGuard, le réseau (certains Wi-Fi
filtrent le port des notifications Google, 5228), ou la batterie de l'application concernée.

1. Testez en **données mobiles** puis en Wi-Fi.
2. Regardez le journal des requêtes d'AdGuard (`https://adguard.…`) : un domaine `mtalk…google.com` ou `fcm…` y est-il
   bloqué ? Par défaut ils sont autorisés par des exceptions (guide 05 pour en ajouter).
3. « Rétablir » le dernier élément appliqué ; puis « Tout rétablir » (niveau 2) pour trancher.

## Niveau 0 — Je veux juste que ça arrête d'envoyer

Dans Vigie › Accueil : interrupteur **« Collecte active »**. Rien ne part, rien n'est collecté. Les politiques déjà
appliquées restent en place (niveau 2 pour les défaire).

## Niveau 1 — Interrupteurs dans l'application

- **Onglet Collecteurs** : chaque collecteur a son interrupteur ; coupez celui qui chauffe ou gêne. Couper « Journal réseau »
  ou « Journal de sécurité » coupe aussi la journalisation du système.
- **Réglages › Enrôlement › Désenrôler** : efface la clé, le certificat, le jeton **et les événements encore en attente
  d'envoi** ; la collecte continue localement. À éviter si vous voulez conserver ce qui n'est pas encore parti (utilisez
  d'abord « Envoyer maintenant »).

## Niveau 2 — Politique : Rétablir et « Tout rétablir »

Dans Vigie › Réglages › Device Owner › Politique :

- **Rétablir** sous chaque élément appliqué (application, permission, restriction, DNS, réglage) : remet exactement
  l'état d'avant.
- **Tout rétablir** (bas de l'écran, confirmation) : défait tout ce que Vigie a appliqué, du plus récent au plus ancien. Un
  élément qui résiste reste listé avec son erreur : réessayez. Les journaux réseau et de sécurité restent actifs ;
  Vigie reste Device Owner.

Le « Journal des actions » de l'écran, et la console (Sécurité › Politique appliquée), disent ce qui a réussi ou échoué.

## Niveau 3 — L'issue de secours par ADB (l'application n'est pas utilisable)

Équivalent de « Tout rétablir », envoyé depuis le PC. Seul le shell ADB (ou le système) peut envoyer cet ordre ; aucune
autre application ne le peut. Il ne fait que **défaire**.

```bash
./scripts/rescue-revert.sh
./scripts/rescue-revert.sh --sweep      # en plus : rétablit tout ce que le catalogue a pu modifier, même sans trace dans l'état de Vigie
```

```powershell
.\scripts\rescue-revert.ps1
.\scripts\rescue-revert.ps1 -Sweep
```

**Limite :** l'application n'est pas démarrable avant le premier déverrouillage ; l'issue de secours ne répond donc
qu'**après avoir déverrouillé le téléphone au moins une fois depuis son dernier redémarrage**.

| Résultat | Signification | Que faire |
|---|---|---|
| `Tout est rétabli (reverted=…)`, code 0 | c'est fait | vérifier l'Internet et les applications |
| code 2, « Rétablissement partiel » | un élément résiste | relancer, puis `--sweep` (`-Sweep`) ; sinon niveau 4 |
| code 3, « Vigie n'est plus Device Owner » | Vigie ne peut plus rien défaire elle-même | le script contrôle l'état réel des paquets qu'elle avait masqués ou suspendus et tente `pm unhide` / `pm unsuspend` pour ceux qui le sont encore (niveau 5 pour la suite) |
| code 4, délai dépassé | l'opération continue sur le téléphone | relancer dans une minute |
| code 5, « Pas de réponse exploitable de Vigie » | téléphone pas déverrouillé depuis le redémarrage, application qui ne démarre pas, ou version sans issue de secours | déverrouiller et relancer ; sinon niveau 4 |

Si `adb devices` ne voit plus le téléphone : Blocage automatique (Auto Blocker) réactivé ou câble ; débloquez le
téléphone, désactivez Auto Blocker, rebranchez.

## Niveau 4 — Retirer le Device Owner

À faire quand vous voulez tout arrêter. Vigie défait sa politique, coupe les journaux, retire la protection contre
l'arrêt forcé, puis abandonne le rôle. Le retrait est annoncé : **pas de fausse alerte `agent.tamper`**.

- **Par l'application** (si elle répond) : Réglages › Device Owner › Politique › **Retirer le Device Owner** ; cochez
  « J'ai compris » et confirmez. Si quelque chose n'a pas pu être rétabli, l'application s'arrête avant le retrait et
  propose « Retirer quand même ».
- **Par le script** (sans interface) :

  ```bash
  ./scripts/remove-device-owner.sh              # ajoutez --uninstall pour aussi désinstaller Vigie
  ```

  ```powershell
  .\scripts\remove-device-owner.ps1             # ajoutez -Uninstall pour aussi désinstaller Vigie
  ```

  Répondez `oui` à la confirmation. Attendu : `Vigie n'est plus Device Owner`. Équivalent : `rescue-revert.sh --remove-owner`
  (PowerShell : `rescue-revert.ps1 -RemoveOwner`). **Si un élément n'a pas pu être défait, Vigie garde le rôle** (elle seule peut
  réessayer) : le script vous le dit et vous propose de **forcer** le retrait. Forcer laisse ces éléments en place ; selon la
  version d'Android, un paquet resté masqué ou suspendu ne peut ensuite plus être rétabli que par un Device Owner. Préférez
  d'abord `rescue-revert` puis `rescue-revert --sweep`.

Ensuite : Paramètres › Comptes et sauvegarde : réactivez la **sauvegarde Android** que le mode Device Owner avait coupée ;
vous pouvez désinstaller Vigie normalement ; côté serveur, révoquez l'appareil : `sudo ./enroll.sh --revoke dev_xxx`
(`sudo ./enroll.sh --list` donne l'identifiant). Vérification : `adb shell dpm list-owners` ne doit plus citer Vigie.

## Niveau 5 — `dpm remove-active-admin` (APK « testOnly » seulement)

Si l'application ne répond plus du tout (le script a affiché « Pas de réponse exploitable ») **et** que l'APK est
`testOnly` (la variante par défaut, guide 02), `remove-device-owner` vous propose ce repli ; répondez `oui`. Équivalent manuel :

```bash
adb shell dpm remove-active-admin --user 0 io.github.erwsim.vigie/io.github.erwsim.vigie.policy.VigieAdminReceiver
```

```powershell
adb shell dpm remove-active-admin --user 0 io.github.erwsim.vigie/io.github.erwsim.vigie.policy.VigieAdminReceiver
```

Attention : dans ce cas **Vigie ne défait rien elle-même**. Android lève en principe de lui-même les politiques d'un Device
Owner retiré, paquets masqués ou suspendus compris (affirmation des scripts, **non vérifiée**) ; le script contrôle l'état réel
de chaque paquet que Vigie avait masqué ou suspendu et ne tente `pm unhide` / `pm unsuspend` que pour ceux qui le sont encore.
Ces commandes peuvent être **refusées** au shell ADB : le recours est alors de **redonner le rôle à Vigie**
(`enable-device-owner`, comptes retirés, guide 03 étape 7) puis de lancer `rescue-revert` (Vigie a gardé la liste de ce qu'elle
avait appliqué). Contrôlez aussi le DNS privé (Paramètres › Connexions › Plus de paramètres de connexion › DNS privé) et que vos
applications marchent. Le retrait sera signalé par `agent.tamper` (`admin_disabled`, `device_owner_lost`) : c'est attendu.
C'est la raison pour laquelle il faut essayer les niveaux 2 à 4 **avant** celui-ci.

Avec un APK **non** testOnly, Android refuse cette commande (« Attempt to remove non-test admin »).

Pour vérifier chaque étape : `adb shell dpm list-owners` (ne doit plus citer Vigie).

## Niveau 6 — Réinitialisation d'usine (dernier recours)

Seulement si : l'APK n'est **pas** testOnly et l'application est inutilisable, ou si aucun des niveaux 3 à 5 ne vous rend un
téléphone utilisable.

- **Avant**, si le téléphone démarre encore : sauvegardez (Smart Switch, photos). Retirez votre compte Google (et Samsung)
  du téléphone avant la réinitialisation pour éviter le blocage antivol : sinon, Android exigera ensuite les identifiants
  du dernier compte Google (et éventuellement Samsung) enregistré. Ayez-les.
- **Comment** : Paramètres › Gestion globale › Réinitialisation › Rétablir la configuration d'usine (chemin habituel) ; si
  le téléphone ne démarre plus correctement, par le mode de récupération (combinaison de touches propre au modèle,
  indiquée par Samsung).
- **Effet** : tout est effacé, le Device Owner aussi. Vous repartirez de zéro : réinstallez, ou non, selon le guide 03.

Aucune de ces étapes n'est vérifiée sur ce téléphone ; la réinitialisation est le seul geste qui ne dépend pas de Vigie.

## Après un retour en arrière

- Notez ce qui s'est passé (le symptôme, le dernier élément appliqué, les messages) et reportez-le : c'est ce que le
  [guide 06](06-verifications-sur-appareil.md) et Claude Code ([guide 07](07-reprise-developpement.md)) utilisent
  pour corriger.
- Pour **revenir au Device Owner** après un retrait : retirez vos comptes, puis `enable-device-owner` (guide 03, étape 7).
