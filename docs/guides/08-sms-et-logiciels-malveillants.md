# 08 — Suis-je protégé contre un logiciel qui envoie des SMS à mon insu ?

Ce guide répond sans détour à la question qui a motivé la version 1.2 : sur un précédent téléphone du propriétaire, un
logiciel malveillant envoyait environ **2 000 SMS de hameçonnage par jour** sans que l'application SMS ne montre rien.
Il dit ce que Vigie empêche, ce qu'il ne peut pas empêcher, ce qu'il détecte, et ce qui n'a **jamais été vu fonctionner**.

> **Statut de vérification.** Tout ce qui suit a été vérifié par des tests et des essais sur la JVM, contre le vrai
> collecteur, avec le simulateur et ses scénarios d'attaque. **Rien n'a été exécuté sur un téléphone** : ni la garde
> SMS, ni la quarantaine, ni le suivi des applications par défaut, ni le comptage des envois. Les cases à cocher du
> [guide 06](06-verifications-sur-appareil.md) servent à le vérifier.

## 1. La réponse courte

- **Ce qui l'empêche** : la **garde SMS**, *si vous l'avez activée* (elle est éteinte par défaut) et *si* l'application
  malveillante cherche à envoyer des SMS en demandant la permission `SEND_SMS` de façon ordinaire.
- **L'angle mort** : une application qui se fait désigner **appli SMS par défaut** (une boîte de dialogue du système, un
  seul appui) peut envoyer des SMS. Vigie **ne la bloque pas** : il la **signale** (notification prioritaire, alerte).
- **Ce qui le détecte sans le comptage expérimental** : une application qui n'est ni l'appli SMS ni du système **détient**
  la permission d'envoi ; une application à risque est installée ; l'appli SMS par défaut change. Jamais le *volume*
  des envois.
- **Ce qui le détecte avec le comptage** : les envois eux-mêmes, dès la première heure. Mais ce comptage est
  **expérimental, éteint par défaut, et n'a jamais été vu fonctionner** : **considérez-le comme absent** tant que vous ne
  l'avez pas vérifié sur votre téléphone (section 5).
- **La mesure indépendante de Vigie** : l'opérateur (section 6).

## 2. Ce qui l'empêche : la garde SMS

Écran **Vigie › Réglages › Device Owner › Politique › Gardes › SMS** (Vigie doit être Device Owner).

**Ce qu'elle fait.** Elle refuse la permission `SEND_SMS` à **toute application qui la demande, sauf une liste** que vous
choisissez (pré-remplie avec l'appli SMS par défaut). Elle s'applique aux applications déjà installées (une permission déjà
accordée est retirée, ce qui arrête l'application) et à celles installées ou mises à jour ensuite. Une permission refusée
par Vigie est verrouillée dans les Paramètres (« contrôlé par l'administrateur »). Une option « Refuser aussi la lecture et
la réception des SMS » ajoute `READ_SMS`, `RECEIVE_SMS`, `RECEIVE_MMS` et `RECEIVE_WAP_PUSH` : elle empêche aussi le vol des
codes reçus par SMS, mais la saisie automatique de ces codes dans les applications tierces cesse.

**Conditions pour qu'elle protège** :

1. Vigie est Device Owner, et la garde est **activée** (« Aperçu et activation », lisez l'aperçu : il dit quelle application
   perd quoi, puis confirmez). Aucune garde n'est activée tant que vous ne l'avez pas fait.
2. L'application malveillante passe par la demande de permission ordinaire.
3. Le téléphone et l'agent tournent : entre l'installation d'une application et le refus, comptez **quelques secondes, jusqu'à
   15 minutes** si le processus de Vigie était arrêté. Une application fraîchement installée ne s'exécute pas avant
   d'être lancée, mais une application qui en installe et lance une autre le peut.

**Effets de bord** (l'aperçu les dit) : une application légitime qui envoie des SMS (messagerie qui envoie aussi des SMS,
messagerie vocale visuelle de l'opérateur, application de montre ou de voiture qui répond par SMS, vérification de numéro)
perd cette fonction tant que vous ne l'avez pas mise dans la liste. Le groupe « SMS » de chaque application refusée est
**gelé** dans les Paramètres (vous ne pouvez plus lui accorder ni retirer les autres permissions SMS).

**La quarantaine** est une seconde couche : toute application non système installée *après* l'activation se voit refuser
SMS, appels, journal d'appels, contacts, micro, caméra, position en arrière-plan et appareils à proximité, jusqu'à ce que
vous la « libériez » (Politique › Gardes › Applications en quarantaine). Elle ne touche pas les applications déjà présentes.
Une notification vous prévient à chaque nouvelle mise en quarantaine.

## 3. L'angle mort : une application désignée appli SMS par défaut

C'est la voie classique des chevaux de Troie SMS. L'application demande à devenir l'appli SMS par défaut ; Android affiche
une boîte de dialogue ; **un seul appui** suffit. Elle reçoit alors les permissions du rôle SMS, et **la garde SMS ne la
bloque pas** : une garde ne touche jamais le détenteur du rôle correspondant.

Ce que fait Vigie : il lui accorde les permissions du rôle (sinon les SMS entrants seraient perdus sans bruit), l'ajoute à la
liste de la garde, et **vous prévient** :

- une **notification prioritaire** « Attention : appli par défaut changée » (affichée en haut de l'écran et sur l'écran
  verrouillé), qui nomme le paquet ; une application en quarantaine désignée appli SMS **reste en quarantaine** pour tout le
  reste (contacts, micro, caméra…), la notification le dit ;
- l'événement `app.role` (alerte Wazuh 100511, niveau 8) et la détection `detect.default_app_changed` (sévérité 3, alerte
  Wazuh 100476, niveau 12), non masquable dans la console.

**Que faire** si vous n'avez pas choisi cette application : remettez votre application SMS dans Paramètres › Applications ›
Applications par défaut (chemin habituel, peut varier selon One UI), retirez l'intruse de la liste de la garde dans Vigie,
puis désinstallez-la (si elle est administrateur de l'appareil, retirez d'abord ce droit). Contrôlez la facture de l'opérateur.

**Autres angles morts des gardes** (liste complète dans `android/README.md`, « Ce que les gardes ne peuvent pas empêcher ») :
un **service d'accessibilité déjà activé** appuie à votre place, y compris dans Vigie pour éteindre une garde (l'écran de
Vigie ne redemande pas le code de déverrouillage avant ces actions : piste suivante) ; les **applications du système** ne sont
jamais touchées ; un SMS préparé par une application puis envoyé par l'appli SMS (il faut un appui sur Envoyer, ou un service
d'accessibilité) ; les messageries par Internet ; ce qui a été envoyé **avant** l'activation de la garde.

## 4. Ce qui le détecte, sans le comptage

Les détections sont calculées côté serveur et affichées dans la page **Détections** de la console (guide 05) ; Wazuh les
reçoit aussi. Sans le comptage expérimental :

| Ce qui est vu | Détection | Gravité | Alerte Wazuh |
|---|---|---|---|
| Une application qui n'est **ni l'appli SMS par défaut ni une application du système** *détient* `SEND_SMS` | `detect.sms_permission` | 2 | 100475, niveau 10 |
| L'appli SMS (ou composeur, clavier, assistant) par défaut a **changé** | `detect.default_app_changed` | 3 pour le SMS, 2 pour les autres | 100476 (12), pour le SMS |
| Une application installée depuis moins de 24 h est à **risque élevé** ou obtient une capacité sensible | `detect.new_app_risky` | 1 à 3 | 100470 à 100474 |
| Une application obtient `SEND_SMS`, `READ_SMS`, `RECEIVE_SMS` ou `RECEIVE_MMS` (événement brut, indépendant du collecteur) | `app.permission_changed` | | 100161, niveau 8 |

À savoir :

- `detect.sms_permission` se déclenche à la **première observation**, inventaire initial compris : un téléphone sain a souvent
  quelques applications non système qui détiennent `SEND_SMS` (messagerie vocale visuelle, application d'opérateur, montre
  connectée). Vous recevrez donc **une détection chacune, une seule fois** : c'est une revue initiale voulue ; examinez-les,
  puis rangez celles que vous connaissez par la mise en sourdine (guide 05).
- Le **profil de risque** d'une application mesure des capacités *déclarées* : une application sans icône installée **hors
  boutique** qui déclare l'envoi de SMS et le démarrage au boot sort « élevé » dès l'installation ; la même application venue
  du **Play Store** ne sort que « moyen », et une application qui ne déclare rien de suspect peut sortir « faible ». C'est un
  indicateur d'attention, pas un verdict.
- **Le cas réellement subi** (application du Play Store, permission d'envoi obtenue plus de 24 h après l'installation, serveur
  absent des listes de menaces), rejoué sur le serveur sans le comptage : **une seule détection**, `detect.sms_permission`,
  au moment où la permission est détenue. Rien à l'installation, et jamais le nombre de SMS envoyés. C'est cette alerte-là
  (niveau 10, donc notifiée au seuil par défaut) qu'il ne faut pas laisser passer.
- **Les notifications d'alerte** (guide 05, §3) sont à 10 par défaut : l'alerte « permission SMS accordée » (100161) et
  « nouvelle appli SMS par défaut » (100511) sont de niveau 8 et **ne sont pas notifiées** à ce seuil. Baissez
  `VIGIE_NOTIFY_LEVEL` à **8** pour les recevoir (guide 05, §3).

## 5. Ce qui le détecte avec le comptage expérimental (`app_ops`) : à considérer comme absent

Le collecteur **« Usage des opérations sensibles (expérimental) »** lit l'historique des opérations d'Android (`appops`) et
compte, par application et par heure, les accès autorisés **et refusés** à l'envoi de SMS, aux appels, au micro, à la
caméra… Avec lui, `detect.sms_abuse` (gravité 3, alerte 100462 de niveau 12) signale une application autre que l'appli SMS qui
a envoyé ou tenté d'envoyer des SMS (les tentatives refusées par la garde comptent), ou un volume au-delà de 200 par jour.

**Pourquoi il faut le tenir pour absent.**

- Il est **éteint par défaut** et **n'a jamais été vu fonctionner** : le format du texte qu'il lit a été relevé dans le code
  d'Android 14, 15 et 16, jamais observé sur un Samsung ; Android 16 peut le rendre indisponible (indicateur de stockage de
  l'historique), SELinux peut refuser la lecture. S'il ne peut pas lire, il s'annonce « indisponible » sans dommage.
- Un envoi bloqué *par la garde* peut ne jamais atteindre l'opération comptée (la permission est refusée plus tôt) : donc
  ne jamais apparaître. Non vérifié.
- La console affiche « **Non surveillé ici** » (page Détections et vue d'ensemble) tant que le dernier battement de cœur du
  téléphone ne le signale pas « en marche » ; et « en marche » ne prouve pas que des données arrivent.

**Comment le vérifier sur votre téléphone** (commande donnée par `android/README.md`) :

1. Téléphone branché, `./scripts/grant-adb-permissions.sh` accorde `DUMP` et `PACKAGE_USAGE_STATS` (les deux sont exigées :
   `DUMP` seule est refusée). Sous PowerShell : `powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\grant-adb-permissions.ps1`.
2. Dans Vigie › Collecteurs, activez « Usage des opérations sensibles (expérimental) ».
3. Vérifiez que le système tient bien cet historique :

   ```bash
   adb shell dumpsys appops --history --op SEND_SMS
   ```

   ```powershell
   adb shell dumpsys appops --history --op SEND_SMS
   ```

   Attendu : des lignes du type `[bg-s] = access=N`. Sans elles, le collecteur se déclarera indisponible : le comptage ne
   fonctionnera pas sur votre téléphone, et la protection repose alors sur la garde et sur les détections de la section 4.
4. Envoyez un SMS depuis Messages, relancez la commande : le compteur de l'application Messages doit augmenter.
5. Une heure plus tard, console › Applications › **Opérations sensibles** : l'événement `app.ops` doit apparaître. Une
   détection `sms_abuse` ne se déclenche que pour une autre application que l'appli SMS ; ne cherchez pas à la provoquer
   avec une application inconnue.

Tant que ces cinq points ne sont pas constatés, notez dans votre tête : *je ne sais pas compter les SMS envoyés*.

## 6. La mesure indépendante de Vigie : l'opérateur

Vigie ne peut ni limiter ni compter de façon fiable les SMS qui quittent le téléphone. Une mesure qui **ne dépend ni du
téléphone ni de Vigie** vaut donc plus que toutes les autres. Demandez à votre opérateur (l'offre dépend de l'opérateur et
n'a pas été vérifiée ici) :

- un **plafond** ou une **alerte** sur le volume de SMS envoyés ;
- le **blocage des SMS surtaxés** et des numéros courts ;
- le détail de vos envois sur la facture ou l'espace client, que vous consulterez de temps en temps.

## 7. Que faire pour être raisonnablement couvert (et que faire si vous soupçonnez quelque chose)

**Mise en place**, dans l'ordre prudent du guide 03 (une garde à la fois, avec les contrôles) :

1. quarantaine, claviers, accessibilité, appels, puis **SMS** ; l'option « aussi la lecture » en dernier ;
2. dans Vigie, laisser le collecteur d'inventaire, de risque et d'applications par défaut actifs (ils le sont par défaut) ;
3. abaisser `VIGIE_NOTIFY_LEVEL` à 8 et configurer une notification (guide 05) ;
4. examiner la revue initiale de la page Détections ;
5. demander le plafond à l'opérateur.

**Si vous soupçonnez un logiciel malveillant** :

1. console › **Détections** puis Applications › **Risque** (premier onglet) et **Accès spéciaux** : quelle application est
   à risque élevé, a l'accessibilité, est administrateur, a été installée hors boutique ?
2. Applications par défaut (Sécurité › Rôles par défaut) : l'appli SMS est-elle la vôtre ?
3. Désinstallez l'application suspecte (retirez-lui d'abord les droits d'administrateur et d'accessibilité), contrôlez la
   facture de l'opérateur, changez les mots de passe saisis depuis ce téléphone.
4. Si vous ne la trouvez pas ou si elle revient : sauvegarde, puis réinitialisation d'usine (guide 04, niveau 6).

## 8. Récapitulatif

| Situation | Empêchée ? | Détectée ? |
|---|---|---|
| Application qui demande `SEND_SMS` | **oui**, si la garde SMS est activée | oui, par `sms_permission` (détention) ; les envois : seulement avec le comptage, qui n'a jamais été vu fonctionner |
| Application qui se fait désigner appli SMS par défaut | **non** (signalée seulement) | **oui**, notification prioritaire et alerte |
| Service d'accessibilité déjà activé qui envoie à votre place | non | indirectement (accès spéciaux, risque) |
| Application du système compromise | non | non |
| Envoi avant l'activation de la garde ou dans les quelques secondes d'une installation | non | selon le cas |
| Volume des envois | non | **seulement l'opérateur** (ou le comptage expérimental) |
