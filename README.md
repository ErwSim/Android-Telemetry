# Vigie

Vigie est une chaîne personnelle de sécurité et de réduction du pistage pour **le téléphone Android de son
propriétaire** (cible : Samsung Galaxy S25+, ROM d'origine, non rootée). Une application installée sur le
téléphone, **Vigie Agent**, observe ce que fait le téléphone (positions, réseau, applications, capteurs, posture de
sécurité), envoie ces observations à un serveur que vous administrez, applique localement une politique
anti-pistage et anti-logiciel-malveillant que vous choisissez, et reçoit, de ce même serveur, un petit nombre de
commandes d'une liste fermée (sonner, localiser, verrouiller, effacer) que vous activez vous-même.

## Ce que Vigie est, et ce qu'il n'est pas

- C'est un outil **personnel**, installé par vous, sur **votre** téléphone, qui rend visible ce que le téléphone
  fait réellement.
- Ce n'est **pas un outil de surveillance d'autrui** et il n'est **pas furtif** : l'agent affiche une notification
  permanente et garde son icône, l'écran d'accueil de l'application montre ce qui est collecté, chaque commande
  reçue du serveur s'affiche en notification, et Android affiche lui-même la mention « appareil géré » une fois le
  mode Device Owner activé. Il n'existe aucune fonction de masquage et il n'y en aura pas.
- **Principe sur ce que le serveur peut faire au téléphone** (décision du propriétaire du 16/11/2026) : le serveur
  ne décide de rien d'important. Le téléphone pousse ses événements ; dans l'autre sens, le serveur ne peut
  transmettre que des **commandes d'une liste fermée** (sonner, vibrer, arrêter la sonnerie, localiser,
  verrouiller avec un message, retirer ce message, effacer), **jamais** de configuration, de politique ni de
  changement d'enrôlement : toute la politique se règle dans l'application, sur le téléphone. Les commandes
  sensibles (verrouiller, effacer) portent une signature calculée dans votre navigateur à partir d'un **code de
  commande** que le serveur ne connaît pas ; le canal de commandes est **coupé par défaut** et l'effacement à
  distance est **interdit par défaut**, à autoriser à part.
- **Cette protection a des limites, dites sans détour** (contrat §8) : elle ne vaut qu'avec un code à forte entropie
  (cinq mots tirés au hasard, réservé à cet usage) ; la page où vous tapez ce code est servie par le serveur, donc un
  serveur compromis peut le lire à la saisie suivante ; une commande signée reste exécutable jusqu'à son expiration
  quoi qu'en dise la console (« annulée » ou « expirée » n'engage que le serveur) ; seul le changement du code sur
  le téléphone rend caduque une commande déjà signée. Un serveur compromis **peut** donc faire sonner le téléphone, le
  localiser, et, s'il obtient votre code, le verrouiller ou l'effacer (si vous l'avez autorisé).
- Aucune dépendance Google dans l'agent (ni Play Services, ni Firebase). Ni contenu de SMS, ni journal d'appels,
  ni frappe au clavier, ni capture d'écran, ni service d'accessibilité dans l'agent. La lecture des notifications vit
  dans un **APK compagnon séparé et optionnel** ; le titre et le texte ne sont collectés que si vous l'activez.

## Ce que Vigie fait aujourd'hui (versions 1, 1.1 et 1.2)

| Version | Contenu |
|---|---|
| **1** | collecte (25 collecteurs), tampon hors ligne, envoi par mTLS, DNS privé filtrant (AdGuard Home), SIEM (Wazuh), console web, politique anti-pistage (profils équilibré et strict), issue de secours par ADB |
| **1.1** | **commandes à distance** ; page **Pistage** de la console (bloqué ou autorisé par éditeur, domaine et application ; bloquer ou autoriser un domaine ; niveaux permissif, équilibré, strict) ; **APK compagnon de notifications** ; **modes de localisation** (GPS seul par défaut, « GPS + réseau », « fusionné », avec ce qui part alors chez Google) ; notifications des alertes par webhook ou e-mail ; renouvellement d'un appareil sans perdre son historique |
| **1.2** | écrite après qu'un précédent téléphone du propriétaire a subi un logiciel malveillant qui envoyait 2 000 SMS de hameçonnage par jour : **gardes de capacités** (SMS, appels, accessibilité, claviers, quarantaine des nouvelles applications) ; **profil de risque** des applications ; suivi des **applications par défaut** (SMS, composeur, clavier…) ; comptage **expérimental** des opérations sensibles ; **détections côté serveur** et page Détections de la console ; règles et corrélations Wazuh correspondantes |

## Vue d'ensemble

```
 Galaxy S25+                                   VPS (Docker Compose, 8 Go de RAM ou plus)
┌───────────────────────────┐               ┌────────────────────────────────────────────┐
│ Vigie Agent (Device Owner)│  HTTPS mTLS   │ Caddy (TLS ; certificat client exigé sur   │
│  collecteurs ─► tampon    │──────────────►│ ingest.*)                                  │
│  (Room/SQLite) ─► envoi   │  lots gzip    │   └► vigie-collector (Go, SQLite)          │
│                           │◄──────────────│         ├► console web (carte, pistage,    │
│  commandes (liste fermée, │  flux de      │         │   détections, commandes)         │
│  canal coupé par défaut)  │  commandes    │         └► events.ndjson ─► Wazuh manager  │
│ politique locale :        │               │ Wazuh indexer + dashboard (alertes, SIEM)  │
│  DNS privé imposé,        │  DNS sur TLS  │   └► notifications (webhook, e-mail)       │
│  applications désactivées,│  port 853     │ AdGuard Home (DNS filtrant, DoT)           │
│  restrictions, gardes     │──────────────►│   └► journal des requêtes ─► Wazuh         │
│ Vigie Notifications (APK  │               │                                            │
│  compagnon, optionnel)    │               │                                            │
└───────────────────────────┘               └────────────────────────────────────────────┘
```

Chemins entre le téléphone et le serveur : l'**ingestion** des événements et le **flux de commandes** (HTTPS avec
certificat client, c'est le téléphone qui ouvre la connexion dans les deux sens), le **DNS privé** (DNS sur TLS vers
AdGuard Home, qui bloque les domaines de pistage et journalise), et la **console** (que vous ouvrez dans un navigateur).

## Ce que Vigie collecte

25 collecteurs, chacun désactivable dans l'application (onglet Collecteurs) :

- **Position** : GPS et fournisseur passif par défaut. Deux autres modes sont un choix explicite : « GPS + réseau » et
  « fusionné » passent par les Services Google Play, et l'application dit pour chaque mode ce qui part alors chez Google.
- **Réseau** : connectivité, Wi-Fi (SSID et BSSID), cellule, Bluetooth, NFC, point d'accès, traceurs Bluetooth
  (AirTag, SmartTag, Tile), rétrogradation 2G, volumes de données par application.
- **Applications** : inventaire quotidien, installations, mises à jour, retraits, permissions, accès spéciaux
  (accessibilité, administrateur, superposition, VPN), application au premier plan, **profil de risque**, **applications
  par défaut**, et, de façon expérimentale, **usage des opérations sensibles** (envoi de SMS, appels, micro, caméra…).
- **Appareil** : écran, batterie, stockage, USB, démarrage et arrêt.
- **Capteurs** : usage de la caméra et du micro (le fait, l'heure, l'état de l'écran ; jamais le contenu).
- **Notifications** (avec l'APK compagnon seulement) : l'application, la catégorie, l'importance ; le titre et le texte
  seulement si vous l'activez, avec masquage des codes de 4 à 8 chiffres et une liste d'applications exclues (SMS,
  téléphone, banques courantes, authentificateurs, gestionnaires de mots de passe).
- **Mode Device Owner seulement** : journal réseau du système (requêtes DNS et connexions TCP par application),
  journal de sécurité du système (ADB, déverrouillages, certificats, installations de paquets…), posture de
  sécurité (chiffrement, démarrage vérifié, ADB, autorités de certification ajoutées…).

Le détail est dans [`android/README.md`](android/README.md) (tableau « Collecteurs ») et le format exact des
événements dans [`docs/contrat/contrat.md`](docs/contrat/contrat.md).

## Ce que Vigie bloque ou change

Rien n'est appliqué automatiquement : vous choisissez dans l'écran **Politique** de l'application, lisez
l'aperçu, puis appliquez. Chaque action est journalisée et réversible (« Tout rétablir », retrait du Device Owner,
issue de secours par ADB).

- **DNS privé imposé** vers votre AdGuard Home : listes de blocage (télémétrie Google et Samsung, publicité,
  traqueurs, domaines malveillants) et journal des requêtes. Trois niveaux, changeables depuis la console.
- **Applications Samsung, Google et Meta de télémétrie, de publicité ou de diagnostic** masquées ou suspendues
  (profil **équilibré**, par défaut : les Services Google Play, le Play Store, les notifications push et les
  applications bancaires restent fonctionnels). Le profil **strict** ajoute une dé-googlisation et une
  dé-samsungisation poussées qui casse volontairement des fonctions.
- Quelques **permissions refusées** à des applications Google ou Samsung, et des **restrictions de sécurité**
  (2G, sources inconnues, ajout de certificats…).
- **Gardes de capacités** (éteintes par défaut, une par une) : refuser `SEND_SMS` ou `CALL_PHONE` à toute application sauf
  une liste, n'autoriser que des services d'accessibilité et des claviers approuvés, **mettre en quarantaine** toute
  nouvelle application (permissions à risque refusées jusqu'à ce que vous la libériez).

## Ce que Vigie ne peut pas faire (limites réelles)

- **Contre un logiciel qui envoie des SMS à votre insu**, la vraie protection est la **garde SMS**, à activer ; la
  détection de l'envoi lui-même repose sur un comptage **expérimental jamais vu fonctionner**. Une application qui se fait
  désigner appli SMS par défaut n'est pas bloquée, seulement signalée. Lisez le
  [guide 08](docs/guides/08-sms-et-logiciels-malveillants.md) avant de vous croire protégé.
- Les **détections** et le **profil de risque** sont des **indices**, pas des verdicts : le score mesure des capacités
  *déclarées*, un contrôle parental, un antivirus ou une application d'automatisation sortent « élevé », et un logiciel
  malveillant discret publié sur une boutique peut sortir « faible ». « Rien à signaler » n'est pas une garantie.
- **Pas d'attribution fiable de la caméra et du micro à une application** : Android ne donne pas le paquet aux
  applications ordinaires. Vigie sait *qu'*ils sont utilisés, pas toujours *par qui* (une attribution
  expérimentale existe, désactivée par défaut, jamais testée).
- **Le journal réseau du système ne voit que le DNS et les connexions TCP** passant par la bibliothèque système.
  Le trafic UDP/QUIC, les adresses IP codées en dur et le DNS chiffré propre à une application lui échappent. Il est
  livré par lots, avec jusqu'à 1 h 30 de retard. Le journal d'AdGuard (tout le DNS du téléphone, en direct) et les
  volumes par application complètent le tableau. Les octets par éditeur de la vue Pistage sont des **estimations**.
- **La télémétrie des Services Google Play ne peut pas être filtrée par le DNS sans casser le Play Store** : une
  partie passe par des domaines partagés (`play.googleapis.com`, `www.googleapis.com`). Seul le profil strict
  (désactivation des Services Google Play) la supprime, au prix des notifications push, de la plupart des
  applications bancaires et du Play Store.
- **Les gardes ont des angles morts** : application du système ou appli SMS/composeur par défaut jamais touchées, service
  d'accessibilité déjà activé (il peut éteindre les gardes), quelques secondes à 15 minutes avant qu'une nouvelle
  application soit mise en quarantaine, groupes de permissions gelés, applications d'un autre utilisateur ou profil.
- **Le compagnon de notifications** ne lit que ce qu'Android lui remet ; la liste d'exclusion est une liste de noms de
  paquets forcément incomplète ; la réaction de Play Protect à son installation est inconnue.
- **Rien n'est collecté entre un redémarrage et le premier déverrouillage** (Direct Boot non utilisé) ; l'issue de
  secours par ADB ne répond pas non plus avant.
- Le **mode Device Owner a des effets de bord** sur un Samsung : Dual Messenger, espace privé et profil professionnel
  deviennent impossibles (et le Dossier sécurisé très probablement aussi), la sauvegarde Android est coupée (le profil
  équilibré la réactive), Android affiche « appareil géré » et une notification de surveillance réseau. Voir le [guide 03](docs/guides/03-telephone.md).
- Wazuh ne déclenche **qu'une règle par événement**, et un défaut **déjà présent à l'enrôlement** ne produit pas
  d'alerte : lisez la posture initiale dans la console. Les notifications d'alerte (webhook, e-mail) sont désactivées
  tant que vous ne les configurez pas.

## État de vérification

Dit sans détour : **rien de ce qui touche au téléphone n'a jamais été exécuté sur un vrai appareil**, y compris tout ce
que les versions 1.1 et 1.2 ajoutent. Le propriétaire est le premier à le faire ; le
[guide 06](docs/guides/06-verifications-sur-appareil.md) est la feuille de route de la première semaine d'essai.

| Élément | Testé par exécution (environnement de développement) | Jamais testé sur appareil | Non testé du tout |
|---|---|---|---|
| Collecteur Go (ingestion, stockage, API, export Wazuh, renouvellement d'appareil, commandes, pistage, détections) | `go vet`, `go test -race`, essais réels avec le simulateur et ses scénarios d'attaque, image Docker construite et lancée, revues de sécurité (v1, v1.1) et revue indépendante de la v1.2 ; renouvellement et flux de commandes à travers Caddy en mTLS | — | — |
| Console web (dont Commandes, Pistage, Détections, Risque) | typage, lint, tests Vitest, parcours Chromium contre un serveur factice **et** contre le vrai collecteur (huit types de détection, parc sain) | — | tuiles OpenStreetMap réelles ; rendu du tableau de bord Wazuh « détections et applications » dans un navigateur |
| Pile serveur (Docker Compose, mode TLS interne) | installation complète et rejouée, mTLS, DNS sur TLS, vrai AdGuard Home (blocage, niveaux, règles posées par la console), export vers Wazuh sans perte, 209 cas de règles Wazuh, préservation des réglages utilisateur, renouvellement des certificats Wazuh, notifications par webhook et e-mail (récepteur local), sauvegarde puis restauration | — | Let's Encrypt réel, défi DNS-01 (mode ClientID), listes HaGeZi réelles par Internet (testées via un faux CDN), listes Multi PRO, résolution amont par Quad9, WireGuard, mémoire avec les listes chargées, ARM, SMTP avec TLS et authentification, ntfy réel, `update.sh` |
| Agent Android : code | compilation, lint, 392 tests JVM (dernier décompte de `android/README.md`), conformité au contrat des collecteurs, essais croisés du vrai code d'envoi, de commandes et de détections contre le vrai collecteur, APK release et compagnon signés (même clé) et inspectés | — | — |
| Agent Android : comportement | — | **tout** : Device Owner sur S25+, service 24 h, Keystore et TLS client, journaux réels, GPS, batterie, interface, politique, DNS privé et repli, issue de secours par ADB, canal de commandes (sonner, localiser, verrouiller, **effacer**), gardes et quarantaine, rôles par défaut, comptage `app.ops`, modes de localisation, compagnon et Play Protect | Robolectric (indisponible), tests instrumentés |
| Scripts ADB bash (`android/scripts/*.sh`, dont ceux du compagnon) | syntaxe, relecture, exécution contre un `adb` factice | exécution sur un téléphone | — |
| Scripts PowerShell (`android/scripts/*.ps1`) | relus ligne à ligne contre les `.sh` | — | ni exécutés ni analysés par PowerShell (absent de l'environnement de développement) |
| Ces guides | commandes relues contre les scripts et le code ; `apksigner` et `aapt2` exécutés sur les APK construits (agent et compagnon) | — | aucun guide n'a été suivi de bout en bout par une personne |

Sources : [`docs/ETAT.md`](docs/ETAT.md), `infra/README.md` §11, `android/README.md` (dernière section).

## Les guides

À suivre dans l'ordre pour une première installation :

1. [Installer le serveur](docs/guides/01-serveur.md) : VPS, DNS, installation, pare-feu, premier accès, sauvegardes.
2. [Compiler l'APK](docs/guides/02-compiler-apk.md) : Windows ou Linux/macOS, keystore (à conserver !), vérification.
3. [Préparer et configurer le téléphone](docs/guides/03-telephone.md) : Device Owner, permissions, enrôlement, puis
   mise en service **progressive** de la politique. Le guide critique.
4. [Retour en arrière](docs/guides/04-retour-arriere.md) : tout défaire, du plus doux au plus radical. À garder
   ouvert pendant le guide 03.
5. [Exploitation](docs/guides/05-exploitation.md) : console, alertes Wazuh, AdGuard, mises à jour, renouvellements.
6. [Vérifications à faire sur l'appareil](docs/guides/06-verifications-sur-appareil.md) : tout ce qui n'a jamais été
   vérifié, ordonné par risque.
7. [Reprendre le développement](docs/guides/07-reprise-developpement.md) : cloner, construire, tester, lancer le
   serveur en local avec le simulateur, pistes suivantes.
8. [Suis-je protégé contre un logiciel qui envoie des SMS à mon insu ?](docs/guides/08-sms-et-logiciels-malveillants.md) :
   ce qui l'empêche, l'angle mort, ce qui le détecte, ce qui n'a jamais été vu fonctionner.

## Les trois avertissements essentiels

1. **Gardez le keystore de signature, chiffré et hors de l'ordinateur.** Android n'accepte une mise à jour que
   signée par la même clé ; pour une application Device Owner, il n'existe pas de contournement, et le compagnon de
   notifications doit être signé par la même clé que l'agent (guide 02).
2. **Vous activez le Device Owner sur votre téléphone de tous les jours, sans test préalable sur un autre appareil.**
   Gardez le débogage USB actif, un PC sous la main et le [guide 04](docs/guides/04-retour-arriere.md) ouvert ;
   appliquez la politique par étapes, jamais d'un bloc (guide 03). Aucune des fonctions « irréversibles » (effacement à
   distance) ne s'active avant d'avoir été essayée sur un appareil sacrifiable ou entièrement sauvegardé.
3. **Un DNS privé imposé dont le serveur tombe coupe Internet sur le téléphone.** C'est voulu (pas de fuite en
   clair), mais testez-le d'abord avec le verrou du DNS éteint (il l'est par défaut), sur Wi-Fi, chez vous, et lancez `rescue-revert` à vide
   avant toute politique : l'issue de secours ne répond qu'après le premier déverrouillage qui suit un redémarrage (guides 03 et 04).

## Arborescence du dépôt

```
Android-Telemetry/
├── README.md                    ce fichier
├── CLAUDE.md                    consignes pour Claude Code (à lire en premier pour développer)
├── docs/
│   ├── ARCHITECTURE.md          décisions, principes non négociables, composants
│   ├── ETAT.md                  état d'avancement et de vérification (fichier de reprise)
│   ├── contrat/contrat.md       format des événements et API : référence commune
│   ├── research/                recherches (plateforme Android/Samsung, serveur SIEM/DNS)
│   └── guides/                  les guides ci-dessus
├── android/                     Vigie Agent (Kotlin) ; README.md, ARCHITECTURE-CODE.md
│   ├── core/  collectors/  policy/  app/  notifier/    modules Gradle (notifier = APK compagnon)
│   └── scripts/                 scripts ADB en double (.sh et .ps1)
├── server/
│   ├── collector/               collecteur Go (ingestion, API, export Wazuh, CLI, simulateur)
│   └── console/                 console web (React, Vite)
└── infra/                       Docker Compose, Caddy, AdGuard Home, Wazuh, scripts d'installation ; README.md
```

Les secrets (`.env`, `.vigie`, `.p12`, keystore, mots de passe) sont générés localement et ne sont jamais versionnés.
