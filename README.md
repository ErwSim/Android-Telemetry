# Vigie

Vigie est une chaîne personnelle de télémétrie de sécurité et de réduction du pistage pour **le téléphone Android
de son propriétaire** (cible : Samsung Galaxy S25+, ROM d'origine, non rootée). Une application installée sur le
téléphone, **Vigie Agent**, observe ce que fait le téléphone (positions, réseau, applications, capteurs, posture de
sécurité), envoie ces observations à un serveur que vous administrez, et applique localement une politique
anti-pistage que vous choisissez (DNS filtrant, désactivation d'applications de télémétrie Google et Samsung,
restrictions de sécurité).

## Ce que Vigie est, et ce qu'il n'est pas

- C'est un outil **personnel**, installé par vous, sur **votre** téléphone, qui rend visible ce que le téléphone
  fait réellement.
- Ce n'est **pas un outil de surveillance d'autrui** et il n'est **pas furtif** : l'agent affiche une notification
  permanente et garde son icône, l'écran d'accueil de l'application montre ce qui est collecté, et Android affiche
  lui-même la mention « appareil géré » une fois le mode Device Owner activé. Il n'existe aucune fonction de
  masquage et il n'y en aura pas.
- Le flux est **à sens unique** : le téléphone envoie, le serveur ne peut ni commander le téléphone ni modifier sa
  politique. Un serveur compromis ne donne donc aucun contrôle sur l'appareil. Corollaire : Vigie n'est pas non
  plus un antivol (pas de verrouillage ni d'effacement à distance).
- Aucune dépendance Google dans l'agent (ni Play Services, ni Firebase). Ni contenu de SMS, ni journal d'appels,
  ni frappe au clavier, ni capture d'écran, ni service d'accessibilité, ni contenu des notifications.

## Vue d'ensemble

```
 Galaxy S25+                                   VPS (Docker Compose, 8 Go de RAM ou plus)
┌───────────────────────────┐               ┌────────────────────────────────────────────┐
│ Vigie Agent (Device Owner)│  HTTPS mTLS   │ Caddy (TLS ; certificat client exigé sur   │
│  collecteurs ─► tampon    │──────────────►│ ingest.*)                                  │
│  (Room/SQLite) ─► envoi   │  lots gzip    │   └► vigie-collector (Go, SQLite)          │
│                           │               │         ├► console web (carte, tableaux)   │
│ politique locale :        │               │         └► events.ndjson ─► Wazuh manager  │
│  DNS privé imposé,        │  DNS sur TLS  │ Wazuh indexer + dashboard (alertes, SIEM)  │
│  applications désactivées,│  port 853     │ AdGuard Home (DNS filtrant, DoT)           │
│  restrictions             │──────────────►│   └► journal des requêtes ─► Wazuh         │
└───────────────────────────┘               └────────────────────────────────────────────┘
```

Trois chemins distincts entre le téléphone et le serveur : l'**ingestion** des événements (HTTPS avec certificat
client, vers la console Vigie et Wazuh), le **DNS privé** (DNS sur TLS vers AdGuard Home, qui bloque les domaines de
pistage et journalise), et la **console** (que vous ouvrez dans un navigateur).

## Ce que Vigie collecte

21 collecteurs, chacun désactivable dans l'application (onglet Collecteurs) :

- **Position** : GPS et fournisseur passif (pas les fournisseurs « réseau » ou « fusionné », qui passent par les
  Services Google Play).
- **Réseau** : connectivité, Wi-Fi (SSID et BSSID), cellule, Bluetooth, NFC, point d'accès, traceurs Bluetooth
  (AirTag, SmartTag, Tile), rétrogradation 2G, volumes de données par application.
- **Applications** : inventaire quotidien, installations, mises à jour, retraits, permissions, accès spéciaux
  (accessibilité, administrateur, superposition, VPN), application au premier plan.
- **Appareil** : écran, batterie, stockage, USB, démarrage et arrêt.
- **Capteurs** : usage de la caméra et du micro (le fait, l'heure, l'état de l'écran ; jamais le contenu).
- **Mode Device Owner seulement** : journal réseau du système (requêtes DNS et connexions TCP par application),
  journal de sécurité du système (ADB, déverrouillages, certificats, installations de paquets…), posture de
  sécurité (chiffrement, démarrage vérifié, ADB, autorités de certification ajoutées…).

Le détail est dans [`android/README.md`](android/README.md) (tableau « Collecteurs ») et le format exact des
événements dans [`docs/contrat/contrat.md`](docs/contrat/contrat.md).

## Ce que Vigie bloque ou change

Rien n'est appliqué automatiquement : vous choisissez un profil dans l'écran **Politique** de l'application, lisez
l'aperçu, puis appliquez. Chaque action est journalisée et réversible.

- **DNS privé imposé** vers votre AdGuard Home : listes de blocage (télémétrie Google et Samsung, publicité,
  traqueurs, domaines malveillants) et journal des requêtes.
- **Applications Samsung, Google et Meta de télémétrie, de publicité ou de diagnostic** masquées ou suspendues
  (profil **équilibré**, par défaut : les Services Google Play, le Play Store, les notifications push et les
  applications bancaires restent fonctionnels). Le profil **strict** ajoute une dé-googlisation et une
  dé-samsungisation poussées qui casse volontairement des fonctions.
- Quelques **permissions refusées** à des applications Google ou Samsung, et des **restrictions de sécurité**
  (2G, sources inconnues, ajout de certificats…).

## Ce que Vigie ne peut pas faire (limites réelles)

- **Pas d'attribution fiable de la caméra et du micro à une application** : Android ne donne pas le paquet aux
  applications ordinaires. Vigie sait *qu'*ils sont utilisés, pas toujours *par qui* (une attribution
  expérimentale existe, désactivée par défaut, jamais testée).
- **Le journal réseau du système ne voit que le DNS et les connexions TCP** passant par la bibliothèque système.
  Le trafic UDP/QUIC, les adresses IP codées en dur et le DNS chiffré propre à une application lui échappent. Il est
  livré par lots, avec jusqu'à 1 h 30 de retard. Le journal d'AdGuard (tout le DNS du téléphone, en direct) et les
  volumes par application complètent le tableau.
- **La télémétrie des Services Google Play ne peut pas être filtrée par le DNS sans casser le Play Store** : une
  partie passe par des domaines partagés (`play.googleapis.com`, `www.googleapis.com`). Seul le profil strict
  (désactivation des Services Google Play) la supprime, au prix des notifications push, de la plupart des
  applications bancaires et du Play Store.
- **Pas de notifications** (ni contenu, ni métadonnées) : un service d'écoute des notifications dans l'APK
  déclencherait Play Protect. Piste v2 : module séparé.
- **Rien n'est collecté entre un redémarrage et le premier déverrouillage** (Direct Boot non utilisé).
- Le **mode Device Owner a des effets de bord** sur un Samsung : Dual Messenger, espace privé et profil professionnel
  deviennent impossibles (et le Dossier sécurisé très probablement aussi), la sauvegarde Android est coupée (le profil
  équilibré la réactive), Android affiche « appareil géré » et une notification de surveillance réseau. Voir le [guide 03](docs/guides/03-telephone.md).
- Wazuh ne déclenche **qu'une règle par événement**, et un défaut **déjà présent à l'enrôlement** ne produit pas
  d'alerte : lisez la posture initiale dans la console.

## État de vérification

Dit sans détour : **rien de ce qui touche au téléphone n'a jamais été exécuté sur un vrai appareil**. Le propriétaire
est le premier à le faire ; le [guide 06](docs/guides/06-verifications-sur-appareil.md) est la feuille de route de la
première semaine d'essai.

| Élément | Testé par exécution (environnement de développement) | Jamais testé sur appareil | Non testé du tout |
|---|---|---|---|
| Collecteur Go (ingestion, stockage, API, export Wazuh) | `go vet`, `go test -race`, essai réel avec simulateur, image Docker construite et lancée, 6 défauts de sécurité corrigés | — | — |
| Console web | typage, lint, 43 tests, parcours Chromium contre un serveur factice et contre le vrai collecteur | — | tuiles OpenStreetMap réelles |
| Pile serveur (Docker Compose, mode TLS interne) | installation complète et rejouée, mTLS, DNS sur TLS, export vers Wazuh sans perte (autant de documents indexés que de lignes exportées), 121 cas de règles Wazuh, rotation des mots de passe, sauvegarde puis restauration après destruction totale | — | Let's Encrypt réel, défi DNS-01 (mode ClientID avec joker), téléchargement des listes HaGeZi, résolution amont par Quad9, WireGuard, consommation mémoire avec les listes chargées, architecture ARM |
| Agent Android : code | compilation, lint, tests JVM (180 au dernier décompte de `android/README.md`), test de conformité au contrat des 21 collecteurs, APK release signé et inspecté | — | — |
| Agent Android : comportement | — | tout : activation Device Owner sur S25+, permissions automatiques, démarrage au boot et survie 24 h, Keystore et TLS client, journaux réseau et de sécurité réels, GPS, batterie, interface, politique (profils, DNS privé, repli), retrait du Device Owner | Robolectric (indisponible), tests instrumentés |
| Scripts ADB bash (`android/scripts/*.sh`) | syntaxe (`bash -n`), relecture contre le code | exécution sur un téléphone | — |
| Scripts PowerShell (`android/scripts/*.ps1`) | — | — | ni exécutés ni analysés (pas de PowerShell dans l'environnement de développement) |
| Ces guides | commandes relues contre les scripts ; `apksigner` et `aapt2` exécutés sur l'APK construit | — | aucun guide n'a été suivi de bout en bout par une personne |

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
   serveur en local avec le simulateur, pistes v2.

## Les trois avertissements essentiels

1. **Gardez le keystore de signature, chiffré et hors de l'ordinateur.** Android n'accepte une mise à jour que
   signée par la même clé ; pour une application Device Owner, il n'existe pas de contournement (guide 02).
2. **Vous activez le Device Owner sur votre téléphone de tous les jours, sans test préalable sur un autre appareil.**
   Gardez le débogage USB actif, un PC sous la main et le [guide 04](docs/guides/04-retour-arriere.md) ouvert ;
   appliquez la politique par étapes, jamais d'un bloc (guide 03).
3. **Un DNS privé imposé dont le serveur tombe coupe Internet sur le téléphone.** C'est voulu (pas de fuite en
   clair), mais testez-le d'abord avec le verrou désactivé, sur Wi-Fi, chez vous (guides 03 et 04).

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
│   ├── core/  collectors/  policy/  app/     modules Gradle
│   └── scripts/                 scripts ADB en double (.sh et .ps1)
├── server/
│   ├── collector/               collecteur Go (ingestion, API, export Wazuh, CLI, simulateur)
│   └── console/                 console web (React, Vite)
└── infra/                       Docker Compose, Caddy, AdGuard Home, Wazuh, scripts d'installation ; README.md
```

Les secrets (`.env`, `.vigie`, `.p12`, keystore, mots de passe) sont générés localement et ne sont jamais versionnés.
