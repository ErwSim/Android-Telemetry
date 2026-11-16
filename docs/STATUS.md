# État d'avancement

Fichier de reprise : à lire en premier, à mettre à jour à chaque fin de session de travail.
Dernière mise à jour : 16/11/2026.

## Où on en est

Trois versions sont écrites de bout en bout : la v1 (télémétrie, politique anti-pistage, serveur), la v1.1
(commandes à distance, vue « pistage », notifications, modes de localisation) et la v1.2 (protection contre
un logiciel malveillant quel que soit son vecteur). Le serveur a été exécuté et testé réellement ;
**l'application Android n'a jamais tourné sur un téléphone** (ni émulateur) : elle est vérifiée par
compilation, lint, tests JVM et des essais croisés de son vrai code contre le vrai collecteur.

| Lot | Répertoire | État | Vérifié par exécution |
|---|---|---|---|
| Architecture, contrat | `docs/ARCHITECTURE.md`, `docs/contrat/contrat.md` (§1 à §11) | fait | — |
| Recherches plateforme | `docs/research/` | fait | sources web ; points « non vérifié » signalés dans les fichiers |
| Collecteur Go | `server/collector/` | fait, trois revues | `go vet`, `go test -race`, essais réels avec le simulateur et ses scénarios d'attaque, image Docker |
| Console web | `server/console/` | fait | typage, lint, 174 tests, parcours Chromium contre serveur factice et contre le vrai collecteur ; tuiles OSM réelles non chargées |
| Infrastructure Docker | `infra/` | fait | pile réellement démarrée en TLS `internal` : mTLS, DoT, flux de commandes, pistage sur le vrai AdGuard, export → Wazuh sans perte, cas de test des règles tous verts (`infra/wazuh/tests/run-tests.sh`) |
| Agent Android et APK compagnon | `android/` | fait, trois revues indépendantes | `./gradlew lint test assembleDebug assembleRelease` vert : 392 tests JVM (5 ignorés : essais croisés, à lancer avec les variables `VIGIE_CROSS_*`), APK inspectés |
| Guides utilisateur | `README.md`, `docs/guides/01` à `08` | faits | commandes relues contre les scripts ; aucune exécutée sur un VPS ni sur un téléphone |

## Ce que chaque version apporte

- **v1** : 21 collecteurs, tampon hors-ligne, envoi mTLS, politique Device Owner (DNS privé imposé, paquets
  désactivés, permissions refusées, restrictions), issue de secours ADB, collecteur, console, Wazuh, AdGuard.
- **v1.1** (contrat §8 à §10) : commandes à distance (sonner, vibrer, localiser ; verrouiller et effacer
  signés par un code que le serveur ne connaît pas ; canal coupé par défaut) ; vue « pistage » pilotant
  AdGuard ; APK compagnon de notifications ; modes de localisation ; notifications des alertes ;
  renouvellement d'appareil.
- **v1.2** (contrat §11) : gardes de capacités (SMS, appels, accessibilité, claviers, quarantaine), profil de
  risque des applications, rôles par défaut, comptage expérimental des opérations sensibles, détections côté
  serveur avec sourdine, règles et corrélations Wazuh.

## Conclusions des revues à ne pas perdre de vue

- **Signature des commandes** : elle ne vaut qu'avec un code à forte entropie (cinq mots aléatoires) ; le
  serveur sert la page où le code est saisi ; une commande signée reste exécutable jusqu'à son expiration.
  L'effacement à distance ne s'active qu'après essai sur un appareil sacrifiable ou sauvegardé.
- **Envoi de SMS à l'insu du propriétaire** (l'attaque qu'il a subie sur un précédent téléphone) : la vraie
  protection est la **garde SMS**. Sans le comptage expérimental `app_ops` — jamais vu fonctionner,
  probablement indisponible sur Android 16 —, ce cas ne produit qu'**une** détection,
  `detect.sms_permission`. Une application acceptée comme appli SMS par défaut n'est pas bloquée, seulement
  signalée. Voir `docs/guides/08-sms-et-logiciels-malveillants.md`.
- **Profil de risque** : indicateur d'attention sur des capacités déclarées, pas un verdict (contrôle
  parental, antivirus, automatisation sortent « élevé » ; un logiciel discret de boutique peut sortir « faible »).
- **Détections** : les seuils ont été réglés sur un simulateur écrit par le même agent ; les faux positifs sur
  un téléphone réel sont à attendre (DNS chiffré d'un navigateur, première sauvegarde de photos, appel vidéo
  long) et se traitent par la mise en sourdine et les variables `VIGIE_DETECT_*`.

## Jamais testé (à faire par le propriétaire)

- **Tout le comportement sur le Galaxy S25+** : activation Device Owner, service permanent, collecteurs,
  politique, gardes, canal de commandes, compagnon, issue de secours ADB. La feuille de route est
  `docs/guides/06-verifications-sur-appareil.md` (90 cases par ordre de risque) ; l'ordre d'essai prudent est
  en tête de `docs/guides/03-telephone.md`.
- **Scripts PowerShell** (`android/scripts/*.ps1`) : relus ligne à ligne, jamais exécutés.
- **Serveur en conditions réelles** : Let's Encrypt et défi DNS-01, résolution DNS en amont, WireGuard,
  `update.sh`, SMTP avec TLS et authentification, ntfy réel, consommation mémoire en charge réelle.

## Limites connues et choix assumés

- Journaux réseau du Device Owner : DNS et `connect()` TCP seulement, par lots (~1 h 30) ; UDP/QUIC y échappent.
- Caméra et micro : usage signalé sans l'application responsable (attribution expérimentale, éteinte par défaut).
- Pas de VPN local, pas de Knox SDK (voir `docs/ARCHITECTURE.md`).
- Rien n'est collecté avant le premier déverrouillage suivant un redémarrage ; l'issue de secours ADB non plus
  ne répond pas avant.
- Les journaux réseau et de sécurité du système s'allument dès l'activation du Device Owner (interrupteur par
  collecteur) ; Android affiche alors la mention de surveillance du réseau.
- Sonnerie à distance muette si « Ne pas déranger » coupe les alarmes.
- Vue « pistage » : octets par éditeur et compteurs bloqué/autorisé par application sont des estimations.
- Gardes : elles ne touchent ni les applications du système ni le détenteur du rôle correspondant ; les gardes
  claviers et accessibilité n'éteignent jamais un service déjà actif, et leur effet réel sur One UI est à vérifier.
- Compte console : qui connaît l'identifiant peut le bloquer par des échecs répétés.
- Tuiles de carte OpenStreetMap publiques par défaut (`VIGIE_TILE_URL`).
- Échéances des certificats d'appareils (2 ans) non notifiées : `infra/enroll.sh --list`.

## Environnement de développement cloud (si on y revient)

- SDK Android dans `/opt/android-sdk` (plateformes 36 et 37.0, build-tools 36.0.0) ; `dl.google.com` doit être
  dans les domaines autorisés de l'environnement. Pas de KVM, donc pas d'émulateur.
- Robolectric impossible (`gcp.mirrors.maven.org` bloqué par le proxy) : tests Android en JVM pure.
- Docker : lancer `dockerd` à la main ; conteneurs sans accès Internet sortant ; Docker Hub peut répondre 429
  (images de base sur `mirror.gcr.io`, voir `server/collector/README.md`). Disque limité : nettoyer images et caches.
- Le keystore de signature utilisé ici était un keystore de test local, non versionné : **le propriétaire génère
  le sien** (`android/scripts/generate-keystore.*`) et le conserve ; il signe l'agent et le compagnon.
- Travail à plusieurs agents : chacun confiné à son répertoire, commits par chemin, et n'arrêter que ses propres
  processus par PID (un `pkill` par nom a déjà tué le serveur d'un autre agent).

## Prochaines étapes

1. Propriétaire : installer le serveur (`docs/guides/01`), compiler les deux APK avec son propre keystore (`02`),
   suivre l'ordre d'essai du guide téléphone (`03`), cocher `06` au fur et à mesure et rapporter les écarts.
2. Corriger ce que les essais sur appareil révèlent : c'est là que se trouvent les défauts restants. En premier :
   la garde SMS, le canal de commandes en veille, et `adb shell dumpsys appops --history --op SEND_SMS`.
3. Pistes suivantes : `docs/guides/07-reprise-developpement.md` (code de déverrouillage avant d'affaiblir une
   garde, limite de débit SMS du système, listes d'exclusion du compagnon éditables dans l'agent, VPN local).
