# État d'avancement

Fichier de reprise : à lire en premier, à mettre à jour à chaque fin de session de travail.
Dernière mise à jour : 16/11/2026.

## Où on en est

La v1 est écrite de bout en bout. Le serveur a été exécuté et testé réellement ; **l'application Android n'a
jamais tourné sur un téléphone** (ni émulateur) : elle est vérifiée par compilation, lint, tests JVM et un essai
croisé de son code d'envoi contre le vrai collecteur.

| Lot | Répertoire | État | Vérifié par exécution |
|---|---|---|---|
| Architecture, contrat | `docs/ARCHITECTURE.md`, `docs/contrat/contrat.md` | fait | — |
| Recherches plateforme | `docs/research/` | fait | sources web ; points « non vérifié » signalés dans les fichiers |
| Collecteur Go | `server/collector/` | fait, revue de sécurité faite | `go vet`, `go test -race`, essais réels avec le simulateur, image Docker |
| Console web | `server/console/` | fait | typage, lint, 43 tests, parcours Chromium contre serveur factice et contre le vrai collecteur ; tuiles OSM réelles non chargées |
| Infrastructure Docker | `infra/` | fait | pile réellement démarrée en TLS `internal` : mTLS, DoT, export → Wazuh sans perte, 121/121 cas de règles, rotation des mots de passe, sauvegarde/restauration, renouvellements, notification par webhook |
| Agent Android | `android/` | fait, revue indépendante faite | `./gradlew lint test assembleDebug assembleRelease` vert : 221 tests JVM (1 ignoré : essai croisé, à lancer avec `VIGIE_CROSS_ENROLL`), APK release signé inspecté |
| Guides utilisateur | `README.md`, `docs/guides/01` à `07` | faits | commandes relues contre les scripts ; aucune exécutée sur un VPS ni sur un téléphone |

## Jamais testé (à faire par le propriétaire)

- **Tout le comportement sur le Galaxy S25+** : activation Device Owner, service permanent, collecteurs,
  politique, issue de secours ADB. La feuille de route est `docs/guides/06-verifications-sur-appareil.md` ;
  l'ordre d'essai prudent est en tête de `docs/guides/03-telephone.md`.
- **Scripts PowerShell** (`android/scripts/*.ps1`) : relus ligne à ligne, jamais exécutés.
- **Serveur en conditions réelles** : Let's Encrypt et défi DNS-01, téléchargement des listes de blocage,
  résolution DNS en amont, WireGuard, consommation mémoire avec les listes chargées, SMTP avec TLS et
  authentification, ntfy réel.

## Limites connues et choix assumés

- Journaux réseau du Device Owner : DNS et `connect()` TCP seulement, par lots (~1 h 30) ; UDP/QUIC y échappent.
- Caméra et micro : usage signalé sans l'application responsable (attribution expérimentale, désactivée par défaut).
- Pas de lecture des notifications, pas de VPN local, pas de Knox SDK en v1 (voir `docs/ARCHITECTURE.md`).
- Rien n'est collecté avant le premier déverrouillage suivant un redémarrage ; l'issue de secours ADB non plus
  ne répond pas avant.
- Les journaux réseau et de sécurité du système s'allument dès l'activation du Device Owner (interrupteur par
  collecteur pour les couper) ; Android affiche alors la mention de surveillance du réseau.
- Un défaut de posture déjà présent à l'enrôlement ne produit pas d'alerte (pas de changement) : vérifier la
  posture initiale dans la console.
- Compte console : qui connaît l'identifiant peut le bloquer par des échecs répétés (limite par compte).
- Tuiles de carte OpenStreetMap publiques par défaut (`VIGIE_TILE_URL` pour en changer).
- Les échéances des certificats d'appareils (2 ans) ne sont pas notifiées : `infra/enroll.sh --list`.
- Tampon de l'agent : une horloge durablement fausse en avant fait vieillir les événements environ deux fois
  plus vite (voir `android/ARCHITECTURE-CODE.md`).

## Environnement de développement cloud (si on y revient)

- SDK Android dans `/opt/android-sdk` (plateformes 36 et 37.0, build-tools 36.0.0) ; il faut que `dl.google.com`
  soit dans les domaines autorisés de l'environnement. Pas de KVM, donc pas d'émulateur.
- Robolectric impossible (`gcp.mirrors.maven.org` bloqué par le proxy) : les tests Android sont en JVM pure.
- Docker : lancer `dockerd` à la main ; les conteneurs n'ont pas d'accès Internet sortant ; Docker Hub peut
  répondre 429 (les images de base se prennent alors sur `mirror.gcr.io`, voir `server/collector/README.md`).
- Le keystore de signature utilisé ici était un keystore de test local, non versionné : **le propriétaire génère
  le sien** (`android/scripts/generate-keystore.*`) et le conserve.

## Prochaines étapes

1. Propriétaire : installer le serveur (`docs/guides/01-serveur.md`), compiler l'APK avec son propre keystore
   (`02`), suivre l'ordre d'essai du guide téléphone (`03`), cocher `06` au fur et à mesure et rapporter les
   écarts.
2. Corriger ce que les essais sur appareil révèlent (c'est là que se trouvent les défauts restants).
3. Pistes v2 déjà identifiées : `docs/guides/07-reprise-developpement.md`.
