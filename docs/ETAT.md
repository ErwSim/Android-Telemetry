# État d'avancement

Fichier de reprise : à lire en premier, à mettre à jour à chaque fin de session de travail.
Dernière mise à jour : 15/11/2026.

## Où on en est

| Lot | Répertoire | État | Vérifié par exécution ? |
|---|---|---|---|
| Architecture et contrat | `docs/` | fait | — |
| Recherche pile serveur | `docs/research/serveur-siem-dns.md` | fait | sources web |
| Recherche plateforme Android/Samsung | `docs/research/android-plateforme.md` | fait | sources web, rien testé sur appareil |
| Collecteur Go | `server/collector/` | fait, revue de sécurité faite (6 défauts corrigés) | `go vet`, `go test -race`, essai réel avec simulateur, image Docker construite et lancée ; pas encore derrière Caddy/Wazuh réels |
| Console web | `server/console/` | fait (revue à faire) | typage, lint, 43 tests, parcours Chromium contre serveur factice et contre le vrai collecteur ; tuiles OSM réelles non testées |
| Infrastructure Docker | `infra/` | fait | pile réellement démarrée en TLS interne : mTLS, DoT, export → Wazuh (6220/6220 documents), 93/93 règles, rotation des mots de passe, sauvegarde/restauration. **Non testé** : Let's Encrypt/DNS-01, téléchargement des listes de blocage, WireGuard, RAM avec listes chargées |
| Agent Android | `android/` | socle fait ; collecteurs restants et politique Device Owner en cours | `./gradlew lint test assembleDebug assembleRelease` vert (73 tests JVM, APK release 2,9 Mo signé). **Rien testé sur appareil.** Robolectric impossible ici (`gcp.mirrors.maven.org` bloqué par le proxy) |
| Guides d'installation | `docs/guides/` | à faire | — |

## Limites de l'environnement de développement cloud

- `dl.google.com` a été autorisé par le propriétaire : le SDK Android est installé dans `/opt/android-sdk`
  (à réinstaller dans une nouvelle session : `sdkmanager "platform-tools" "platforms;android-36" …`).
  Pas de KVM, donc pas d'émulateur : l'agent Android est vérifié par compilation, lint et tests unitaires.
- Docker fonctionne (lancer `dockerd` à la main), les images Docker Hub se téléchargent ; les conteneurs
  n'ont pas d'accès Internet sortant sans configurer le proxy.
- Aucun appareil Android réel ni émulateur : rien de ce qui touche au téléphone n'est testé sur matériel.

## Prochaines étapes

Voir la fin de ce fichier, mise à jour au fil des lots.
