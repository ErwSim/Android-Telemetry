# État d'avancement

Fichier de reprise : à lire en premier, à mettre à jour à chaque fin de session de travail.
Dernière mise à jour : 15/11/2026.

## Où on en est

| Lot | Répertoire | État | Vérifié par exécution ? |
|---|---|---|---|
| Architecture et contrat | `docs/` | fait | — |
| Recherche pile serveur | `docs/research/serveur-siem-dns.md` | fait | sources web |
| Recherche plateforme Android/Samsung | `docs/research/android-plateforme.md` | fait | sources web, rien testé sur appareil |
| Collecteur Go | `server/collector/` | à faire | — |
| Console web | `server/console/` | à faire | — |
| Infrastructure Docker | `infra/` | à faire | — |
| Agent Android | `android/` | à faire | — |
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
