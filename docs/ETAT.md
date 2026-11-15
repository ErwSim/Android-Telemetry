# État d'avancement

Fichier de reprise : à lire en premier, à mettre à jour à chaque fin de session de travail.
Dernière mise à jour : 15/11/2026.

## Où on en est

| Lot | Répertoire | État | Vérifié par exécution ? |
|---|---|---|---|
| Architecture et contrat | `docs/` | fait | — |
| Recherche pile serveur | `docs/research/serveur-siem-dns.md` | fait | sources web |
| Recherche plateforme Android/Samsung | `docs/research/android-plateforme.md` | en cours | — |
| Collecteur Go | `server/collector/` | à faire | — |
| Console web | `server/console/` | à faire | — |
| Infrastructure Docker | `infra/` | à faire | — |
| Agent Android | `android/` | à faire | — |
| Guides d'installation | `docs/guides/` | à faire | — |

## Limites de l'environnement de développement cloud

- `dl.google.com` (SDK Android et dépôt Maven Google) est bloqué par la politique réseau : **l'APK ne peut
  pas être compilé dans cet environnement** tant que `dl.google.com` et `maven.google.com` ne sont pas ajoutés
  aux domaines autorisés. Sur un PC, la compilation fonctionne normalement.
- Docker fonctionne (lancer `dockerd` à la main), les images Docker Hub se téléchargent ; les conteneurs
  n'ont pas d'accès Internet sortant sans configurer le proxy.
- Aucun appareil Android réel ni émulateur : rien de ce qui touche au téléphone n'est testé sur matériel.

## Prochaines étapes

Voir la fin de ce fichier, mise à jour au fil des lots.
