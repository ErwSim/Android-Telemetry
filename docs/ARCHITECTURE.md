# Vigie — architecture

Vigie est une chaîne personnelle de télémétrie de sécurité et de réduction du pistage pour **un téléphone
Android dont l'utilisateur est le propriétaire** (cible : Samsung Galaxy S25+, ROM stock, non rooté).

## Décisions du propriétaire (15/11/2026)

| Sujet | Décision |
|---|---|
| Mode d'administration | **Device Owner** (activé par ADB après retrait temporaire des comptes). Mode dégradé tant que ce n'est pas fait. |
| Serveur | **VPS ou dédié, 8 Go+ de RAM**, IP publique, Docker Compose. |
| SIEM/XDR | **Wazuh** single-node (manager + indexer + dashboard). |
| Dé-googlisation par défaut | Profil **équilibré** (Play Services, Play Store, push FCM et apps bancaires restent fonctionnels). Profil strict disponible. |
| Build APK | Compilation locale (domaines Google à autoriser dans l'environnement cloud, ou sur le PC). |

## Principes non négociables

1. **Aucune furtivité.** L'agent affiche une notification permanente, garde son icône, et l'écran d'accueil de
   l'app montre ce qui est collecté. Aucune fonction de masquage. Ce n'est pas un outil de surveillance d'autrui.
2. **Flux à sens unique.** Le téléphone pousse vers le serveur ; le serveur ne peut **ni** commander le
   téléphone **ni** modifier sa politique. Un serveur compromis ne donne aucun contrôle sur l'appareil.
   Toute la politique (DNS, paquets désactivés, restrictions) se règle dans l'app, localement.
3. **Zéro dépendance Google dans l'agent** : pas de Play Services, Firebase, ML Kit. Localisation par
   `LocationManager`.
4. **Pas de contenu privé de tiers** : ni contenu de SMS, ni journal d'appels, ni frappe clavier, ni capture
   d'écran, ni service d'accessibilité. Le contenu des notifications est désactivé par défaut (métadonnées
   seulement).
5. **Tout collecteur est désactivable** individuellement dans l'app.
6. **Tout ce que l'agent change est réversible** (paquets désactivés, restrictions, DNS) depuis l'app, et une
   procédure de retrait complet du Device Owner est documentée.

## Vue d'ensemble

```
 Galaxy S25+                                   VPS (Docker Compose)
┌───────────────────────────┐               ┌────────────────────────────────────────────┐
│ Vigie Agent (Device Owner)│  HTTPS mTLS   │ Caddy (TLS, mTLS sur ingest.*)             │
│  collecteurs ─► tampon    │──────────────►│   └► vigie-collector (Go, SQLite)          │
│  (Room/SQLite) ─► envoi   │  lots gzip    │         ├► console web (carte, tableaux)   │
│                           │               │         └► events.ndjson ─► Wazuh manager  │
│ politique locale :        │               │ Wazuh indexer + dashboard (SIEM/XDR)       │
│  DNS privé imposé,        │  DoT :853     │ AdGuard Home (DNS filtrant, DoT)           │
│  paquets désactivés,      │──────────────►│   └► querylog ─► Wazuh                     │
│  restrictions             │               │ (option) WireGuard                         │
└───────────────────────────┘               └────────────────────────────────────────────┘
```

## Composants et répertoires

| Répertoire | Composant | Techno |
|---|---|---|
| `android/` | **Vigie Agent** : app Device Owner, collecteurs, tampon hors-ligne, envoi, politique vie privée/sécurité | Kotlin, Gradle, Room, WorkManager, OkHttp. Package `io.github.erwsim.vigie` |
| `server/collector/` | **vigie-collector** : API d'ingestion, stockage, API console, export NDJSON vers Wazuh, CLI d'enrôlement, simulateur | Go, SQLite (pur Go) |
| `server/console/` | **Console web** : carte des positions, chronologie, réseau par app, inventaire, posture, alertes | TypeScript, React, Vite, MapLibre |
| `infra/` | Déploiement : `docker-compose.yml`, Caddy, AdGuard Home, Wazuh (règles/décodeurs Vigie), PKI, script d'installation, option WireGuard | Docker Compose, shell |
| `docs/` | Architecture, contrat, recherches, guides d'installation et d'exploitation | Markdown (français) |

## Agent Android

- **Service de premier plan** permanent (démarré au boot) qui héberge les collecteurs « temps réel »
  (localisation, écran, connectivité, capteurs, notifications) ; **WorkManager** pour les collectes périodiques
  (inventaire, posture, usage réseau) et pour l'envoi.
- **Collecteurs** : une interface commune `Collector` (id, permissions/capacités requises, `start/stop` ou
  `collectOnce`), chacun dans son fichier, activable par réglage. Un collecteur dont la capacité manque
  (pas Device Owner, permission absente) se déclare « indisponible » sans planter.
- **Tampon hors-ligne** : table Room `outbox` ; chaque événement reçoit un identifiant unique et un numéro de
  séquence. Plafond configurable (défaut 200 Mo / 30 jours) ; en cas de dépassement on purge d'abord les
  événements les plus anciens de plus faible sévérité et on émet `agent.buffer_overflow`.
- **Envoi** : lots gzip sur HTTPS avec certificat client (clé dans l'Android Keystore) + jeton d'appareil ;
  idempotent (le serveur déduplique par `id`), suppression locale seulement après accusé de réception ;
  reprise avec backoff exponentiel ; option « gros volumes en Wi-Fi seulement ».
- **Politique locale (Device Owner)** : DNS privé imposé vers le serveur AdGuard, profils de désactivation de
  paquets Google/Samsung (équilibré / strict), refus de permissions à des apps, restrictions utilisateur de
  sécurité, journalisation réseau et sécurité du système. Chaque action est journalisée (`security.policy`).
- **Enrôlement** : import d'un fichier `.vigie` produit par le serveur (URL, identifiant d'appareil, jeton,
  certificat client PKCS#12, hôte DNS privé).

### Décisions issues de la recherche plateforme (`docs/research/android-plateforme.md`)

- Cible : Android 16/17 (One UI 8/9), `minSdk 36`. Activation Device Owner par ADB uniquement.
- L'APK principal ne contient **ni** service d'écoute des notifications, **ni** accessibilité, **ni** SMS, **ni**
  superposition (déclencheurs Play Protect). Pas de Knox SDK en v1.
- Journaux réseau du Device Owner = DNS + `connect()` TCP par app, remontés par lots (~1 h 30) ; UDP/QUIC y
  échappent. On complète par le journal AdGuard côté serveur (tout le DNS, en direct) et par les volumes par app
  (`NetworkStatsManager`). **Pas de VPN local en v1** (complexité, batterie, conflit avec WireGuard) : piste v2.
- Localisation : GPS + fournisseur passif seulement (les fournisseurs « network »/« fused » passent par Play
  Services).
- Désactivation de paquets : liste de refus embarquée (jamais `kgclient`, paquets OTA, `rkpdapp`, lanceur,
  composeur, Play Store en profil équilibré…) car `setApplicationHidden` n'a pas de garde-fou.
- Jamais `DISALLOW_DEBUGGING_FEATURES` ni coupure du signal USB : ADB reste la porte de secours.
- Variante de build `testOnly` par défaut pour pouvoir retirer le Device Owner par ADB
  (`dpm remove-active-admin`) ; l'app sait aussi tout défaire puis `clearDeviceOwnerApp`.

## Serveur

- **vigie-collector** valide (mTLS vérifié par Caddy + jeton), déduplique, stocke en SQLite, alimente la
  console et écrit chaque événement dans un fichier NDJSON lu par le manager Wazuh (`<localfile>` JSON).
- **Wazuh** applique les règles Vigie (`infra/wazuh/`) → alertes ; tous les événements sont aussi archivés.
- **AdGuard Home** sert le DNS privé du téléphone en DoT avec listes de blocage (télémétrie Google/Samsung,
  publicité, traqueurs) ; son journal de requêtes part aussi dans Wazuh.
- **Console** protégée par authentification locale ; l'enrôlement et la révocation d'appareils ne se font
  qu'en ligne de commande sur le serveur.

## Contrat

Le format des événements et les API sont définis dans [`docs/contrat/contrat.md`](contrat/contrat.md).
C'est la référence commune : toute évolution se fait d'abord dans ce fichier.
