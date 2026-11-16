# Vigie (dépôt Android-Telemetry)

Chaîne personnelle de télémétrie de sécurité et de réduction du pistage pour le téléphone Android du
propriétaire du dépôt (Samsung Galaxy S25+). Le propriétaire parle français : documentation, messages de
commit et textes d'interface en français ; identifiants de code en anglais.

## À lire avant de travailler

1. `docs/ETAT.md` — état d'avancement, ce qui est vérifié ou non, prochaines étapes. **À mettre à jour à
   chaque fin de session de travail.**
2. `docs/ARCHITECTURE.md` — décisions, principes non négociables, composants.
3. `docs/contrat/contrat.md` — format des événements et API. Toute évolution commence par ce fichier.
4. `docs/research/` — faits de plateforme vérifiés (Android/Samsung, Wazuh, AdGuard).

## Répertoires

- `android/` — Vigie Agent (Kotlin, Device Owner). Voir `android/README.md`.
- `server/collector/` — collecteur Go (ingestion, stockage, API console, export Wazuh, CLI).
- `server/console/` — console web (React + Vite).
- `infra/` — Docker Compose (Caddy, collecteur, Wazuh, AdGuard Home, WireGuard optionnel), PKI, installation.

## Règles

- Principes non négociables de `docs/ARCHITECTURE.md` : aucune furtivité ; le serveur n'envoie au téléphone
  que des commandes d'une liste fermée (les sensibles signées par un code qu'il ne connaît pas), jamais de
  configuration ni de politique ; aucune dépendance Google dans l'agent ; contenu privé de tiers réduit au
  minimum ; tout est désactivable et réversible.
- Ne jamais committer de secrets (`.env`, clés, `.vigie`, `.p12`) : ils sont générés à l'installation.
- Dire clairement ce qui a été réellement exécuté/testé et ce qui ne l'a pas été.
