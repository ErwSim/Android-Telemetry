# Console web Vigie

Tableau de bord du propriétaire : position, réseau par application, inventaire, posture de sécurité,
événements et alertes Wazuh. React 19, TypeScript strict, Vite, MapLibre GL JS, uPlot, React Router.
Interface en français, thèmes clair et sombre. Aucune ressource externe au chargement, hors tuiles de carte.

La console ne parle qu'à l'API `/api/console/*` du collecteur (contrat §6 de `docs/contrat/contrat.md`).

## Développement

```sh
npm install
npm run mock      # serveur factice sur http://127.0.0.1:8787 (identifiants : admin / vigie)
npm run dev       # Vite sur http://localhost:5173, proxy /api vers le serveur factice
```

Pour viser un autre collecteur : `VIGIE_API_TARGET=http://127.0.0.1:8080 npm run dev`.

Le serveur factice (`mock/`) génère sept jours de télémétrie déterministe autour de Paris : trajets, trous de
données (téléphone éteint, arrêt forcé de l'agent, perte du fix), DNS et connexions par paquet Google/Samsung,
volumes, inventaire d'applications, posture avec changements, alertes, événements `sev` 2-3, un type hors
catalogue et des `data` partiels. Il émet aussi des événements en direct sur `/stream`.
`POST /__mock/control` permet de simuler `{"wazuh": false}`, `{"expire": true}` (session expirée),
`{"fail": ["/stats/top"]}` (erreur 500) ou `{"latency_ms": 800}`.

## Build, tests, vérification

```sh
npm run typecheck   # tsc strict (src + mock)
npm run lint
npm test            # vitest : formatage, agrégations, trous de trajet, posture, filtres…
npm run build       # sortie statique dans dist/
npm run verify      # parcours Chromium (Playwright global) contre le serveur factice servant dist/
```

`npm run verify` démarre le serveur factice avec `--static dist` (qui applique la CSP ci-dessous et le repli SPA),
parcourt chaque page en clair/sombre et en bureau/téléphone, et échoue sur toute erreur console, exception,
violation CSP, statut HTTP inattendu ou requête hors hôte local et hors tuiles. Captures dans `OUT` (défaut
`verify-out/`). `TILES=real` laisse passer les vrais appels aux tuiles OSM (sinon une tuile synthétique est servie).

## Déploiement

`dist/` est servi à la racine du même hôte que l'API (chemins absolus `/assets/…`, API en `/api/console/…`).
Le serveur doit renvoyer `index.html` pour toute URL de page inconnue (routage côté client : `/carte`,
`/evenements`, `/evenements/:id`, `/reseau`, `/applications`, `/securite`, `/alertes`, `/connexion`) mais un 404
pour un fichier absent (`/assets/…`). Les fichiers `.js` doivent être servis en `text/javascript` (le worker
MapLibre est publié en `.js` pour cela).

### Tuiles de carte

Par défaut `https://tile.openstreetmap.org/{z}/{x}/{y}.png`, attribution OSM affichée. Pour un autre hôte :
modifier `config.json` à la racine de `dist/` (`tileUrl`, `tileAttribution`, `tileAttributionUrl`), ou
définir `VITE_TILE_URL` (et `VITE_TILE_ATTRIBUTION`, `VITE_TILE_ATTRIBUTION_URL`) à la compilation.
L'URL doit être en https et contenir `{z}`, `{x}`, `{y}` ; **la CSP doit alors autoriser cet hôte** (`img-src` et `connect-src`).
Si `config.json` est absent ou invalide, la valeur par défaut est utilisée.

### Politique de sécurité du contenu (CSP)

Le build n'a besoin que de ceci (aucun `'unsafe-inline'`, aucun `'unsafe-eval'`) ; chaque directive a été
éprouvée dans Chromium en la retirant ou en la durcissant (`npm run verify` applique cette politique) :

```
default-src 'none';
script-src 'self';
style-src 'self';
img-src 'self' data:;
connect-src 'self' https://tile.openstreetmap.org;
worker-src 'self';
font-src 'self';
base-uri 'none'; form-action 'self'; frame-ancestors 'none'
```

- `worker-src 'self'` : le worker MapLibre est un fichier de `dist/assets/` ; `worker-src blob:` ne suffirait pas, et
  `blob:` n'est pas nécessaire. Sans directive `worker-src`, le repli sur `script-src 'self'` convient aussi.
- `connect-src` : `'self'` couvre l'API, `config.json` et le flux SSE ; l'hôte de tuiles est requis car MapLibre
  charge les tuiles par `fetch` (sans lui : une violation par tuile, carte sans fond).
- `img-src 'self' data:` : `data:` est requis par MapLibre ; l'hôte de tuiles n'a pas besoin d'y figurer (ni `blob:`).
- `font-src` : aucune police n'est chargée ; la directive est inoffensive. `default-src 'none'` suffit sinon.
- Les styles dynamiques de React, MapLibre et uPlot passent par le CSSOM (`element.style`), autorisé sans `'unsafe-inline'`.
  Les feuilles de style (dont celles de MapLibre et d'uPlot) sont dans le CSS du bundle.
- `script-src 'self'` suffit : `/theme-init.js` est un fichier externe, `index.html` ne contient aucun script en ligne.

## Structure

```
index.html, public/            point d'entrée, config.json (tuiles), theme-init.js, favicon
src/api/                       client HTTP, types du contrat, useApi, pagination par curseur, flux SSE
src/lib/                       formatage fr, périodes, trous de trajet, géo, agrégations, posture, Google/Samsung
src/state/                     session, appareil sélectionné, thème, libellés d'applications
src/components/                mise en page, carte (MapLibre), graphique (uPlot), tableaux, JSON, sélecteur de période
src/pages/                     Login, Overview, MapPage, Events, Network, Apps, Security, Alerts
mock/                          serveur factice (Node 22, TypeScript sans compilation) et générateur de données
scripts/verify-browser.cjs     vérification navigateur
```

## Limites connues liées au contrat §6

- `/stats/top` n'accepte pas de filtre par paquet : le détail « domaines d'une application » lit les événements
  `net.dns` / `net.connect` (`q=<paquet>`, jusqu'à 4 pages de 500) et agrège côté navigateur ; au-delà, un
  avertissement signale un échantillon partiel.
- `/stats/timeline` n'a pas de filtre de type : la chronologie réseau demande `by=type` et ne garde que `net.dns` et `net.connect`.
- `last_heartbeat` n'a pas d'horodatage propre : l'ancienneté de l'appareil est celle de `last_seen`.
- Pour distinguer « téléphone éteint » et « pas de fix » dans un trou de trajet, la carte croise la trace avec la chronologie d'activité.
