# Console web Vigie

Tableau de bord du propriétaire : position, réseau par application, pistage (ce qui est bloqué ou autorisé),
commandes à distance, inventaire, posture de sécurité, événements et alertes Wazuh. React 19, TypeScript strict, Vite, MapLibre GL JS, uPlot, React Router.
Interface en français, thèmes clair et sombre. Aucune ressource externe au chargement, hors tuiles de carte.

La console ne parle qu'à l'API `/api/console/*` du collecteur (contrat §6, §8 commandes, §9 pistage, §10
notifications de `docs/contrat/contrat.md`).

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

Le mock simule aussi (contrat §8-§10) :

- **commandes** : validation du collecteur (type, bornes, validité, `sig` présent si et seulement si sensible, limites 20/h
  et 10 en attente, `409` à l'annulation d'une commande déjà remise) et **agent simulé** qui récupère les commandes, vérifie la
  signature avec la clé dérivée de `MOCK_COMMAND_CODE` (défaut `correct horse battery staple`, le code du vecteur du contrat),
  respecte l'ordre des vérifications du §8 (`disabled`, `malformed`, `bad_signature`, `locked_out` après 5 échecs, `replay`,
  `expired`, `not_device_owner`…), émet `command.result` et, pour `locate`, une vraie `location.fix` sur le flux SSE. Contrôles :
  `{"channel": "stream"|"poll"|"offline"}`, `{"agent": {"disabled", "wipe_allowed", "code_configured", "device_owner",
  "locate_fail", "deliver_ms", "exec_ms"}}` ; `GET /__mock/requests` rend les corps des requêtes modifiantes reçues ;
- **pistage** : décomptes dérivés des `net.dns`/`net.usage` générés, politique (niveau + règles manuelles) évaluée à l'heure de
  chaque requête (changer le niveau produit des domaines « mixtes »), motifs au format AdGuard, `PUT /tracking/override` avec
  `409` pour les domaines indispensables (`force`), `PUT /tracking/level`, et `{"adguard": false}` (vue DNS seule, `503` sur les `PUT`) ;
- **notifications** : `app.notification` avec titre/texte (depuis J-3), contenu masqué (`redacted`), texte hostile et texte très long.

## Build, tests, vérification

```sh
npm run typecheck   # tsc strict (src + mock)
npm run lint
npm test            # vitest : formatage, agrégations, trous de trajet, posture, filtres, signature des commandes (vecteur §8), pistage…
npm run build       # sortie statique dans dist/
npm run verify      # parcours Chromium (Playwright global) contre le serveur factice servant dist/
```

`npm run verify` démarre le serveur factice avec `--static dist` (qui applique la CSP ci-dessous et le repli SPA),
parcourt chaque page en clair/sombre et en bureau/téléphone, et échoue sur toute erreur console, exception,
violation CSP, statut HTTP inattendu ou requête hors hôte local et hors tuiles. Il rejoue aussi, contre le mock, les
parcours de bout en bout : commandes simples et suivi en direct, annulation, verrouillage avec un mauvais code
(`bad_signature` constaté par l'agent simulé) puis le bon, effacement en trois étapes, position qui arrive après « Localiser
maintenant » (carte et trace en direct), pistage (filtres, Bloquer/Autoriser/Remettre par défaut, `409` puis `force`, niveau,
`adguard: false`), notifications hostiles affichées comme texte, fournisseurs de position ; et **prouve que le code de
commande ne quitte pas la page** (aucune requête, aucun journal console, aucun corps reçu par le serveur factice, aucun
stockage, cookie ou champ ne le contient, ni en clair ni encodé). Captures dans `OUT` (défaut `verify-out/`). `TILES=real` laisse passer les vrais appels aux tuiles OSM (sinon une tuile synthétique est servie).

### Contre le vrai collecteur

`scripts/verify-real.cjs` rejoue dans Chromium les parcours commandes (simple, mauvais code puis bon code, annulation, position
reçue), pistage, notifications et carte contre un collecteur réel (`REAL_URL`, `REAL_PASSWORD`, `REAL_CODE`), avec les mêmes
contrôles (console, CSP, tiers, fuite du code). Prérequis : collecteur lancé avec `VIGIE_CONSOLE_DIR=$PWD/dist`, un appareil
enrôlé et alimenté par `sim --command-code 'correct horse battery staple' --fake-adguard 127.0.0.1:3001 …` (agent de commandes et faux
AdGuard Home du simulateur : voir `server/collector/README.md`). Avec AdGuard joignable, le script rejoue aussi le blocage
d'un domaine, le `409` d'un domaine indispensable et un changement de niveau ; sans AdGuard, il contrôle le mode dégradé.

## Déploiement

`dist/` est servi à la racine du même hôte que l'API (chemins absolus `/assets/…`, API en `/api/console/…`).
Le serveur doit renvoyer `index.html` pour toute URL de page inconnue (routage côté client : `/carte`,
`/evenements`, `/evenements/:id`, `/reseau`, `/pistage`, `/applications`, `/securite`, `/alertes`, `/commandes`, `/connexion`) mais un 404
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
src/lib/                       formatage fr, périodes, trous de trajet, géo, agrégations, posture, Google/Samsung,
                               commandes (ULID, payload, signature WebCrypto), pistage, notifications, fournisseurs
src/state/                     session, appareil sélectionné, thème, libellés d'applications
src/components/                mise en page, carte (MapLibre), graphique (uPlot), tableaux, JSON, sélecteur de période
src/pages/                     Login, Overview, MapPage, Events, Network, Tracking, Apps, Security, Alerts, Commands
mock/                          serveur factice (Node 22, TypeScript sans compilation) et générateur de données
scripts/verify-browser.cjs     vérification navigateur
```

## Commandes à distance (page « Commandes »)

Choix : une **page dédiée** (et non la vue d'ensemble) car elle porte des gestes lourds (dialogues de confirmation, historique
qui se met à jour en direct) ; la vue d'ensemble n'affiche que l'état du canal et renvoie vers elle.

- Le **navigateur** génère l'ULID, construit `payload` (JSON sérialisé **une seule fois** ; c'est cette chaîne exacte qui est
  signée et envoyée), fixe la validité (1 h simple, 7 jours sensible par défaut, 30 jours au plus) et signe les commandes
  sensibles : `K = PBKDF2-HMAC-SHA256(code, "vigie-cmd-v1:" + device_id, 600 000, 32 octets)` puis
  `sig = base64(HMAC-SHA256(K, UTF-8(payload)))`, par WebCrypto (`src/lib/commands.ts`). Le test `commands.test.ts` reproduit
  le vecteur du contrat §8 (K, payload reconstruit à l'identique, signature, accents en UTF-8).
- Le **code de commande** est saisi à chaque commande dans un champ **non contrôlé** (il n'existe pas dans l'état React), sert
  à dériver la clé puis à signer, et le champ est vidé aussitôt. Ni code ni clé dans `localStorage`, `sessionStorage`,
  IndexedDB, cookie, journal ou requête ; seul `{ device_id, payload, sig }` part. La clé dérivée est remise à zéro après
  import dans WebCrypto. Limite assumée : une chaîne JavaScript ne peut pas être effacée de la mémoire, elle est seulement
  abandonnée au ramasse-miettes. WebCrypto exige un contexte sécurisé (HTTPS ou localhost) : sinon l'interface le dit et
  désactive les commandes sensibles.
- Garde-fous : confirmation explicite pour verrouiller ; effacement du téléphone en trois étapes (irréversibilité et rappel
  que l'effacement doit être autorisé dans l'app, nom de l'appareil à retaper, puis code). L'interface explique que le serveur
  ne connaît pas le code, ne peut pas vérifier la signature, et qu'un code faux n'est détecté que par le téléphone
  (`bad_signature`, avertissement après chaque refus, rappel de la limite de 5 par heure).
- Précisions du contrat appliquées : `issued_at` à moins de 10 min de l'heure du serveur (la console compare l'en-tête `Date` des
  réponses à son horloge, avertit à 8 min d'écart et traduit le `400` en « horloge de cet ordinateur décalée ») ; message de
  verrouillage ≤ 200 unités UTF-16, sans caractère de contrôle hors saut de ligne, validé avant de signer ; corps limité à
  `{ device_id, payload, sig }` ; un appareil en interrogation se juge sur `last_contact` (`connected` n'est vrai que pour un flux
  ouvert) ; une commande `delivered` peut le rester plusieurs minutes (renvoi du serveur après 5 min).
- L'historique se rafraîchit toutes les 2,5 s tant qu'une commande est `pending`/`delivered` (et à chaque `command.result` du
  flux SSE) ; annulation possible tant que `pending`.
- « Localiser maintenant » : le flux SSE apporte le `location.fix` ; la carte de la page Commandes et la trace de la page Carte
  (« Suivi en direct ») se mettent à jour.

## Pistage (page « Pistage »)

Répartition avec **Réseau** : *Réseau* décrit le trafic observé (noms demandés, destinations, volumes, chronologie) et marche
sans AdGuard ; *Pistage* répond à « qu'est-ce qui est bloqué ou autorisé, vers qui, et que fait-on » (éditeurs, statut, motif,
actions, niveau). Les deux pages se renvoient l'une à l'autre (`/reseau?app=<paquet>` ouvre le détail d'une application).
La page affiche en permanence que Vigie voit à qui le téléphone parle, combien et depuis quelle application, **pas le contenu**
(chiffré). AdGuard injoignable (`adguard: false`) : actions et niveau désactivés avec explication ; sans décompte bloqué/autorisé la vue est
celle des seules requêtes DNS, avec des agrégats déjà stockés ils restent affichés (avertissement « enregistrés avant la
panne »). Les octets par éditeur et les décomptes bloqué/autorisé par application sont présentés comme des **estimations**
(prorata des requêtes DNS). Les erreurs `409 essential_domain` (détail `breaks`, confirmation puis `force`), `409 corrupt_rules`,
`502 adguard_error`, `503 adguard_unavailable` et `503 levels_not_configured` sont traduites.

## Limites connues liées au contrat §6

- `/stats/top` n'accepte pas de filtre par paquet : le détail « domaines d'une application » lit les événements
  `net.dns` / `net.connect` (`q=<paquet>`, jusqu'à 4 pages de 500) et agrège côté navigateur ; au-delà, un
  avertissement signale un échantillon partiel.
- `/stats/timeline` n'a pas de filtre de type : la chronologie réseau demande `by=type` et ne garde que `net.dns` et `net.connect`.
- `last_heartbeat` n'a pas d'horodatage propre : l'ancienneté de l'appareil est celle de `last_seen`.
- Pour distinguer « téléphone éteint » et « pas de fix » dans un trou de trajet, la carte croise la trace avec la chronologie d'activité.
