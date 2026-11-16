# Console web Vigie

Tableau de bord du propriétaire : position, réseau par application, pistage (ce qui est bloqué ou autorisé),
commandes à distance, inventaire et profil de risque des applications, détections de comportements anormaux,
posture de sécurité, événements et alertes Wazuh. React 19, TypeScript strict, Vite, MapLibre GL JS, uPlot, React Router.
Interface en français, thèmes clair et sombre. Aucune ressource externe au chargement, hors tuiles de carte.

La console ne parle qu'à l'API `/api/console/*` du collecteur (contrat §6, §8 commandes, §9 pistage, §10
notifications, §11 risque, opérations et détections de `docs/contrat/contrat.md`).

## Développement

```sh
npm install
npm run mock      # serveur factice sur http://127.0.0.1:8787 (identifiants : admin / watchpost)
npm run dev       # Vite sur http://localhost:5173, proxy /api vers le serveur factice
```

Pour viser un autre collecteur : `WATCHPOST_API_TARGET=http://127.0.0.1:8080 npm run dev`.

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
- **notifications** : `app.notification` avec titre/texte (depuis J-3), contenu masqué (`redacted`), texte hostile et texte très long ;
- **version 1.2** (`mock/scenario.ts`, `mock/detect.ts`, `mock/risk.ts`) : `GET /detections` (curseur, filtres `from`/`to`/`type`),
  `GET /apps/risk`, `GET /apps/ops`, calculés à partir d'événements `detect.*`, `app.risk`, `app.ops`, `app.role` ajoutés aux données
  générées (donc aussi visibles dans `/events` et sur `/stream`). Trois scénarios, choisis au démarrage par `--scenario` (ou
  `MOCK_SCENARIO`) : **`mixed`** (défaut) : parc de 70 applications aux profils variés, les trois combinaisons `combo_*`, les huit types de
  détection, un type inconnu, un texte hostile, `app.ops` présent, des changements de rôle dont un inquiétant ; **`healthy`** :
  « téléphone sain », aucune détection, aucune application à risque élevé, `app.ops` absent ; **`fraud`** : « fraude au SMS », une
  application hors boutique installée 40 h plus tôt envoie 1 984 SMS en deux jours civils (dont 1 790 en arrière-plan), contacte
  trois domaines de menaces, se connecte à 214 adresses ; `app.ops` présent. Les formes des preuves et des réponses suivent le
  collecteur (`server/collector/internal/detect`, `internal/server/detections.go`). Contrôles en plus :
  `{"ops_mode": "normal"|"empty"|"404"}` (`app.ops` absent ou route inconnue), `{"more_detections": 70}` (pagination),
  `{"emit_detection": {type, package, label, severity, evidence}}` (arrivée en direct) ; les changements de niveau ou de règle de
  pistage produisent `tracking.level_changed` / `tracking.override` comme le collecteur.

## Build, tests, vérification

```sh
npm run typecheck   # tsc strict (src + mock)
npm run lint
npm test            # vitest : formatage, agrégations, trous de trajet, posture, filtres, signature des commandes (vecteur §8), pistage,
                    # codes de raison et types de détection (traductions, phrases, preuves, états vides), opérations, rôles…
npm run build       # sortie statique dans dist/
npm run verify      # parcours Chromium (Playwright global) contre le serveur factice servant dist/
```

`npm run verify` démarre le serveur factice avec `--static dist` (qui applique la CSP ci-dessous et le repli SPA ; une instance par
scénario : `mixed` sur `PORT`, `healthy` sur `PORT+1`, `fraud` sur `PORT+2`, arrêtées par leur PID),
parcourt chaque page en clair/sombre et en bureau/téléphone, et échoue sur toute erreur console, exception,
violation CSP, statut HTTP inattendu ou requête hors hôte local et hors tuiles. Il rejoue aussi, contre le mock, les
parcours de bout en bout : commandes simples et suivi en direct, annulation, verrouillage avec un mauvais code
(`bad_signature` constaté par l'agent simulé) puis le bon, effacement en trois étapes, position qui arrive après « Localiser
maintenant » (carte et trace en direct), pistage (filtres, Bloquer/Autoriser/Remettre par défaut, `409` puis `force`, niveau,
`adguard: false`), notifications hostiles affichées comme texte, fournisseurs de position ; et **prouve que le code de
commande ne quitte pas la page** (aucune requête, aucun journal console, aucun corps reçu par le serveur factice, aucun
stockage, cookie ou champ ne le contient, ni en clair ni encodé). Pour la version 1.2 il parcourt aussi (`ONLY=v12` pour ne rejouer que cela) : les huit types de détection et un type inconnu, filtres de
type, de gravité et de période, pagination par curseur (70 détections de plus), arrivée en direct par le flux SSE (page Détections et
résumé de la vue d'ensemble), texte hostile (nom d'application, domaine, motif) affiché comme du texte, profil de risque (tri par score,
trois combinaisons, code inconnu), fiche d'application (ouverture directe et rechargement d'une URL dont le paquet contient des points),
opérations sensibles présentes / vides / route absente, rôles, événements de pistage et détections dans le journal, validité de l'effacement
(15 min, 24 h au plus), textes sur les limites de la signature, annulation d'une commande signée ; puis les scénarios « sain » et « fraude
au SMS » dans les quatre configurations (clair/sombre, bureau/téléphone). Captures dans `OUT` (défaut `verify-out/`). `TILES=real` laisse passer les vrais appels aux tuiles OSM (sinon une tuile synthétique est servie).

### Contre le vrai collecteur

`scripts/verify-real.cjs` rejoue dans Chromium les parcours commandes (simple, mauvais code puis bon code, annulation, position
reçue), pistage, notifications et carte contre un collecteur réel (`REAL_URL`, `REAL_PASSWORD`, `REAL_CODE`), avec les mêmes
contrôles (console, CSP, tiers, fuite du code). Les parcours de la version 1.2 contre le vrai collecteur sont décrits plus bas. Prérequis : collecteur lancé avec `WATCHPOST_CONSOLE_DIR=$PWD/dist`, un appareil
enrôlé et alimenté par `sim --command-code 'correct horse battery staple' --fake-adguard 127.0.0.1:3001 …` (agent de commandes et faux
AdGuard Home du simulateur : voir `server/collector/README.md`). Avec AdGuard joignable, le script rejoue aussi le blocage
d'un domaine, le `409` d'un domaine indispensable et un changement de niveau ; sans AdGuard, il contrôle le mode dégradé.

`scripts/verify-real-v12.cjs` rejoue la version 1.2 contre un vrai collecteur alimenté par `sim --scenario tout` (ou `sain`) : détections
par type (phrases construites à partir des vraies preuves), filtre par type, fiche d'application ouverte depuis une détection puis rechargée,
profil de risque (tri, combinaisons, aucune raison non traduite), opérations sensibles, rôles, dans les quatre configurations
(`REAL_URL`, `REAL_PASSWORD`, `SCENARIO`, `OUT`). Derniers passages (collecteur et simulateur du dépôt, `--scenario tout` puis `sain`) : les huit types de détection produits par le vrai
collecteur s'affichent ; le parc sain donne « Rien à signaler » ; aucune erreur console, violation CSP ni requête tierce.

## Déploiement

`dist/` est servi à la racine du même hôte que l'API (chemins absolus `/assets/…`, API en `/api/console/…`).
Le serveur doit renvoyer `index.html` pour toute URL de page inconnue (routage côté client : `/carte`,
`/evenements`, `/evenements/:id`, `/reseau`, `/pistage`, `/detections`, `/applications`, `/applications/fiche`, `/securite`, `/alertes`,
`/commandes`, `/connexion`) mais un 404
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
src/lib/                       formatage fr, périodes, trous de trajet, géo, agrégations, posture, Google/Samsung, détections, risque,
                               opérations, rôles, gardes,
                               commandes (ULID, payload, signature WebCrypto), pistage, notifications, fournisseurs
src/state/                     session, appareil sélectionné, thème, libellés d'applications
src/components/                mise en page, carte (MapLibre), graphique (uPlot), tableaux, JSON, sélecteur de période
src/pages/                     Login, Overview, MapPage, Events, Network, Tracking, Detections, Apps, AppSheet, Security, Alerts, Commands
mock/                          serveur factice (Node 22, TypeScript sans compilation) et générateur de données
scripts/verify-browser.cjs     vérification navigateur
```

## Commandes à distance (page « Commandes »)

Choix : une **page dédiée** (et non la vue d'ensemble) car elle porte des gestes lourds (dialogues de confirmation, historique
qui se met à jour en direct) ; la vue d'ensemble n'affiche que l'état du canal et renvoie vers elle.

- Le **navigateur** génère l'ULID, construit `payload` (JSON sérialisé **une seule fois** ; c'est cette chaîne exacte qui est
  signée et envoyée), fixe la validité (1 h simple ; verrouillage 7 jours par défaut et 30 au plus ; **effacement 15 min par défaut et 24 h au plus**, contrat §8) et signe les commandes
  sensibles : `K = PBKDF2-HMAC-SHA256(code, "watchpost-cmd-v1:" + device_id, 600 000, 32 octets)` puis
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
- Précisions du contrat appliquées : `issued_at` à moins de 10 min de l'heure du serveur. La console compare l'en-tête `Date`
  des réponses à son horloge et **date la commande à l'heure du serveur quand l'écart est de 30 s à 10 min** (`issueTime`) :
  le téléphone refuse `expired` une commande émise plus de 5 min dans son futur, alors que le serveur en tolère 10 — un
  ordinateur en avance de 5 à 10 min produisait des commandes acceptées par le serveur puis refusées par le téléphone.
  Au-delà de 10 min l'écart n'est jamais suivi (avertissement, et `400` traduit en « horloge de cet ordinateur décalée ») :
  le serveur ne doit pas pouvoir faire signer une commande datée du futur. Message de
  verrouillage ≤ 200 unités UTF-16, sans caractère de contrôle hors saut de ligne ni séparateur U+2028/U+2029 (refusés par
  le collecteur), validé avant de signer ; corps limité à
  `{ device_id, payload, sig }` ; un appareil en interrogation se juge sur `last_contact` (`connected` n'est vrai que pour un flux
  ouvert) ; une commande `delivered` peut le rester plusieurs minutes (renvoi du serveur après 5 min).
- L'historique se rafraîchit toutes les 2,5 s tant qu'une commande est `pending`/`delivered` (et à chaque `command.result` du
  flux SSE) ; annulation possible tant que `pending`. Une commande **remise puis expirée sans résultat** est affichée
  « Expirée sans réponse » : elle a pu être exécutée (un effacement éteint le téléphone dix secondes après avoir tenté
  d'envoyer son compte rendu) ; seule une commande jamais remise est dite « jamais exécutée ».
- **Ce que la signature dans le navigateur garantit, et ce qu'elle ne garantit pas.** Le code ne quitte pas la page tant que
  le JavaScript servi est celui de ce dépôt. Mais c'est le serveur qui sert ce JavaScript : un serveur compromis peut le
  remplacer et lire le code à la saisie (ou le demander sous un faux prétexte), et la CSP, servie par le même serveur, n'y
  change rien. Le dialogue le dit, rappelle que l'annulation n'engage que le serveur et montre l'identifiant d'appareil qui
  sera signé. Pistes hors de ce dépôt : signer depuis une copie de la console gardée hors du serveur (fichiers `dist/`
  servis en local) ou un outil en ligne de commande ; en cas de doute sur le serveur, changer le code dans l'application.
- **Cas difficiles partagés** : `src/lib/commandVectors.ts` construit et signe, avec le vrai code de la console, des
  commandes à accents, émojis, guillemets, sauts de ligne, texte bidirectionnel, codes non ASCII, décomposés (NFD) ou bordés
  d'espaces. Figées dans `src/lib/fixtures/command-vectors.json` (`commandVectors.test.ts` ; régénération :
  `node scripts/command-vectors.ts > src/lib/fixtures/command-vectors.json`), elles sont rejouées par le vérificateur
  Kotlin de l'agent (`ConsoleVectorsTest`) et par le collecteur Go (`internal/command/vectors_test.go`) ;
  `node scripts/command-vectors.ts <device_id>` les produit pour un appareil réel (essai croisé `CrossCommandsTest`).
- « Localiser maintenant » : le flux SSE apporte le `location.fix` ; la carte de la page Commandes et la trace de la page Carte
  (« Suivi en direct ») se mettent à jour.

## Détections, risque, opérations, rôles (version 1.2)

Objectif : voir venir un logiciel malveillant (par exemple celui qui envoyait 2 000 SMS de hameçonnage par jour sans que rien ne se voie)
**quel que soit son vecteur**. Contrat §11.

**Où est quoi, et pourquoi.**

- **Détections : page dédiée `/detections`** (deuxième entrée du menu), pas une refonte de la page Sécurité. *Sécurité* décrit l'état du
  téléphone (posture, journal système, certificats) : des relevés, sans verdict. Une détection est un **verdict expliqué** (« l'application X a
  fait Y, voici pourquoi c'est suspect, ce que ça peut être d'innocent, que faire ») : il lui faut de la place et une lecture en dix secondes,
  que la table de la page Sécurité ne donne pas. *Alertes* reste la vue de **Wazuh** (règles et niveaux de Wazuh, tous sujets, absente si Wazuh
  n'est pas configuré) : le collecteur exporte aussi les détections vers Wazuh, qui les y retrouve ; pour ne pas faire doublon, la page
  Alertes le dit et renvoie vers Détections (lien « Voir la détection » sur les alertes de type `detect.*`), et Détections fonctionne sans Wazuh.
- **Vue d'ensemble** : en tête, bandeau « Rien à signaler » (vert) ou nombre de détections des 7 derniers jours par gravité avec
  l'application la plus préoccupante et les trois plus graves ; il se met à jour à l'arrivée d'une détection sur le flux SSE.
- **Applications** : onglet **Risque** (premier onglet) = profil `app.risk` (tri par score, niveau, raisons traduites avec explication et
  « souvent légitime parce que… », combinaisons `combo_*` en rouge et en tête, installateur et « hors boutique » ; un code inconnu est affiché
  tel quel, marqué « code inconnu ») ; onglet **Opérations sensibles** = `app.ops`.
- **Fiche d'application** `/applications/fiche?pkg=<paquet>` (depuis le risque, l'inventaire, les détections, les rôles) : profil et raisons, rôles
  (`app.special_access.default_apps` et historique `app.role`), informations, détections de l'application (avec arrivée en direct),
  permissions, opérations, domaines contactés, historique d'installation. **Le paquet est un paramètre de requête et non un segment de chemin** :
  il contient des points, et le serveur répond 404 à un chemin dont la fin ressemble à une extension de fichier (contrat §6).
- **Sécurité > Rôles par défaut** : rôles actuels et historique des changements (`app.role`).
- **Journal** : `detect.*`, `app.risk`, `app.role`, `app.ops`, `tracking.level_changed` et `tracking.override` sont décrits en clair.

**Chaque détection** montre : gravité (mots et couleur), type, application (nom et paquet), heure, **une phrase de ce qui a été observé** (construite
à partir de la preuve, sinon le `summary` du collecteur), période, aperçu des preuves, puis (dépliable ; la première est ouverte) preuves complètes,
pourquoi c'est suspect, explications innocentes, que faire, liens (fiche, domaines dans Pistage pré-filtrés, trafic dans Réseau, Caméra et micro) et rappel de la
garde de l'application qui répond au risque. **Les gardes ne se règlent que sur le téléphone** : le texte le dit (le serveur ne commande jamais le
téléphone). Filtres : type, gravité, période ; pagination par curseur (« Charger plus ») ; les nouvelles détections du flux SSE s'ajoutent en tête
sans doublon (identifiant de l'événement serveur).

**Honnêteté.** « Rien à signaler » n'est pas une garantie et le dit ; les détections sont des indices, pas des preuves. **`app.ops` est expérimental
et peut être absent** : l'onglet affiche alors un état vide qui explique l'activation (permission `DUMP` accordée par ADB avec
`grant-adb-permissions`, collecteur expérimental dans l'onglet Collecteurs de l'application) et rappelle que l'absence de données n'est pas une absence
d'usage ; jamais un écran cassé (réponse vide, route 404 et erreur de réseau sont distinguées). Tout texte venu du téléphone ou du réseau est
affiché comme du texte (`cleanText` : contrôles et marques bidirectionnelles retirés).

**Lecture tolérante de l'API** (`src/lib/risk.ts`, `ops.ts`, `detections.ts`) : le contrat fixe les champs mais pas toute l'enveloppe ni les clés de
`evidence`. `GET /apps/risk` : `{apps:[…]}` (ou tableau nu) ; `GET /apps/ops` : `{apps:[{package, ops:[{op,count,background_count,last_ts}]}]}` (format du
collecteur) ou lignes à plat ; `GET /detections` : `{detections, next_cursor}`, gravité `severity` de 0 à 3 (ou `low`/`medium`/`high`/`critical`). Les clés de preuve lues sont
celles de `internal/detect` du collecteur (`domain`/`requests`, `tx_bytes`/`median_bytes`, `addresses`, `ports`, `resolvers`/`providers`, `sent`/`background`/`reason`,
`op`/`background_count`, `trigger`/`capability`/`reasons`…), avec des alias pour d'autres formes ; une preuve illisible retombe sur le `summary` du collecteur.

**Écarts avec le contrat §11 (à y consigner)** : (1) l'enveloppe de `/apps/risk` et `/apps/ops` et les clés de `evidence` de chaque type ne sont pas
spécifiées ; (2) `GET /detections` n'a pas de filtre `package` : la fiche d'application le transmet (ignoré par le contrat) et filtre côté client,
en enchaînant jusqu'à 6 pages ; un filtre serveur éviterait ce balayage ; (3) `window_from`/`window_to` sont décrits comme portés par chaque détection mais absents de la
liste des champs de l'API (le collecteur les renvoie : lus s'ils sont là, sinon « détectée le … ») ; (4) l'échelle de `severity` (0 à 3 comme `sev`) n'est pas écrite ;
(5) le niveau de `app.risk` fait foi ; s'il est absent ou inconnu, repli sur le score avec les seuils du contrat §11.2 (< 30 faible, < 70 moyen, sinon élevé) ;
(6) le nom du collecteur `app.ops` dans `agent.heartbeat.collectors` n'est pas fixé (la console cherche une clé contenant « ops ») ; (7) `tracking.level_changed.changes`
n'a pas de type fixé (nombre ou liste : les deux sont lus) ; (8) `/detections` renvoie une détection par domaine de menace et par jour : la phrase « a tenté de joindre
3 domaines » n'existe que pour une preuve groupée (`domains`).

**Ce que le verdict ne couvre pas (revue v1.2).** `detect.sms_abuse` et `detect.sensor_background` ne
reposent que sur `app.ops`, collecteur expérimental et éteint par défaut : sans lui, une appli qui enverrait
des milliers de SMS ne produit aucune détection, et « Rien à signaler » serait trompeur. Le bandeau de verdict
(page Détections et vue d'ensemble) affiche donc une ligne « Non surveillé ici… » tant que le dernier battement
de cœur du téléphone ne signale pas ce collecteur `running` (`opsBlindSpot` dans `src/lib/detections.ts`,
testé). « En marche » ne prouve pas que des données arrivent : le vérifier dans Applications › Opérations
sensibles. Noms d'applis et de paquets hostiles : rendus par React comme du texte (aucun `innerHTML`), API en
`application/json` avec `nosniff` ; essai avec un libellé `<img onerror>` et des champs de mauvais type contre le
vrai collecteur : renvoyé tel quel en JSON, aucune erreur serveur (le rendu dans un navigateur n'a pas été
rejoué pendant la revue : conclusion tirée de la lecture du code).

**Revue indépendante de la v1.2 (contrat §11.4).**

- **Nouveaux types** : `detect.sms_permission` (une *revue* : « cette application peut envoyer des SMS sans passer par votre messagerie ; est-ce voulu ? », badge « À vérifier »,
  renvoi vers la garde SMS), `detect.default_app_changed` (sur le rôle `sms`, la console dit que c'est la voie classique des chevaux de Troie SMS), `detect.flood` (plafond de
  200 détections par jour : agent défectueux ou appareil compromis) et `detect.inventory_mismatch` (application déclarée « système » à tort). Evidence lue au format du collecteur
  (`suppressed`/`limit`, `role`/`old`/`new`/`risk`…).
- **Mise en sourdine** : sur une détection, « Ne plus signaler pour cette application » (sauf `sms_abuse`, `default_app_changed`, `flood`, `inventory_mismatch` et les détections sans
  application), avec motif facultatif (200 caractères) et une confirmation qui dit que la détection **reste calculée et enregistrée** mais ne sera **plus ni envoyée vers Wazuh ni notifiée**.
  Les détections en sourdine sont repliées (case « Afficher les détections en sourdine (N) »), ne comptent pas dans le verdict, et la carte « Sourdines en cours » liste les sourdines
  avec leur motif, qui et quand, et leur levée. `POST`/`DELETE /detections/mute`, `GET /detections/mutes` ; un `detect.muted` / `detect.unmuted` du flux relit la liste ; une sourdine
  s'applique aussi aux détections créées avant elle. Les événements `detect.muted`/`detect.unmuted` sont décrits dans le journal. Même bouton sur la fiche d'application.
- **Récurrence** : `recurring: true` s'affiche « Déjà signalé, récurrent » (gravité déjà plafonnée à 1 par le collecteur). **Mises à jour** : un événement `update: true` + `detection_id`
  remplace la carte existante (pas de doublon).
- **Déclaré / accordé** : `app.risk` porte sur les capacités **demandées** ; la liste parallèle `granted` (avec ou sans suffixe `:granted`) distingue, dans l'onglet Risque et sur la fiche,
  « Accordée » de « Demandée, pas accordée » (trait pointillé) pour les raisons qui sont des capacités ; sans liste `granted`, aucune distinction n'est inventée. Une note explique que le
  score reste élevé quand une garde empêche l'octroi.
- **Le verdict dit la vérité** (page Détections et vue d'ensemble, vert compris) : toujours ce qui est surveillé (permission d'envoi de SMS détenue, changement d'application SMS par défaut,
  domaines de menaces, gros envois, connexions, nouvelles applications à risque) ; sans collecteur `app_ops` en marche (d'après la dernière pulsation), « Non surveillé ici : les envois de SMS
  eux-mêmes… » ; avec lui, « en marche » ne prouve pas que des données arrivent ; et que **la garde SMS de l'application Vigie est la vraie protection** (`monitoringScope`, testé).
- Hypothèses faites faute de précision au contrat : forme de `GET /detections/mutes` (`{mutes:[{device_id,type,package,reason,created_at,created_by}]}`, confirmée par le collecteur), clés
  d'evidence de `sms_permission` (aucune requise) et de `default_app_changed` (`role`, `old`, `new`, profil aplati depuis `risk` ou lu tel quel).

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
