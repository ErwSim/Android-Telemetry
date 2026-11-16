# Vigie — infrastructure serveur

Déploiement Docker Compose de la partie serveur de Vigie sur **un VPS Linux public de 8 Go de RAM ou
plus** : frontal TLS **Caddy**, **collecteur Vigie** (ingestion + console), **AdGuard Home** (DNS privé
filtrant en DNS-over-TLS) et **Wazuh** 4.14.10 nœud unique (manager, indexeur, dashboard), plus un
tunnel **WireGuard** optionnel. L'installation tient en trois commandes ; tout ce qui est secret est
généré sur le serveur et n'est jamais versionné.

```
Internet ──► 80/443 Caddy ─┬─ console.D  ─► collecteur:8080 (console + /api/console, dont commandes et pistage)
                           ├─ ingest.D   ─► collecteur:8080 (/api/v1, certificat client OBLIGATOIRE ;
                           │                 dont le flux de commandes SSE /api/v1/commands/stream)
                           ├─ siem.D     ─► wazuh.dashboard:5601   ┐ liste d'IP + mot de passe Caddy,
                           ├─ adguard.D  ─► adguardhome:3000       ┘ puis compte propre au service
                           └─ dns.D      (certificat seulement)
         ──► 853 AdGuard Home (DoT, certificat de dns.D fourni par Caddy, rechargé à chaud)
collecteur ──events.ndjson──► wazuh.manager ◄──querylog.json── AdGuard Home
collecteur ──API :3000 (réseau interne, compte vigie-collecteur)──► AdGuard Home (vue « pistage », niveaux)
wazuh.manager ──Filebeat──► wazuh.indexer (wazuh-alerts-*, wazuh-archives-*) ◄── wazuh.dashboard
```

## 1. Prérequis

| | Minimum | Conseillé |
|---|---|---|
| RAM | 8 Go (Wazuh n'est pas pris en charge en dessous) | 8 Go + 2 Go de swap |
| CPU | 2 vCPU | 4 vCPU |
| Disque | 30 Go SSD | 50 Go SSD (≈ 90 jours d'archives pour un téléphone) |
| Système | Debian 12 / Ubuntu 24.04, noyau ≥ 5.10 | |
| Logiciels | Docker Engine **≥ 26** et le greffon `docker compose` v2, `git`, `openssl`, `curl` | |
| Réseau | IPv4 publique fixe, ports 80, 443, 853/tcp joignables | IPv6 en plus |

Installer Docker : <https://docs.docker.com/engine/install/> (dépôt officiel ; les paquets
`docker.io` des distributions sont souvent trop anciens). `install.sh` règle `vm.max_map_count=262144`
(exigé par l'indexeur) et le rend persistant dans `/etc/sysctl.d/99-vigie-wazuh.conf`.

## 2. Enregistrements DNS

Avec un domaine `vigie.exemple.fr` (n'importe quel sous-domaine d'un domaine à vous, ou un nom gratuit
DuckDNS/deSEC), créez chez votre fournisseur DNS, **avant** l'installation :

| Nom | Type | Valeur |
|---|---|---|
| `console.vigie.exemple.fr` | A (et AAAA) | IP du VPS |
| `ingest.vigie.exemple.fr` | A (et AAAA) | IP du VPS |
| `siem.vigie.exemple.fr` | A (et AAAA) | IP du VPS |
| `adguard.vigie.exemple.fr` | A (et AAAA) | IP du VPS |
| `dns.vigie.exemple.fr` | A (et AAAA) | IP du VPS |
| `*.dns.vigie.exemple.fr` | A (et AAAA) | IP du VPS — **seulement** en mode ClientID (§6.3) |

Let's Encrypt valide chaque nom par le port 80 (défi HTTP-01) : les noms doivent déjà pointer vers le
VPS. Un TTL court (300 s) facilite un changement de serveur.

## 3. Installation

```bash
git clone <ce dépôt> vigie && cd vigie/infra
sudo ./install.sh --domain vigie.exemple.fr --email vous@exemple.fr --tls acme
sudo ./firewall/ufw.sh            # pare-feu de l'hôte (SSH, 80, 443, 853)
sudo ./enroll.sh s25              # fichier d'enrôlement du téléphone : s25.vigie
```

Sans option, `install.sh` pose les questions. Il :

1. vérifie Docker, Compose, la RAM, le disque, `vm.max_map_count` ;
2. écrit `infra/.env` (droits 600) avec **tous les secrets générés** (mots de passe de l'indexeur, de
   l'API Wazuh, d'AdGuard et du compte AdGuard du collecteur, du compte d'administration Caddy, de la
   console) ; les valeurs existantes
   sont conservées d'une exécution à l'autre ;
3. génère la PKI interne de Wazuh (`secrets/wazuh-certs/`, openssl, sans téléchargement) ;
4. génère les configurations (`data/`) : comptes de l'indexeur hachés (bcrypt) — les comptes de
   démonstration de l'image (`kibanaro`, `logstash`, `readall`, `snapshotrestore`, mots de passe
   publics) sont supprimés —, `wazuh.yml` du dashboard, `AdGuardHome.yaml`, compte d'administration
   Caddy ;
5. construit l'image du collecteur (`server/Dockerfile`) si elle est absente (`--build` pour forcer) ;
6. démarre l'indexeur ; au premier démarrage, les comptes sont créés depuis `internal_users.yml` ;
   ensuite, un compte Vigie (admin, kibanaserver, vigie_reader) dont le mot de passe ne correspond
   plus à `.env` est corrigé, un par un, par l'API de sécurité (les utilisateurs créés dans le
   dashboard sont conservés) ; vérifie le mot de passe admin ; pose le modèle d'index et les
   politiques de rétention ;
7. démarre le collecteur, récupère l'AC de ses certificats clients pour Caddy (mTLS), démarre Wazuh,
   Caddy (obtention des certificats), puis AdGuard Home dès que le certificat de `dns.D` existe ;
8. crée le compte console `admin` (`vigie-collector user set-password`) **à la première installation
   seulement** et importe les tableaux de bord Wazuh « Vigie » ;
9. affiche le récapitulatif : adresses, enregistrements DNS, ports à ouvrir, où sont les mots de passe.

Il est **rejouable** : on le relance après toute modification de `.env` ou une mise à jour du dépôt
(vérifié : deux exécutions successives laissent `.env` identique octet pour octet et la pile saine).
Il ne défait pas ce que vous avez réglé dans les interfaces : mot de passe de la console changé
avec `set-password`, niveau de blocage DNS et règles posées depuis la console (§6.2), réglages
d'AdGuard, utilisateurs créés dans le dashboard Wazuh.

Options utiles : `--profile permissif|equilibre|strict` (applique un niveau de blocage DNS, §6.2),
`--clientid` (§6.3), `--admin-allow
"203.0.113.0/24 2001:db8::/32"` (§5), `--rotate-passwords` (§8.3), `--reset-console-password`
(§8.3), `--reset-adguard` (§6.2), `--renew-wazuh-certs` / `--renew-wazuh-ca` (§8.6), `--build`,
`--no-start`.

**Où sont les mots de passe ?** `infra/secrets/identifiants.txt` (récapitulatif lisible) et
`infra/.env` (source de vérité), droits 600, jamais versionnés. Sauvegardez-les (§8.2).

### Sur le téléphone

1. Transférer `s25.vigie` par câble (`adb push s25.vigie /sdcard/Download/`), l'importer dans Vigie
   Agent, puis le détruire des deux côtés (`shred -u s25.vigie`) : il contient la clé privée et le
   jeton de l'appareil.
2. Paramètres → Connexions → Plus de paramètres → DNS privé → *Nom d'hôte du fournisseur* :
   `dns.vigie.exemple.fr` (l'app Vigie peut l'imposer en mode Device Owner). En mode strict, si le
   serveur est injoignable le téléphone **n'a plus de DNS** : c'est voulu (pas de fuite en clair), mais
   gardez en tête qu'une panne du VPS se voit immédiatement sur le téléphone.

### Mode TLS interne (tests, réseau local)

`--tls internal` utilise l'AC interne de Caddy au lieu de Let's Encrypt (aucun port 80 public ni
domaine réel nécessaires). Il faut alors faire confiance à `data/caddy/server-root-ca.crt` : dans le
navigateur, et sur Android (Paramètres → Sécurité → Chiffrement → Installer un certificat AC) pour
que le DNS privé fonctionne. Les fichiers `.vigie` contiennent cette AC (`server_ca_pem`) pour
l'agent. Ce mode est celui des essais décrits au §11.

## 4. Ce qui est exposé sur Internet, et pourquoi

| Port | Service | Pourquoi |
|---|---|---|
| 80/tcp | Caddy | Défi ACME HTTP-01 de Let's Encrypt, redirection vers HTTPS |
| 443/tcp | Caddy | Console, ingestion (mTLS), dashboard Wazuh et AdGuard (protégés, §5) |
| 853/tcp | AdGuard Home | DNS-over-TLS : seul protocole du « DNS privé » d'Android |
| 51820/udp | WireGuard | **Seulement** avec le profil optionnel `wireguard` |

Rien d'autre n'est publié : pas de 53 (DNS en clair), ni 1514/1515 (agents Wazuh : il n'y en a pas,
`remoted` n'écoute que sur la boucle locale du conteneur et l'enrôlement exige un mot de passe
aléatoire), ni 55000 (API Wazuh), ni 9200 (indexeur), ni 3000 (AdGuard), ni 2019 (admin Caddy). Les
conteneurs communiquent sur un réseau Docker privé (`172.31.250.0/24`, modifiable par `VIGIE_SUBNET`).

> **Docker et ufw** : les ports publiés par Docker contournent les règles `ufw`/INPUT. La liste
> ci-dessus est donc garantie par `docker-compose.yml`, pas par le pare-feu ; `firewall/ufw.sh` et
> `firewall/nftables.conf` protègent le reste de l'hôte (SSH…) et expliquent comment filtrer un port
> publié (chaîne `DOCKER-USER`).

Durcissement des conteneurs : images épinglées, `no-new-privileges`, toutes les capacités retirées
pour Caddy, le collecteur (image `scratch`, UID 65532) et AdGuard (sauf celles nécessaires),
limites mémoire, journaux Docker bornés (3 × 20 Mo). Les conteneurs Wazuh gardent leurs réglages
d'origine (l'image du manager a besoin de root pour s6-overlay et Filebeat).

## 5. Protection des interfaces d'administration

`siem.D` (dashboard Wazuh) et `adguard.D` passent par **deux barrières** :

1. **Caddy** : liste d'adresses autorisées (`VIGIE_ADMIN_ALLOW`, défaut : toutes) puis
   authentification HTTP (`basic_auth`, compte `admin`, mot de passe généré, haché bcrypt) ;
2. le **compte propre** du service (Wazuh `admin`, AdGuard `admin`).

Pourquoi : ces deux interfaces sont de grosses applications web dont l'historique compte des failles
exploitables **avant** authentification ; la barrière Caddy les rend invisibles aux robots qui
balaient Internet, sans ajouter de service (Authelia, SSO) ni de certificat client à installer dans
le navigateur. La liste d'IP est optionnelle car l'IP d'un accès mobile change : si vous administrez
depuis une connexion fixe ou via WireGuard, restreignez-la :

```bash
sudo ./install.sh --admin-allow "203.0.113.7/32 2001:db8:1234::/48"
```

L'en-tête `Authorization` de Caddy est retiré avant le dashboard (sinon il le prendrait pour des
identifiants de l'indexeur). La console Vigie (`console.D`) n'a pas cette barrière : elle a sa propre
authentification (argon2id, limitation des essais, cookie `__Host-`, CSP stricte) et c'est
l'interface du quotidien. L'ingestion exige un certificat client émis par le collecteur **et** le
jeton de l'appareil ; Caddy n'y expose que `/api/v1/*`, supprime tout en-tête `X-Vigie-*` entrant et
pose `X-Vigie-Client-Cert-Sha256`, que le collecteur n'accepte que de l'adresse fixe de Caddy.

### 5.1 Commandes à distance (v1.1) : ce qui transite

Depuis la v1.1 (principe n° 2 révisé de `docs/ARCHITECTURE.md`, contrat §8), la console peut envoyer au
téléphone des commandes d'une **liste fermée** : sonner, vibrer, arrêter la sonnerie, localiser
(simples) ; verrouiller avec un message, retirer ce message, effacer (sensibles).

- **Chemin** : navigateur → `console.D` (`/api/console/commands*`, session console) → collecteur →
  `ingest.D` → agent, par le flux `GET /api/v1/commands/stream` (Server-Sent Events) que l'agent
  ouvre lui-même avec son certificat client et son jeton (ou par interrogation `GET /api/v1/commands`).
  Le résultat revient par `POST /api/v1/commands/{id}/result` et un événement `command.result`. Rien
  n'est ouvert vers le téléphone : c'est lui qui se connecte. Les routes `/api/console/*` ne passent
  que par `console.D` ; `ingest.D` n'expose que `/api/v1/*` (404 sinon).
- **Ce que le serveur peut faire** : relayer une commande de la liste, telle que le navigateur l'a
  construite (le collecteur la transmet à l'octet près), au plus 20 par heure et 10 en attente par
  appareil. Un serveur compromis peut au pire faire sonner, vibrer ou localiser le téléphone.
- **Ce qu'il ne peut pas faire** : signer une commande sensible. La signature (HMAC-SHA256) est
  calculée dans le navigateur avec une clé dérivée d'un **code de commande** saisi à chaque fois,
  jamais envoyé au serveur ni stocké par lui ; l'agent la vérifie et refuse (`bad_signature`), puis
  se ferme aux commandes sensibles pendant une heure après 5 échecs (`locked_out`). L'effacement est
  en plus désactivé par défaut dans l'app. Aucune commande ne peut modifier un réglage, la politique
  ou l'enrôlement ; le canal se coupe dans l'app.
- **Ce qui est journalisé** : chaque émission, annulation, expiration et résultat est un événement
  (`command.issued`, `.cancelled`, `.expired`, `.reported` produits par le collecteur avec
  `vigie.source = "server"`, `command.result` produit par l'appareil), exporté vers Wazuh (§7.2). Le
  **message de verrouillage n'est jamais exporté** (seulement `message_set`) ni journalisé : il reste
  dans la base du collecteur pour la console.
- **Caddy et le flux SSE** : réponse transmise sans tampon (`flush_interval -1`), aucun délai de
  Caddy ne coupe une réponse en cours (`read_body`/`read_header` ne visent que la lecture de la
  requête, `idle` les connexions inactives entre deux requêtes) ; le collecteur envoie un maintien
  toutes les 120 s (`VIGIE_CMD_KEEPALIVE_S`). Le journal d'accès de Caddy compte **une ligne par
  connexion** (écrite à sa fermeture), pas une par message ; l'en-tête `Authorization` (jeton) y est
  masqué. Les limites de taille de corps (9 Mo sur `ingest.D`, 1 Mo sur `console.D`) sont inchangées.
  Vérifié (§11) : flux ouvert plus de 5 min à travers Caddy en HTTP/1.1 et HTTP/2 sans coupure.

## 6. DNS privé filtrant (AdGuard Home)

### 6.1 Résolveur, amont, DNSSEC

- **DoT sur 853** avec le certificat de `dns.D` obtenu par Caddy (volume `caddy_data`, seul le
  répertoire de ce certificat est monté, en lecture seule). AdGuard surveille le fichier et **recharge
  le certificat renouvelé sans redémarrer** (vérifié, §11).
- **Amont : Quad9** (`https://dns.quad9.net/dns-query` et `tls://dns.quad9.net`) — fondation suisse à
  but non lucratif, pas de journalisation des adresses IP, pas d'ECS sur ce point d'accès, **validation
  DNSSEC** ; secours : **Mullvad DNS** (DoH, sans filtrage ni journalisation). Ni Google ni Cloudflare.
  AdGuard demande DNSSEC à l'amont (`enable_dnssec`) : une réponse à signature invalide revient en
  SERVFAIL et le bit AD est transmis au téléphone.
- DNS en clair (53) : actif seulement sur le réseau Docker interne (WireGuard), jamais publié.

### 6.2 Listes de blocage et niveaux

Trois **niveaux de blocage** ; la correspondance niveau → listes est **un seul fichier versionné**,
[`adguard/niveaux.json`](adguard/niveaux.json), lu à la fois par `install.sh` (qui construit les
listes d'AdGuard) et par le collecteur (`VIGIE_ADGUARD_LEVELS_FILE`, vue « pistage » de la console).

| ID | Liste | Permissif | Équilibré | Strict |
|---|---|---|---|---|
| 1 | `adguard/vigie-base.txt` (versionné) : exceptions indispensables + télémétrie Google/Samsung commentée ligne à ligne | ✓ | ✓ | ✓ |
| 2 | `adguard/vigie-strict.txt` (versionné) : Firebase Remote Config, Galaxy Store, push et cloud Samsung… | | | ✓ |
| 10 | HaGeZi **Multi PRO** (publicité, pistage, télémétrie ; faux positifs rares) | | ✓ | |
| 11 | HaGeZi **Multi PRO++** (plus agressive) | | | ✓ |
| 20 | HaGeZi **Native Tracker Samsung** | | ✓ | ✓ |
| 30 | HaGeZi **Threat Intelligence Feeds (medium)** : maliciels, hameçonnage, C2 | ✓ | ✓ | ✓ |
| 90 | `data/adguard/userfilters/regles-perso.txt` (vos règles, non versionnées, sauvegardées) — hors niveaux, toujours active | ✓ | ✓ | ✓ |

**Équilibré** (défaut à la première installation, décision du propriétaire) : Play Services, Play
Store, notifications push FCM et apps bancaires (Play Integrity) restent fonctionnels grâce aux
exceptions `@@…$important` de `vigie-base.txt` (test de connectivité, `mtalk*.google.com`, FCM,
installations Firebase, Play, comptes Google, mises à jour Google et Samsung FOTA) ; Firebase
Analytics, Crashlytics, journaux Firebase, télémétrie Play Services, régies Google et Samsung,
diagnostic Samsung sont bloqués. **Strict** : PRO++ au lieu de PRO, plus `vigie-strict.txt`.
**Permissif** : le minimum jugé utile — le flux de menaces (protection, pas confort : il ne casse
rien d'ordinaire) et `vigie-base.txt` (une vingtaine de domaines de télémétrie et de régie Google
et Samsung choisis un par un, sans effet visible, plus les exceptions qui garantissent push, Play et
mises à jour) ; aucune liste publicitaire générale, pour dépanner une app récalcitrante sans
renoncer à la protection contre les domaines malveillants.

Chaque liste de `niveaux.json` porte une **catégorie** (`category`) : `threat` (menaces : hameçonnage,
maliciels, serveurs de commande), `ads`, `tracking`, `mixed` (liste générale qui mêle publicité, pistage et
quelques menaces), `custom`, `allowlist`. Seule `threat` change un comportement : un blocage dû à une liste
`threat` alimente la détection `detect.threat_domain` du collecteur (§7.4) ; sans aucune liste `threat`, cette
détection reste muette. Ici : HaGeZi TIF (30) est `threat` ; Multi PRO et PRO++ sont `mixed` ; Vigie base,
Vigie strict et Samsung sont `tracking`. Le collecteur refuse de démarrer sur une catégorie inconnue ;
`merge-config.py` la vérifie dès l'installation. Si vous ajoutez une liste de menaces au fichier, donnez-lui
`"category": "threat"` (le nom ou l'adresse ne suffisent pas).

Toutes les listes sont **présentes** dans AdGuard quel que soit le niveau ; un niveau n'est qu'un
jeu de listes **activées** (une liste désactivée n'est ni téléchargée ni chargée en mémoire). Les
listes HaGeZi (GPL-3.0) sont téléchargées par AdGuard depuis jsDelivr (chemins vérifiés dans le
dépôt `hagezi/dns-blocklists`) et rafraîchies toutes les 12 h.

**Changer de niveau** : dans la console (vue « Pistage »), ou `sudo ./install.sh --profile strict`
(`permissif`, `equilibre`). Les deux font la même chose : activer exactement les listes du niveau.

**Source de vérité du niveau : l'état des listes dans la configuration d'AdGuard Home**, et rien
d'autre. La console le change par l'API d'AdGuard (qui l'écrit aussitôt dans `AdGuardHome.yaml`) ;
`install.sh` (et donc `update.sh`) le **conserve** ; seul `--profile` le change, ponctuellement — il
n'est mémorisé nulle part ailleurs (`VIGIE_DNS_PROFILE` de la v1 n'est plus utilisé : lu une fois
pour la migration, puis retiré de `.env`). Le niveau courant est celui dont les listes activées sont
exactement celles du fichier (`install.sh` l'affiche ; « personnalisé » si vous avez activé ou
désactivé une liste à la main dans AdGuard). Une liste ajoutée au fichier par une mise à jour du dépôt
prend l'état du niveau en service.

**Règles posées par la console** (`PUT /tracking/override`) : le collecteur les écrit dans un bloc
`! vigie:begin … ! vigie:end` des « règles de filtrage personnalisées » d'AdGuard (`||domaine^$important`
ou `@@||domaine^$important`). `install.sh` ne touche jamais aux règles personnalisées, et
`--reset-adguard` recopie ce bloc dans la configuration régénérée (ainsi que le niveau).

**Qui décide de quoi** (`adguard/merge-config.py`) : à chaque `install.sh`, la configuration gérée
par Vigie est **fusionnée** dans celle en service (AdGuard est arrêté quelques secondes, ce qui
l'oblige à écrire sa configuration à jour avant la fusion).

| Géré par Vigie (réappliqué à chaque `install.sh`, depuis `.env` et le dépôt) | Décidé dans la console (conservé) | À vous (conservé) |
|---|---|---|
| comptes `admin` et `vigie-collecteur` et leurs mots de passe ; TLS/DoT et certificat ; écoute DNS ; amonts (Quad9, Mullvad) et DNSSEC ; clients autorisés (mode ClientID) et client « Telephone (Vigie) » ; journal des requêtes lu par Wazuh et le collecteur (dont `size_memory: 50`, ci-dessous) ; **présence**, adresse, nom et identifiant des listes de `niveaux.json` et de la liste 90 | niveau de blocage (listes activées) ; bloc `! vigie:begin … ! vigie:end` des règles personnalisées | autres règles personnalisées, listes ajoutées (autres adresses), listes d'autorisation, clients, services bloqués, réécritures DNS, limitation de débit, cache, statistiques, durée du journal |

Vérifié (§11) : niveau changé dans la console et règle posée par la console conservés par
`install.sh` rejoué ; `--profile` appliqué puis vu identique par la console. Pour repartir de zéro :
`sudo ./install.sh --reset-adguard` (l'ancienne configuration est gardée dans
`data/adguard/conf/AdGuardHome.yaml.avant-reset-*` ; niveau et bloc de la console conservés). Les
règles versionnables à la main restent possibles dans `data/adguard/userfilters/regles-perso.txt`.

**Journal des requêtes (`querylog.size_memory: 50`, v1.2)** : nombre d'entrées qu'AdGuard garde en mémoire
avant de les écrire sur disque. À 1 (valeur de la v1 et de la v1.1), AdGuard perd lui-même des entrées sous
requêtes simultanées (mesuré : 187 entrées écrites pour 240 réponses avec 8 clients) ; au-delà de 500 (une page
de son API), le relevé du collecteur peut en sauter. 50 est réappliqué par chaque `install.sh`, **y compris sur
une installation existante** (vérifié : 1 → 50 au rejeu). Conséquence : le journal arrive dans Wazuh par paquets
de 50 requêtes (quelques secondes à quelques minutes de retard avec un téléphone).

### 6.3 Risque de résolveur ouvert

Un serveur DoT public répond à quiconque connaît son nom. Le DoT étant en TCP+TLS, il ne sert pas à
l'amplification (contrairement au DNS UDP), mais il peut être utilisé comme résolveur gratuit.

**Mode par défaut (simple, raisonnablement protégé)** : pas de port 53 public ; limitation de débit
par client (50 requêtes/s par /24 IPv4 ou /56 IPv6) ; `refuse_any` ; requêtes de version refusées ;
**tout est journalisé** et part dans Wazuh (on voit qui utilise le résolveur).

**Option durcie, `--clientid`** : AdGuard n'accepte plus que l'identifiant secret du téléphone,
présenté par le nom d'hôte DoT `tel-xxxxxxxxxxxx.dns.D` (+ l'adresse fixe du conteneur WireGuard).
Toute autre connexion reçoit REFUSED. Exigences :

- un enregistrement DNS joker `*.dns.D` ;
- un certificat joker `*.dns.D`, que Let's Encrypt ne délivre que par **défi DNS-01** : il faut un
  fournisseur DNS doté d'une API et d'un jeton (`--dns-provider cloudflare|desec|duckdns
  --dns-token …`) ; `install.sh` construit alors une image Caddy avec le module correspondant
  (`caddy/Dockerfile.dns`, quelques minutes, accès Internet requis) ;
- le nom d'hôte DNS privé à saisir sur le téléphone devient `tel-….dns.D` (affiché par `install.sh`,
  écrit dans les fichiers `.vigie`).

```bash
sudo ./install.sh --clientid --dns-provider desec --dns-token 'jeton-deSEC'
```

Le mode ClientID a été vérifié en mode TLS interne (§11) ; l'obtention réelle d'un joker par DNS-01
ne peut pas être testée sans domaine et jeton réels. Le sous-réseau Docker n'est volontairement pas
autorisé : sa passerelle est l'adresse vue pour toute connexion relayée par `docker-proxy` (IPv6
sans ip6tables), ce qui rouvrirait le résolveur.

### 6.4 Vue « pistage » : accès du collecteur à AdGuard Home

Le collecteur lit le journal des requêtes d'AdGuard et change niveaux et règles par l'**API
d'AdGuard sur le réseau Docker interne** (`VIGIE_ADGUARD_URL=http://adguardhome:3000`) ; rien de plus
n'est publié (le port 3000 ne l'est pas, `adguard.D` garde ses deux barrières). Il utilise un compte
dédié, **`vigie-collecteur`**, dont le mot de passe est généré par `install.sh`
(`ADGUARD_COLLECTOR_PASSWORD` dans `.env`, haché bcrypt dans `AdGuardHome.yaml`, transmis au
collecteur par variable d'environnement, jamais journalisé). **AdGuard Home n'a qu'un type de
compte : ce compte est administrateur complet d'AdGuard.** Le secret est donc traité comme celui
d'`admin` (`.env` en 600, sauvegardes chiffrées, `--rotate-passwords`) ; un compte distinct permet de
le changer sans toucher à celui que vous utilisez, et de voir qu'il ne sert qu'au collecteur.

Variables du collecteur posées par `docker-compose.yml` : `VIGIE_ADGUARD_URL`, `VIGIE_ADGUARD_USER`,
`VIGIE_ADGUARD_PASSWORD`, `VIGIE_ADGUARD_LEVELS_FILE` (= `adguard/niveaux.json`, monté en lecture
seule), `VIGIE_ADGUARD_POLL_S` (`.env`, défaut 60), `VIGIE_CMD_KEEPALIVE_S` (`.env`, défaut 120) et,
en mode ClientID (§6.3), `VIGIE_ADGUARD_CLIENTS` : `install.sh` et `enroll.sh` y écrivent
`<device_id>=<ClientID>` pour chaque appareil actif, afin que la vue n'attribue au téléphone que les
requêtes de son ClientID. Hors mode ClientID, l'adresse IP d'un téléphone change sans cesse : la
variable reste vide et tout le journal d'AdGuard est attribué à l'appareil consulté (avec plusieurs
téléphones, un blocage « menace » de l'un peut donc être rattaché à une application d'un autre qui a
demandé le même domaine le même jour). Les variables `VIGIE_DETECT_*` des détections sont au §7.4.

**Lecture du journal d'AdGuard (limite de l'essai §11.1, corrigée depuis dans le collecteur)** : AdGuard
Home v0.107.80 ne trouve, pour `older_than=T`, que l'horodatage exact d'une entrée. Le collecteur ne
passe donc plus d'instant arbitraire : première page sans `older_than`, puis l'horodatage exact de la plus
ancienne entrée lue ; chaque entrée est comptée une fois (détail : `server/collector/README.md`, relevé du
journal). Condition côté infrastructure : `size_memory` entre 1 et 500 exclus, d'où 50 (§6.2).

## 7. Wazuh

### 7.1 Ingestion et archives

- Le collecteur écrit `events.ndjson` (contrat §5) dans le volume `vigie_export`, monté en lecture
  seule dans le manager (`/var/vigie`) ; AdGuard écrit `querylog.json` dans `adguard_querylog`
  (`/var/adguard`). Deux `<localfile>` au format `json` (voir `wazuh/manager/ossec.conf`).
- `logall_json` + Filebeat (archives activées par `vigie-init.sh`) : **tous** les événements vont dans
  `wazuh-archives-4.x-AAAA.MM.JJ`, les alertes (niveau ≥ 3) dans `wazuh-alerts-4.x-*`.
- Le champ `Answer`/`OrigAnswer` du journal AdGuard (réponse DNS en base64) est retiré par Filebeat
  avant l'indexation (il reste dans `archives.json` sur disque, purgé après 14 jours).
- Rotation **par renommage** des deux fichiers : aucune perte constatée, et la règle 591 (« fichier
  tourné ») est neutralisée pour eux par la règle 100290 (niveau 0). Une troncature resterait
  signalée par la règle 592 (falsification de journal).
- `@timestamp`/`timestamp` = heure d'ingestion par Wazuh. L'heure réelle d'un événement de l'appareil
  est `data.vigie.ts` (un historique envoyé en différé arrive « d'un coup »).

### 7.2 Règles Vigie (`wazuh/rules/`, identifiants 100100-100549)

| Domaine | Détections (niveau) |
|---|---|
| Agent | altération `agent.tamper` (12), collecte ou envoi désactivé (5), tampon saturé (6), arrêt (3) |
| Absence | aucun événement depuis 60 min (7, `VIGIE_WATCH_SILENCE_MIN`), reprise (3), trous de séquence (6, ou 3 si expliqués par une purge), compteur revenu en arrière (8) — sonde `wazuh/watch/vigie_watch.py` toutes les 10 min |
| Posture (`security.posture_change`, une alerte par champ modifié) | démarrage vérifié dégradé (12), chiffrement perdu (10), perte du Device Owner (10), DNS privé désactivé/non strict (10) ou vers un hôte inattendu (10, liste CDB générée), ADB sans fil (9), verrouillage sécurisé supprimé (8), ADB (7), sources inconnues (6), Play Protect désactivé (5), options développeur (4), correctif installé et retours à la normale (3) |
| Posture (`security.posture`, état complet) | correctif > 6 mois (9) / > 3 mois (6), au plus une fois par semaine ; les autres constats sont marqués sans alerte (niveau 2, groupe `vigie_posture_state`) pour ne pas doubler les alertes de changement |
| Capteurs | micro (10) ou caméra (10) utilisés appareil verrouillé ; micro hors appel (6) ou caméra (8) utilisés écran éteint ; tout usage marqué (2) |
| Apps | installée hors Play/Galaxy Store (8) ou sans installateur/ADB (8), nouvelle app d'accessibilité (10), administrateur de l'appareil (10), écoute des notifications (8), VPN (7), permission sensible accordée (5) |
| Sécurité | AC utilisateur ajoutée (10, une seule alerte : `security.ca_cert` ; le journal système et la posture sont marqués), déverrouillages échoués répétés (10 : 5 en 10 min, ou ≥ 10 consécutifs), `security.log` (champs nommés selon la table du contrat) : shell ADB (10), commande/transfert ADB (8), journalisation arrêtée (12), tampon critique (7), violation d'intégrité de clé (12), autotest crypto (10), dm-verity non appliqué (7), échec d'effacement (8), restriction retirée (5), échec d'opération sur une clé (5), support monté (3), code modifié (3) |
| Réseau | chiffrement cellulaire nul (12), rétrogradation 2G / IMSI-catcher (10), traceur BLE qui suit (10), position simulée (9), Wi-Fi ouvert (4), réseau sans DNS privé (5), changement d'heure ≥ 1 h (5), USB avec ADB (5) |
| Pistage | requête DNS d'une app vers la télémétrie Google/Samsung (2 : sans alerte, marquée pour les tableaux) |
| AdGuard | domaine du flux de menaces demandé (10), répété (12), rafale de blocages (5) |
| Commandes à distance (émises par le collecteur, `vigie.source = "server"` exigé : un appareil ne peut pas les imiter) | effacement demandé (12), verrouillage demandé (10), retrait du message (5), localisation demandée (5), autre commande émise (3), rafale de 8 commandes en 10 min (8, déclenchée par une commande simple pour ne jamais masquer une alerte de niveau 10-12), commande sensible expirée sans résultat (6), autre expiration et annulation (3), résultat reçu par l'API `command.reported` (2 : marqué seulement) |
| Commandes à distance (résultat dit par le téléphone, `command.result`) | effacement exécuté (12), canal des commandes sensibles verrouillé après 5 signatures invalides `locked_out` (12), signature invalide `bad_signature` : quelqu'un essaie de commander le téléphone sans le code (10), verrouillage exécuté (10), commande échouée (6), commande refusée pour un autre motif (5), commande simple exécutée (3), refus `replay` d'un renvoi (2) |
| Notifications (`app.notification`, APK compagnon) | marquées sans alerte (2) ; le titre et le texte ne figurent jamais dans une description |
| Détections du collecteur (v1.2, `detect.*`, `vigie.source = "server"` exigé) | voir §7.4 : de 3 (trace) à 12, et 13 quand plusieurs types de détection visent la même application en 24 h |
| Profil de risque (`app.risk`) | marqué (2) ; risque élevé à l'installation, corrélé avec `app.installed` du même paquet dans l'heure (9), avec une raison `combo_*` (11) ; risque élevé hors installation (4) ; rien sur `low` |
| Rôles (`app.role`) | nouvelle appli SMS par défaut (8), clavier (8), téléphone (7), assistant ou saisie automatique (7), autre rôle (3) |
| Opérations (`app.ops.app`) | marquées (2) ; envoi de SMS refusé = tentative bloquée par une garde (4) ; autre accès refusé (3) |
| Permissions SMS (`app.permission_changed`) | `SEND_SMS`, `READ_SMS`, `RECEIVE_SMS`, `RECEIVE_MMS` accordée (8 : défense en profondeur, indépendante du collecteur) ; `CALL_PHONE` dans les permissions sensibles (5) |
| Gardes (`security.policy`, `profile = "guard:…"`) | garde **désactivée** (8), libération de quarantaine (5), activation, mise en quarantaine, permission rendue (3), permission refusée (2 : marqué) ; un échec reste alerté par 100187 (5) |
| Vue « pistage » (`tracking.*`, émis par le collecteur) | blocage affaibli : niveau abaissé ou posé depuis un état inconnu (8), domaine **autorisé de force** (8), blocage forcé d'un domaine indispensable (6), blocage manuel retiré (5), autre changement (3) |
| Repli | sévérité 3 / 2 signalée par l'agent pour un type sans règle dédiée (10 / 6) ; pour un type `detect.*` sans règle dédiée (ajouté au collecteur après ces règles) : 10 / 6, 3 sinon |

Correspondances MITRE ATT&CK **Mobile** (T1629.003, T1638, T1461, T1453, T1517, T1626.001…) : la base
MITRE embarquée dans Wazuh ne connaît que la matrice Entreprise (une balise `<mitre>` mobile est
rejetée et disparaît de l'alerte) ; elles sont donc portées par les groupes `attack_mobile_<ID>`.

**Tests** : `wazuh/tests/cases/*.log` (210 cas, un fichier par cas, la dernière ligne doit déclencher
la règle attendue) ; `./wazuh/tests/run-tests.sh` les rejoue avec `wazuh-logtest` dans le manager ;
`wazuh/tests/generer-cas.py` les régénère.

Limites (de Wazuh, documentées dans les règles) : un événement ne déclenche qu'**une** règle (les
règles filles sont essayées par niveau décroissant), d'où les événements `security.posture_change`
(un par champ) ; un défaut **déjà présent à l'enrôlement** ne produit pas de changement, donc pas
d'alerte : vérifier la posture initiale dans la console. Un micro utilisé écran éteint pendant un
appel (source `voice_communication`, capteur de proximité) n'alerte pas. `wazuh-logtest` n'applique
pas l'option `ignore` des règles (vérifiée dans le flux réel). Le résultat d'une commande arrive deux
fois (`command.result` de l'appareil, `command.reported` du collecteur) : seul le premier alerte.
Les règles de corrélation (`if_matched_group`) doivent suivre dans le fichier les règles du groupe
qu'elles observent (sinon elles ne voient aucun événement passé : constaté). **Un seul fil d'analyse**
(`analysisd.event_threads=1`, `rule_matching_threads=1`, posés par `vigie-init.sh`) : avec un fil par
processeur, des événements arrivés dans la même milliseconde (le collecteur écrit ses détections par
rafales) étaient évalués en parallèle et les corrélations 100489 et 100502/100503 les manquaient une fois
sur deux dans l'essai ; avec un fil, 20 sur 20. Débit mesuré avec un fil : 121 000 événements analysés et
indexés en 54 s.

Les changements de niveau de blocage et les règles posées par la vue « pistage » sont exportés depuis
la v1.2 (`tracking.level_changed`, `tracking.override`, un événement par appareil non révoqué) et
alertés quand ils affaiblissent le blocage (ci-dessus).

### 7.3 Rétention, carte, tableaux de bord

- Politiques ISM : alertes 180 jours (`WAZUH_ALERTS_RETENTION_DAYS`), archives 90 jours
  (`WAZUH_ARCHIVES_RETENTION_DAYS`), supervision 30 jours. Modifier `.env` puis `./install.sh`.
- Modèle d'index `vigie` (ordre 1, complète celui de Wazuh) : 1 shard sans réplique ;
  `data.vigie.data.location` en **geo_point** (carte) ; feuilles de `data.vigie.data.*` en `keyword`
  (un même nom de champ porte des types différents selon l'événement : sans cela l'indexeur rejetait
  des documents) ; champs numériques connus typés pour les graphiques. Un modèle ne s'applique qu'aux
  index créés après lui (index quotidiens : effet le lendemain d'une modification). Les champs
  libres de la v1.1 — `title` et `text` d'`app.notification` (512 caractères chacun, n'importe quel
  contenu), `params.*` et `message_set` des commandes, `vigie.source` — sont indexés en `keyword`
  (au-delà de 1024 caractères une valeur reste dans le document sans être indexée : jamais de rejet) ;
  le message de verrouillage n'est pas exporté. Vérifié (§11) : notification de 512 caractères avec
  guillemets, barres obliques inverses, sauts de ligne et émojis indexée, export = archives à l'unité,
  politiques de rétention rattachées aux index du jour. Le contenu des notifications est donc dans
  `wazuh-archives-*` (90 jours) si l'option « contenu » est activée dans l'app.
- Tableaux de bord importés : **« Vigie — sécurité du téléphone »** (alertes dans le temps, par règle,
  par technique ATT&CK Mobile, liste, carte des positions), **« Vigie — pistage et DNS »** (apps qui
  contactent la télémétrie, domaines bloqués, événements par type) et, depuis la v1.2, **« Vigie —
  détections et applications »** (détections par type et application, applications à risque moyen ou
  élevé, refus et actions des gardes), + recherches enregistrées (dont « détections du collecteur » et
  « profil de risque des applications »). Import vérifié (API `_import`, objets relus, requêtes non
  vides) ; l'affichage dans un navigateur n'a pas été regardé pour le troisième.
  Le fond de la carte est chargé par le navigateur depuis le service de tuiles d'OpenSearch (tiers) ;
  la console Vigie a sa propre carte.

### 7.4 Détections du collecteur (v1.2) : règles, que faire quand elles sonnent

Le collecteur calcule des détections comportementales sur les données reçues (contrat §11.3 et §11.4,
`server/collector/README.md`) et les exporte comme événements `detect.*` avec `vigie.source = "server"`.
Une détection par application, par type et par jour UTC (24 h après l'installation pour
`new_app_risky`). Une **mise à jour** (`update: true`, réexportée seulement si un élément nouveau apparaît,
une fois par heure au plus) donne une alerte de niveau 5, sans notification ; si elle fait passer à la
sévérité 3 une détection émise sous 3 dans les 24 h : « détection aggravée » (100452, 12). Une détection
`recurring: true` (déjà signalée dans les 30 jours, sévérité plafonnée à 1) n'est qu'une trace (100456, 3).
Deux **types** différents pour la même application en 24 h : 100489, niveau 13, qui remplace l'alerte du
second type et le nomme.

| Détection | Règle (niveau) | Que faire |
|---|---|---|
| `threat_domain` : l'application a demandé un domaine bloqué par une liste `threat` | 100460 (12) ; navigateur ou moins de 3 requêtes : 100461 (10) | Domaine de commande d'un maliciel probable : identifier l'application, la désinstaller (ou la mettre en quarantaine), vérifier ses accès spéciaux. Navigateur : lien d'hameçonnage suivi, vérifier qu'aucun mot de passe n'a été saisi. Ne jamais autoriser le domaine dans la console. |
| `sms_abuse` : envoi (ou tentative) de SMS par une autre appli que l'appli SMS, ou volume (exige `app_ops`) | 100462 (12) | Fraude au SMS : activer la garde SMS si ce n'est fait, désinstaller l'application, vérifier la facture chez l'opérateur, bloquer les SMS surtaxés chez l'opérateur. |
| `sms_permission` (§11.4) : une appli qui n'est ni l'appli SMS ni du système détient `SEND_SMS` | 100475 (10) | Savoir pourquoi elle peut envoyer des SMS ; sinon retirer la permission ou désinstaller ; garde SMS. |
| `default_app_changed` (§11.4) rôle `sms` | 100476 (12) ; autres rôles : 100477 (3, déjà alerté par `app.role`) | Si vous n'avez pas choisi cette appli SMS, remettre Messages par défaut et désinstaller l'application. |
| `sensor_background` : micro ou caméra en arrière-plan au-delà du seuil (exige `app_ops`) | micro 100463 (10), caméra 100464 (10) | Logiciel espion probable : retirer micro et caméra, désinstaller ; s'il est administrateur de l'appareil, le retirer d'abord. |
| `new_app_risky` : appli installée depuis moins de 24 h qui obtient une capacité sensible | sév. 3 : 100470 (12) ; 2 : 100471 (9) ; 1 (VPN, superposition) : 100472 (4) ; risque élevé sans capacité : 100473/100474 (3, déjà alerté par `app.risk` 100502/100503) | Vérifier que l'installation est voulue ; sinon désinstaller (la quarantaine aurait refusé ces permissions). |
| `mail_ports` : appli ordinaire qui envoie du courriel | 100467 (8) ; volume de spam : 100468 (10) | Spam envoyé depuis le téléphone : désinstaller. Client de messagerie légitime absent de la liste : `VIGIE_DETECT_MAIL_CLIENTS`. |
| `fanout` : centaines d'adresses en une heure | 100466 (8) | Relais / proxy résidentiel (votre connexion revendue) : désinstaller. Pair à pair ou test de débit : ignorer, ou relever `VIGIE_DETECT_FANOUT`. |
| `dns_bypass` : résolveur DoH/DoT public utilisé | 100469 (7) | L'appli échappe au filtrage DNS. Navigateur avec « DNS sécurisé » : le désactiver, ou l'exempter (`VIGIE_DETECT_DNS_BYPASS_EXEMPT`, ou sourdine dans la console). |
| `upload_spike` : envoi massif en une heure | 100465 (7) | Sauvegarde ou vidéo : rien. Sinon (galerie « coffre », appli inconnue) : exfiltration possible, désinstaller et changer les mots de passe exposés. |
| `inventory_mismatch` (§11.4, non masquable) : l'appareil déclare « système » une appli que son installateur ou un `app.installed` antérieur contredisent | 100481 (12) | Une appli qui se fait passer pour le système échapperait aux autres détections : vérifier son installateur dans la console, la désinstaller si elle n'est pas d'origine. |
| `flood` (§11.4) : plus de 200 détections dans la journée | 100478 (12) | Données incohérentes ou appareil compromis : regarder la console, l'état de l'agent et la posture. |
| `muted` / `unmuted` (§11.4) : sourdine posée / levée dans la console (`POST`/`DELETE /api/console/detections/mute` ; `sms_abuse`, `default_app_changed`, `inventory_mismatch`, `flood` refusées : `400 not_mutable`) | 100479 (6) / 100480 (3) | Sourdine non voulue = quelqu'un a utilisé la console : changer le mot de passe console. |
| type `detect.*` sans règle dédiée | 100454 (sév. 3 : 10), 100455 (sév. 2 : 6), 100450 (3) | Lire le résumé ; mettre à jour le dépôt. |

**Ce qui sonne pour l'attaque « SMS discret »** (application de boutique sans icône, `SEND_SMS` accordée
25 à 30 h après l'installation, puis envois en masse ; scénario `sms-discret` du simulateur, rejoué ici,
§11.2) :

| | Sans `app_ops` (cas réel probable) | Avec `app_ops` |
|---|---|---|
| À l'installation | `app.risk` `medium` : marqué, aucune alerte (pas de `new_app_risky`) | idem |
| À l'octroi de `SEND_SMS` | 100161 (8, `app.permission_changed`) **et** `detect.sms_permission` 100475 (**10, notifiée** au seuil par défaut) | idem |
| Pendant les envois | rien : les SMS ne sont pas comptés | `detect.sms_abuse` 100462 (12), ou 100489 (13) si une autre détection vise la même appli dans les 24 h ; refus de la garde : 100522 (4) |
| Si elle se fait appli SMS par défaut | 100511 (8, `app.role`) et `detect.default_app_changed` 100476 (12) | idem |

**Sans le collecteur expérimental `app_ops` de l'agent, l'envoi de SMS lui-même n'est pas compté** :
`sms_abuse` et `sensor_background` restent muettes (les SMS ne passent pas par le réseau IP). La protection
contre la fraude au SMS repose alors sur la **garde SMS** de l'application (qui refuse `SEND_SMS` à tout
sauf l'appli SMS), sur `detect.sms_permission` et `detect.default_app_changed`, et, indépendamment du
collecteur, sur les alertes Wazuh de permission (100161 : `SEND_SMS`/`READ_SMS`/`RECEIVE_SMS` accordée,
niveau 8) et de rôle (100511 : nouvelle appli SMS par défaut, 8 ; 100512 : téléphone, 7). Ces deux
dernières ne sont pas notifiées au seuil par défaut (10) : abaissez `VIGIE_NOTIFY_LEVEL` à 8 pour les
recevoir.

Doubles alertes évitées ou assumées : `new_app_risky` sans capacité répète l'`app.risk` de l'installation
(marquée seulement) ; `default_app_changed` hors `sms` répète `app.role` (marquée) ; `default_app_changed`
`sms` (12) et `app.role` `sms` (8) coexistent volontairement (la seconde ne dépend pas du collecteur) ; une
appli installée hors store et à risque élevé donne 100151 (8) **et** 100502/100503 (9/11) : deux faits ; un
domaine de menaces donne l'alerte AdGuard 100402 (10, par requête, sans l'application) **et**
`threat_domain` (une par jour, avec l'application).

**Variables** (`.env`, créées vides par `install.sh` et jamais écrasées ; vide = défaut du collecteur ;
après modification : `./install.sh`). Une valeur invalide empêche le collecteur de démarrer
(`docker compose logs collector`).

| Variable | Défaut du collecteur | Rôle |
|---|---|---|
| `VIGIE_DETECT_ENABLED` | `true` | `false` : aucune détection |
| `VIGIE_DETECT_DISABLE` | vide | détections éteintes, ex. `fanout,mail_ports` |
| `VIGIE_DETECT_INTERVAL_S` | `300` | intervalle entre deux passages (10 à 86400 s) |
| `VIGIE_DETECT_UPLOAD_FLOOR_MB` / `_UPLOAD_FACTOR` / `_UPLOAD_LEARN_DAYS` | `1024` / `10` / `7` | `upload_spike` : plancher en Mio/h, k × médiane, jours d'apprentissage |
| `VIGIE_DETECT_FANOUT` / `_FANOUT_SCREEN_OFF` | `300` / `100` | adresses distinctes par heure (écran allumé / éteint) |
| `VIGIE_DETECT_MAIL_MIN` / `_MAIL_CLIENTS` | `1` / vide | connexions SMTP par jour ; clients de messagerie ajoutés |
| `VIGIE_DETECT_DNS_BYPASS_MIN` / `_PORTS` / `_EXEMPT` | `1` / `443,853` / vide | résolveurs publics : connexions, ports suivis, applications exemptées |
| `VIGIE_DETECT_SMS_OTHER_MIN` / `_SMS_DAILY_MAX` | `1` / `200` | SMS par jour (autre appli / toute appli) |
| `VIGIE_DETECT_MIC_BG_MIN` / `_CAMERA_BG_MIN` | `10` / `3` | accès en arrière-plan par jour |

## 8. Exploitation

### 8.1 Mises à jour

```bash
sudo ./update.sh        # sauvegarde, git pull, images, reconstruction du collecteur, install.sh
```

Les versions sont épinglées (`docker-compose.yml`) : Wazuh 4.14.10, AdGuard Home v0.107.80,
Caddy 2.11.9. Pour monter de version, modifier le fichier (les trois images Wazuh ensemble, après
lecture des notes de version), puis `update.sh`. Les listes de blocage se mettent à jour seules.

### 8.2 Sauvegarde et restauration

```bash
sudo ./backup.sh                    # backups/vigie-AAAAMMJJ-HHMMSS.tar.gz (secrets compris)
gpg -c backups/vigie-….tar.gz       # chiffrer avant de sortir l'archive du serveur
sudo ./restore.sh backups/vigie-….tar.gz
```

La sauvegarde contient `.env`, `secrets/`, `data/` et les volumes du collecteur (**base et AC des
appareils : sans elle, il faut réenrôler les téléphones**), de Caddy (certificats), d'AdGuard et de
l'état du manager. L'index Wazuh n'y est pas par défaut (volumineux ; les événements restent dans la
base du collecteur) : `--with-siem` l'inclut en arrêtant Wazuh. Vérifié : destruction de tous les
volumes et de la configuration, puis `restore.sh` → pile saine, téléphone enrôlé accepté.

### 8.3 Mots de passe

```bash
sudo ./install.sh --rotate-passwords
```

régénère tous les mots de passe de `.env` et les applique partout : comptes de l'indexeur (par
l'API de sécurité, compte par compte : les utilisateurs créés dans le dashboard sont conservés),
Filebeat, dashboard, API Wazuh, collecteur, AdGuard (`admin` et `vigie-collecteur` : vérifié, ancien
mot de passe refusé par AdGuard, collecteur reconnecté avec le nouveau), Caddy, et le compte console `admin` (vérifié :
ancien mot de passe refusé, nouveau accepté, utilisateur ajouté dans le dashboard toujours valide).

Règle par compte :

| Compte | Source de vérité | Changer le mot de passe |
|---|---|---|
| Console Vigie `admin` | la base du collecteur | `docker compose exec collector vigie-collector user set-password admin` : conservé par `install.sh` ; `--reset-console-password` repose celui de `.env` |
| Indexeur `admin`, `kibanaserver`, `vigie_reader` ; API `wazuh-wui` | `.env` | modifier `.env` puis `./install.sh` (pas dans le dashboard : Filebeat, le dashboard et le collecteur utilisent ces comptes ; une modification faite ailleurs est remise à la valeur de `.env`) |
| Autres utilisateurs du dashboard Wazuh | le dashboard | dans le dashboard (jamais touchés par `install.sh`) |
| AdGuard `admin`, AdGuard `vigie-collecteur` (compte du collecteur, administrateur comme tout compte AdGuard), accès Caddy `admin`, WireGuard | `.env` | modifier `.env` puis `./install.sh` |

### 8.4 Dépannage

| Symptôme | Piste |
|---|---|
| État des services | `docker compose ps` (tous doivent être `healthy`), `docker compose logs -f <service>` |
| Le téléphone n'a plus d'Internet | DNS privé injoignable : `python3 tools/dot-query.py dns.D example.org` ; `docker compose logs adguardhome` ; désactiver temporairement le DNS privé sur le téléphone |
| Une app est cassée | Journal des requêtes AdGuard (`adguard.D`) ou tableau « pistage et DNS » : repérer le domaine bloqué, ajouter `@@\|\|domaine^$important` à `data/adguard/userfilters/regles-perso.txt`, `./install.sh` |
| Pas de certificat | DNS pas encore propagé ou port 80 fermé : `docker compose logs caddy` |
| Rien dans Wazuh | `./wazuh/tests/run-tests.sh` ; `docker compose exec wazuh.manager tail /var/ossec/logs/ossec.log` ; erreurs d'indexation : `docker compose logs wazuh.manager \| grep 'Cannot index'` |
| Indexeur en lecture seule, dashboard `unhealthy` (« create-index blocked ») | disque trop plein (seuils 90/95/97 %) : réduire la rétention, libérer de la place ; le blocage se lève seul quand l'espace revient |
| Après un redémarrage de l'hôte | tout redémarre seul (`restart: unless-stopped`) ; un défaut de l'image wazuh-manager (réinitialisation interrompue au redémarrage) est contourné par `wazuh/manager/cont-init/00-vigie-pre` |

### 8.5 Notifications (optionnelles)

Sans notification, une alerte grave ne se voit qu'en ouvrant la console ou le dashboard. Dans
`.env` (désactivé tant que `VIGIE_NOTIFY_URL` et `VIGIE_NOTIFY_SMTP_HOST` sont vides), puis
`./install.sh` :

| Variable | Rôle |
|---|---|
| `VIGIE_NOTIFY_LEVEL` | niveau Wazuh minimal notifié (défaut 10) ; le silence de l'agent (règle 100301) et la remise à zéro de séquence (100305) sont toujours notifiés |
| `VIGIE_NOTIFY_URL` | webhook : `POST` d'un JSON `{"title","message","priority","tags"}` |
| `VIGIE_NOTIFY_TOPIC` | sujet ntfy : ajouté au JSON (`"topic"`) ; avec ntfy, `VIGIE_NOTIFY_URL` est la racine du serveur, ex. `https://ntfy.sh` |
| `VIGIE_NOTIFY_TOKEN` | jeton facultatif, envoyé en `Authorization: Bearer …` |
| `VIGIE_NOTIFY_SMTP_HOST`, `_PORT` (587), `_TLS` (`starttls`, `tls` ou `none`), `_USER`, `_PASSWORD`, `_FROM`, `_TO` (adresses séparées par des virgules) | e-mail par un relais SMTP (celui de votre messagerie) |

Exemple avec ntfy : `VIGIE_NOTIFY_URL='https://ntfy.sh'` et `VIGIE_NOTIFY_TOPIC='un-nom-long-et-secret'`,
puis s'abonner à ce sujet dans l'app ntfy. Contenu : titre de la règle, niveau, nom de l'appareil,
type d'événement, heures, techniques ATT&CK Mobile — **jamais** le journal brut, les données de
l'événement (position GPS, identifiants, contenu) ni un secret : la notification part chez un tiers.
Un sujet ntfy public est lisible par quiconque en connaît le nom : choisissez-le long et aléatoire,
ou utilisez votre propre serveur ntfy avec jeton. Vérifié avec un récepteur local : alerte de niveau
12 et silence de l'agent reçus (webhook et e-mail), alertes sous le seuil non envoyées. Mise en
œuvre : intégration Wazuh `custom-vigie-notify` (`wazuh/notify/`), configurée au démarrage du manager.
Les échéances des certificats d'appareils ne sont pas notifiées : `./enroll.sh --list` (§8.7).

Détections (v1.2) : au seuil par défaut (10), sont notifiés les domaines de menaces contactés, la fraude au
SMS, la permission SMS détenue par une autre appli, le changement d'appli SMS par défaut, le micro ou la
caméra en arrière-plan, une appli récente qui obtient des capacités graves, le spam, le plafond de
détections, les aggravations et les corrélations (13) ; pas les pics d'envoi, l'éventail d'adresses, le
contournement DNS, les mises à jour de détection ni les traces. Le titre nomme l'application (son libellé
et son paquet) et le fait ; aucun contenu de notification ni message de verrouillage.

Commandes à distance (v1.1) : au seuil par défaut (10), sont notifiés le verrouillage et l'effacement
demandés, le verrouillage et l'effacement exécutés, une signature invalide et le verrouillage du canal
après 5 signatures invalides. La notification ne contient jamais le **message de verrouillage** (le
collecteur ne l'exporte pas) ni le **contenu d'une notification** du téléphone (`app.notification`
est de niveau 2 et sa description ne reprend ni titre ni texte). Vérifié avec un récepteur local
(§11).

### 8.6 Certificats internes Wazuh

La PKI interne (indexeur, manager, dashboard, admin) est valable 5 ans (AC : 10 ans). L'échéance est
rappelée à la fin de chaque `install.sh` (avertissement sous 90 jours).

```bash
sudo ./install.sh --renew-wazuh-certs   # nouveaux certificats, même AC (cas normal)
sudo ./install.sh --renew-wazuh-ca      # nouvelle AC et nouveaux certificats (AC compromise ou expirée)
```

Les anciens fichiers sont gardés dans `secrets/wazuh-certs/ancien-<date>/` ; les conteneurs Wazuh (et
le collecteur, avec `--renew-wazuh-ca`) sont recréés, Caddy rechargé. Vérifié pour les deux : pile
saine, données de l'indexeur conservées, nouveaux événements indexés, alertes lues par la console,
dashboard joignable par Caddy.

### 8.7 Appareils : liste, renouvellement, révocation

```bash
sudo ./enroll.sh --list                 # appareils, dernier contact, expiration du certificat (« à renouveler » sous 30 jours)
sudo ./enroll.sh --renew s25            # s25-renouvellement.vigie : nouveau jeton et certificat, même appareil
sudo ./enroll.sh --revoke s25           # ou dev_… : jeton et certificat refusés immédiatement
```

Après `--renew`, importer le nouveau fichier dans l'app (puis le détruire) : l'ancien couple reste
accepté jusqu'au premier envoi fait avec le nouveau, puis il est refusé. Vérifié à travers Caddy en
mTLS : ancien accepté (200), nouveau accepté (200), ancien refusé ensuite (401). Les certificats
d'appareils durent 2 ans.

## 9. Dimensionnement mémoire (hôte 8 Go)

| Service | Limite | Mesuré au repos (essai) |
|---|---|---|
| wazuh.indexer | 3 Go (tas Java `WAZUH_INDEXER_HEAP=2g`) | 2,4 Go |
| wazuh.manager | 1,5 Go | 0,3 Go |
| wazuh.dashboard | 1 Go (tas Node 640 Mo) | 0,2-0,5 Go |
| adguardhome | 768 Mo | 110 Mo avec les vraies listes chargées (niveau strict : PRO++, Samsung, menaces ≈ 620 000 règles ; équilibré : 107 Mo) |
| collector | 512 Mo | < 50 Mo |
| caddy | 256 Mo | 15 Mo |

Total des limites ≈ 7 Go ; prévoir 2 Go de swap. Sur un hôte plus grand, augmenter
`WAZUH_INDEXER_HEAP` (au plus la moitié de la RAM) et `WAZUH_INDEXER_MEM_LIMIT` (tas + 1 Go).
Sous 8 Go : `WAZUH_INDEXER_HEAP=1g` et `WAZUH_INDEXER_MEM_LIMIT=2g`, à vos risques.

## 10. Options

### 10.1 WireGuard (profil `wireguard`)

```bash
sudo docker compose --profile wireguard up -d wireguard
ssh -L 51821:127.0.0.1:51821 vps     # interface wg-easy : http://127.0.0.1:51821 (admin / WG_ADMIN_PASSWORD)
sudo ./firewall/ufw.sh --wireguard
```

Le tunnel donne au téléphone une adresse fixe, utilise AdGuard en DNS interne et fait passer tout son
trafic par le VPS. **Inconvénients** : Android n'accepte qu'un VPN actif (incompatible avec un
pare-feu local de type VpnService) ; batterie et latence ; toute la bande passante passe par le VPS ;
si le VPS tombe, plus d'Internet en mode « VPN permanent » ; le contenu reste chiffré en TLS (seules
les métadonnées sont visibles) ; module noyau WireGuard requis. À n'activer que si l'on en a l'usage.
Non testé ici (configuration Compose validée seulement).

### 10.2 Tuiles de la carte de la console (`VIGIE_TILE_URL`)

La console charge le fond de carte depuis `VIGIE_TILE_URL` (défaut :
`https://tile.openstreetmap.org/{z}/{x}/{y}.png`). Le serveur de tuiles voit donc l'adresse IP du
navigateur et **les zones consultées** (donc les lieux fréquentés par le téléphone). Pour l'éviter :

- choisir un fournisseur dont la politique de confidentialité vous convient (clé d'API souvent
  requise) : `VIGIE_TILE_URL='https://tuiles.fournisseur.example/{z}/{x}/{y}.png'` dans `.env`, puis
  `./install.sh` (la CSP de la console suit automatiquement) ;
- ou auto-héberger un serveur de tuiles (par exemple tileserver-gl ou un fichier PMTiles de votre
  région derrière Caddy) : plusieurs Go de disque et un peu de travail, non fourni ici.

L'URL doit être en `https://` avec les marqueurs `{z}`, `{x}`, `{y}`.

## 11. Ce qui a été vérifié (essai du 15/11/2026, mode TLS interne)

Environnement : Docker 29, 16 Go de RAM, sans accès Internet sortant pour les conteneurs. Prouvé :
installation complète puis rejouée (idempotente) ; indexeur, manager, dashboard sains avec les mots de
passe générés (anciens et comptes de démonstration refusés) ; rotation des mots de passe ; collecteur
réel : enrôlement, simulateur (48 types, dont `security.posture_change` et les capteurs avec état de
l'écran) envoyé à travers Caddy en mTLS, 13 131 lignes exportées = 13 131 documents dans
`wazuh-archives-*` (aucun rejet de l'indexeur), alertes dans `wazuh-alerts-*` lues par la console
(`/api/console/alerts`) ; rotation par renommage sans perte ni alerte ; mTLS (refus sans certificat
et avec une autre AC, acceptation avec le certificat enrôlé) ; DoT avec le certificat de Caddy,
blocage d'un domaine de `vigie-base.txt`, rechargement du certificat renouvelé sans redémarrage ;
mode ClientID (identifiant inconnu → REFUSED) ; geo_point ; import et affichage des tableaux de bord ;
sauvegarde puis restauration après destruction totale ; 121 cas de règles.

Non vérifié ici (limites de l'environnement) : Let's Encrypt (pas d'accès entrant/sortant), défi
DNS-01 et image Caddy à module DNS, téléchargement des listes HaGeZi et résolution par Quad9 (pas
d'Internet dans les conteneurs), WireGuard, `ulimits` d'origine (l'hôte d'essai plafonne `nofile` à
20 000 : surcharge de test uniquement), consommation mémoire avec les listes chargées.

### 11.1 Version 1.1 (essai du 16/11/2026, mode TLS interne)

Pile installée avec l'image du collecteur reconstruite depuis le code courant, trois appareils
enrôlés, simulateur du collecteur en agent de commandes **à travers Caddy en mTLS**
(`sim --enroll s25.vigie --follow --command-code 'correct horse battery staple'`, conteneur sur le
réseau `vigie`). Prouvé :

- **flux SSE** : `curl -N` sur `https://ingest.D/api/v1/commands/stream` (certificat et jeton d'un
  appareil) ouvert 7 min en HTTP/1.1 et en HTTP/2, maintiens reçus toutes les 120 s, aucune coupure
  par Caddy ; une commande émise pendant ce temps arrive dans la seconde (pas de tampon) ; une seule
  ligne de journal d'accès par connexion, jeton masqué ; le simulateur se reconnecte seul après une
  recréation du collecteur ;
- **commandes** : `ring` émise par `POST /api/console/commands` → exécutée, résultat revenu
  (`executed`) ; `lock` signée avec le code du vecteur de test du contrat (§8, clé dérivée pour
  l'identifiant de l'appareil) → exécutée ; `lock` signée avec un autre code → `bad_signature` ; 5
  signatures invalides → `locked_out` ; annulation d'une commande en attente ; alertes Wazuh
  correspondantes (100230-100245) dans `wazuh-alerts-*`, webhook reçu pour les niveaux ≥ 10, sans
  message de verrouillage ni contenu de notification ; message de verrouillage absent de
  `events.ndjson`, des archives et des alertes ;
- **routage** : `/api/console/*` → 404 sur `ingest.D` ; `/api/v1/*` → 404 sur `console.D` ; refus
  TLS sans certificat client ou avec une autre AC ; certificat d'un appareil + jeton d'un autre →
  401 ; en-tête `X-Vigie-Client-Cert-Sha256` forgé ignoré ; corps de 2 Mo → 413 sur `console.D` ;
- **AdGuard réel** : listes HaGeZi réelles téléchargées par AdGuard (depuis un faux CDN de test,
  voir ci-dessous) ; requêtes DoT (`tools/dot-query.py`) vers des domaines de `vigie-base.txt`
  bloquées et visibles dans la vue « pistage » avec leur motif ; `PUT /tracking/override` →
  domaine bloqué par une requête DoT (avant : non bloqué ; après : `0.0.0.0`), domaine
  indispensable refusé (`409 essential_domain`) ; `PUT /tracking/level` strict puis permissif →
  listes 2/11/20 et 10 activées ou désactivées dans AdGuard (PRO++ téléchargée à l'activation) ;
- **source de vérité** : `install.sh` rejoué → niveau `permissif` et bloc `vigie:begin` conservés, `.env`
  identique octet pour octet ; `install.sh --profile strict` → la console lit `strict` (au relevé
  suivant, ≤ 60 s) ; `--reset-adguard` → configuration régénérée, niveau et bloc conservés ;
  `--rotate-passwords` → compte `vigie-collecteur` changé, ancien mot de passe refusé, vue
  « pistage » joignable ;
- **indexation** : 435 lignes exportées = 435 documents dans `wazuh-archives-*` (dont 25 événements
  serveur), aucun rejet ; `run-tests.sh` : 143 cas sur 143.

Aménagements propres à l'environnement d'essai (fichier Compose supplémentaire hors dépôt, par
`VIGIE_COMPOSE_EXTRA`) : faux CDN `cdn.jsdelivr.net` (alias réseau, AC d'essai ajoutée au magasin
d'AdGuard, amont `[/jsdelivr.net/]127.0.0.11` posé par l'API le temps de l'essai) servant les vraies
listes HaGeZi récupérées depuis GitHub ; `nofile`/`memlock` plafonnés ; seuils disque de l'indexeur
en valeurs absolues (disque de 252 Go presque plein en proportion). Non vérifié ici : `update.sh`
(reconstruction depuis les registres d'images), expiration réelle d'une commande (1 h au moins),
vrai téléphone et vrai agent Android.

### 11.2 Version 1.2 (essai du 16/11/2026, mode TLS interne)

Pile installée avec l'image du collecteur reconstruite depuis le code courant (`docker build` avec
`mirror.gcr.io`), cinq appareils enrôlés par `enroll.sh`, simulateur en conteneur sur le réseau `vigie`
**à travers Caddy en mTLS** : `sim --enroll s25-fraude.vigie --backfill 72h --scenario fraude-sms`, puis
`--scenario tout` et `--scenario sain` (un appareil chacun ; puis `fraude-sms` et `tout` rejoués sur deux
appareils neufs après le passage à un fil d'analyse). Prouvé :

- **indexation** : 298 231 lignes exportées (dont trois fichiers après rotation) = 298 231 documents Vigie
  dans `wazuh-archives-*`, aucun rejet (`docker compose logs wazuh.manager | grep 'Cannot index'` vide),
  champs d'`evidence` de types variables compris ;
- **détections** : les 8 types du §11.3 exportés et indexés, chacun avec la règle attendue (100460,
  100462, 100465, 100466, 100468, 100470, 100472) ou, quand la même application avait déjà une détection
  d'un autre type dans les 24 h, avec la corrélation 100489 (13) — toujours le cas pour
  `sensor_background` et `dns_bypass`, précédées par `new_app_risky` de la même application : leurs
  règles propres (100463, 100469) ne sont vérifiées que par `run-tests.sh` ; `app.risk` à l'installation : 100503 pour les trois applications `combo_*` ; envois
  de SMS refusés après activation de la garde : 100522 ; `guard_enabled` : 100531 ; **scénario sain :
  zéro détection**, zéro alerte `detect.*` ;
- **`detect.threat_domain` avec le vrai AdGuard Home et le vrai `niveaux.json`** : la vraie liste HaGeZi
  TIF (353 203 domaines, récupérée sur GitHub) servie par un faux `cdn.jsdelivr.net` à l'adresse exacte du
  fichier, plus les 4 domaines de commande des scénarios ajoutés à la fin (le simulateur n'en demande pas
  d'autres) ; requêtes DoT par `tools/dot-query.py` → `0.0.0.0`, relevé du collecteur, détections
  `threat_domain` (sév. 3) pour les applications qui avaient demandé ces domaines. Un domaine réel de la
  liste (`pl.0003201.site`) est bloqué de même ; il n'a pas fait de détection faute de `net.dns` simulé
  pour lui ;
- **vue « pistage »** : `PUT /tracking/level` permissif → 100541 (8) ; `PUT /tracking/override` allow →
  100543 (8), block → 100542 (3) (un événement par appareil) ;
- **notifications** (récepteur webhook et SMTP local) : alertes ≥ 10 reçues, dont les détections graves et
  les corrélations ; aucune sous le seuil ; aucun titre ni texte de notification du téléphone dans les 155
  corps reçus ;
- **`install.sh` rejoué** : `.env` identique (`sha256sum -c`), niveau `permissif` et bloc `vigie:begin`
  conservés, `size_memory` remis de 1 à 50, tableaux de bord importés ;
- `run-tests.sh` : 210 cas sur 210.

**Second essai (même jour, collecteur avec le §11.4, image reconstruite deux fois)** : scénarios
`sms-discret --app-ops=false`, `cheval-de-troie`, `tout`, `sain`, puis `contournement-dns` sur un appareil
mis en sourdine, et `sms-discret --app-ops=false` rejoué avec le simulateur aligné sur les seuils réels du
profil de risque. Prouvé : 320 585 lignes exportées = 320 585 documents, aucun rejet ;
**`sms-discret` sans `app_ops` → une seule détection, `detect.sms_permission`, règle 100475 (10), reçue par
le webhook et par SMTP** (plus 100161, 8, à l'octroi) ; `cheval-de-troie` → `default_app_changed` exporté
(`evidence.role = sms`) et alerté (100489 en direct car corrélé à `new_app_risky` ; la ligne exportée,
rejouée seule dans `wazuh-logtest`, donne 100476, 12) ; `app.role` réel → 100511 (8) ; `tout` →
`sms_permission` 100475, `recurring` → 100456 ; **sourdine** par `POST /api/console/detections/mute` →
`detect.muted` exporté (`type`, `package`, `reason`, `user`) et alerté (100479) ; la détection couverte est
`muted: true` dans l'API et **absente de l'export** ; type non masquable → `400 not_mutable` ; `sain` :
aucune détection. Non produits par le simulateur, vérifiés par `run-tests.sh` seulement :
`inventory_mismatch`, `flood`, `unmuted`.

Constaté et corrigé pendant l'essai : corrélations manquées une fois sur deux avec plusieurs fils
d'analyse (§7.2) ; règle de corrélation placée avant les règles de son groupe (jamais déclenchée).
Aménagements de l'environnement d'essai (hors dépôt, `VIGIE_COMPOSE_EXTRA`) : faux CDN, `nofile`
plafonné, seuils disque de l'indexeur en valeurs absolues. Non vérifié ici : vrai téléphone, collecteur
`app_ops` réel, listes Multi PRO (non servies par le faux CDN), types du §11.4 émis par le vrai collecteur.

## 12. Fichiers

```
infra/
├── install.sh  enroll.sh  backup.sh  restore.sh  update.sh
├── docker-compose.yml
├── lib/common.sh                    fonctions communes
├── caddy/                           Caddyfile, modes TLS, sites DNS, Dockerfile.dns (DNS-01)
├── adguard/                         gabarit AdGuardHome.yaml, règles Vigie (base, strict),
│                                    niveaux.json (niveaux de blocage, lu aussi par le collecteur),
│                                    merge-config.py (fusion de la configuration en service)
├── wazuh/
│   ├── gen-certs.sh                 PKI interne Wazuh (openssl)
│   ├── indexer/  dashboard/          configurations (gabarits *.tmpl rendus dans data/)
│   ├── manager/                     ossec.conf, scripts d'initialisation
│   ├── rules/                       règles Vigie et AdGuard
│   ├── watch/vigie_watch.py         sonde silence / séquence
│   ├── setup/indexer-setup.sh       modèle d'index, politiques ISM
│   ├── dashboards/                  objets sauvegardés (ndjson) et leur générateur
│   └── tests/                       cas de test, run-tests.sh
├── firewall/                        ufw.sh, nftables.conf
├── tools/dot-query.py               client DoT de diagnostic
├── .env              (généré)       paramètres et secrets
├── secrets/          (généré)       identifiants.txt, PKI Wazuh, cache de hachages
└── data/             (généré)       configurations rendues, règles AdGuard personnelles
```
