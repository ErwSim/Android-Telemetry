# Vigie — infrastructure serveur

Déploiement Docker Compose de la partie serveur de Vigie sur **un VPS Linux public de 8 Go de RAM ou
plus** : frontal TLS **Caddy**, **collecteur Vigie** (ingestion + console), **AdGuard Home** (DNS privé
filtrant en DNS-over-TLS) et **Wazuh** 4.14.10 nœud unique (manager, indexeur, dashboard), plus un
tunnel **WireGuard** optionnel. L'installation tient en trois commandes ; tout ce qui est secret est
généré sur le serveur et n'est jamais versionné.

```
Internet ──► 80/443 Caddy ─┬─ console.D  ─► collecteur:8080 (console + /api/console)
                           ├─ ingest.D   ─► collecteur:8080 (/api/v1, certificat client OBLIGATOIRE)
                           ├─ siem.D     ─► wazuh.dashboard:5601   ┐ liste d'IP + mot de passe Caddy,
                           ├─ adguard.D  ─► adguardhome:3000       ┘ puis compte propre au service
                           └─ dns.D      (certificat seulement)
         ──► 853 AdGuard Home (DoT, certificat de dns.D fourni par Caddy, rechargé à chaud)
collecteur ──events.ndjson──► wazuh.manager ◄──querylog.json── AdGuard Home
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
   l'API Wazuh, d'AdGuard, du compte d'administration Caddy, de la console) ; les valeurs existantes
   sont conservées d'une exécution à l'autre ;
3. génère la PKI interne de Wazuh (`secrets/wazuh-certs/`, openssl, sans téléchargement) ;
4. génère les configurations (`data/`) : comptes de l'indexeur hachés (bcrypt) — les comptes de
   démonstration de l'image (`kibanaro`, `logstash`, `readall`, `snapshotrestore`, mots de passe
   publics) sont supprimés —, `wazuh.yml` du dashboard, `AdGuardHome.yaml`, compte d'administration
   Caddy ;
5. construit l'image du collecteur (`server/Dockerfile`) si elle est absente (`--build` pour forcer) ;
6. démarre l'indexeur, **applique les comptes avec `securityadmin.sh`** puis vérifie que le mot de
   passe admin généré est accepté ; pose le modèle d'index et les politiques de rétention ;
7. démarre le collecteur, récupère l'AC de ses certificats clients pour Caddy (mTLS), démarre Wazuh,
   Caddy (obtention des certificats), puis AdGuard Home dès que le certificat de `dns.D` existe ;
8. crée le compte console `admin` (`vigie-collector user set-password`) et importe les tableaux de
   bord Wazuh « Vigie » ;
9. affiche le récapitulatif : adresses, enregistrements DNS, ports à ouvrir, où sont les mots de passe.

Il est **rejouable** : on le relance après toute modification de `.env` ou une mise à jour du dépôt
(vérifié : deux exécutions successives laissent `.env` identique octet pour octet et la pile saine).

Options utiles : `--profile strict` (filtrage DNS strict), `--clientid` (§6.3), `--admin-allow
"203.0.113.0/24 2001:db8::/32"` (§5), `--rotate-passwords`, `--no-start`.

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

### 6.2 Listes de blocage et profils

| ID | Liste | Équilibré | Strict |
|---|---|---|---|
| 1 | `adguard/vigie-base.txt` (versionné) : exceptions indispensables + télémétrie Google/Samsung commentée ligne à ligne | ✓ | ✓ |
| 2 | `adguard/vigie-strict.txt` (versionné) : Firebase Remote Config, Galaxy Store, push et cloud Samsung… | | ✓ |
| 10 | HaGeZi **Multi PRO** (publicité, pistage, télémétrie ; faux positifs rares) | ✓ | |
| 10 | HaGeZi **Multi PRO++** (plus agressive) | | ✓ |
| 20 | HaGeZi **Native Tracker Samsung** | ✓ | ✓ |
| 30 | HaGeZi **Threat Intelligence Feeds (medium)** : maliciels, hameçonnage, C2 | ✓ | ✓ |
| 90 | `data/adguard/userfilters/regles-perso.txt` (vos règles, non versionnées, sauvegardées) | ✓ | ✓ |

Profil **équilibré** (défaut, décision du propriétaire) : Play Services, Play Store, notifications
push FCM et apps bancaires (Play Integrity) restent fonctionnels grâce aux exceptions `@@…$important`
de `vigie-base.txt` (test de connectivité, `mtalk*.google.com`, FCM, installations Firebase, Play,
comptes Google, mises à jour Google et Samsung FOTA) ; Firebase Analytics, Crashlytics, journaux
Firebase, télémétrie Play Services, régies Google et Samsung, diagnostic Samsung sont bloqués.
Profil **strict** : `sudo ./install.sh --profile strict` (retour : `--profile equilibre`).

Les listes HaGeZi (GPL-3.0) sont téléchargées par AdGuard depuis jsDelivr et rafraîchies toutes les
12 h. `install.sh` régénère `AdGuardHome.yaml` à chaque exécution : **les réglages faits dans
l'interface web d'AdGuard sont écrasés**, mettez vos règles dans `regles-perso.txt`.

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

### 7.2 Règles Vigie (`wazuh/rules/`, identifiants 100100-100449)

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
| Repli | sévérité 3 / 2 signalée par l'agent pour un type sans règle dédiée (10 / 6) |

Correspondances MITRE ATT&CK **Mobile** (T1629.003, T1638, T1461, T1453, T1517, T1626.001…) : la base
MITRE embarquée dans Wazuh ne connaît que la matrice Entreprise (une balise `<mitre>` mobile est
rejetée et disparaît de l'alerte) ; elles sont donc portées par les groupes `attack_mobile_<ID>`.

**Tests** : `wazuh/tests/cases/*.log` (121 cas, un fichier par cas, la dernière ligne doit déclencher
la règle attendue) ; `./wazuh/tests/run-tests.sh` les rejoue avec `wazuh-logtest` dans le manager ;
`wazuh/tests/generer-cas.py` les régénère.

Limites (de Wazuh, documentées dans les règles) : un événement ne déclenche qu'**une** règle (les
règles filles sont essayées par niveau décroissant), d'où les événements `security.posture_change`
(un par champ) ; un défaut **déjà présent à l'enrôlement** ne produit pas de changement, donc pas
d'alerte : vérifier la posture initiale dans la console. Un micro utilisé écran éteint pendant un
appel (source `voice_communication`, capteur de proximité) n'alerte pas. `wazuh-logtest` n'applique
pas l'option `ignore` des règles (vérifiée dans le flux réel).

### 7.3 Rétention, carte, tableaux de bord

- Politiques ISM : alertes 180 jours (`WAZUH_ALERTS_RETENTION_DAYS`), archives 90 jours
  (`WAZUH_ARCHIVES_RETENTION_DAYS`), supervision 30 jours. Modifier `.env` puis `./install.sh`.
- Modèle d'index `vigie` (ordre 1, complète celui de Wazuh) : 1 shard sans réplique ;
  `data.vigie.data.location` en **geo_point** (carte) ; feuilles de `data.vigie.data.*` en `keyword`
  (un même nom de champ porte des types différents selon l'événement : sans cela l'indexeur rejetait
  des documents) ; champs numériques connus typés pour les graphiques. Un modèle ne s'applique qu'aux
  index créés après lui (index quotidiens : effet le lendemain d'une modification).
- Tableaux de bord importés : **« Vigie — sécurité du téléphone »** (alertes dans le temps, par règle,
  par technique ATT&CK Mobile, liste, carte des positions) et **« Vigie — pistage et DNS »** (apps qui
  contactent la télémétrie, domaines bloqués, événements par type), + recherches enregistrées.
  Le fond de la carte est chargé par le navigateur depuis le service de tuiles d'OpenSearch (tiers) ;
  la console Vigie a sa propre carte.

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

régénère tous les mots de passe, réapplique les comptes de l'indexeur avec `securityadmin.sh`
(procédure délicate de Wazuh, automatisée et vérifiée : ancien mot de passe refusé, nouveau accepté
par l'indexeur, Filebeat, le dashboard, l'API, le collecteur, AdGuard et Caddy). Pour un seul mot de
passe : modifier la valeur dans `.env`, puis `./install.sh`.

### 8.4 Dépannage

| Symptôme | Piste |
|---|---|
| État des services | `docker compose ps` (tous doivent être `healthy`), `docker compose logs -f <service>` |
| Le téléphone n'a plus d'Internet | DNS privé injoignable : `python3 tools/dot-query.py dns.D example.org` ; `docker compose logs adguardhome` ; désactiver temporairement le DNS privé sur le téléphone |
| Une app est cassée | Journal des requêtes AdGuard (`adguard.D`) ou tableau « pistage et DNS » : repérer le domaine bloqué, ajouter `@@\|\|domaine^$important` à `data/adguard/userfilters/regles-perso.txt`, `./install.sh` |
| Pas de certificat | DNS pas encore propagé ou port 80 fermé : `docker compose logs caddy` |
| Rien dans Wazuh | `./wazuh/tests/run-tests.sh` ; `docker compose exec wazuh.manager tail /var/ossec/logs/ossec.log` ; erreurs d'indexation : `docker compose logs wazuh.manager \| grep 'Cannot index'` |
| Indexeur en lecture seule | disque plein (> 95 %) : réduire la rétention, libérer de la place |
| Après un redémarrage de l'hôte | tout redémarre seul (`restart: unless-stopped`) ; un défaut de l'image wazuh-manager (réinitialisation interrompue au redémarrage) est contourné par `wazuh/manager/cont-init/00-vigie-pre` |

## 9. Dimensionnement mémoire (hôte 8 Go)

| Service | Limite | Mesuré au repos (essai) |
|---|---|---|
| wazuh.indexer | 3 Go (tas Java `WAZUH_INDEXER_HEAP=2g`) | 2,4 Go |
| wazuh.manager | 1,5 Go | 0,3 Go |
| wazuh.dashboard | 1 Go (tas Node 640 Mo) | 0,2-0,5 Go |
| adguardhome | 768 Mo (listes HaGeZi chargées : ≈ 300 Mo attendus) | 15 Mo sans listes |
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

## 12. Fichiers

```
infra/
├── install.sh  enroll.sh  backup.sh  restore.sh  update.sh
├── docker-compose.yml
├── lib/common.sh                    fonctions communes
├── caddy/                           Caddyfile, modes TLS, sites DNS, Dockerfile.dns (DNS-01)
├── adguard/                         gabarit AdGuardHome.yaml, règles Vigie (base, strict)
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
