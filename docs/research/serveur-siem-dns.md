# Vigie - Recherche technique : serveur SIEM / DNS / proxy

Date de la recherche : 15 novembre 2026. Méthode : Docker Hub (API), raw.githubusercontent.com (code, CHANGELOG, sources de la doc Wazuh), recherche web.
Mention « non vérifié » = non confirmé par une source primaire dans cette session.
Hôtes inaccessibles depuis l'environnement : `documentation.wazuh.com`, `caddyserver.com`, `oisd.nl`. Pour Wazuh et Caddy, la doc a été lue via les sources `.rst` / `.md` des dépôts GitHub `wazuh/wazuh-documentation` et `caddyserver/website`.

## 0. Versions retenues (état au 15/11/2026)

| Composant | Version stable | Source |
|---|---|---|
| Wazuh | **4.14.10** (tag Docker Hub du 05/11/2026). Pré-versions : 4.14.11-rc1 (12/11), **5.0.0-rc2 (30/10)** : ne pas utiliser en prod | https://hub.docker.com/v2/repositories/wazuh/wazuh-manager/tags?ordering=last_updated |
| AdGuard Home | **v0.107.80** (03/11/2026) = tag `latest` ; bêta `v1.0.0-b.2` (05/11) | https://hub.docker.com/v2/repositories/adguard/adguardhome/tags |
| Caddy | **2.11.9** (`caddy:2.11.9-alpine`) | https://hub.docker.com/v2/repositories/library/caddy/tags |
| wg-easy | image `ghcr.io/wg-easy/wg-easy:15` | https://raw.githubusercontent.com/wg-easy/wg-easy/master/docker-compose.yml |
| linuxserver/wireguard | `1.0.20260223` (reconstruite le 12/11) | https://hub.docker.com/v2/repositories/linuxserver/wireguard/tags |
| Technitium | 15.6.2 | https://hub.docker.com/v2/repositories/technitium/dns-server/tags |
| Pi-hole | 2026.11.0 | https://hub.docker.com/v2/repositories/pihole/pihole/tags |

Note AdGuard Home : le CHANGELOG indique que les upstream/bootstrap par défaut sont passés de Quad9 à Cloudflare (restrictions géographiques Quad9 en France). Définir ses propres upstream. https://raw.githubusercontent.com/AdguardTeam/AdGuardHome/master/CHANGELOG.md

---

## 1. Wazuh : version, images, dépôt, dimensionnement

**Images** (même tag pour les trois) : `wazuh/wazuh-manager:4.14.10`, `wazuh/wazuh-indexer:4.14.10`, `wazuh/wazuh-dashboard:4.14.10`. Générateur de certificats : `wazuh/wazuh-certs-generator:0.0.5`.
Sources : https://hub.docker.com/v2/repositories/wazuh/wazuh-indexer/tags, https://hub.docker.com/v2/repositories/wazuh/wazuh-dashboard/tags, https://raw.githubusercontent.com/wazuh/wazuh-docker/v4.14.10/.env

**Dépôt `wazuh/wazuh-docker`, tag `v4.14.10`, dossier `single-node/`**
- `docker-compose.yml` : 3 services (`wazuh.manager`, `wazuh.indexer`, `wazuh.dashboard`), `restart: always`.
- `generate-indexer-certs.yml` + `config/certs.yml` : génération des certificats (noms `wazuh.indexer`, `wazuh.manager`, `wazuh.dashboard`). Commande : `docker compose -f generate-indexer-certs.yml run --rm generator`. Sortie dans `config/wazuh_indexer_ssl_certs/`.
- Prérequis hôte : `sysctl -w vm.max_map_count=262144` (à rendre persistant).
- Configs montées : `config/wazuh_cluster/wazuh_manager.conf`, `config/wazuh_indexer/`, `config/wazuh_dashboard/opensearch_dashboards.yml` (+ fichiers de certificats).
- **Ports publiés par défaut** : manager 1514, 1515, 514/udp, 55000 ; indexer 9200 ; dashboard 443->5601. Sans agent Wazuh, **retirer 1514/1515/514/55000/9200** de la publication : seul le dashboard (derrière Caddy) est utile.
- Variables : `INDEXER_URL/USERNAME/PASSWORD`, `API_USERNAME/PASSWORD`, `DASHBOARD_USERNAME/PASSWORD`, `FILEBEAT_SSL_VERIFICATION_MODE`, `SSL_CERTIFICATE*`, `OPENSEARCH_JAVA_OPTS=-Xms1g -Xmx1g`. Mots de passe par défaut = valeurs d'exemple (`SecretPassword`, `MyS3cr37P450r.*-`, `kibanaserver`) : à changer (le changement des mots de passe indexer exige aussi de mettre à jour `internal_users.yml` hachés et de relancer securityadmin ; non détaillé ici).
- Volumes nommés : manager `wazuh_etc` (/var/ossec/etc, donc `rules/local_rules.xml`), `wazuh_logs`, `wazuh_queue`, `wazuh_api_configuration`, `wazuh_var_multigroups`, `wazuh_integrations`, `wazuh_active_response`, `wazuh_agentless`, `wazuh_wodles`, `filebeat_etc`, `filebeat_var` ; indexer `wazuh-indexer-data` ; dashboard `wazuh-dashboard-config`, `wazuh-dashboard-custom`.
- ulimits : manager nofile 655360 + memlock -1 ; indexer nofile 65536 + memlock -1.
Sources : https://raw.githubusercontent.com/wazuh/wazuh-docker/v4.14.10/single-node/docker-compose.yml, https://raw.githubusercontent.com/wazuh/wazuh-docker/v4.14.10/single-node/README.md

**RAM / disque**
- Doc officielle (quickstart) : 1-25 agents = 4 vCPU / **8 GiB** / 50 Go (90 jours). Doc Docker : « au moins 8 Go de RAM pour l'hôte Docker ». **4 Go n'est pas un profil supporté.** https://raw.githubusercontent.com/wazuh/wazuh-documentation/v4.14.10/source/quickstart.rst, https://raw.githubusercontent.com/wazuh/wazuh-documentation/v4.14.10/source/deployment-options/docker/wazuh-container.rst
- Le tag est le même pour tous : l'indexer (OpenSearch, JVM) est le gros consommateur ; le manager (analysisd, remoted, API Python) et le dashboard (Node) ajoutent chacun environ 0,5 à 1 Go (estimation, non vérifié).
- Règle heap (forums/docs d'indexer tuning) : Xms = Xmx, jamais > 50 % de la RAM, jamais > 32 Go. https://documentation.wazuh.com/current/user-manual/wazuh-indexer/wazuh-indexer-tuning.html (inaccessible directement ; reflété par la recherche web).
- **Réglages proposés (estimations à valider par test de charge, non vérifié)** :
  - **Hôte 8 Go** (Wazuh + AdGuard + Caddy + collecteur) : `OPENSEARCH_JAVA_OPTS=-Xms2g -Xmx2g` ; swap 2 Go ; `index.number_of_shards: 1` (le template Wazuh impose 3 shards, 0 réplica, inutile en single-node) ; politique ISM de rétention (ex. 30-90 jours).
  - **Hôte 4 Go** : `-Xms1g -Xmx1g` (défaut compose), `mem_limit` par service, swap 2-4 Go, `NODE_OPTIONS=--max-old-space-size=512` côté dashboard (prise en compte non vérifiée), désactiver modules inutiles du manager (vulnerability-detector, syscollector, rootcheck, SCA, wodles aws/gcp/azure, etc.). Marge faible : AdGuard + Caddy + Go collecteur consomment peu (<300 Mo), mais le cumul reste serré. Sinon, voir §9.
  - Les deux : retirer 1514/1515/9200/55000 des `ports`, et garder les index sur SSD.

---

## 2. Injecter des événements JSON applicatifs dans Wazuh sans agent

### Comparatif
| Option | Verdict |
|---|---|
| **`<localfile>` `log_format json` sur un NDJSON partagé par volume** | **Recommandé.** Simple, fiable, sans port exposé, décodeur JSON natif. |
| Syslog (`<remote><connection>syslog`, UDP/TCP 514) | Perd la structure JSON (il faut décoder un message syslog contenant du JSON, via `offset`) ; UDP sans garantie ; taille limitée. Non recommandé. |
| API Wazuh (55000) | À ma connaissance pas d'endpoint d'ingestion d'événements arbitraires (non vérifié). Alternative : écrire directement dans l'indexer via `_bulk` (voir §3), ce qui contourne le moteur de règles. |

### Configuration (dans `config/wazuh_cluster/wazuh_manager.conf`)
```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/vigie/events.ndjson</location>
  <label key="source">vigie</label>   <!-- label : champ ajouté à chaque événement JSON -->
</localfile>
```
Le volume du collecteur est monté en lecture seule dans le conteneur manager (`/var/vigie`). La doc localfile indique que `log_format json` sert aux fichiers JSON **mono-ligne** et que `label` permet d'ajouter des champs. `location` accepte les chaînes `strftime` (ex. `events-%Y-%m-%d.ndjson`) et les jokers (non combinables) ; un fichier absent au démarrage est re-scanné après `logcollector.vcheck_files` secondes. `only-future-events` est à `yes` par défaut (à `no` : reprise des lignes écrites pendant l'arrêt). Source : https://raw.githubusercontent.com/wazuh/wazuh-documentation/v4.14.10/source/user-manual/reference/ossec-conf/localfile.rst

### Décodage et champs
- Le décodeur `json` est natif : `<prematch>^{\s*"</prematch>` + `JSON_Decoder`. **La ligne doit donc commencer par `{"`** (pas de préfixe). https://raw.githubusercontent.com/wazuh/wazuh/v4.14.10/ruleset/decoders/0006-json_decoders.xml
- Types gérés : nombres, chaînes, booléens, null, tableaux de scalaires, objets. **« Un tableau d'objets n'est pas supporté »** : un événement = un objet avec champs scalaires/objets imbriqués, pas de `events:[{...}]`. https://raw.githubusercontent.com/wazuh/wazuh-documentation/v4.14.10/source/user-manual/ruleset/decoders/json-decoder.rst
- Les champs imbriqués sont référencés par notation pointée (`alert.severity`) dans les règles et apparaissent sous `data.*` dans l'alerte (`data.alert.severity`) (déduit de la doc ; format exact des types dans l'index non vérifié).
- Dans le code (`read_json.c`) : la ligne non-objet JSON est ignorée (debug), les lignes contenant des octets nuls sont abandonnées. L'`@timestamp`/`timestamp` indexé est l'heure d'ingestion par Wazuh, pas l'heure du JSON : conserver l'heure réelle de l'événement dans un champ (ex. `data.ts`) et trier dessus dans les visualisations.

### Règles personnalisées
- Fichier `/var/ossec/etc/rules/local_rules.xml` (volume `wazuh_etc`) ; **IDs 100000-120000** ; niveaux 0-16 ; `overwrite="yes"` pour modifier une règle existante. https://raw.githubusercontent.com/wazuh/wazuh-documentation/v4.14.10/source/user-manual/ruleset/rules/custom.rst
- Exemple :
```xml
<group name="vigie,">
  <rule id="100100" level="0">
    <decoded_as>json</decoded_as>
    <field name="source">^vigie$</field>
    <description>Vigie : événement générique</description>
  </rule>
  <rule id="100110" level="8">
    <if_sid>100100</if_sid>
    <field name="event.type">^wifi_open_network$</field>
    <description>Vigie : connexion à un Wi-Fi ouvert</description>
  </rule>
</group>
```
- `<field name="...">` prend une regex ; pas de comparaison numérique native (utiliser une regex ou pré-calculer un booléen/catégorie côté collecteur). Syntaxe : https://raw.githubusercontent.com/wazuh/wazuh-documentation/v4.14.10/source/user-manual/ruleset/ruleset-xml-syntax/rules.rst
- **Niveau 0 = pas d'alerte** (l'événement n'est donc que dans les archives). Seuil d'alerte par défaut `log_alert_level` = 3 (valeur par défaut non revérifiée dans la doc `global.rst`).
- Tester avec `/var/ossec/bin/wazuh-logtest`.

### Conserver TOUS les événements (archives)
1. `ossec.conf` du manager, bloc `<global>` : `<logall_json>yes</logall_json>` (`<logall>` pour le format texte, pas indexable). Fichier `/var/ossec/logs/archives/archives.json` (compressé/rotaté quotidiennement par le manager, **conservé indéfiniment** : prévoir purge).
2. Filebeat du conteneur manager (`/etc/filebeat/filebeat.yml`, volume `filebeat_etc`) : `filebeat.modules: wazuh: archives: enabled: true` (défaut docker : `false`). Redémarrer Filebeat. Dans l'image docker, le fichier est généré à partir de `build-docker-images/wazuh-manager/config/filebeat.yml` ; le plus propre est de monter votre propre `filebeat.yml` (méthode exacte non vérifiée).
3. Dashboard : index pattern `wazuh-archives-*`, champ temps `timestamp`. Le template Wazuh couvre `wazuh-archives-4.x-*`.
Sources : https://raw.githubusercontent.com/wazuh/wazuh-documentation/v4.14.10/source/user-manual/manager/event-logging.rst, https://raw.githubusercontent.com/wazuh/wazuh-docker/v4.14.10/build-docker-images/wazuh-manager/config/filebeat.yml
Coût disque : chaque événement est stocké deux fois (archives.json + index) ; ajouter une politique ISM sur `wazuh-archives-*`.

### Rotation du NDJSON côté producteur (comportement logcollector, code v4.14.10)
- **Inode changé** (rotation par renommage + nouveau fichier) : logcollector rouvre le fichier et émet un événement interne `ossec: File rotated` -> règle 591 niveau 3 (bénin).
- **Taille réduite avec même inode** (`copytruncate`, troncature) : relecture depuis le début et événement `File size reduced` -> **règle 592 niveau 8, MITRE T1565.001** (alerte « falsification de logs »). À éviter.
- Recommandation : **rotation par renommage** (ex. fichier daté `events-%Y-%m-%d.ndjson` avec `<location>` strftime, ou renommage + création immédiate d'un nouveau fichier), garder l'ancien fichier lisible quelques minutes (la vérification n'a lieu que toutes les `logcollector.vcheck_files` secondes ; les lignes écrites entre la dernière lecture et la rotation peuvent être perdues si le fichier est supprimé trop vite). Écrire chaque événement en **un seul `write` terminé par `\n`** : une ligne incomplète (EOF sans `\n`) est retentée plus tard.
Sources : https://raw.githubusercontent.com/wazuh/wazuh/v4.14.10/src/logcollector/logcollector.c, https://raw.githubusercontent.com/wazuh/wazuh/v4.14.10/ruleset/rules/0015-ossec_rules.xml

### Limites de taille
- `OS_MAXSTR` = 65536 ; lecture ligne = `OS_MAXSTR - 256` (~65 279 octets). **Une ligne plus longue est coupée, l'objet tronqué n'est plus du JSON valide -> événement perdu** (erreur « Large message size » dans `ossec.log`, reste de la ligne sautée). Prévoir un événement ≤ 16-32 Ko en pratique et envoyer les gros blobs ailleurs. https://raw.githubusercontent.com/wazuh/wazuh/v4.14.10/src/logcollector/read_json.c, https://raw.githubusercontent.com/wazuh/wazuh/v4.14.10/src/headers/defs.h
- `<localfile><max-size>` (défaut 10 Mo) ne concerne que le rattrapage d'anciennes données à la reprise.
- Limite de champs de l'index : `index.mapping.total_fields.limit: 10000` (template Wazuh) ; garder un schéma JSON stable (pas de clés dynamiques).
- Débit maximal (EPS) du manager pour un `localfile` : non vérifié.

---

## 3. Position GPS en `geo_point` (carte du dashboard)

- Le template Wazuh (`wazuh-alerts-4.x-*` et `wazuh-archives-4.x-*`, `order: 0`) définit `GeoLocation.location` en `geo_point`, mais ce champ est rempli par le GeoIP du décodage sur `srcip`, pas par des champs applicatifs. Les chaînes dynamiques sont mappées en `keyword`. https://raw.githubusercontent.com/wazuh/wazuh/v4.14.10/extensions/elasticsearch/7.x/wazuh-template.json
- **Faisable, mais pas « zéro configuration »** : 
  1. Dans l'événement, émettre `{"gps":{"location":{"lat":48.85,"lon":2.35}}}` (forme objet lat/lon, acceptée par `geo_point`).
  2. Ajouter un **template additionnel** (API legacy `PUT _template/vigie-geo`, `index_patterns: ["wazuh-alerts-4.x-*","wazuh-archives-4.x-*"]`, `order: 1`, mapping `data.gps.location: {type: geo_point}`). Le template `wazuh` a `order: 0` et Filebeat le réécrit au démarrage (`setup.template.overwrite: true`) ; un template distinct d'`order` supérieur n'est pas écrasé (fusion d'orders : comportement standard OpenSearch, à tester).
  3. Un mapping ne s'applique qu'aux **nouveaux index** (index quotidiens) : attendre minuit ou `reindex` ; si un index a déjà `data.gps.location` en `object` dynamique, l'événement geo_point échouera. Rafraîchir les champs de l'index pattern.
  4. Visualisation « Coordinate map »/Maps d'OpenSearch Dashboards sur le champ ; fond de carte : probablement un service de tuiles externe accessible par le navigateur (non vérifié).
- Pas de pipeline Filebeat nécessaire (le module `wazuh` a le sien ; le modifier est fragile).
- **Alternative plus simple et plus robuste** : en parallèle du NDJSON Wazuh, le collecteur Go écrit les événements géolocalisés par `_bulk` dans un index dédié (`vigie-geo-*`) avec son propre mapping `geo_point` ; carte via le dashboard ou Grafana (Geomap). Perd la corrélation par règles Wazuh pour cet index, d'où le double envoi.
- Aucune source officielle Wazuh trouvée pour la procédure complète : tout ce paragraphe est à valider par test. Références indirectes : https://groups.google.com/g/wazuh/c/7mgaXm2hOPA (type de `GeoLocation.location`, besoin de reindex).

---

## 4. AdGuard Home

**Version/image** : `adguard/adguardhome:v0.107.80` (épingler ce tag plutôt que `latest`). Volumes de l'image : `/opt/adguardhome/work` (le journal est dans `work/data/`) et `/opt/adguardhome/conf` (`AdGuardHome.yaml`) (chemins image non revérifiés ; `dataDir = "data"` confirmé dans `internal/home/config.go`). Ports : 53 tcp/udp, 853 tcp (DoT), 3000 (assistant initial), 80/443 si HTTPS interne.
Sources : https://hub.docker.com/v2/repositories/adguard/adguardhome/tags, https://raw.githubusercontent.com/AdguardTeam/AdGuardHome/v0.107.80/internal/home/config.go

**DoT / DoH et certificats**
- Clés YAML (section `tls`) : `enabled`, `server_name`, `force_https`, `port_https`, `port_dns_over_tls` (853), `port_dns_over_quic`, `certificate_path`, `private_key_path`, `strict_sni_check`. Plain DNS désactivable : `dns.serve_plain_dns: false`. https://raw.githubusercontent.com/AdguardTeam/AdGuardHome/v0.107.80/internal/home/config.go
- **Caddy ne proxifie pas du DoT** (HTTP uniquement ; il faudrait le plugin `caddy-l4`). Publier donc le **853/tcp directement depuis le conteneur AdGuard**. Le DoH, lui, peut passer par Caddy (`reverse_proxy` vers AGH ; AGH accepte alors du DoH non chiffré via une option du type `allow_unencrypted_doh` + `trusted_proxies`, noms de clés à vérifier, non vérifié).
- **Certificat : laisser Caddy faire l'ACME** (AGH n'a pas d'ACME intégré à ma connaissance, non vérifié) et monter en lecture seule dans AGH le dossier de certificats du volume `caddy_data` (`/data/caddy/certificates/acme-v02.api.letsencrypt.org-directory/<nom>/<nom>.crt|.key`, chemin usuel, non revérifié). **Depuis v0.107.72, AGH surveille les fichiers certificat/clé et les recharge** (CHANGELOG #3962), donc le renouvellement par Caddy est repris sans redémarrage ; tester une fois.
- Wildcard : Caddy doit être compilé avec un module DNS (image `caddy:2.11.9-builder` + `xcaddy build --with github.com/caddy-dns/desec` ou `.../duckdns`) ; bloc de site `*.dns.exemple.fr, dns.exemple.fr { tls { dns desec {env.DESEC_TOKEN} } }`. Les modules `caddy-dns/desec` et `caddy-dns/duckdns` existent (README vérifiés). https://raw.githubusercontent.com/caddy-dns/desec/main/README.md, https://raw.githubusercontent.com/caddy-dns/duckdns/master/README.md

**Restriction par ClientID**
- Formats : DoT `tls://<id>.dns.exemple.fr` (SNI), DoQ idem, DoH `https://dns.exemple.fr/dns-query/<id>` (chemin, **sans wildcard**) ou `https://<id>.dns.exemple.fr/dns-query` (sous-domaine, wildcard). Pour les formes sous-domaine, **le certificat doit couvrir `*.dns.exemple.fr` ET `dns.exemple.fr`** -> défi **DNS-01** obligatoire. Le code extrait l'ID comme sous-domaine immédiat de `server_name`. https://raw.githubusercontent.com/wiki/AdguardTeam/AdGuardHome/Clients.md, https://raw.githubusercontent.com/AdguardTeam/AdGuardHome/v0.107.80/internal/dnsforward/clientid.go
- `dns.allowed_clients` accepte **IP, CIDR et ClientID** ; si non vide, seuls ceux-ci sont autorisés (et `disallowed_clients` est ignoré). Sans ça, un DoT public = résolveur ouvert. https://raw.githubusercontent.com/AdguardTeam/AdGuardHome/v0.107.80/internal/dnsforward/config.go
- **Android « DNS privé » = DoT seulement**, donc l'ID ne peut passer que par le nom d'hôte (`<id>.dns.exemple.fr`) -> wildcard indispensable.
- **Sans wildcard** : (a) `allowed_clients` par IP/CIDR : possible si le téléphone sort par WireGuard (IP de tunnel stable, §8) ; (b) IP publique mobile : impraticable (change) ; (c) accepter un résolveur DoT exposé protégé uniquement par un nom d'hôte secret (non, l'ID n'étant pas vérifiable sans wildcard) -> déconseillé. **Conclusion** : wildcard via deSEC/DuckDNS DNS-01, ou WireGuard + `allowed_clients` en CIDR.

**Journal des requêtes**
- Fichier `<work_dir>/data/querylog.json` (NDJSON), rotation : à l'échéance de `querylog.interval` le fichier est renommé en `querylog.json.1` (**un seul fichier de secours**) puis recréé ; il faut donc lire en continu (changement d'inode géré par logcollector, §2). Clés de configuration : `querylog.enabled`, `file_enabled`, `interval`, `size_memory`, `ignored`, `dir_path`. https://raw.githubusercontent.com/AdguardTeam/AdGuardHome/v0.107.80/internal/querylog/querylogfile.go
- Champs d'une ligne : `T` (horodatage), `QH` (nom), `QT` (type), `QC`, `CID` (ClientID), `CP` (protocole client), `Upstream`, `Answer`/`OrigAnswer` (réponse DNS **empaquetée en base64**, bruyante), `IP` (client), `Result` (objet : blocage, règles/listes), `Elapsed` (durée), `Cached`, `AD`, `ECS`. https://raw.githubusercontent.com/AdguardTeam/AdGuardHome/v0.107.80/internal/querylog/entry.go
- Vers Wazuh : monter `work/data` en lecture seule dans le manager et ajouter un `<localfile>` json sur `querylog.json` (la ligne commence par `{"T":` donc compatible avec le prématch). Règles sur `Result.IsFiltered`, `QH`, `CID` (noms exacts du sous-objet `Result` non revérifiés). Alternative : interroger `/control/querylog` (API REST) depuis le collecteur Go pour filtrer `Answer`.

**Provisioning déclaratif d'`AdGuardHome.yaml`**
- `schema_version` courant : **34** (v0.107.80). Au démarrage AGH migre et **réécrit** le fichier : monter le dossier `conf/` (pas le fichier seul), générer le YAML par un script d'init avant le premier démarrage. Si `users` est présent, l'assistant d'installation est sauté.
- Squelette (champs vérifiés dans `config.go` : `users`, `filters`, `user_rules`, `dns.*`, `tls.*`, `querylog.*`) :
```yaml
schema_version: 34
http: { address: 0.0.0.0:3000 }          # derrière Caddy, jamais publié
users:
  - name: admin
    password: $2y$10$...                  # bcrypt : htpasswd -nbB -C 10 admin 'motdepasse'
dns:
  bind_hosts: [0.0.0.0]
  serve_plain_dns: false
  upstream_dns: [https://dns.quad9.net/dns-query]   # à choisir (cf. note Quad9/France)
  bootstrap_dns: [9.9.9.9, 1.1.1.1]
  allowed_clients: [mon-tel-1, mon-tel-2, 10.13.13.0/24]
tls:
  enabled: true
  server_name: dns.exemple.fr
  port_dns_over_tls: 853
  port_https: 0
  certificate_path: /certs/dns.exemple.fr.crt
  private_key_path: /certs/dns.exemple.fr.key
filters:
  - { enabled: true, name: "HaGeZi Pro++", url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.plus.txt", id: 1 }
user_rules:
  - '@@||mtalk.google.com^$important'
querylog: { enabled: true, file_enabled: true, interval: 24h }
```
(les clés `filters[].{enabled,name,url,id}` suivent la forme `FilterYAML` standard ; non revérifiées au code.)

**Comparaison rapide**
| | AdGuard Home | Technitium | Pi-hole + unbound |
|---|---|---|---|
| DoT/DoH serveur natif | oui | oui (certificat **PFX** requis, DoT/DoQ 853, DoH `/dns-query`) | **non** natif en v6 : proxy/stunnel à ajouter |
| ClientID par SNI/chemin | **oui** | non trouvé (non vérifié) ; politique par IP/sous-réseau (app Advanced Blocking) | non |
| Journal exploitable | **NDJSON natif** | UI/applications ; export non vérifié | base FTL, pas JSON |
| Config déclarative | un YAML | UI/API | TOML + gravity |
Sources : https://blog.technitium.com/search/label/DNS-over-HTTPS, https://selfhost.it.com/blog/pi-hole-quad9-dls-over-tls
**Conclusion : AdGuard Home** (DoT + ClientID + journal JSON + YAML déclaratif). Technitium en repli si l'on abandonne le ClientID.

---

## 5. Listes de blocage

HaGeZi, licence **GPL-3.0**, formats adblock/dnsmasq/wildcard/RPZ, expiration annoncée 8 h (mise à jour AGH automatique). URL brutes testées (HTTP 200) sur `main` ; le README recommande jsDelivr (`https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/<liste>.txt`). https://raw.githubusercontent.com/hagezi/dns-blocklists/main/README.md

| Liste | URL brute (format adblock, pour AGH) | Entrées (15/11/2026) | Remarque |
|---|---|---|---|
| Pro | `https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.txt` | 237 247 | Recommandée par l'auteur, faux positifs rares |
| **Pro++** | `.../adblock/pro.plus.txt` | 259 753 | Plus agressive, « pour utilisateurs expérimentés », admin prêt à débloquer |
| Ultimate | `.../adblock/ultimate.txt` | 297 087 | À éviter ici |
| TIF (menaces) | `.../adblock/tif.txt` (`tif.medium.txt` 353 174 ; `tif.mini.txt` 182 874) | 1 455 489 | Malware/phishing/C2 ; **version medium pour économiser la RAM** |
| Native Samsung | `.../adblock/native.samsung.txt` | ~201 | Télémétrie Samsung |
| Native Xiaomi/Huawei/OPPO-Realme/Vivo | `.../adblock/native.xiaomi.txt` etc. | - | Un fichier par constructeur |

- « Native Tracker » : les listes natives sont **déjà intégrées dans les paliers** Light -> Ultimate avec un niveau croissant ; les fichiers `native.*` servent à les ajouter à un palier plus léger.
- **OISD** : `small.oisd.nl` / `big.oisd.nl` (formats multiples, dont adblock et `domainswild2`). Site inaccessible ici : URL exacte pour AGH et **licence non vérifiée** (aucune licence CC trouvée ; dépôt miroir GPL-3 sans valeur pour la liste d'origine). HaGeZi Pro suffit, éviter de cumuler avec OISD (doublons).
- **Google télémétrie** : pas de liste dédiée vérifiée. Pro++ (testé) bloque notamment `firebaselogging.googleapis.com`, `firebaselogging-pa.googleapis.com`, `firebasecrashlytics.googleapis.com`, `play-services-telemetry.googleapis.com`, `fcmatch.google.com` ; Pro et plus bloquent `app-measurement.com`.
- **Faux positifs Android** : vérification directe dans les fichiers du 15/11/2026 : `mtalk.google.com`, `connectivitycheck.gstatic.com`, `connectivitycheck.android.com`, `clients3.google.com`, `play.googleapis.com`, `android.clients.google.com`, `update.googleapis.com` ne figurent **pas** dans Pro, Pro++ ni Ultimate (entrées exactes `||hôte^`). Risque réel venant d'autres listes ou de mises à jour futures : ajouter des règles d'autorisation `@@||hôte^$important` pour ces hôtes (rapports de blocages de `connectivitycheck.gstatic.com` -> « pas d'Internet » : https://discourse.pi-hole.net/t/pi-hole-blocks-samsung-galaxy-wifi-dns-occasionally/22640 ; `mtalk.google.com` = push FCM : https://discuss.privacyguides.net/t/google-push-notifications-routing-change/20508). 
- **Samsung** : Pro contient 135 entrées `samsung*` (dont `*.samsungdm.com` diagnostic) ; les domaines de mise à jour FOTA testés (`ospserver`, `samsungotn`) n'y figurent pas. Surveiller `samsungapps.com`, `samsungdm.com` si les mises à jour échouent (non testé sur appareil).

---

## 6. Fonction « DNS privé » d'Android

- Mode strict = nom d'hôte saisi, **DoT sur 853**, certificat validé contre les CA système et le nom d'hôte ; pas d'IP ni d'URL. Le mode Automatique est opportuniste (peut retomber en clair). En strict, **serveur injoignable = plus de résolution (fail closed)** ; Android peut afficher « réseau sans Internet » / « serveur DNS privé inaccessible ». Sources (secondaires, non officielles) : https://www.internetsociety.org/blog/2018/08/dns-privacy-in-new-android-9/, https://git.com.de/Mikaela/mikaela.github.io/raw/branch/master/blog/_posts/2019-07-11-android-private-dns-in-practice.md, https://www.privateinternetaccess.com/blog/private-dns-server-cannot-be-accessed/
- Conséquence : le serveur DNS est un **point de panne unique** du téléphone ; surveiller et prévoir une procédure de bascule (désactiver DNS privé).
- DoH3 : annoncé en 2022 pour Android 11+ via mise à jour Play, limité aux résolveurs prédéfinis (Google, Cloudflare) ; les autres utilisent DoT. État 2026 non vérifié (aucune annonce trouvée). https://9to5google.com/2022/07/19/android-dns-over-http/, https://discuss.privacyguides.net/t/google-rejects-feature-request-for-arbitrary-dns-over-https-server-support/24320
- **Sans domaine** : sous-domaine gratuit **DuckDNS** (`monnom.duckdns.org`) ou **deSEC** (`monnom.dedyn.io`) + Let's Encrypt. HTTP-01 impose 80/443 joignables ; DNS-01 (module `caddy-dns/duckdns` ou `desec`) fonctionne sans ouvrir le 80 et permet le wildcard (wildcard sur duckdns/dedyn : non testé).
- **Derrière une box** : redirection **853/tcp** (DNS privé), **443/tcp** (ingestion mTLS/admin), éventuellement 80/tcp, **51820/udp** (WireGuard) ; IPv6 : AAAA + règle de pare-feu entrante (pas de NAT) ; IP dynamique : mise à jour DDNS (TTL bas), car une IP périmée = plus de DNS sur le téléphone. **CGNAT** (aucun port entrant) : VPS peu coûteux hébergeant au moins Caddy/AdGuard, ou tunnel WireGuard de la maison vers le VPS.

---

## 7. Caddy 2.11.9 : mTLS, PKI, front d'administration

- Syntaxe vérifiée (doc `tls`) :
```caddy
ingest.exemple.fr {
  tls {
    client_auth {
      mode require_and_verify
      trust_pool file /etc/caddy/pki/vigie-ca.crt
    }
  }
  reverse_proxy collecteur:8080 {
    header_up X-Client-Cert-FP {tls_client_fingerprint}
  }
}
```
`mode` par défaut = `require_and_verify` si `trust_pool` fourni. Placeholders disponibles : `{tls_client_fingerprint}`, `{tls_client_issuer}`, `{tls_client_serial}`, `{tls_client_certificate_pem}`. https://raw.githubusercontent.com/caddyserver/website/master/src/docs/markdown/caddyfile/directives/tls.md, https://raw.githubusercontent.com/caddyserver/website/master/src/docs/markdown/caddyfile/concepts.md
- **mTLS = par connexion TLS donc par nom d'hôte, pas par chemin.** Utiliser un **sous-domaine dédié** (`ingest.`) ; pour un seul hôte, `verify_if_given` + matcher sur `{tls_client_fingerprint}` avec `respond 403` sur les chemins protégés (plus fragile). 
- **Révocation** : pas de CRL native ; utiliser le vérificateur `leaf` (liste de certificats feuilles autorisés : loaders `file`/`folder`) pour n'accepter que les appareils enrôlés, ou des certificats courts. https://raw.githubusercontent.com/caddyserver/website/master/src/docs/markdown/caddyfile/directives/tls.md (section `leaf`)
- **PKI** : CA privée ECDSA P-256 (`openssl` ou `step-cli`), CA hors ligne ; un certificat client par appareil (CN = identifiant appareil, `extendedKeyUsage=clientAuth`, validité ~1 an). Export PKCS#12 pour l'app : `openssl pkcs12 -export -inkey dev.key -in dev.crt -certfile ca.crt -out dev.p12`. Compatibilité PKCS#12 d'Android avec les algorithmes par défaut d'OpenSSL 3 (AES-256/PBKDF2) : ajouter `-legacy` ou des algorithmes SHA1/3DES en cas d'échec d'import (non vérifié). Côté app : le serveur est un certificat public (Let's Encrypt), la CA privée ne sert qu'au certificat client ; ne pas faire confiance à la CA privée pour le serveur.
- **Front d'administration** (AdGuard UI, dashboard Wazuh) : sur un sous-domaine séparé (`admin.`), idéalement **aussi en mTLS** (certificat administrateur dans le navigateur) + `basic_auth` (hash `caddy hash-password`, directive `basic_auth`) en seconde barrière. Forward-auth (Authelia) via la directive `forward_auth` est possible mais ajoute un service, une base et du SSO : surdimensionné pour un utilisateur unique (version d'Authelia non vérifiée). https://raw.githubusercontent.com/caddyserver/website/master/src/docs/markdown/caddyfile/directives/forward_auth.md
- Proxy vers le dashboard Wazuh (HTTPS interne 5601 avec CA propre) : `reverse_proxy https://wazuh.dashboard:5601` avec transport TLS approuvant `root-ca.pem` (nom de la sous-directive selon version non revérifié ; à défaut `tls_insecure_skip_verify` sur réseau Docker interne).

---

## 8. WireGuard (optionnel)

- **Image** : `ghcr.io/wg-easy/wg-easy:15` (interface web, QR code, IPv6 ; exige `NET_ADMIN`, `SYS_MODULE`, sysctls `ip_forward`) si l'on veut gérer plusieurs appareils ; `linuxserver/wireguard` (config par fichiers via `PEERS`, plus sobre, pas d'UI) si l'on préfère le déclaratif. Les deux : le module noyau WireGuard doit exister sur l'hôte. https://raw.githubusercontent.com/wg-easy/wg-easy/master/docker-compose.yml, https://raw.githubusercontent.com/linuxserver/docker-wireguard/master/README.md
- **Intérêt réel** : (1) tout le trafic du téléphone traverse le serveur : DNS, SNI, flux, certificats TLS visibles -> **Suricata/Zeek** sur l'interface `wg0` (Wazuh décode nativement `eve.json` de Suricata, cf. exemple du décodeur JSON) ; (2) IP de tunnel **stable** -> `allowed_clients` par CIDR dans AdGuard sans wildcard ; (3) contourne CGNAT / IP dynamique (keepalive), (4) chiffre le trafic sur Wi-Fi hostile.
- **Limites** : le contenu applicatif reste chiffré en TLS (on ne voit que métadonnées, pas de déchiffrement sans MITM) ; **Android n'autorise qu'un seul VPN actif** : incompatible si l'agent Vigie lui-même utilise `VpnService` (capture locale) ; batterie et latence ; toute la bande passante remonte par la connexion montante du serveur ; si le serveur tombe, le téléphone perd Internet (en mode toujours actif/bloquer sans VPN) ; Suricata/Zeek demandent des ressources supplémentaires (≥ 2 Go de RAM, estimation non vérifiée), donc incompatible avec le profil 4 Go ; exposition du réseau domestique si mal cloisonné (`AllowedIPs`, pare-feu). Interaction DNS privé Android / VPN actif : non vérifiée.
- Recommandation : **ne pas l'activer par défaut** ; l'ajouter quand l'IP fixe ou le NDR sont nécessaires.

---

## 9. Alternatives légères à Wazuh (< 4 Go de RAM)

Profils d'une phrase chacun (consommation non mesurée ici ; versions Docker Hub du 15/11/2026) :
- **VictoriaLogs + Grafana** (`victoriametrics/victoria-logs:v1.54.0`) : meilleur choix léger, ingestion JSON native (`/insert/jsonline`) directement depuis le collecteur Go, requêtes LogsQL, alertes via vmalert, carte Geomap dans Grafana ; pas de règles de détection prêtes à l'emploi (à écrire).
- **Loki + Grafana** : léger et familier, mais indexe seulement des labels (les champs JSON sont filtrés à la requête) ; moins confortable pour de gros volumes d'événements structurés (version Loki non vérifiée).
- **OpenObserve** (tag `v1.1.2` sur Docker Hub, binaire Rust unique) : tout-en-un (ingestion JSON, UI, alertes, stockage compressé) sans Grafana ; maturité cartographique non vérifiée.
- **Graylog 7.2.2** : à éviter sous 4 Go (nécessite MongoDB + Data Node/OpenSearch ; profil comparable à Wazuh sans le jeu de règles).
- Option complémentaire : garder AdGuard + Caddy + collecteur et envoyer le querylog AdGuard au même moteur léger (VictoriaLogs lit du JSON ligne à ligne).
Sources : https://hub.docker.com/v2/repositories/victoriametrics/victoria-logs/tags, https://hub.docker.com/v2/repositories/openobserve/openobserve/tags, https://hub.docker.com/v2/repositories/graylog/graylog/tags
