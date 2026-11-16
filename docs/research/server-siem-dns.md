# Watchpost: technical research on the SIEM / DNS / proxy server

Research date: 15 November 2026. Method: Docker Hub (API), raw.githubusercontent.com (code, CHANGELOG, sources of
the Wazuh documentation), web search.
"Unverified" means not confirmed by a primary source during the research.
Hosts that could not be reached during the research: `documentation.wazuh.com`, `caddyserver.com`, `oisd.nl`. For
Wazuh and Caddy, the documentation was read through the `.rst` / `.md` sources of the GitHub repositories
`wazuh/wazuh-documentation` and `caddyserver/website`.

## 0. Versions selected (state on 2026-11-15)

| Component | Stable version | Source |
|---|---|---|
| Wazuh | **4.14.10** (Docker Hub tag of 2026-11-05). Pre-releases: 4.14.11-rc1 (11-12), **5.0.0-rc2 (10-30)**: do not use in production | https://hub.docker.com/v2/repositories/wazuh/wazuh-manager/tags?ordering=last_updated |
| AdGuard Home | **v0.107.80** (2026-11-03) = tag `latest`; beta `v1.0.0-b.2` (11-05) | https://hub.docker.com/v2/repositories/adguard/adguardhome/tags |
| Caddy | **2.11.9** (`caddy:2.11.9-alpine`) | https://hub.docker.com/v2/repositories/library/caddy/tags |
| wg-easy | image `ghcr.io/wg-easy/wg-easy:15` | https://raw.githubusercontent.com/wg-easy/wg-easy/master/docker-compose.yml |
| linuxserver/wireguard | `1.0.20260223` (rebuilt on 11-12) | https://hub.docker.com/v2/repositories/linuxserver/wireguard/tags |
| Technitium | 15.6.2 | https://hub.docker.com/v2/repositories/technitium/dns-server/tags |
| Pi-hole | 2026.11.0 | https://hub.docker.com/v2/repositories/pihole/pihole/tags |

AdGuard Home note: the CHANGELOG states that the default upstream/bootstrap servers moved from Quad9 to Cloudflare
(Quad9 geographic restrictions in France). Define your own upstreams.
https://raw.githubusercontent.com/AdguardTeam/AdGuardHome/master/CHANGELOG.md

---

## 1. Wazuh: version, images, repository, sizing

**Images** (same tag for all three): `wazuh/wazuh-manager:4.14.10`, `wazuh/wazuh-indexer:4.14.10`,
`wazuh/wazuh-dashboard:4.14.10`. Certificate generator: `wazuh/wazuh-certs-generator:0.0.5`.
Sources: https://hub.docker.com/v2/repositories/wazuh/wazuh-indexer/tags,
https://hub.docker.com/v2/repositories/wazuh/wazuh-dashboard/tags,
https://raw.githubusercontent.com/wazuh/wazuh-docker/v4.14.10/.env

**Repository `wazuh/wazuh-docker`, tag `v4.14.10`, folder `single-node/`**
- `docker-compose.yml`: 3 services (`wazuh.manager`, `wazuh.indexer`, `wazuh.dashboard`), `restart: always`.
- `generate-indexer-certs.yml` + `config/certs.yml`: certificate generation (names `wazuh.indexer`,
  `wazuh.manager`, `wazuh.dashboard`). Command: `docker compose -f generate-indexer-certs.yml run --rm generator`.
  Output in `config/wazuh_indexer_ssl_certs/`.
- Host prerequisite: `sysctl -w vm.max_map_count=262144` (to be made persistent).
- Mounted configs: `config/wazuh_cluster/wazuh_manager.conf`, `config/wazuh_indexer/`,
  `config/wazuh_dashboard/opensearch_dashboards.yml` (+ certificate files).
- **Ports published by default**: manager 1514, 1515, 514/udp, 55000; indexer 9200; dashboard 443->5601. Without a
  Wazuh agent, **remove 1514/1515/514/55000/9200** from publication: only the dashboard (behind Caddy) is useful.
- Variables: `INDEXER_URL/USERNAME/PASSWORD`, `API_USERNAME/PASSWORD`, `DASHBOARD_USERNAME/PASSWORD`,
  `FILEBEAT_SSL_VERIFICATION_MODE`, `SSL_CERTIFICATE*`, `OPENSEARCH_JAVA_OPTS=-Xms1g -Xmx1g`. Default passwords =
  example values (`SecretPassword`, `MyS3cr37P450r.*-`, `kibanaserver`): to be changed (changing the indexer
  passwords also requires updating the hashed `internal_users.yml` and re-running securityadmin; not detailed here).
- Named volumes: manager `wazuh_etc` (/var/ossec/etc, hence `rules/local_rules.xml`), `wazuh_logs`, `wazuh_queue`,
  `wazuh_api_configuration`, `wazuh_var_multigroups`, `wazuh_integrations`, `wazuh_active_response`,
  `wazuh_agentless`, `wazuh_wodles`, `filebeat_etc`, `filebeat_var`; indexer `wazuh-indexer-data`; dashboard
  `wazuh-dashboard-config`, `wazuh-dashboard-custom`.
- ulimits: manager nofile 655360 + memlock -1; indexer nofile 65536 + memlock -1.
Sources: https://raw.githubusercontent.com/wazuh/wazuh-docker/v4.14.10/single-node/docker-compose.yml,
https://raw.githubusercontent.com/wazuh/wazuh-docker/v4.14.10/single-node/README.md

**RAM / disk**
- Official documentation (quickstart): 1-25 agents = 4 vCPU / **8 GiB** / 50 GB (90 days). Docker documentation:
  "at least 8 GB of RAM for the Docker host". **4 GB is not a supported profile.**
  https://raw.githubusercontent.com/wazuh/wazuh-documentation/v4.14.10/source/quickstart.rst,
  https://raw.githubusercontent.com/wazuh/wazuh-documentation/v4.14.10/source/deployment-options/docker/wazuh-container.rst
- The tag is the same for all: the indexer (OpenSearch, JVM) is the big consumer; the manager (analysisd, remoted,
  Python API) and the dashboard (Node) each add about 0.5 to 1 GB (estimate, unverified).
- Heap rule (indexer tuning forums/docs): Xms = Xmx, never > 50 % of RAM, never > 32 GB.
  https://documentation.wazuh.com/current/user-manual/wazuh-indexer/wazuh-indexer-tuning.html (not directly
  reachable; reflected by the web search).
- **Proposed settings (estimates to be validated by load testing, unverified)**:
  - **8 GB host** (Wazuh + AdGuard + Caddy + collector): `OPENSEARCH_JAVA_OPTS=-Xms2g -Xmx2g`; 2 GB swap;
    `index.number_of_shards: 1` (the Wazuh template imposes 3 shards, 0 replicas, useless on a single node); an ISM
    retention policy (e.g. 30-90 days).
  - **4 GB host**: `-Xms1g -Xmx1g` (compose default), `mem_limit` per service, 2-4 GB swap,
    `NODE_OPTIONS=--max-old-space-size=512` on the dashboard side (whether it is honoured is unverified), disable
    unneeded manager modules (vulnerability-detector, syscollector, rootcheck, SCA, wodles aws/gcp/azure, etc.).
    Thin margin: AdGuard + Caddy + the Go collector consume little (<300 MB), but the total remains tight.
    Otherwise, see §9.
  - Both: remove 1514/1515/9200/55000 from `ports`, and keep the indices on SSD.

---

## 2. Injecting application JSON events into Wazuh without an agent

### Comparison
| Option | Verdict |
|---|---|
| **`<localfile>` `log_format json` on an NDJSON file shared by volume** | **Recommended.** Simple, reliable, no exposed port, native JSON decoder. |
| Syslog (`<remote><connection>syslog`, UDP/TCP 514) | Loses the JSON structure (a syslog message containing JSON must be decoded, through `offset`); UDP without guarantees; limited size. Not recommended. |
| Wazuh API (55000) | To our knowledge no endpoint for ingesting arbitrary events (unverified). Alternative: write directly into the indexer through `_bulk` (see §3), which bypasses the rules engine. |

### Configuration (in `config/wazuh_cluster/wazuh_manager.conf`)
```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/watchpost/events.ndjson</location>
  <label key="source">watchpost</label>   <!-- label: field added to every JSON event -->
</localfile>
```
The collector's volume is mounted read-only in the manager container (`/var/watchpost`). The localfile documentation
states that `log_format json` is for **single-line** JSON files and that `label` lets you add fields. `location`
accepts `strftime` strings (e.g. `events-%Y-%m-%d.ndjson`) and wildcards (not combinable); a file that is absent at
startup is rescanned after `logcollector.vcheck_files` seconds. `only-future-events` defaults to `yes` (with `no`:
lines written during a shutdown are picked up again). Source:
https://raw.githubusercontent.com/wazuh/wazuh-documentation/v4.14.10/source/user-manual/reference/ossec-conf/localfile.rst

### Decoding and fields
- The `json` decoder is native: `<prematch>^{\s*"</prematch>` + `JSON_Decoder`. **The line must therefore start with
  `{"`** (no prefix).
  https://raw.githubusercontent.com/wazuh/wazuh/v4.14.10/ruleset/decoders/0006-json_decoders.xml
- Types handled: numbers, strings, booleans, null, arrays of scalars, objects. **"An array of objects is not
  supported"**: one event = one object with scalar or nested-object fields, no `events:[{...}]`.
  https://raw.githubusercontent.com/wazuh/wazuh-documentation/v4.14.10/source/user-manual/ruleset/decoders/json-decoder.rst
- Nested fields are referenced with dot notation (`alert.severity`) in rules and appear under `data.*` in the alert
  (`data.alert.severity`) (deduced from the documentation; exact types in the index unverified).
- In the code (`read_json.c`): a line that is not a JSON object is ignored (debug), and lines containing null bytes
  are dropped. The indexed `@timestamp`/`timestamp` is the time of ingestion by Wazuh, not the time in the JSON:
  keep the real event time in a field (e.g. `data.ts`) and sort on it in visualisations.

### Custom rules
- File `/var/ossec/etc/rules/local_rules.xml` (volume `wazuh_etc`); **IDs 100000-120000**; levels 0-16;
  `overwrite="yes"` to modify an existing rule.
  https://raw.githubusercontent.com/wazuh/wazuh-documentation/v4.14.10/source/user-manual/ruleset/rules/custom.rst
- Example:
```xml
<group name="watchpost,">
  <rule id="100100" level="0">
    <decoded_as>json</decoded_as>
    <field name="source">^watchpost$</field>
    <description>Watchpost: generic event</description>
  </rule>
  <rule id="100110" level="8">
    <if_sid>100100</if_sid>
    <field name="event.type">^wifi_open_network$</field>
    <description>Watchpost: connection to an open Wi-Fi network</description>
  </rule>
</group>
```
- `<field name="...">` takes a regex; there is no native numeric comparison (use a regex or precompute a boolean or
  category on the collector side). Syntax:
  https://raw.githubusercontent.com/wazuh/wazuh-documentation/v4.14.10/source/user-manual/ruleset/ruleset-xml-syntax/rules.rst
- **Level 0 = no alert** (the event is then only in the archives). Default alert threshold `log_alert_level` = 3
  (default value not re-checked in the `global.rst` documentation).
- Test with `/var/ossec/bin/wazuh-logtest`.

### Keeping ALL events (archives)
1. Manager `ossec.conf`, `<global>` block: `<logall_json>yes</logall_json>` (`<logall>` is for the text format,
   not indexable). File `/var/ossec/logs/archives/archives.json` (compressed/rotated daily by the manager,
   **kept indefinitely**: plan a purge).
2. Filebeat of the manager container (`/etc/filebeat/filebeat.yml`, volume `filebeat_etc`):
   `filebeat.modules: wazuh: archives: enabled: true` (docker default: `false`). Restart Filebeat. In the docker
   image, the file is generated from `build-docker-images/wazuh-manager/config/filebeat.yml`; the cleanest way is
   to mount your own `filebeat.yml` (exact method unverified).
3. Dashboard: index pattern `wazuh-archives-*`, time field `timestamp`. The Wazuh template covers
   `wazuh-archives-4.x-*`.
Sources: https://raw.githubusercontent.com/wazuh/wazuh-documentation/v4.14.10/source/user-manual/manager/event-logging.rst,
https://raw.githubusercontent.com/wazuh/wazuh-docker/v4.14.10/build-docker-images/wazuh-manager/config/filebeat.yml
Disk cost: every event is stored twice (archives.json + index); add an ISM policy on `wazuh-archives-*`.

### Rotating the NDJSON on the producer side (logcollector behaviour, v4.14.10 code)
- **Inode changed** (rotation by renaming + new file): logcollector reopens the file and emits an internal event
  `ossec: File rotated` -> rule 591 level 3 (benign).
- **Size reduced with the same inode** (`copytruncate`, truncation): re-read from the start and event
  `File size reduced` -> **rule 592 level 8, MITRE T1565.001** ("log tampering" alert). To be avoided.
- Recommendation: **rotation by renaming** (e.g. a dated file `events-%Y-%m-%d.ndjson` with a strftime `<location>`,
  or renaming + immediate creation of a new file), keep the old file readable for a few minutes (the check happens
  only every `logcollector.vcheck_files` seconds; lines written between the last read and the rotation may be lost
  if the file is deleted too fast). Write each event as **a single `write` ending with `\n`**: an incomplete line
  (EOF without `\n`) is retried later.
Sources: https://raw.githubusercontent.com/wazuh/wazuh/v4.14.10/src/logcollector/logcollector.c,
https://raw.githubusercontent.com/wazuh/wazuh/v4.14.10/ruleset/rules/0015-ossec_rules.xml

### Size limits
- `OS_MAXSTR` = 65536; line reading = `OS_MAXSTR - 256` (~65,279 bytes). **A longer line is cut, the truncated object
  is no longer valid JSON -> event lost** ("Large message size" error in `ossec.log`, rest of the line skipped).
  In practice, plan for an event ≤ 16-32 KB and send large blobs elsewhere.
  https://raw.githubusercontent.com/wazuh/wazuh/v4.14.10/src/logcollector/read_json.c,
  https://raw.githubusercontent.com/wazuh/wazuh/v4.14.10/src/headers/defs.h
- `<localfile><max-size>` (default 10 MB) only concerns catching up on old data when resuming.
- Index field limit: `index.mapping.total_fields.limit: 10000` (Wazuh template); keep a stable JSON schema (no
  dynamic keys).
- Maximum throughput (EPS) of the manager for one `localfile`: unverified.

---

## 3. GPS position as a `geo_point` (dashboard map)

- The Wazuh template (`wazuh-alerts-4.x-*` and `wazuh-archives-4.x-*`, `order: 0`) defines `GeoLocation.location` as
  a `geo_point`, but that field is filled by the GeoIP of decoding on `srcip`, not by application fields. Dynamic
  strings are mapped as `keyword`.
  https://raw.githubusercontent.com/wazuh/wazuh/v4.14.10/extensions/elasticsearch/7.x/wazuh-template.json
- **Feasible, but not "zero configuration"**:
  1. In the event, emit `{"gps":{"location":{"lat":48.85,"lon":2.35}}}` (lat/lon object form, accepted by
     `geo_point`).
  2. Add an **additional template** (legacy API `PUT _template/watchpost-geo`,
     `index_patterns: ["wazuh-alerts-4.x-*","wazuh-archives-4.x-*"]`, `order: 1`, mapping
     `data.gps.location: {type: geo_point}`). The `wazuh` template has `order: 0` and Filebeat rewrites it at
     startup (`setup.template.overwrite: true`); a separate template of higher `order` is not overwritten (merging
     of orders: standard OpenSearch behaviour, to be tested).
  3. A mapping applies only to **new indices** (daily indices): wait for midnight or `reindex`; if an index already
     has `data.gps.location` as a dynamic `object`, the geo_point event will fail. Refresh the index pattern
     fields.
  4. "Coordinate map"/Maps visualisation of OpenSearch Dashboards on the field; base map: probably an external tile
     service reachable by the browser (unverified).
- No Filebeat pipeline needed (the `wazuh` module has its own; modifying it is fragile).
- **Simpler and more robust alternative**: in parallel with the Wazuh NDJSON, the Go collector writes geolocated
  events through `_bulk` into a dedicated index (`watchpost-geo-*`) with its own `geo_point` mapping; map through the
  dashboard or Grafana (Geomap). Loses correlation by Wazuh rules for that index, hence the double send.
- No official Wazuh source found for the full procedure: this whole paragraph is to be validated by testing.
  Indirect reference: https://groups.google.com/g/wazuh/c/7mgaXm2hOPA (type of `GeoLocation.location`, need for a
  reindex).

---

## 4. AdGuard Home

**Version/image**: `adguard/adguardhome:v0.107.80` (pin this tag rather than `latest`). Image volumes:
`/opt/adguardhome/work` (the log is in `work/data/`) and `/opt/adguardhome/conf` (`AdGuardHome.yaml`) (image paths
not re-checked; `dataDir = "data"` confirmed in `internal/home/config.go`). Ports: 53 tcp/udp, 853 tcp (DoT), 3000
(initial wizard), 80/443 if internal HTTPS.
Sources: https://hub.docker.com/v2/repositories/adguard/adguardhome/tags,
https://raw.githubusercontent.com/AdguardTeam/AdGuardHome/v0.107.80/internal/home/config.go

**DoT / DoH and certificates**
- YAML keys (`tls` section): `enabled`, `server_name`, `force_https`, `port_https`, `port_dns_over_tls` (853),
  `port_dns_over_quic`, `certificate_path`, `private_key_path`, `strict_sni_check`. Plain DNS can be disabled:
  `dns.serve_plain_dns: false`.
  https://raw.githubusercontent.com/AdguardTeam/AdGuardHome/v0.107.80/internal/home/config.go
- **Caddy does not proxy DoT** (HTTP only; the `caddy-l4` plugin would be needed). Publish **853/tcp directly from
  the AdGuard container**. DoH, on the other hand, can go through Caddy (`reverse_proxy` to AGH; AGH then accepts
  unencrypted DoH through an option of the `allow_unencrypted_doh` + `trusted_proxies` kind, key names to be
  verified, unverified).
- **Certificate: let Caddy do the ACME** (AGH has no built-in ACME to our knowledge, unverified) and mount, read-only
  in AGH, the certificates folder of the `caddy_data` volume
  (`/data/caddy/certificates/acme-v02.api.letsencrypt.org-directory/<name>/<name>.crt|.key`, usual path, not
  re-checked). **Since v0.107.72, AGH watches the certificate/key files and reloads them** (CHANGELOG #3962), so
  Caddy's renewal is picked up without a restart; test once.
- Wildcard: Caddy must be built with a DNS module (image `caddy:2.11.9-builder` +
  `xcaddy build --with github.com/caddy-dns/desec` or `.../duckdns`); site block
  `*.dns.example.org, dns.example.org { tls { dns desec {env.DESEC_TOKEN} } }`. The `caddy-dns/desec` and
  `caddy-dns/duckdns` modules exist (READMEs verified).
  https://raw.githubusercontent.com/caddy-dns/desec/main/README.md,
  https://raw.githubusercontent.com/caddy-dns/duckdns/master/README.md

**Restriction by ClientID**
- Formats: DoT `tls://<id>.dns.example.org` (SNI), DoQ the same, DoH `https://dns.example.org/dns-query/<id>`
  (path, **no wildcard**) or `https://<id>.dns.example.org/dns-query` (sub-domain, wildcard). For the sub-domain
  forms, **the certificate must cover `*.dns.example.org` AND `dns.example.org`** -> **DNS-01** challenge
  mandatory. The code extracts the ID as the immediate sub-domain of `server_name`.
  https://raw.githubusercontent.com/wiki/AdguardTeam/AdGuardHome/Clients.md,
  https://raw.githubusercontent.com/AdguardTeam/AdGuardHome/v0.107.80/internal/dnsforward/clientid.go
- `dns.allowed_clients` accepts **IP, CIDR and ClientID**; if non-empty, only those are allowed (and
  `disallowed_clients` is ignored). Without it, a public DoT = an open resolver.
  https://raw.githubusercontent.com/AdguardTeam/AdGuardHome/v0.107.80/internal/dnsforward/config.go
- **Android "Private DNS" = DoT only**, so the ID can only go through the host name (`<id>.dns.example.org`) ->
  wildcard indispensable.
- **Without a wildcard**: (a) `allowed_clients` by IP/CIDR: possible if the phone goes out through WireGuard (stable
  tunnel IP, §8); (b) mobile public IP: impractical (it changes); (c) accept an exposed DoT resolver protected only
  by a secret host name (no, the ID cannot be verified without a wildcard) -> not recommended. **Conclusion**:
  wildcard through deSEC/DuckDNS DNS-01, or WireGuard + `allowed_clients` as a CIDR.

**Query log**
- File `<work_dir>/data/querylog.json` (NDJSON), rotation: when `querylog.interval` expires, the file is renamed to
  `querylog.json.1` (**a single backup file**) and then recreated; it must therefore be read continuously (inode
  change handled by logcollector, §2). Configuration keys: `querylog.enabled`, `file_enabled`, `interval`,
  `size_memory`, `ignored`, `dir_path`.
  https://raw.githubusercontent.com/AdguardTeam/AdGuardHome/v0.107.80/internal/querylog/querylogfile.go
- Fields of a line: `T` (timestamp), `QH` (name), `QT` (type), `QC`, `CID` (ClientID), `CP` (client protocol),
  `Upstream`, `Answer`/`OrigAnswer` (DNS response **packed as base64**, noisy), `IP` (client), `Result` (object:
  blocking, rules/lists), `Elapsed` (duration), `Cached`, `AD`, `ECS`.
  https://raw.githubusercontent.com/AdguardTeam/AdGuardHome/v0.107.80/internal/querylog/entry.go
- Towards Wazuh: mount `work/data` read-only in the manager and add a json `<localfile>` on `querylog.json` (the
  line starts with `{"T":` so it is compatible with the prematch). Rules on `Result.IsFiltered`, `QH`, `CID` (exact
  names of the `Result` sub-object not re-checked). Alternative: query `/control/querylog` (REST API) from the Go
  collector to filter `Answer`.

**Declarative provisioning of `AdGuardHome.yaml`**
- Current `schema_version`: **34** (v0.107.80). At startup AGH migrates and **rewrites** the file: mount the `conf/`
  folder (not the file alone), generate the YAML with an init script before the first start. If `users` is present,
  the setup wizard is skipped.
- Skeleton (fields verified in `config.go`: `users`, `filters`, `user_rules`, `dns.*`, `tls.*`, `querylog.*`):
```yaml
schema_version: 34
http: { address: 0.0.0.0:3000 }          # behind Caddy, never published
users:
  - name: admin
    password: $2y$10$...                  # bcrypt: htpasswd -nbB -C 10 admin 'password'
dns:
  bind_hosts: [0.0.0.0]
  serve_plain_dns: false
  upstream_dns: [https://dns.quad9.net/dns-query]   # to be chosen (see the Quad9/France note)
  bootstrap_dns: [9.9.9.9, 1.1.1.1]
  allowed_clients: [my-phone-1, my-phone-2, 10.13.13.0/24]
tls:
  enabled: true
  server_name: dns.example.org
  port_dns_over_tls: 853
  port_https: 0
  certificate_path: /certs/dns.example.org.crt
  private_key_path: /certs/dns.example.org.key
filters:
  - { enabled: true, name: "HaGeZi Pro++", url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.plus.txt", id: 1 }
user_rules:
  - '@@||mtalk.google.com^$important'
querylog: { enabled: true, file_enabled: true, interval: 24h }
```
(the keys `filters[].{enabled,name,url,id}` follow the standard `FilterYAML` form; not re-checked in the code.)

**Quick comparison**
| | AdGuard Home | Technitium | Pi-hole + unbound |
|---|---|---|---|
| Native DoT/DoH server | yes | yes (**PFX** certificate required, DoT/DoQ 853, DoH `/dns-query`) | **not** native in v6: add a proxy/stunnel |
| ClientID by SNI/path | **yes** | not found (unverified); policy by IP/subnet (Advanced Blocking app) | no |
| Usable log | **native NDJSON** | UI/apps; export unverified | FTL database, not JSON |
| Declarative config | one YAML | UI/API | TOML + gravity |
Sources: https://blog.technitium.com/search/label/DNS-over-HTTPS, https://selfhost.it.com/blog/pi-hole-quad9-dls-over-tls
**Conclusion: AdGuard Home** (DoT + ClientID + JSON log + declarative YAML). Technitium as a fallback if the
ClientID is given up.

---

## 5. Blocking lists

HaGeZi, **GPL-3.0** licence, adblock/dnsmasq/wildcard/RPZ formats, announced expiry 8 h (automatic AGH update).
Raw URLs tested (HTTP 200) on `main`; the README recommends jsDelivr
(`https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/<list>.txt`).
https://raw.githubusercontent.com/hagezi/dns-blocklists/main/README.md

| List | Raw URL (adblock format, for AGH) | Entries (2026-11-15) | Remark |
|---|---|---|---|
| Pro | `https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.txt` | 237,247 | Recommended by the author, rare false positives |
| **Pro++** | `.../adblock/pro.plus.txt` | 259,753 | More aggressive, "for experienced users", the admin must be ready to unblock |
| Ultimate | `.../adblock/ultimate.txt` | 297,087 | To be avoided here |
| TIF (threats) | `.../adblock/tif.txt` (`tif.medium.txt` 353,174; `tif.mini.txt` 182,874) | 1,455,489 | Malware/phishing/C2; **medium version to save RAM** |
| Native Samsung | `.../adblock/native.samsung.txt` | ~201 | Samsung telemetry |
| Native Xiaomi/Huawei/OPPO-Realme/Vivo | `.../adblock/native.xiaomi.txt` etc. | - | One file per manufacturer |

- "Native Tracker": the native lists are **already included in the tiers** Light -> Ultimate with an increasing
  level; the `native.*` files serve to add them to a lighter tier.
- **OISD**: `small.oisd.nl` / `big.oisd.nl` (multiple formats, including adblock and `domainswild2`). Site not
  reachable during the research: exact URL for AGH and **licence unverified** (no CC licence found; a GPL-3 mirror
  repository has no value for the original list). HaGeZi Pro is enough, avoid combining it with OISD (duplicates).
- **Google telemetry**: no verified dedicated list. Pro++ (tested) blocks in particular
  `firebaselogging.googleapis.com`, `firebaselogging-pa.googleapis.com`, `firebasecrashlytics.googleapis.com`,
  `play-services-telemetry.googleapis.com`, `fcmatch.google.com`; Pro and above block `app-measurement.com`.
- **Android false positives**: direct check in the files of 2026-11-15: `mtalk.google.com`,
  `connectivitycheck.gstatic.com`, `connectivitycheck.android.com`, `clients3.google.com`, `play.googleapis.com`,
  `android.clients.google.com`, `update.googleapis.com` are **not** in Pro, Pro++ or Ultimate (exact entries
  `||host^`). The real risk comes from other lists or future updates: add allow rules `@@||host^$important` for
  these hosts (reports of `connectivitycheck.gstatic.com` being blocked -> "no Internet":
  https://discourse.pi-hole.net/t/pi-hole-blocks-samsung-galaxy-wifi-dns-occasionally/22640 ; `mtalk.google.com` =
  FCM push: https://discuss.privacyguides.net/t/google-push-notifications-routing-change/20508).
- **Samsung**: Pro contains 135 `samsung*` entries (including `*.samsungdm.com` diagnostics); the FOTA update
  domains tested (`ospserver`, `samsungotn`) are not in it. Watch `samsungapps.com`, `samsungdm.com` if updates
  fail (not tested on a device).

---

## 6. Android's "Private DNS" feature

- Strict mode = host name typed in, **DoT on 853**, certificate validated against the system CAs and the host name;
  no IP or URL. Automatic mode is opportunistic (may fall back to plain text). In strict mode, **server
  unreachable = no resolution (fail closed)**; Android may display "network without Internet" / "private DNS
  server cannot be accessed". Sources (secondary, unofficial):
  https://www.internetsociety.org/blog/2018/08/dns-privacy-in-new-android-9/,
  https://git.com.de/Mikaela/mikaela.github.io/raw/branch/master/blog/_posts/2019-07-11-android-private-dns-in-practice.md,
  https://www.privateinternetaccess.com/blog/private-dns-server-cannot-be-accessed/
- Consequence: the DNS server is a **single point of failure** for the phone; monitor it and plan a fallback
  procedure (turn Private DNS off).
- DoH3: announced in 2022 for Android 11+ through a Play update, limited to predefined resolvers (Google,
  Cloudflare); the others use DoT. State in 2026 unverified (no announcement found).
  https://9to5google.com/2022/07/19/android-dns-over-http/,
  https://discuss.privacyguides.net/t/google-rejects-feature-request-for-arbitrary-dns-over-https-server-support/24320
- **Without a domain**: free sub-domain from **DuckDNS** (`myname.duckdns.org`) or **deSEC** (`myname.dedyn.io`) +
  Let's Encrypt. HTTP-01 requires 80/443 to be reachable; DNS-01 (module `caddy-dns/duckdns` or `desec`) works
  without opening 80 and allows a wildcard (wildcard on duckdns/dedyn: not tested).
- **Behind a home router**: forward **853/tcp** (Private DNS), **443/tcp** (mTLS ingestion/admin), possibly 80/tcp,
  **51820/udp** (WireGuard); IPv6: AAAA + inbound firewall rule (no NAT); dynamic IP: DDNS update (low TTL), because
  a stale IP = no DNS on the phone. **CGNAT** (no inbound port): an inexpensive VPS hosting at least Caddy/AdGuard,
  or a WireGuard tunnel from home to the VPS.

---

## 7. Caddy 2.11.9: mTLS, PKI, administration front

- Syntax verified (`tls` documentation):
```caddy
ingest.example.org {
  tls {
    client_auth {
      mode require_and_verify
      trust_pool file /etc/caddy/pki/watchpost-ca.crt
    }
  }
  reverse_proxy collector:8080 {
    header_up X-Watchpost-Client-Cert-Sha256 {tls_client_fingerprint}
  }
}
```
`mode` defaults to `require_and_verify` if `trust_pool` is given. Available placeholders: `{tls_client_fingerprint}`,
`{tls_client_issuer}`, `{tls_client_serial}`, `{tls_client_certificate_pem}`.
https://raw.githubusercontent.com/caddyserver/website/master/src/docs/markdown/caddyfile/directives/tls.md,
https://raw.githubusercontent.com/caddyserver/website/master/src/docs/markdown/caddyfile/concepts.md
- **mTLS = per TLS connection, therefore per host name, not per path.** Use a **dedicated sub-domain** (`ingest.`);
  for a single host, `verify_if_given` + a matcher on `{tls_client_fingerprint}` with `respond 403` on the protected
  paths (more fragile).
- **Revocation**: no native CRL; use the `leaf` verifier (list of authorised leaf certificates: `file`/`folder`
  loaders) to accept only enrolled devices, or short-lived certificates.
  https://raw.githubusercontent.com/caddyserver/website/master/src/docs/markdown/caddyfile/directives/tls.md
  (`leaf` section)
- **PKI**: private ECDSA P-256 CA (`openssl` or `step-cli`), offline CA; one client certificate per device (CN =
  device identifier, `extendedKeyUsage=clientAuth`, validity ~1 year). PKCS#12 export for the app:
  `openssl pkcs12 -export -inkey dev.key -in dev.crt -certfile ca.crt -out dev.p12`. Android's PKCS#12 compatibility
  with OpenSSL 3's default algorithms (AES-256/PBKDF2): add `-legacy` or SHA1/3DES algorithms if the import fails
  (unverified). On the app side: the server uses a public certificate (Let's Encrypt), the private CA serves only
  for the client certificate; do not trust the private CA for the server.
- **Administration front** (AdGuard UI, Wazuh dashboard): on a separate sub-domain (`admin.`), ideally **also under
  mTLS** (administrator certificate in the browser) + `basic_auth` (hash `caddy hash-password`, `basic_auth`
  directive) as a second barrier. Forward-auth (Authelia) through the `forward_auth` directive is possible but adds
  a service, a database and SSO: oversized for a single user (Authelia version unverified).
  https://raw.githubusercontent.com/caddyserver/website/master/src/docs/markdown/caddyfile/directives/forward_auth.md
- Proxy to the Wazuh dashboard (internal HTTPS 5601 with its own CA): `reverse_proxy https://wazuh.dashboard:5601`
  with a TLS transport trusting `root-ca.pem` (name of the sub-directive depends on the version, not re-checked;
  failing that, `tls_insecure_skip_verify` on the internal Docker network).

---

## 8. WireGuard (optional)

- **Image**: `ghcr.io/wg-easy/wg-easy:15` (web interface, QR code, IPv6; requires `NET_ADMIN`, `SYS_MODULE`,
  `ip_forward` sysctls) to manage several devices; `linuxserver/wireguard` (configuration through files via
  `PEERS`, leaner, no UI) if the declarative approach is preferred. Both: the WireGuard kernel module must exist on
  the host.
  https://raw.githubusercontent.com/wg-easy/wg-easy/master/docker-compose.yml,
  https://raw.githubusercontent.com/linuxserver/docker-wireguard/master/README.md
- **Real benefit**: (1) all of the phone's traffic goes through the server: DNS, SNI, flows, TLS certificates are
  visible -> **Suricata/Zeek** on the `wg0` interface (Wazuh natively decodes Suricata's `eve.json`, see the JSON
  decoder example); (2) a **stable** tunnel IP -> `allowed_clients` by CIDR in AdGuard without a wildcard; (3) gets
  around CGNAT / dynamic IP (keepalive); (4) encrypts traffic on hostile Wi-Fi.
- **Limits**: application content remains TLS-encrypted (only metadata is visible, no decryption without MITM);
  **Android allows only one active VPN**: incompatible if the Watchpost agent itself uses `VpnService` (local
  capture); battery and latency; all the bandwidth goes up through the server's upstream connection; if the server
  goes down, the phone loses Internet (in always-on / block-without-VPN mode); Suricata/Zeek require additional
  resources (≥ 2 GB of RAM, unverified estimate), hence incompatible with the 4 GB profile; exposure of the home
  network if poorly partitioned (`AllowedIPs`, firewall). Interaction between Android Private DNS and an active
  VPN: unverified.
- Recommendation: **do not enable by default**; add it when a fixed IP or NDR is needed.

---

## 9. Lightweight alternatives to Wazuh (< 4 GB of RAM)

One-sentence profiles each (consumption not measured here; Docker Hub versions of 2026-11-15):
- **VictoriaLogs + Grafana** (`victoriametrics/victoria-logs:v1.54.0`): best lightweight choice, native JSON
  ingestion (`/insert/jsonline`) straight from the Go collector, LogsQL queries, alerts through vmalert, Geomap
  in Grafana; no ready-made detection rules (to be written).
- **Loki + Grafana**: light and familiar, but indexes only labels (JSON fields are filtered at query time); less
  comfortable for large volumes of structured events (Loki version unverified).
- **OpenObserve** (tag `v1.1.2` on Docker Hub, single Rust binary): all-in-one (JSON ingestion, UI, alerts,
  compressed storage) without Grafana; mapping maturity unverified.
- **Graylog 7.2.2**: to be avoided under 4 GB (requires MongoDB + Data Node/OpenSearch; profile comparable to
  Wazuh without the ruleset).
- Complementary option: keep AdGuard + Caddy + the collector and send the AdGuard querylog to the same lightweight
  engine (VictoriaLogs reads line-by-line JSON).
Sources: https://hub.docker.com/v2/repositories/victoriametrics/victoria-logs/tags,
https://hub.docker.com/v2/repositories/openobserve/openobserve/tags,
https://hub.docker.com/v2/repositories/graylog/graylog/tags
