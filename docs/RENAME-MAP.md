# Rename and translation map (temporary working document)

This file is the single reference for the "Vigie → Watchpost, French → English" pass. Every component is
converted by a different agent at the same time; cross-component names MUST match this table exactly.
It is deleted once the pass is complete.

## 1. Goals

1. The project is renamed **Watchpost** everywhere, internal identifiers included.
2. **Everything is in English**: documentation, UI strings, CLI and script messages, log messages, rule
   descriptions, notification texts, code identifiers, test names, file and directory names, comments,
   example data. No French word remains anywhere in the repository.
3. **No origin story.** The repository must read as a general-purpose project. Remove every mention of:
   the Samsung Galaxy S25 / S25+ as "the" target; "the owner" and their personal decisions, dates of
   decisions, questions and answers; the personal incident ("2,000 phishing SMS a day on a previous
   phone"); the way the project was produced (agents, sessions, usage limits, reviews "by another agent",
   the cloud development environment). Technical facts stay: Watchpost targets Android 16+ (`minSdk 36`),
   is developed against Samsung One UI 8/9 and ships a Samsung/Google package catalogue; state plainly what
   has and has not been run on a physical device.

## 2. Wording

- Address the reader as "you" in guides. Use **"the user"** for the person who owns the phone, never
  "the owner" (it collides with "Device Owner", which keeps its Android meaning and capitalisation).
- Plain, sober technical English. No marketing tone, no emoji. Keep every warning and every honest
  "not tested on a device" statement: translating must not soften them.
- Commit messages are in English from now on.

| French | English |
|---|---|
| garde (de capacités) | (capability) guard |
| quarantaine | quarantine |
| libérer (une application) | release |
| pistage / vue pistage | tracking / Tracking page |
| mise en sourdine | mute |
| issue de secours (ADB) | (ADB) rescue |
| Tout rétablir | Restore everything |
| Politique (écran) | Policy (screen) |
| collecteur (agent) / collecteur (serveur) | collector / the collector (server) |
| tampon | buffer (table name stays `outbox`) |
| enrôlement / enrôler | enrollment / enroll |
| code de commande | command passphrase |
| niveau de blocage | blocking level |
| profil équilibré / strict | balanced / strict profile |
| APK compagnon | companion APK |
| profil de risque | risk profile |
| détection | detection |
| appli SMS par défaut / composeur | default SMS app / default dialer |
| téléphone sain | healthy phone |
| comptage expérimental (`app_ops`) | experimental usage counters (`app_ops`) |
| console | console |
| journal (d'événements) | event log |
| vue d'ensemble | Overview |
| Effacer le téléphone | Erase the phone |
| confirmation word `EFFACER` | `ERASE` |

## 3. Identifiers

| Kind | Before | After |
|---|---|---|
| Project / app name | Vigie, Vigie Agent, Vigie Notifications | Watchpost, Watchpost Agent, Watchpost Notifications |
| Repository / Go module | `github.com/erwsim/android-telemetry/server/collector` | `github.com/erwsim/watchpost/server/collector` |
| Android package | `io.github.erwsim.vigie` (and sub-packages) | `io.github.erwsim.watchpost` |
| Companion package | `io.github.erwsim.vigie.notifier` | `io.github.erwsim.watchpost.notifier` |
| Android permission | `io.github.erwsim.vigie.permission.*` | `io.github.erwsim.watchpost.permission.*` |
| Kotlin/Java classes | `Vigie…` (`VigieApplication`, `VigieAdminReceiver`, …) | `Watchpost…` |
| Gradle property | `vigie.testOnly` | `watchpost.testOnly` |
| Android prefs, channels, actions | `vigie_…`, `…vigie…` | `watchpost_…` |
| Environment variables (all components) | `VIGIE_…` | `WATCHPOST_…` (same suffix) |
| Collector binary / image / DB | `vigie-collector`, `vigie.db` | `watchpost-collector`, `watchpost.db` |
| Enrollment file | `*.vigie`, `<name>-renouvellement.vigie` | `*.watchpost`, `<name>-renewal.watchpost` |
| Proxy header | `X-Vigie-Client-Cert-Sha256`, `X-Vigie-*` | `X-Watchpost-Client-Cert-Sha256`, `X-Watchpost-*` |
| Console anti-CSRF header value | `X-Requested-With: vigie` | `X-Requested-With: watchpost` |
| Export root key (NDJSON, Wazuh, indexer) | `vigie` (`vigie.type`, `data.vigie.data.*`, `vigie.source`) | `watchpost` (`watchpost.type`, `data.watchpost.data.*`, `watchpost.source`) |
| AdGuard managed rule block | `! vigie:begin` / `! vigie:end` | `! watchpost:begin` / `! watchpost:end` |
| Command signature salt | `"vigie-cmd-v1:" + device_id` | `"watchpost-cmd-v1:" + device_id` |
| Example device name | `s25` (`--name s25`, `s25.vigie`) | `phone` (`--name phone`, `phone.watchpost`) |
| Example domain | `exemple.fr`, `vigie.example` | `example.org`, `watchpost.example` |

API paths (`/api/v1/…`, `/api/console/…`), event types and event field names are already English and do
not change. Wazuh rule IDs do not change.

### New command-signature test vector (replaces the old one in all three implementations)

- passphrase `correct horse battery staple`, `device_id` `dev_0123456789abcdef`
- `K` = `05fd656216f9ae34c3be8e6afcfa857c535e9e0ef438ab6c2de7130891abdb8b`
- `payload` (UTF-8, contains an em dash U+2014):
  `{"v":1,"id":"01JCQ8Z3K4M5N6P7Q8R9S0T1V2","device_id":"dev_0123456789abcdef","type":"lock","params":{"message":"Lost phone — please call +1 555 0100"},"issued_at":"2026-11-16T10:00:00.000Z","expires_at":"2026-11-23T10:00:00.000Z"}`
- `sig` = `VVQ7B/b3fOzaG+sWd7Fqi7NKVRzdu5L3+NEIKurMXdE=`

## 4. Values shared between components

| Kind | Before | After |
|---|---|---|
| Blocking levels (API, levels file, console, infra) | `permissif`, `equilibre`, `strict` | `permissive`, `balanced`, `strict` |
| Simulator scenarios (`sim --scenario`) | `sain`, `fraude-sms`, `cheval-de-troie`, `proxy`, `spam`, `exfiltration`, `contournement-dns`, `espion`, `sms-discret`, `tout` | `healthy`, `sms-fraud`, `banking-trojan`, `proxy`, `spam`, `exfiltration`, `dns-bypass`, `stalkerware`, `silent-sms`, `all` |
| Levels file | `infra/adguard/niveaux.json` | `infra/adguard/levels.json` |
| Watchpost AdGuard rule files | `vigie-base.txt`, `vigie-strict.txt` | `watchpost-base.txt`, `watchpost-strict.txt` |
| AdGuard managed config | `data/adguard/vigie-gere.yaml` | `data/adguard/watchpost-managed.yaml` |
| Credentials summary | `identifiants.txt` | `credentials.txt` |
| Console account marker | `data/console-admin.cree` | `data/console-admin.created` |
| Old Wazuh certificates | `secrets/wazuh-certs/ancien-<date>/` | `secrets/wazuh-certs/old-<date>/` |
| Indexer read-only account | `vigie_reader` | `watchpost_reader` |
| AdGuard account of the collector | `vigie-collecteur` | `watchpost-collector` |
| Wazuh rules / scripts | `vigie_rules.xml`, `vigie_watch.py`, `custom-vigie-notify`, `vigie-init.sh` | `watchpost_rules.xml`, `watchpost_watch.py`, `custom-watchpost-notify`, `watchpost-init.sh` |
| Wazuh rule description prefix | `Vigie : …` | `Watchpost: …` |
| Console routes | `/commandes`, `/pistage`, French page slugs | English slugs: `/overview`, `/map`, `/events`, `/network`, `/tracking`, `/apps`, `/apps/detail`, `/security`, `/commands`, `/detections`, `/alerts` |
| Script options in French, if any | e.g. `--profile equilibre` | English values and option names |

## 5. Documentation files

| Before | After |
|---|---|
| `docs/ETAT.md` | `docs/STATUS.md` |
| `docs/contrat/contrat.md` | `docs/contract/contract.md` |
| `docs/research/android-plateforme.md` | `docs/research/android-platform.md` |
| `docs/research/serveur-siem-dns.md` | `docs/research/server-siem-dns.md` |
| `docs/guides/01-serveur.md` | `docs/guides/01-server.md` |
| `docs/guides/02-compiler-apk.md` | `docs/guides/02-build-apk.md` |
| `docs/guides/03-telephone.md` | `docs/guides/03-phone.md` |
| `docs/guides/04-retour-arriere.md` | `docs/guides/04-rollback.md` |
| `docs/guides/05-exploitation.md` | `docs/guides/05-operations.md` |
| `docs/guides/06-verifications-sur-appareil.md` | `docs/guides/06-on-device-checks.md` |
| `docs/guides/07-reprise-developpement.md` | `docs/guides/07-development.md` |
| `docs/guides/08-sms-et-logiciels-malveillants.md` | `docs/guides/08-sms-and-malware.md` |

Component documents keep their names (`README.md`, `android/ARCHITECTURE-CODE.md`). Links between
documents must point to the new names.

## 6. How to work

- Rename files with `git mv` so history follows.
- After converting, search your scope for leftovers and fix every hit:
  `grep -rIn -i "vigie" <scope>` ; `grep -rIn "[àâçéèêëîïôùûüœÀÂÇÉÈÊËÎÏÔÙÛÜŒ]" <scope>` (accented letters are
  only acceptable inside a test that deliberately exercises non-ASCII input, and then use non-French
  samples) ; `grep -rIn -i "s25\|galaxy s\|propri" <scope>` ; plus a read-through for unaccented French
  (words such as "pour", "avec", "sans", "les", "des", "une", "est", "non", "erreur", "fichier").
- Behaviour must not change: this is a rename and a translation. Every existing test must still pass, with
  the same number of tests.
