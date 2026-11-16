# Vigie Agent — architecture du code et convention des collecteurs

Ce document suffit pour ajouter un collecteur ou une fonction Device Owner sans lire tout le code.
Références : `docs/contrat/contrat.md` (format des événements, **spécification**), `docs/ARCHITECTURE.md`
(principes non négociables), `docs/research/android-plateforme.md` (faits de plateforme).

## 1. Modules

```
:app ──► :collectors ──► :core
  │                        ▲
  └────► :policy ──────────┘
```

| Module | Package | Contenu |
|---|---|---|
| `:core` | `io.github.erwsim.vigie.core` | `Agent` (câblage), commandes à distance (`command/` : vérification, canal, état), modèle d'événement, `EventSink`, tampon `outbox` (Room), envoi (`Uploader`, WorkManager), enrôlement, réglages, interface `Collector` + `CollectorHost`, `Capabilities`, `IntegrityMonitor` (`agent.tamper`). Banc de test partagé (testFixtures) : `CollectorHarness`, référence du contrat `Contract`. |
| `:collectors` | `…vigie.collectors` | 19 collecteurs **sans** privilège Device Owner (dont `notifications`, alimenté par l'APK compagnon `:notifier`). Point d'entrée : `CollectorsModule.all(context)`. |
| `:policy` | `…vigie.policy` | Tout ce qui exige le Device Owner : `VigieAdminReceiver`, `DeviceOwnerManager` (auto-attribution des permissions, protection contre l'arrêt forcé), moteur de politique réversible (`engine/`), DNS privé et son repli (`dns/`), 3 collecteurs (journaux de sécurité et réseau, posture), issue de secours ADB (`rescue/RescueReceiver`), état de l'écran Politique (`ui/PolicyController`), exécuteurs `lock`/`clear_lock_message`/`wipe` (`remote/`). Point d'entrée : `PolicyModule`. |
| `:app` | `…vigie` | `VigieApplication`, service de premier plan `AgentService`, `BootReceiver`, interface Compose (dont l'écran Politique), test de conformité au contrat de bout en bout. |

`VigieApplication` fait `Agent.init(this) { CollectorsModule.all(it) + PolicyModule.collectors(it) }`.
**Ajouter un collecteur ne touche que son module** : sa classe, une ligne dans le point d'entrée, ses
chaînes et ses permissions (fusion de manifestes).

## 2. Ajouter un collecteur (recette)

1. Créer `collectors/src/main/kotlin/io/github/erwsim/vigie/collectors/<domaine>/<Nom>Collector.kt`
   (ou dans `:policy` s'il exige le Device Owner).
2. L'ajouter à la liste de `CollectorsModule.all()` (ou `PolicyModule.collectors()`). L'ordre de la liste est
   l'ordre d'affichage.
3. Chaînes françaises dans `<module>/src/main/res/values/strings.xml`, préfixées par l'id :
   `collector_<id>_title`, `collector_<id>_desc`, `setting_<id>_…` (les ressources de tous les modules sont
   fusionnées : un préfixe évite les collisions).
4. Permissions dans `<module>/src/main/AndroidManifest.xml`. Interdits dans l'APK : écoute des notifications,
   accessibilité, SMS, journal d'appels, superposition (déclencheurs Play Protect, principe 4).
5. Si le collecteur émet un **type** ou des **champs** absents du catalogue (§2 du contrat) : ne pas inventer,
   le signaler pour que le contrat soit complété d'abord.
6. Tests JVM (§9).

```kotlin
class WifiCollector : Collector {
    override val id = "wifi"                                   // [a-z0-9_]+, stable (réglages, heartbeat)
    override val titleRes = R.string.collector_wifi_title
    override val descriptionRes = R.string.collector_wifi_desc // ce qui est collecté, en clair
    override val eventTypes = listOf("net.wifi")
    override val requirements = listOf(Requirement.Permission(Manifest.permission.ACCESS_FINE_LOCATION))
    override val settings = listOf(SettingSpec.BoolSpec(SCAN, R.string.setting_wifi_scan))

    override suspend fun start(ctx: CollectorContext) {
        ctx.registerReceiver(IntentFilter(WifiManager.NETWORK_STATE_CHANGED_ACTION)) { intent ->
            ctx.emit("net.wifi") { put("event", "connected"); put("ssid", ssid) }
        }
    }

    companion object { val SCAN = SettingKey.BoolKey("wifi.scan", false) }
}
```

## 3. Interface `Collector` et cycle de vie

| Membre | Rôle |
|---|---|
| `id`, `titleRes`, `descriptionRes`, `eventTypes` | Identité et transparence (affichés dans l'onglet Collecteurs). |
| `defaultEnabled` | `true` par défaut ; `false` pour un collecteur coûteux ou intrusif (opt-in). |
| `requirements` | `Requirement.Permission(nom, optional)`, `Requirement.DeviceOwner`, `Requirement.SystemFeature(nom)`. Vérifiés par l'hôte **avant** `start`. |
| `checkAvailability(ctx)` | Vérification supplémentaire (matériel, app-op « accès à l'utilisation »…) → `Availability.Unavailable("raison en français")`. |
| `settings` | Réglages propres, rendus automatiquement dans l'écran Réglages. |
| `periodic` | `PeriodicSpec(intervalMinutes ≥ 15, runAtStart)` : `collectOnce` via WorkManager, même service arrêté. |
| `start(ctx)` / `stop(ctx)` | Abonnements temps réel. **Jamais** appelés par le collecteur lui-même. |
| `collectOnce(ctx, reason)` | Relevé ponctuel (`START`, `PERIODIC`, `MANUAL`). |

Le `CollectorHost` (un par processus) décide :
- `start` quand l'agent tourne, que le collecteur est activé (`collector.<id>.enabled`) et que ses exigences
  sont satisfaites ; il est ré-évalué au démarrage du service, à chaque retour dans l'app, toutes les 15 min
  (maintenance) et quand le Device Owner change ;
- `stop` + `start` quand **un de ses réglages** change (les nouvelles cadences s'appliquent ainsi) ;
- `stop` quand il est désactivé, perd une exigence ou que l'agent s'arrête.

États publiés (`host.statuses`, repris tels quels dans `agent.heartbeat.collectors`) : `running`, `disabled`,
`unavailable` (+ raison en français). L'instance du collecteur est réutilisée d'un démarrage à l'autre :
remettez ses champs à zéro au début de `start`.

## 4. Fil d'exécution

- `start`, `stop`, `collectOnce` et tous les rappels enregistrés via `ctx` s'exécutent sur **le fil des
  collecteurs** (un `HandlerThread` partagé « vigie-collectors »). Ils peuvent suspendre, **jamais bloquer**.
- Rappels Android : `ctx.registerReceiver(filter) { intent -> }` (désinscrit automatiquement à l'arrêt ;
  **`exported = true` obligatoire pour les diffusions émises par une app système qui ne tourne pas sous
  l'uid du système** : Bluetooth, NFC, KeyChain, téléphonie. Un récepteur non exporté ne les reçoit jamais.
  À n'utiliser que pour une action déclarée `<protected-broadcast>` par la plateforme),
  `ctx.executor` (pour `LocationManager`, `PowerManager`, `TelephonyManager.registerTelephonyCallback`…),
  `ctx.handler` / `ctx.looper` sinon. Un rappel livré sur le fil principal (ex. `TriggerEventListener`) doit
  repasser par `ctx.handler.post { ctx.guard("…") { … } }`.
- Travail bloquant (I/O, `PackageManager` massif, `getprop`, récupération des journaux) :
  `withContext(ctx.io) { … }` ou `ctx.scope.launch(ctx.io) { … }`. `ctx.io` vaut `Dispatchers.IO` en
  production ; le banc de test le remplace par un exécuteur suivi : **ne jamais écrire `Dispatchers.IO`**
  dans un collecteur (le banc ne verrait pas ce travail). `ctx.scope` est annulé à l'arrêt.
- Nettoyage : `ctx.onStop { … }` (exécuté à l'arrêt, en ordre inverse, erreurs isolées).
- État privé persistant (dernier inventaire, dernière valeur émise) : `ctx.prefs` (SharedPreferences
  `collector_<id>`), jamais les réglages utilisateur.

## 5. Émettre un événement

```kotlin
ctx.emit("device.battery", Severity.INFO) {
    put("pct", pct)                 // Int/Long/Double/Float/String/Boolean ; null → champ absent
    putStrings("functions", list)   // tableau de chaînes
    putObject("device") { put("vendor_id", v) }
    putObjects("apps", apps) { app -> put("package", app.pkg) }
    putMap("collectors", mapOf("location" to "running"))  // clés libres (ids, paquets)
}
```

- L'`EventSink` attribue `id` (ULID), `ts` (RFC 3339 UTC ms), `boot_id`, `elapsed_ms` à l'appel, puis `seq`
  à l'écriture, dans la **même transaction SQLite** que l'insertion et la mise à jour du compteur : ni trou ni
  doublon après un arrêt brutal. `emit` ne bloque pas et est utilisable depuis n'importe quel fil.
- **Horodatage d'origine** (événements relevés après coup : `app.foreground`, `net.dns`, `net.connect`,
  `security.log`, contrat §2 « Précisions ») : passer l'heure fournie par le système,
  `ctx.emit(type, sev, originTsMs = t) { … }` ou `ctx.sink.emit(type, sev, data, originTsMs = t)`. Alors :
  - `ts` = cette heure d'origine (pour un regroupement : la **première** occurrence ; `count` et
    `last_event_ts` dans `data`) ; il n'y a pas de champ `event_ts` ;
  - `elapsed_ms` = `elapsedRealtime` estimé à l'origine (`elapsed_maintenant − (maintenant − origine)`),
    donc `ts − elapsed_ms` reste l'heure de démarrage comme pour les autres événements du même `boot_id` ;
    borné à `[0, elapsed_maintenant]` : **0** pour une origine antérieure au démarrage courant (journaux
    `pre_reboot`, usage d'avant le redémarrage : aucun `elapsedRealtime` n'existe pour eux sur ce `boot_id`),
    `elapsed_maintenant` si l'origine est « dans le futur » (horloge reculée entre-temps) ;
  - `id` (ULID) et `seq` restent l'ordre d'**émission** : `ts` n'est donc pas croissant avec `seq`. Le
    tampon n'en dépend pas : envoi et purge par taille suivent `seq`, la purge par âge et
    `agent.buffer_overflow.oldest_ts/newest_ts` comparent `ts` (testé dans `OriginTimeTest`).
- Écritures groupées : les événements attendent en mémoire au plus 3 s (ou 200 événements) puis sont écrits
  en une transaction ; `sev >= 2` force l'écriture **et** un envoi rapide. Conséquence assumée : un arrêt
  brutal peut perdre les ≤ 3 dernières secondes d'événements non encore écrits (ils n'ont pas encore de `seq`,
  donc pas de trou côté serveur). Avant un arrêt prévisible : `ctx.flushBlocking()` (ex. `ACTION_SHUTDOWN`).
- Règles du contrat, vérifiées à l'exécution : type `^[a-z0-9_]+(\.[a-z0-9_]+)+$`, clés `snake_case`,
  champs **absents plutôt que `null`** (le builder ignore `null`, NaN et ∞), durées `*_ms`, tailles
  `*_bytes`, MAC en minuscules avec `:`, empreintes SHA-256 hex minuscules, horodatages en `Rfc3339.format(ms)`.
  Un type ou une clé invalide n'arrête rien : il devient un `agent.collector_error`.
- Sévérité : 0 info, 1 notable, 2 avertissement, 3 critique. Réserver 2/3 à ce qui mérite un envoi
  immédiat (ils déclenchent un envoi, coûteux en batterie s'ils sont fréquents).
- Sobriété : n'émettre que les **changements** (garder la dernière valeur dans un champ ou `ctx.prefs`),
  plafonner les cadences, préférer les diffusions système au sondage. Un collecteur à fort volume doit
  pouvoir être désactivé et documenter son volume horaire attendu dans sa description.
- Jamais de contenu privé de tiers (SMS, appels, notifications, frappe, écran).

## 6. Capacités et permissions

- `ctx.capabilities` : `isDeviceOwner()`, `hasPermission(p)`, `adminComponent()`, `hasSystemFeature(f)` (faux
  si le `PackageManager` ne répond pas), `isIgnoringBatteryOptimizations()`, `declaredRuntimePermissions()`.
- Permission d'exécution : la déclarer dans le manifeste du module **et** dans `requirements`. Une permission
  `optional = true` n'empêche pas le démarrage (mode dégradé ; la liste `missingPermissions` est affichée).
- En **Device Owner**, `PolicyModule.onAgentStarted` s'accorde **toutes** les permissions d'exécution
  déclarées par le manifeste fusionné (localisation d'avant-plan avant arrière-plan), puis remet l'état à
  `DEFAULT` : la permission reste accordée mais l'utilisateur garde la main. Chaque permission n'est
  auto-accordée qu'une fois par activation du Device Owner (`onOwnerEnabled` remet le compteur à zéro) :
  une permission retirée ensuite par le propriétaire n'est pas reprise par le passage de maintenance. Chaque attribution émet
  `security.policy` (`permission_granted`, `target` = permission, `ok`), et la protection contre l'arrêt
  forcé (`setUserControlDisabledPackages`) `security.policy` (`force_stop_protection`, `enabled`/`disabled`)
  à chaque changement. Rien à coder pour un nouveau collecteur. Sans Device Owner, l'onglet Collecteurs
  propose « Accorder les permissions », et `scripts/grant-adb-permissions.{sh,ps1}` les accorde par ADB.
- Permissions accordables seulement par ADB (aujourd'hui `PACKAGE_USAGE_STATS`, `WRITE_SECURE_SETTINGS`,
  `DUMP`) : les déclarer dans le manifeste du module (avec `tools:ignore="ProtectedPermissions"`), les tester
  dans `checkAvailability` (ou dégrader), et les ajouter à `scripts/grant-adb-permissions.{sh,ps1}`.
- App-op « accès à l'utilisation » (`hasUsageAccess()` de `:collectors`) :
  `AppOpsManager.unsafeCheckOpNoThrow(OPSTR_GET_USAGE_STATS, uid, paquet)` (`checkOpNoThrow`, déprécié, a le
  même effet) ; `MODE_ALLOWED` = accordé dans les Paramètres, `MODE_DEFAULT` = se rabattre sur la permission
  `PACKAGE_USAGE_STATS` (cas de `pm grant`).
- `Requirement.DeviceOwner` : le collecteur passe « indisponible » sans Device Owner et démarre seul quand le
  rôle est accordé (`VigieAdminReceiver.onEnabled` → `host.reconcile()`).
- Une permission retirée par l'utilisateur est signalée par `agent.tamper` (`permission_revoked`) par
  `IntegrityMonitor` ; le collecteur passe « indisponible » au prochain `reconcile`.
- Perte du Device Owner : `agent.tamper` (`device_owner_lost`, et `admin_disabled` depuis le récepteur
  d'administration), **sauf** retrait volontaire annoncé par `IntegrityMonitor.expectOwnershipLoss()` juste
  avant `clearDeviceOwnerApp` (fenêtre de 5 min, persistée ; `cancelOwnershipLossExpectation()` si le retrait
  échoue). `PolicyEngine.removeDeviceOwner` le fait pour l'écran Politique et l'issue de secours ADB, qui
  émettent à la place `security.policy` `device_owner_cleared`. Le repli `dpm remove-active-admin` n'est
  pas annoncé : il reste signalé comme altération.

## 7. Réglages

- `SettingKey.IntKey("<id>.<nom>", défaut, min, max)`, `SettingKey.BoolKey(...)` ou
  `SettingKey.ChoiceKey(nom, défaut, valeurs)` (liste fermée de chaînes : une valeur hors liste n'est jamais
  écrite et se lit comme le défaut), exposés via `settings = listOf(SettingSpec.IntSpec(key, titreRes,
  résuméRes, "s"))` ou `SettingSpec.ChoiceSpec(key, titreRes, résuméRes, options)` (chaque option a son libellé
  et une explication affichée sous elle, ex. le mode de localisation). Lecture : `ctx.settings[KEY]`.
  Ils sont affichés dans la carte du collecteur (onglet Collecteurs). `experimental = true` ajoute la
  mention « Expérimental » (comportement non garanti par Android, ex. attribution par `DUMP`) ;
  `defaultEnabled = false` fait afficher « Désactivé par défaut », `Requirement.DeviceOwner` « Device Owner
  requis ».
- Toute modification passe par `AgentSettings.set` : `agent.config_changed` (`key`, `old`, `new`) est émis
  automatiquement et le collecteur est redémarré. Aucun réglage ne vient du serveur (flux à sens unique).
- Réglages de politique : `PolicyModule.settings` (rendu dans la section « Device Owner » des Réglages).
- Réglages du socle (tampon, envoi) : écran Réglages.

## 8. Erreurs et isolation

- Toute exception dans `start`/`stop`/`collectOnce`, dans un rappel `ctx.registerReceiver`/`ctx.executor`,
  dans `ctx.scope` ou dans `ctx.guard("où") { … }` est attrapée et émise en `agent.collector_error`
  (`collector`, `error`), au plus 5 par heure et par collecteur (les suivantes sont comptées).
- La vérification des exigences (`availability`) ne lève jamais : une exception devient « indisponible »
  (« vérification impossible »). Le rapprochement (`startAll`, `reconcile`, changement de réglage) traite
  chaque collecteur isolément : une erreur sur l'un n'interrompt jamais les suivants.
- Échec de `start` ou 20 erreurs en une heure → le collecteur seul passe « indisponible » jusqu'à sa
  réactivation ou au prochain démarrage de l'agent. Les autres continuent.
- `ctx.reportError(e, "où")` pour signaler une erreur attrapée soi-même.
- Un rappel enregistré **sans** passer par `ctx` (ex. `TriggerEventListener`) doit être protégé par
  `ctx.guard` : une exception non attrapée sur un fil Android tue le processus.

## 9. Tests

- Tests **JVM purs** (`./gradlew test`), sans émulateur ni Robolectric (indisponible dans l'environnement
  de développement : ses jars sont servis par un miroir bloqué). Les stubs Android renvoient des valeurs par
  défaut (`unitTests.isReturnDefaultValues = true`) : services système `null`, aucune diffusion livrée.
- Extraire la logique dans des fonctions/classes pures et les tester directement (`MotionTracker`,
  `DeviceCollector.pluggedName`…).
- Câblage : `CollectorHarness` (testFixtures de `:core`, `testImplementation(testFixtures(project(":core")))`)
  fait tourner de vrais collecteurs dans le vrai `CollectorHost` et enregistre les événements (avec leur
  `ts`, d'origine s'il y en a une). Le fil des collecteurs et `ctx.io` y sont des exécuteurs suivis :
  `settle()` attend qu'aucun des deux n'ait de travail en file ou en cours (pas de course avec `ctx.io`) ;
  une coroutine suspendue dans `delay` est considérée au repos : `awaitEvents(type, n)`. Les fonctions
  système déclarées par `Requirement.SystemFeature` sont celles de `h.features` :

```kotlin
CollectorHarness(MyCollector()).use { h ->
    h.granted += Manifest.permission.ACCESS_FINE_LOCATION
    h.features += PackageManager.FEATURE_WIFI    // Requirement.SystemFeature
    h.deviceOwner = true
    h.startAll()                       // ou h.collectOnce("my_id") ; settle() inclus
    assertEquals(CollectorRunState.RUNNING, h.status("my_id").state)
    val e = h.eventsOf("net.wifi").single()
    Contract.check(e.type, e.data)     // référence unique du contrat
}
```

- **Contrat** : `Contract` (testFixtures de `:core`) est l'unique copie de test du §2 du contrat et de ses
  précisions : types, noms de champs, type JSON de chaque valeur, listes fermées (`sev`, `plugged`,
  `security.policy.action`…), table des `fields` de `security.log`. `Contract.check(type, data)` échoue sur
  un type ou une clé inconnus, un `null`, un mauvais type de valeur. Tout nouveau champ s'y ajoute (après
  le contrat). `app/src/test/…/ContractConformanceTest` fait produire à chaque collecteur de l'APK ses
  événements types (constructeurs de données publics, processeurs de journaux, banc) et vérifie aussi
  `agent.heartbeat.collectors` (les 22 collecteurs, état `running`/`disabled`/`unavailable`) ; un type
  déclaré qui ne peut pas être produit sur la JVM doit y être listé avec sa raison. Les échantillons sont
  dans `ApkSamples`, repris par `CrossServerTest` : envoi au **vrai collecteur** (`server/collector`) par le
  vrai `Uploader`, avec un `.vigie` du vrai `enroll` (ignoré sans `VIGIE_CROSS_ENROLL` ; mode d'emploi en
  tête du fichier).
- Autres aides : `FakeClock`, `MemoryPrefs`, `TestContext`, `openTestDatabase(dir)` (Room sur SQLite JVM
  embarqué, schéma réel).
- Avant de committer : `./gradlew lint test assembleDebug assembleRelease` doit être vert (la release a
  besoin du keystore local, voir le README).

## 10. Repères dans `:core`

| Besoin | Où |
|---|---|
| Événement, JSON, ULID, RFC 3339, `boot_id` | `core/event/` |
| Tampon (Room, `seq`, purge sévérité/âge, `dropped_total`) | `core/outbox/Outbox.kt` |
| Horizon de la purge par âge (saut d'horloge murale) | `core/outbox/AgeHorizon.kt` |
| Écritures groupées, journal local en mémoire | `core/sink/OutboxEventSink.kt` |
| Envoi (lots, gzip, codes HTTP dont la bissection du `400`, backoff, Wi-Fi) | `core/upload/Uploader.kt`, `core/work/Workers.kt` |
| Client mTLS, épinglage de l'AC, ping | `core/upload/IngestApi.kt` |
| Fichier `.vigie`, Keystore, jeton chiffré | `core/enroll/` |
| `agent.tamper` (permission retirée, arrêt forcé, perte du Device Owner), retrait volontaire annoncé | `core/integrity/IntegrityMonitor.kt` |
| Horodatage d'origine (`OriginTime`) | `core/sink/EventSink.kt` |
| Câblage global, maintenance (15 min), file réseau | `core/Agent.kt` |

### Envoi : `400` (lot empoisonné), `413`, erreurs transitoires

`Uploader.runLocked` (contrat §3). Seul le tampon est durable ; rien d'autre n'a besoin de survivre à un arrêt.

- `200` cohérent : lignes supprimées. `200` incohérent, `401`/`403`, `429`, `5xx`, réseau : tout est gardé,
  backoff, **jamais** de coupe du lot.
- `413` : le lot est coupé en deux (taille mémorisée dans `UploadStatus.batchSize`) ; un événement seul est
  supprimé.
- `400` : bissection **en mémoire, dans le passage** : `suspects` (pile des fins de plages refusées, bornent
  `Outbox.batch(..., maxSeq)`) et `bisectLimit` (moitié du lot refusé). Coût ≈ 2·log2(lot) requêtes par
  événement fautif ; au plus `MAX_REFUSALS_PER_RUN` (60) refus `400`/`413` par passage, sinon `PROTOCOL`
  avec backoff. Un événement seul en `400` est supprimé par `Outbox.drop` (suppression **et** `dropped_total`
  dans une seule transaction) et signalé par `onDropped` (`Agent` → `agent.collector_error`).
- **Garde-fou** : sur le premier `400` d'un passage, un lot sans événement est envoyé (`probeEnvelope`). Refusé
  aussi (`http_400_envelope`) : aucun événement n'est supprimé. Un `200` quelconque du passage vaut preuve.
- Arrêt brutal : une ligne n'est supprimée qu'après `200` ou en `400` seule ; la reprise recommence la
  bissection de ce qui reste (≤ 2·log2(500) requêtes de plus), sans perte.

### Purge par âge et horloge murale (`AgeHorizon`)

`Outbox.enforceLimits` ne compare plus `ts` à `horloge_murale − durée` mais à `horizon − durée`, avec
`horizon = min(murale, horizon_précédent + 2 × Δelapsed + 1 min)` (jamais au-delà de la murale ; après un
redémarrage, `+ 2 jours` au plus). État : SharedPreferences `vigie_age_horizon`. Un saut en avant ne vide plus
le tampon ; un saut en arrière rabat l'horizon aussitôt (les événements écrits ensuite ne sont pas purgés).

**Limites connues** (non couvertes) :
- Saut en avant **suivi d'un redémarrage** : l'horizon avance d'au plus 2 jours par redémarrage, pas zéro (on ne
  connaît pas la durée d'arrêt) ; un téléphone vraiment éteint longtemps garde ses vieux événements un peu
  plus longtemps que la durée réglée (rattrapage à vitesse double).
- Une horloge qui reste fausse en avant vieillit quand même les événements deux fois plus vite (≈ 15 jours
  réels pour 30 jours de rétention) ; un attaquant patient peut donc accélérer la purge, pas la déclencher d'un coup.
- Saut en arrière : les événements antérieurs au saut sont conservés plus longtemps que la durée réglée
  (le plafond de taille s'applique toujours) ; leurs `ts` ne sont jamais corrigés.
- La purge **par taille** et `agent.buffer_overflow` ne dépendent pas de l'horloge ; les `ts` des événements
  émis pendant l'erreur d'horloge restent faux (le serveur les compare à son heure à la réception).
- Le `400` : si le serveur refuse l'enveloppe vide ET accepte les lots (comportement non prévu par le
  contrat), aucun événement n'est supprimé et la file reste bloquée (backoff). L'agent n'a jamais été testé
  contre un serveur réel renvoyant `400`, ni sur appareil.

## 11. Module `:policy` (repères)

- `VigieAdminReceiver` (fil principal, rappels courts) : `onEnabled` → intégrité, `PolicyModule.onAgentStarted`
  (auto-attribution, protection contre l'arrêt forcé) et `host.reconcile()` ; `onDisableRequested` →
  `agent.tamper` ; `onDisabled` → `IntegrityMonitor.onAdminDisabled` (pas d'altération si le retrait était
  annoncé) ; journaux réseau et sécurité → `PolicyModule.onNetworkLogsAvailable` / `onSecurityLogsAvailable`,
  qui délèguent aux collecteurs `network_log` / `security_log` (récupération sur `ctx.io`) ; mots de passe →
  `posture` (`security.keyguard`).
- Journaux : traduction pure et testée (`logs/SecurityLogTranslator`, `SecurityLogProcessor`,
  `NetworkLogProcessor`, `Aggregation`) ; chaque sortie porte `tsMs` (heure d'origine de la première
  occurrence), passé en `originTsMs`.
- Politique : `engine/PolicyEngine` (aperçu, application, retour arrière, retrait du Device Owner), sur une
  interface `DevicePolicyGateway` (implémentation Android `AndroidDevicePolicyGateway`, factice dans les
  tests). Chaque action émet `security.policy` et une ligne du journal local ; l'état est écrit avant chaque
  changement. Catalogue : `res/raw/policy_catalog.json` ; garde-fous codés en dur (`engine/Guards.kt`).
- Écran Politique : `app/…/ui/PolicyScreen.kt` (Compose, dans `:app`) sur `policy/…/ui/PolicyController`.
- Issue de secours ADB : `rescue/RescueReceiver` (permission `FORCE_STOP_PACKAGES` exigée de l'expéditeur ;
  extras `sweep`, `remove_owner`, `force`) ; scripts `rescue-revert.*` et `remove-device-owner.*`. Elle tourne
  dans le processus de l'app : rien de ce qui est lancé au démarrage (`VigieApplication`, portées de
  coroutines d'`Agent` et de `PolicyModule`) ne doit pouvoir le faire planter.
- Garde-fous : `PackageDenyList` (liste de refus), `RestrictionGuard` et `SettingGuard` (listes
  **d'autorisation** : toute clé absente est refusée). Ajouter une restriction ou un réglage au catalogue
  exige de l'ajouter d'abord à la liste vérifiée, documentation `UserManager`/`Settings` à l'appui.
- État appliqué : écrit avant chaque changement (`PENDING`), relu enregistrement par enregistrement ;
  illisible → `stateWasUnreadable()` et balayage du catalogue (`sweepCatalog`) à « Tout rétablir ». Défaire
  ne s'arrête jamais sur un élément (`isolated`, `bookkeeping`).
- Les appels bloquants (`setGlobalPrivateDnsModeSpecifiedHost`, sonde DoT) se font hors fil principal.
- Ne jamais poser `DISALLOW_DEBUGGING_FEATURES` ni couper la signalisation USB (porte de secours ADB).

## 12. Commandes à distance (contrat §8)

Le seul flux serveur → téléphone. Liste fermée, rien d'autre : aucun code de ce chemin n'a accès en écriture
aux réglages, à la politique ou à l'enrôlement.

| Élément | Où | Rôle |
|---|---|---|
| Modèle | `core/command/CommandModel.kt` | `CommandTypes` (liste fermée, sensibles, Device Owner), `Refusal` (motifs du contrat), `CommandParams` (seuls champs qui atteignent un exécuteur), `AcceptedCommand` (constructeur `internal` : seul le vérificateur en crée), `CommandExecutor`. |
| Cryptographie | `CommandCrypto.kt` | PBKDF2-HMAC-SHA256 écrit sur `Mac("HmacSHA256")` (l'encodage du mot de passe de `SecretKeyFactory` varie selon le fournisseur : ici toujours UTF-8, sans normalisation, comme `TextEncoder`), HMAC, comparaison `MessageDigest.isEqual`. `isTooWeak` : plancher du code (6 caractères différents ; sans lettre, 20 chiffres), car le serveur peut chercher le code hors ligne à partir d'une commande signée. |
| État | `CommandStore.kt` | `CommandKeyStore` : `K` scellé par `SecretBox` (clé AES-GCM du Keystore, alias `vigie_command_key`), lié au `device_id`. `CommandStateStore` : deux fenêtres anti-rejeu de 500 (signées / simples), signatures invalides et verrouillage, historique (50), résultats en attente. Tout en `commit()` : ce qui garde une exécution est sur disque avant elle. |
| Vérification | `CommandVerifier.kt` | Ordre exact du contrat ; avant la signature, seuls `v`, `id`, `device_id`, `type` sont lus. Un `wipe` signé et valide refusé parce que l'effacement n'est pas autorisé consomme son `id` (il ne s'exécutera pas si le serveur le livre de nouveau après l'activation de l'interrupteur). `JsonNesting` : profondeur du JSON bornée avant toute analyse (payload ici, événements et réponses dans `CommandChannel`). `WipeGate` : les six conditions de l'effacement et leur revérification sur l'état courant. |
| Traitement | `CommandProcessor.kt` | Un à la fois : vérification → exécuteur → `command.result` (sévérités du contrat) → historique → résultat à poster. Commande déjà traitée livrée de nouveau (renvoi du serveur, flux + interrogation) : jamais réexécutée, son résultat d'origine (mémoire de 1000 résultats, `CommandStateStore.rememberResult`) est renvoyé. `wipe` : événement et envoi borné à 10 s **avant** l'exécuteur. |
| Canal | `CommandChannel.kt`, `AndroidChannelPlatform.kt` | Boucle (une coroutine, `Dispatchers.IO`) : désactivé / non enrôlé / refusé (401-403) / sans réseau → attente d'un signal ; sinon flux SSE (`SseParser`) ou interrogation ; backoff à gigue en `elapsedRealtime` ; signaux : réglages, réseau (`Agent.startNetworkWatch`), envoi de lot (`Agent.handleUploadOutcome`), alarme (`CommandAlarmReceiver`), maintenance. Une file + un ouvrier traitent les commandes pendant que la lecture continue. |
| Câblage | `RemoteCommands.kt`, `Agent.commands` | Réglages `commands.*`, code (`setCode` lent : hors fil principal), enregistrement des exécuteurs par module (`register`). |
| Exécuteurs | `LocateExecutor` (`:core`, via `OnDemandLocator` implémenté par `LocationCollector`) ; `RemoteAlerts`/`RingController` (`:app`) ; `remote/RemoteExecutors.kt` (`:policy`) | `lock`/`clear_lock_message` derrière `LockScreenGateway` ; `wipe` derrière `FactoryReset`, dont la seule implémentation réelle (`AndroidFactoryReset`, `wipeDevice(0)`) est construite dans `PolicyModule.registerCommandExecutors`. |
| Interface | `app/…/ui/CommandsScreen.kt`, `CommandLabels.kt`, `service/AgentNotifications.kt` | Écran, accueil, notification permanente (« commandes à distance : à l'écoute »), une notification par commande, sonnerie avec « Arrêter ». |

**Choix de sobriété** (le point non mesurable ici, voir le README pour les mesures à faire) :

- pas de verrou de veille permanent : la lecture du flux est une lecture bloquante d'une connexion au repos ;
  verrous bornés pendant une commande (2 min), une interrogation (60 s), après une alarme (30 s), une sonnerie
  (durée + 10 s) ;
- délai de lecture 300 s = 2,5 × le maintien de 120 s du serveur (`CommandChannel.STREAM_READ_TIMEOUT_MS`) ; le
  serveur ne doit donc pas dépasser environ 240 s de maintien. Les minuteries ne comptent pas le sommeil du
  processeur : la détection d'un flux mort repose aussi sur une alarme `setAndAllowWhileIdle` (15 min) et la
  maintenance, qui comparent la dernière réception à `elapsedRealtime` (sommeil compris) ;
- aucune tentative sans réseau (on attend `onAvailable`), backoff exponentiel à gigue, flux « mort-né » compté
  comme un échec, `401`/`403` = arrêt affiché, `404` = 6 h ; une seule alarme en attente à la fois ;
- l'interrogation à chaque envoi de lot n'a lieu que si le flux n'est pas ouvert, au plus une fois par minute.

**Tests** : `core/src/test/…/command/` (vérification, ordre, vecteur, cas difficiles signés par la console
— `ConsoleVectorsTest` —, rejeu, `wipe` refusé puis rejoué, verrouillage, plancher du code, canal contre
MockWebServer), `policy/src/test/…/RemoteCommandsPolicyTest` (matrice des 64 combinaisons de `wipe`,
isolement de l'appel réel vérifié dans les sources), `app/src/test/…/CommandResultContractTest` (conformité de
`command.result`). Banc partagé : `CommandKit`, `CommandVector`, `RecordingSink`, `PlainSecretBox`
(`core/src/testFixtures/…/CommandFixtures.kt`).

**Ajouter une commande** : d'abord le contrat (§8) et la console/le collecteur ; puis `CommandTypes`,
`CommandVerifier.parseParams` (bornes fermées), un exécuteur enregistré par le module qui possède l'appel
plateforme, les libellés (`CommandLabels`, `strings_commands.xml`) et `Contract.COMMAND_TYPES`.
