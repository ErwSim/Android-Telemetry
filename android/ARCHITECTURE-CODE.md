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
| `:core` | `io.github.erwsim.vigie.core` | `Agent` (câblage), modèle d'événement, `EventSink`, tampon `outbox` (Room), envoi (`Uploader`, WorkManager), enrôlement, réglages, interface `Collector` + `CollectorHost`, `Capabilities`, `IntegrityMonitor` (`agent.tamper`). |
| `:collectors` | `…vigie.collectors` | Collecteurs **sans** privilège Device Owner. Point d'entrée : `CollectorsModule.all(context)`. |
| `:policy` | `…vigie.policy` | Tout ce qui exige le Device Owner : `VigieAdminReceiver`, `DeviceOwnerManager`, futur moteur de politique. Point d'entrée : `PolicyModule`. |
| `:app` | `…vigie` | `VigieApplication`, service de premier plan `AgentService`, `BootReceiver`, interface Compose. |

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
- Rappels Android : `ctx.registerReceiver(filter) { intent -> }` (désinscrit automatiquement à l'arrêt),
  `ctx.executor` (pour `LocationManager`, `PowerManager`, `TelephonyManager.registerTelephonyCallback`…),
  `ctx.handler` / `ctx.looper` sinon. Un rappel livré sur le fil principal (ex. `TriggerEventListener`) doit
  repasser par `ctx.handler.post { ctx.guard("…") { … } }`.
- Travail bloquant (I/O, `PackageManager` massif, `getprop`) : `withContext(Dispatchers.IO) { … }` ou
  `ctx.scope.launch(Dispatchers.IO) { … }`. `ctx.scope` est annulé à l'arrêt.
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

- `ctx.capabilities` : `isDeviceOwner()`, `hasPermission(p)`, `adminComponent()`, `hasSystemFeature(f)`,
  `isIgnoringBatteryOptimizations()`, `declaredRuntimePermissions()`.
- Permission d'exécution : la déclarer dans le manifeste du module **et** dans `requirements`. Une permission
  `optional = true` n'empêche pas le démarrage (mode dégradé ; la liste `missingPermissions` est affichée).
- En **Device Owner**, `PolicyModule.onAgentStarted` s'accorde **toutes** les permissions d'exécution
  déclarées par le manifeste fusionné (localisation d'avant-plan avant arrière-plan), puis remet l'état à
  `DEFAULT` : la permission reste accordée mais l'utilisateur garde la main. Rien à coder pour un nouveau
  collecteur. Sans Device Owner, l'onglet Collecteurs propose « Accorder les permissions ».
- Permissions accordables seulement par ADB (`DUMP`, `WRITE_SECURE_SETTINGS`, `PACKAGE_USAGE_STATS`,
  `BATTERY_STATS`) : les déclarer dans le manifeste du module (avec `tools:ignore="ProtectedPermissions"`),
  les tester dans `checkAvailability`, et vérifier qu'elles sont dans `scripts/grant-adb-permissions.{sh,ps1}`.
  App-op « accès à l'utilisation » : tester `AppOpsManager.unsafeCheckOpNoThrow(OPSTR_GET_USAGE_STATS, …)`.
- `Requirement.DeviceOwner` : le collecteur passe « indisponible » sans Device Owner et démarre seul quand le
  rôle est accordé (`VigieAdminReceiver.onEnabled` → `host.reconcile()`).
- Une permission retirée par l'utilisateur est signalée par `agent.tamper` (`permission_revoked`) par
  `IntegrityMonitor` ; le collecteur passe « indisponible » au prochain `reconcile`.

## 7. Réglages

- `SettingKey.IntKey("<id>.<nom>", défaut, min, max)` ou `SettingKey.BoolKey(...)`, exposés via
  `settings = listOf(SettingSpec.IntSpec(key, titreRes, résuméRes, "s"))`. Lecture : `ctx.settings[KEY]`.
- Toute modification passe par `AgentSettings.set` : `agent.config_changed` (`key`, `old`, `new`) est émis
  automatiquement et le collecteur est redémarré. Aucun réglage ne vient du serveur (flux à sens unique).
- Réglages de politique : `PolicyModule.settings` (rendu dans la section « Device Owner » des Réglages).

## 8. Erreurs et isolation

- Toute exception dans `start`/`stop`/`collectOnce`, dans un rappel `ctx.registerReceiver`/`ctx.executor`,
  dans `ctx.scope` ou dans `ctx.guard("où") { … }` est attrapée et émise en `agent.collector_error`
  (`collector`, `error`), au plus 5 par heure et par collecteur (les suivantes sont comptées).
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
  fait tourner de vrais collecteurs dans le vrai `CollectorHost` et enregistre les événements :

```kotlin
CollectorHarness(MyCollector()).use { h ->
    h.granted += Manifest.permission.ACCESS_FINE_LOCATION
    h.deviceOwner = true
    h.startAll()                       // ou h.collectOnce("my_id")
    assertEquals(CollectorRunState.RUNNING, h.status("my_id").state)
    val e = h.eventsOf("net.wifi").single().data
}
```

- Autres aides : `FakeClock`, `MemoryPrefs`, `TestContext`, `openTestDatabase(dir)` (Room sur SQLite JVM
  embarqué, schéma réel).
- Avant de committer : `./gradlew lint test assembleDebug assembleRelease` doit être vert.

## 10. Repères dans `:core`

| Besoin | Où |
|---|---|
| Événement, JSON, ULID, RFC 3339, `boot_id` | `core/event/` |
| Tampon (Room, `seq`, purge sévérité/âge, `dropped_total`) | `core/outbox/Outbox.kt` |
| Écritures groupées, journal local en mémoire | `core/sink/OutboxEventSink.kt` |
| Envoi (lots, gzip, codes HTTP, backoff, Wi-Fi) | `core/upload/Uploader.kt`, `core/work/Workers.kt` |
| Client mTLS, épinglage de l'AC, ping | `core/upload/IngestApi.kt` |
| Fichier `.vigie`, Keystore, jeton chiffré | `core/enroll/` |
| `agent.tamper` (permission retirée, arrêt forcé, perte du Device Owner) | `core/integrity/IntegrityMonitor.kt` |
| Câblage global, maintenance (15 min), file réseau | `core/Agent.kt` |

## 11. Notes pour le module `:policy`

- `VigieAdminReceiver` (fil principal) délègue à `PolicyModule.onNetworkLogsAvailable(context, token, n)` et
  `PolicyModule.onSecurityLogsAvailable(context)` : y récupérer les lots (hors fil principal, via
  `Agent.get()`), émettre `net.dns` / `net.connect` / `security.log` par `Agent.get().sink`.
- Les appels bloquants (`setGlobalPrivateDnsModeSpecifiedHost`) se font hors fil principal.
- Chaque action de politique émet `security.policy` (contrat §2) et doit être réversible depuis l'app.
- L'écran « Politique » est réservé : remplacer le corps de `app/src/main/kotlin/io/github/erwsim/vigie/ui/PolicyScreen.kt`
  (seul fichier de `:app` à toucher), ou ajouter Compose à `:policy` et y déplacer l'écran.
- Ne jamais poser `DISALLOW_DEBUGGING_FEATURES` ni couper la signalisation USB (porte de secours ADB).
