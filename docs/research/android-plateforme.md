# Vigie — Recherche plateforme Android / Samsung (Galaxy S25+, novembre 2026)

> Périmètre : application Android auto-hébergée, Device Owner (DO) provisionné par ADB sur un Galaxy S25+ européen (ROM stock, bootloader verrouillé, sans root, sans Google Play Services dans l'app).
> Date de la recherche : 15/11/2026. Aucun test sur appareil réel.

## 0. Méthode, fiabilité, limites

- **Niveaux de confiance** utilisés dans ce document :
  - **[Doc]** : documentation officielle developer.android.com / source.android.com lue pendant la recherche.
  - **[AOSP]** : lu dans le code source AOSP via le miroir GitHub `aosp-mirror/platform_frameworks_base` (branche `main`). Ce miroir est probablement **figé autour d'Android 16** (il contient `QUERY_ADVANCED_PROTECTION_MODE` et `DISALLOW_THREAD_NETWORK`, mais pas `ACCESS_LOCAL_NETWORK`, qui arrive avec Android 17). Le comportement Android 17 / One UI 9 peut donc différer.
  - **[Presse]** / **[Communauté]** : articles de presse, forums, GitHub tiers.
  - **[Non vérifié]** : de mémoire ou déduit, à valider sur l'appareil.
- **Sites inaccessibles depuis cette session** (le DNS a échoué) : `docs.samsungknox.com`, `developer.samsung.com`, `developers.google.com`, `blog.google`, `bayton.org`, `dontkillmyapp.com`, `android.googlesource.com`. Pour ces sites, seuls les extraits de moteur de recherche ont été utilisés. Les points Knox et Samsung sont donc moins solides que les points AOSP.

---

## 1. Versions plateforme et outillage

| Élément | Valeur | Source |
|---|---|---|
| Android en cours sur S25+ (UE) | **One UI 9.0 / Android 17 (API 37)**. Déploiement stable : Corée fin septembre 2026, US début octobre, Europe à partir du ~6/10/2026 par vagues selon le pays (Allemagne et France non confirmées pour le S25 au moment des articles) | [Presse] https://www.sammyfans.com/2026/10/06/samsung-galaxy-s25-one-ui-9-0-stable-update-global/ , https://9to5google.com/2026/09/14/samsung-android-17-one-ui-9-update-list , https://www.neoteo.com/en/one-ui-9-rollout-reaches-galaxy-s25-in-europe-reports-say |
| Version précédente | One UI 8.x / Android 16 (API 36). One UI 8 est sorti sur le S25 le 15/09/2025 | [Presse] https://news.samsung.com/uk/samsung-begins-official-rollout-of-one-ui-8-to-galaxy-devices |
| Android 17 stable (AOSP/Pixel) | 16/06/2026. API gelée à la Beta 3 (mars 2026) | [Presse] https://www.androidauthority.com/android-17-3561251/ |
| Prochaine version | One UI 9.x puis Android 18 (2027) : **[Non vérifié]**, aucune date fiable | — |
| SoC | Snapdragon 8 Elite for Galaxy, toutes régions (pas d'Exynos sur le S25) | [Presse] https://www.engadget.com/mobile/smartphones/samsung-galaxy-s25-smartphones-are-powered-by-a-custom-snapdragon-8-elite-soc-180050277.html |

**Outillage recommandé** (toutes valeurs [Doc], sauf mention) :
- **AGP 9.5.x** : la page des notes de version indique 9.5.1 comme dernier correctif. AGP 9.5 exige au minimum **Gradle 9.6.0**, JDK 17 et Build Tools 36.0.0, et supporte au maximum l'API 37. https://developer.android.com/build/releases/gradle-plugin
- AGP 9 active par défaut le **Kotlin intégré** (`android.builtInKotlin=true`) : le plugin `org.jetbrains.kotlin.android` ne doit plus être appliqué. Il active aussi la nouvelle DSL (`android.newDsl=true`), qui retire l'API de variantes historique. https://developer.android.com/build/releases/agp-9-0-0-release-notes
- **Kotlin 2.4.21** (8/10/2026) : c'est la dernière version stable. La 2.5.0 est en bêta. https://kotlinlang.org/docs/releases.html
- **`compileSdk = 37`, `targetSdk = 37`, `minSdk = 36`** (recommandation). `minSdk 36` permet de tourner encore si l'appareil reste temporairement sous One UI 8 (Android 16). `minSdk 37` est acceptable si la mise à jour vers One UI 9 est confirmée sur l'appareil.
- Conséquences de `targetSdk 37` pour Vigie [Doc] (https://developer.android.com/about/versions/17/behavior-changes-17) :
  - **`ACCESS_LOCAL_NETWORK`** devient obligatoire : il faut cette permission d'exécution pour joindre un serveur Wazuh situé en RFC1918 (192.168.x, 10.x, CGNAT…). Le DO peut la pré-accorder par `setPermissionGrantState`. Le trafic DNS vers un résolveur LAN (port 53) en est exempté.
  - Certificate Transparency est activé par défaut. Un certificat auto-signé ou une CA privée sur le serveur SIEM échouera, sauf `network_security_config` adapté (pinning de la CA privée et désactivation de CT pour ce domaine).
  - ECH est activé si la bibliothèque réseau le supporte.
  - Restrictions sur l'audio en arrière-plan, `static final` non modifiables par réflexion, etc.
- Android 17 pour toutes les apps : limites mémoire par app (`MemoryLimiter`), quota de 50 000 clés Keystore. [Doc] https://developer.android.com/about/versions/17/behavior-changes-all

---

## 2. Provisioning Device Owner par ADB (sans factory reset)

### 2.1 Préconditions exactes
Source : code `DevicePolicyManagerService.checkDeviceOwnerProvisioningPreConditionLocked` [AOSP] https://github.com/aosp-mirror/platform_frameworks_base/blob/main/services/devicepolicy/java/com/android/server/devicepolicy/DevicePolicyManagerService.java

Commande : `adb shell dpm set-device-owner --user 0 <pkg>/<.Receiver>`. Si la configuration initiale est terminée, ADB l'autorise à condition que :
1. **Aucun DO ou PO ne soit déjà défini.** Sinon : erreur « device owner … is already set » ou « user already has a profile owner ».
2. **Aucun autre utilisateur ne soit présent** (`nonTestNonPrecreatedUsersExist`). Sinon : *« Not allowed to set the device owner because there are already several users on the device »*. Sur Samsung, cela impose de supprimer **Secure Folder** (utilisateur Knox, en général id 150), **Dual Messenger** (profil clone, en général id 95), tout espace privé ou profil professionnel, et les invités. ID d'utilisateurs : [Communauté], à vérifier avec `adb shell pm list users`.
3. **Aucun compte « incompatible »** n'existe sur l'appareil. Sinon : *« …there are already some accounts on the device »*.
   - Pour une app normale, **n'importe quel compte** bloque l'opération : Google, Samsung account, WhatsApp, Signal, Microsoft, etc. Lister avec `adb shell dumpsys account`.
   - Pour une app `testOnly`, seuls les comptes déclarant la feature `DEVICE_OR_PROFILE_OWNER_ALLOWED` sont tolérés, ce que les comptes Google et Samsung ne font pas, à notre connaissance [Non vérifié]. **En pratique, il faut retirer tous les comptes.**
- L'erreur *« Cannot set the device owner if the device is already set-up »* ne concerne que le chemin non-ADB. Il n'y a donc **pas besoin de factory reset** avec ADB.
- OwnDroid signale sur Samsung une erreur « user limit reached » sans solution connue [Communauté] https://github.com/BinTianqi/OwnDroid. Ses versions 8.4+ contournent la vérification des comptes via Shizuku ou root, ce qui ne s'applique pas ici.
- **Après le provisioning**, on peut rajouter ses comptes Google et Samsung : le DO n'interdit l'ajout que s'il pose `DISALLOW_MODIFY_ACCOUNTS`. Cette pratique est courante chez les utilisateurs de TestDPC et OwnDroid [Communauté] [Non vérifié sur S25].

### 2.2 Effets automatiques de `setDeviceOwner` (vérifiés dans le code [AOSP])
- **Service de sauvegarde Android désactivé** (`toggleBackupServiceActive(false)`) : la sauvegarde Google Drive ou Android Backup s'arrête. On le réactive avec `setBackupServiceEnabled(admin, true)` [Doc+AOSP].
- Restrictions posées sur tous les utilisateurs : `DISALLOW_ADD_MANAGED_PROFILE`, `DISALLOW_ADD_CLONE_PROFILE` et `DISALLOW_ADD_PRIVATE_PROFILE`. Conséquences :
  - **Dual Messenger, l'espace privé et le profil pro deviennent impossibles.**
  - **Secure Folder est très probablement indisponible** : la KBA Knox 1205 « Secure Folder isn't available on a device » et les forums vont dans ce sens [Communauté] https://docs.samsungknox.com/admin/knox-platform-for-enterprise/kbas/kba-1205-secure-folder-not-available-on-a-device/ (non lisible depuis la session).
- Provisionné **via ADB**, le DO reçoit `mAdminCanGrantSensorsPermissions = true` : il peut donc accorder les permissions capteurs (localisation, micro, caméra) [AOSP].

### 2.3 Retrait propre
- `DevicePolicyManager.clearDeviceOwnerApp(pkg)` : appelable par le DO lui-même. Elle est **dépréciée mais fonctionne toujours**. Selon la doc, le nettoyage des politiques est « best-effort » et certaines restent en place [AOSP Javadoc]. **Vigie doit donc défaire elle-même ses politiques avant l'appel** : apps masquées ou suspendues, restrictions, DNS privé, VPN always-on, blocage de désinstallation.
- `adb shell dpm remove-active-admin <comp>` (`forceRemoveActiveAdmin`) **ne fonctionne que si l'app est `testOnly`**. Sinon : `SecurityException "Attempt to remove non-test admin"` [AOSP].
  - Recommandation : builds de dev avec `android:testOnly="true"` (installation par `adb install -t`), ce qui garde une porte de sortie par ADB.
  - Contre-partie : un admin `testOnly` peut aussi être retiré par quiconque a un accès ADB.
- Les apps masquées (`setApplicationHidden`) restent masquées après le retrait du DO si Vigie ne les a pas réaffichées. Rattrapage possible par `adb shell pm unhide <pkg>` [Non vérifié].

### 2.4 Alternative QR code (après factory reset)
- On tape 6 fois sur l'écran d'accueil, puis on scanne un QR contenant :
  - `android.app.extra.PROVISIONING_DEVICE_ADMIN_COMPONENT_NAME` ;
  - `…PACKAGE_DOWNLOAD_LOCATION` (APK sur le serveur perso) ;
  - `…SIGNATURE_CHECKSUM` (SHA-256 du certificat de signature, en base64url) ;
  - optionnellement les extras Wi-Fi.
- Depuis Android 12, le DPC doit gérer `GET_PROVISIONING_MODE` et `ADMIN_POLICY_COMPLIANCE` [Doc/Non revérifié].
- **Risque majeur : depuis 2025, Play Protect applique une « allowlist de DPC » pendant le provisioning QR.** Les DPC personnalisés non approuvés sont bloqués (« Harmful app blocked » / « App blocked to protect your device »), avec de nombreux signalements sur Samsung [Communauté] :
  - https://www.androidenterprise.community/android-enterprise-general-discussions-3/play-protect-blocking-custom-dpc-app-during-6-tap-qr-provisioning-appeal-submitted-2909
  - https://bayton.org/blog/2025/12/the-dpc-allowlist/
  - Un développeur rapporte avoir été débloqué après avoir **retiré NotificationListener et les permissions SMS** de son DPC.
  - **Conclusion : rester sur le provisioning ADB.**

### 2.5 Effets de bord Samsung avec DO actif
| Élément | Effet | Confiance |
|---|---|---|
| Mention « appareil géré » | Bas des réglages rapides et écran de verrouillage ; notifications « Network logging » (voir §3) | [Doc/AOSP] |
| Secure Folder, Dual Messenger, espace privé | Impossibles (restrictions ci-dessus) | [AOSP] + [Communauté] |
| Sauvegarde Google | Désactivée par défaut, réactivable par le DO | [AOSP] |
| Samsung Wallet / Pay / Pass | Inconnu. Aucune source fiable trouvée. Ces services dépendent de Knox (warranty bit), que le DO ne déclenche pas | [Non vérifié] |
| Google Wallet, apps bancaires | Play Integrity `MEETS_DEVICE_INTEGRITY` dépend du bootloader verrouillé et de l'image certifiée, pas de la présence d'un DO. Risques indirects : options développeur ou débogage USB laissés actifs, Play Protect désactivé (profil strict), app sideloadée visible (`UNKNOWN_INSTALLED`) | [Doc] https://developer.android.com/google/play/integrity/verdicts ; le reste [Non vérifié] |
| OTA Samsung | Non bloquées par défaut. `setSystemUpdatePolicy` existe, mais son respect par Samsung n'est pas vérifié | [Non vérifié] |
| Knox / Auto Blocker | Auto Blocker (actif par défaut depuis One UI 6.1.1) **bloque les commandes USB et le sideload**. One UI 8.5 peut le réactiver après 30 min. En One UI 9 bêta, « Maximum restrictions » bloque toute connexion USB. Une source unique affirme que ce mode désactive les apps d'administration de l'appareil, **ce qui serait critique pour Vigie** | [Presse] https://www.androidauthority.com/samsung-one-ui-9-auto-blocker-update-3666893/ , https://www.samsung.com/us/support/answer/ANS10003636 |

---

## 3. API DevicePolicyManager : capacités et limites réelles

### 3.1 Contrainte transverse : l'affiliation
Les logs réseau, les logs de sécurité et `setGlobalPrivateDns*` **échouent (SecurityException) ou sont jetés dès qu'un utilisateur ou profil non affilié existe** [AOSP Javadoc]. Comme le DO interdit déjà profils clone, privé et pro, le seul risque restant est un utilisateur secondaire ou invité créé à la main. On le bloque avec `DISALLOW_ADD_USER`.

### 3.2 Network logging
Doc : `setNetworkLoggingEnabled` / `retrieveNetworkLogs` [AOSP Javadoc + `NetworkLoggingHandler`]. https://developer.android.com/reference/android/app/admin/DevicePolicyManager#setNetworkLoggingEnabled(android.content.ComponentName,%20boolean)

**Contenu**
- `DnsEvent` : `hostname`, `getInetAddresses()` (éventuellement un sous-ensemble), `getTotalResolvedAddressCount()`, `packageName`, `timestamp`.
- `ConnectEvent` : `inetAddress`, `port`, `packageName`, `timestamp`.

**Couverture**
- Seuls les appels `getaddrinfo()`/`gethostbyname()` et `connect()` passant par la libc ou netd sont journalisés.
- **Ne sont pas vus** :
  - UDP sans `connect()` (QUIC, jeux…) ;
  - IP codées en dur ;
  - DoH applicatif ;
  - libc alternative ou appels kernel directs.
- La doc renvoie elle-même au VPN always-on pour une capture L3.

**Volume et rythme**
- Lots de **1200 événements maximum**, finalisés à 1200 événements ou au plus tard après **1 h 30**.
- 5 lots maximum en attente. Un lot récupéré est jeté après 5 min.
- On récupère via le callback `DeviceAdminReceiver.onNetworkLogsAvailable(batchToken)`. En test : `adb shell dpm force-network-logs`.

**Notification**
- Le système affiche une notification « réseau surveillé » au plus **2 fois** au total, au plus une fois par 24 h (`DEF_MAXIMUM_NETWORK_LOGGING_NOTIFICATIONS_SHOWN = 2`).
- Le pied des réglages rapides affiche ensuite en permanence « votre organisation peut surveiller le trafic ».

### 3.3 Security logging
- `setSecurityLoggingEnabled`, `retrieveSecurityLogs`, `retrievePreRebootSecurityLogs`.
- `retrievePreRebootSecurityLogs` : « non supporté sur tous les appareils », renvoie `null` dans ce cas. Support Samsung [Non vérifié].
- **Rythme** : le système interroge logd toutes les minutes. Le DO est notifié à 1024 entrées ou toutes les **2 h**, avec relance toutes les 30 min. Tampon de 10 240 entrées ; les plus anciennes sont perdues au-delà [AOSP `SecurityLogMonitor`]. En test : `adb shell dpm force-security-logs`.
- **Tags publics disponibles** [AOSP `SecurityLog.java`], regroupés par domaine :
  - ADB : `ADB_SHELL_INTERACTIVE`, `ADB_SHELL_CMD`, `SYNC_RECV_FILE`, `SYNC_SEND_FILE` ;
  - processus : `APP_PROCESS_START` (avec hash de l'APK, **réservé au DO**) ;
  - verrouillage : `KEYGUARD_DISMISSED`, `KEYGUARD_DISMISS_AUTH_ATTEMPT`, `KEYGUARD_SECURED`, `KEYGUARD_DISABLED_FEATURES_SET` ;
  - démarrage et journalisation : `OS_STARTUP`, `OS_SHUTDOWN`, `LOGGING_STARTED`, `LOGGING_STOPPED`, `LOG_BUFFER_SIZE_CRITICAL` ;
  - stockage : `MEDIA_MOUNT`, `MEDIA_UNMOUNT` ;
  - mots de passe : `PASSWORD_EXPIRATION_SET`, `PASSWORD_COMPLEXITY_SET`, `PASSWORD_HISTORY_LENGTH_SET`, `MAX_SCREEN_LOCK_TIMEOUT_SET`, `MAX_PASSWORD_ATTEMPTS_SET`, `PASSWORD_COMPLEXITY_REQUIRED`, `PASSWORD_CHANGED` ;
  - administration : `REMOTE_LOCK`, `WIPE_FAILURE`, `USER_RESTRICTION_ADDED`, `USER_RESTRICTION_REMOVED`, `CAMERA_POLICY_SET`, `BACKUP_SERVICE_TOGGLED` ;
  - clés et certificats : `KEY_GENERATED`, `KEY_IMPORT`, `KEY_DESTRUCTION`, `KEY_INTEGRITY_VIOLATION`, `CERT_AUTHORITY_INSTALLED`, `CERT_AUTHORITY_REMOVED`, `CERT_VALIDATION_FAILURE`, `CRYPTO_SELF_TEST_COMPLETED` ;
  - radios : `WIFI_CONNECTION`, `WIFI_DISCONNECTION`, `BLUETOOTH_CONNECTION`, `BLUETOOTH_DISCONNECTION`, `NFC_ENABLED`, `NFC_DISABLED` (cette paire est sous feature flag) ;
  - paquets : `PACKAGE_INSTALLED`, `PACKAGE_UPDATED`, `PACKAGE_UNINSTALLED`.
  - D'éventuels ajouts d'Android 17 ne sont pas vérifiés.
- L'« audit log » (`setAuditLogEnabled`) est une API système, inaccessible.

### 3.4 DNS privé
- `setGlobalPrivateDnsModeSpecifiedHost(admin, host)` [AOSP Javadoc] :
  - **bloquant**, car il effectue un test de connectivité vers le résolveur : annoté `@WorkerThread`, **à appeler hors du main thread** ;
  - renvoie `PRIVATE_DNS_SET_NO_ERROR`, `…ERROR_FAILURE_SETTING` ou `…ERROR_HOST_NOT_SERVING` (le serveur ne parle pas RFC 7858) ;
  - **échoue en présence d'utilisateurs non affiliés** ;
  - avec un VPN, le résolveur doit être joignable à la fois dans et hors du VPN.
- Verrouillage côté utilisateur : `addUserRestriction(DISALLOW_CONFIG_PRIVATE_DNS)` (DO uniquement, portée globale).
- `setGlobalSetting(PRIVATE_DNS_MODE / PRIVATE_DNS_SPECIFIER)` est aussi dans l'allowlist, mais sans validation : préférer l'API dédiée.

### 3.5 VPN always-on
- `setAlwaysOnVpnPackage(admin, pkg, lockdown[, allowlist])`. Le VPN doit déclarer un `VpnService` protégé par `BIND_VPN_SERVICE` et ne pas refuser l'always-on. Le lockdown coupe tout le réseau si le VPN tombe [AOSP Javadoc].
- Un VPN local à la NetGuard ou RethinkDNS dans Vigie donnerait l'attribution par app de **tous** les flux, y compris UDP et IP en dur, via `ConnectivityManager.getConnectionOwnerUid` (réservé à l'app VPN active).
- Limite : un seul VPN à la fois sur l'appareil.

### 3.6 Désactiver des paquets : hide, suspend, enable
- **`setApplicationHidden`** : très permissif [AOSP `PackageManagerService`]. Il refuse seulement :
  - les apps avec un admin actif ;
  - le paquet `android` ;
  - les bibliothèques SDK ou statiques ;
  - les paquets « protégés ».
  - **Il accepte donc Play Store, GMS, le launcher, le composeur ou SystemUI.** Aucun garde-fou plateforme : Vigie doit embarquer sa propre **liste de refus** (launcher par défaut, SystemUI, téléphone, contrôleur de permissions, clavier en Direct Boot, `kgclient`, etc.).
  - Masquer une app la rend inutilisable pour l'utilisateur, ce qui revient à la désactiver.
- **`setPackagesSuspended`** : plus sûr. Il refuse [AOSP `SuspendPackageHelper.canSuspendPackageForUser`] :
  - les apps avec un admin actif et le paquet `android` ;
  - le launcher actif ;
  - les paquets d'installation, de désinstallation et de **vérification** requis (sur GMS, le vérificateur est en principe le Play Store [Non vérifié]) ;
  - le **composeur par défaut** et le **contrôleur de permissions** ;
  - les paquets protégés et ceux marqués `OP_SYSTEM_EXEMPT_FROM_SUSPENSION` ;
  - les bibliothèques SDK ou statiques.
  - L'app suspendue reste visible, grisée.
  - Les deux API passent par une liste `listPolicyExemptApps` définie par l'OEM. Son contenu sur Samsung n'est pas vérifié.
- **`enableSystemApp`** sert uniquement à **réactiver** une app système désactivée par défaut, pas à désactiver.
- **`setUserControlDisabledPackages([vigie])`** : l'utilisateur ne peut plus forcer l'arrêt ni effacer les données, et l'app est **exemptée des App Standby Buckets** [AOSP Javadoc]. **À appliquer à Vigie.** Compléter par `setUninstallBlocked`.

### 3.7 Permissions d'exécution
Source : `setPermissionGrantState` [AOSP Javadoc + code].
- Le DO peut accorder ou refuser n'importe quelle permission *d'exécution* de n'importe quelle app, **y compris aux apps système ou privilégiées** : pour un admin ciblant Q+, un refus sur une app pré-M passe l'app-op à `IGNORED`. Cas particulier non vérifié : les permissions marquées `SYSTEM_FIXED` sont probablement refusées par le PermissionController.
- **Permissions capteurs** (localisation fine, arrière-plan et approximative, caméra, micro, reconnaissance d'activité, capteurs corporels) : un DO provisionné par ADB peut les **accorder**, y compris à lui-même, ce qui couvre `ACCESS_FINE_LOCATION` et `ACCESS_BACKGROUND_LOCATION`. Si l'accord est interdit, l'appel lève une `SecurityException` lorsque le DO cible l'API 35+.
- `DENIED` verrouille la permission dans l'interface. `DEFAULT` rend la main à l'utilisateur sans révoquer.
- Seules les permissions *runtime* sont concernées : pas d'app-ops spéciales (accès à l'utilisation, superposition, écouteur de notifications).

### 3.8 Restrictions utilisateur utiles (`addUserRestriction`)
Liste vérifiée dans `UserManager` [AOSP] :

**Sécurité et vie privée**
- `DISALLOW_CELLULAR_2G` : DO uniquement, portée globale ; les appels d'urgence restent possibles.
- `DISALLOW_CONFIG_PRIVATE_DNS`
- `DISALLOW_INSTALL_UNKNOWN_SOURCES_GLOBALLY`
- `DISALLOW_ADD_USER`
- `DISALLOW_CONFIG_VPN`
- `DISALLOW_CONFIG_CREDENTIALS` : empêche l'ajout de CA utilisateur.
- `DISALLOW_USB_FILE_TRANSFER`
- `DISALLOW_SAFE_BOOT`
- `DISALLOW_FACTORY_RESET` : facultatif.
- `DISALLOW_CONTENT_CAPTURE`, `DISALLOW_CONTENT_SUGGESTIONS`, `DISALLOW_ASSIST_CONTENT` : coupent les flux vers l'IA ou l'Assistant.
- `DISALLOW_SIM_GLOBALLY` : bloque le téléchargement d'eSIM.
- `DISALLOW_ULTRA_WIDEBAND_RADIO`, `DISALLOW_NEAR_FIELD_COMMUNICATION_RADIO`, `DISALLOW_THREAD_NETWORK`
- `DISALLOW_BLUETOOTH_SHARING`
- `DISALLOW_SHARE_LOCATION`
- `DISALLOW_AUTOFILL`

**À NE PAS poser** :
- `DISALLOW_DEBUGGING_FEATURES`, qui coupe ADB et donc la porte de secours ;
- `setUsbDataSignalingEnabled(false)`, qui désactive aussi le débogage USB [Doc] https://source.android.com/docs/core/interaction/accessories/disable-signaling. De plus, le support HAL USB du S25 n'est pas vérifié : appeler `canUsbDataSignalingBeDisabled()` avant.
- `DISALLOW_OEM_UNLOCK` est une API système, inaccessible.

### 3.9 Settings (`setGlobalSetting`, `setSecureSetting`, `setSystemSetting`)
Allowlist [AOSP] :
- **Global** : `ADB_ENABLED`, `ADB_WIFI_ENABLED`, `AUTO_TIME`, `AUTO_TIME_ZONE`, `DATA_ROAMING`, `USB_MASS_STORAGE_ENABLED`, `WIFI_SLEEP_POLICY`, `STAY_ON_WHILE_PLUGGED_IN`, `WIFI_DEVICE_OWNER_CONFIGS_LOCKDOWN`, `PRIVATE_DNS_MODE`, `PRIVATE_DNS_SPECIFIER`. Toute autre clé lève une `SecurityException` ; les clés obsolètes sont ignorées.
- **Secure** (DO) : `DEFAULT_INPUT_METHOD`, `SKIP_FIRST_USE_HINTS`, `INSTALL_NON_MARKET_APPS`, `LOCATION_MODE`.
- **System** : `SCREEN_BRIGHTNESS`, `SCREEN_BRIGHTNESS_MODE`, `SCREEN_OFF_TIMEOUT`.
- Pour d'autres clés, il faut `WRITE_SECURE_SETTINGS` accordé par ADB (§4).

### 3.10 Autres API
- **`getInstalledCaCerts(admin)`** : renvoie les CA de confiance hors CA système, y compris celles ajoutées par l'utilisateur [Non revérifié mot à mot]. À journaliser, avec les événements `CERT_AUTHORITY_*`.
- **`setMtePolicy`** : un DO peut forcer l'activation de MTE, qui prend effet au redémarrage, ou lever `UnsupportedOperationException` si le matériel ne le gère pas [AOSP Javadoc]. Le support MTE du S25 est **incertain** : un article affirme qu'il arrive avec One UI 9 [Presse] https://www.webpronews.com/samsungs-quiet-security-bet-memory-tagging-extension-is-coming-to-one-ui-9-and-it-could-rewrite-androids-defense-playbook/. À tester avec gestion de l'exception.
- **`setSystemUpdatePolicy`** : existe ; son respect par Samsung FOTA n'est pas vérifié.
- **`setPersonalAppsSuspended`** : **non pertinent**, réservé au PO d'un profil pro sur appareil d'entreprise (COPE).
- **`setAppFunctionsPolicy(APP_FUNCTIONS_DISABLED)`** (A16+) et **`setNearbyAppStreamingPolicy`** (A17, coupe l'automatisation par agents IA) : utiles côté vie privée [Doc] https://developer.android.com/work/versions/android-17
- **`setContentProtectionPolicy`** : contrôle le scan des apps trompeuses [AOSP].
- **`setAutoTimePolicy` / `setAutoTimeZonePolicy`** (A16) [Doc] https://developer.android.com/work/versions/android-16
- **Protection avancée**. `AdvancedProtectionManager` (API 36) se limite en public à :
  - `isAdvancedProtectionEnabled()` ;
  - `registerAdvancedProtectionCallback()`.
  - Permission `QUERY_ADVANCED_PROTECTION_MODE`, de niveau **normal** [Doc+AOSP] https://developer.android.com/reference/android/security/advancedprotection/AdvancedProtectionManager
  - Vigie peut donc **observer** le mode, pas l'activer. Sur le S25 sous One UI 8, il se trouve dans Réglages > Google > Tous les services > Protection avancée [Presse] https://www.sammobile.com/news/android-16-one-ui-8-protect-galaxy-phone/
  - La politique entreprise pour imposer la Protection avancée est annoncée « plus tard en 2026 » avec Android 17 [Presse, non vérifié].
  - **Intrusion logging** : journaux chiffrés de bout en bout dans le cloud Google, liés au compte Google, gérés par l'OS. **Aucune API publique** pour les lire [Presse] https://thehackernews.com/2026/05/android-adds-intrusion-logging-for.html

---

## 4. Permissions accordables par ADB à une app tierce

Niveaux de protection relevés dans `core/res/AndroidManifest.xml` [AOSP] https://github.com/aosp-mirror/platform_frameworks_base/blob/main/core/res/AndroidManifest.xml. **Seules les permissions portant le flag `development` (ou `appop`) sont accordables par `pm grant`.**

| Permission | Niveau | `pm grant` ? | Ce que ça débloque réellement |
|---|---|---|---|
| `READ_LOGS` | signature\|privileged\|**development** | Oui | Depuis Android 13, `LogcatManagerService` exige un **consentement à chaque accès** : dialogue si l'app est au premier plan (`PROCESS_STATE_TOP`), **refus automatique en arrière-plan**, accord valable 60 s [AOSP `LogcatManagerService.java`]. Aucune exemption DO dans le code. Un flux `logcat` ouvert pendant que l'app est au premier plan pourrait continuer en arrière-plan [Non vérifié]. **Inutilisable pour une collecte continue fiable.** |
| `DUMP` | signature\|privileged\|**development** | Oui | `android.os.Debug.dumpService(name, fd, args)` (API publique) sur les services joignables par SELinux depuis `untrusted_app`, par ex. `appops`, `activity`, `package`, `connectivity` [Non vérifié sur S25]. Lancer le binaire `dumpsys` ne marchera probablement pas : listing de `servicemanager` refusé par SELinux [Non vérifié]. Piste intéressante : `dumpService("appops")` donne l'historique des accès micro, caméra et localisation par app. |
| `WRITE_SECURE_SETTINGS` | …\|**development**\|role\|installer | Oui | Écriture des tables Global et Secure, par ex. `private_dns_*`, `wifi_scan_throttle_enabled`, `adb_enabled`. Depuis `targetSdk 31`, la **lecture** des clés non `@Readable` est bloquée [Non revérifié]. |
| `PACKAGE_USAGE_STATS` | …\|**development**\|**appop**\|retailDemo | Oui, puis `appops set <pkg> GET_USAGE_STATS allow` | `UsageStatsManager.queryEvents` ; `NetworkStatsManager` pour tous les UID de l'utilisateur. Le DO a de toute façon accès aux stats réseau de tous les utilisateurs [Doc] https://developer.android.com/reference/android/app/usage/NetworkStatsManager |
| `BATTERY_STATS` | signature\|privileged\|**development** | Oui | `BatteryStatsManager` et `dumpService("batterystats")` (ce dernier exige aussi DUMP) [Non vérifié] |
| `GET_APP_OPS_STATS` | signature\|privileged\|**development** | Oui | Les API qui l'utilisent (`getPackagesForOps`, `getHistoricalOps`) sont **@SystemApi** et bloquées par les restrictions d'API cachées. Peu utile seule ; passer par `DUMP` + `dumpService("appops")`. |
| `INTERACT_ACROSS_USERS` | …\|**development**\|role | Oui | Peu utile : un seul utilisateur sous DO |
| `WATCH_APPOPS` | signature\|privileged | **Non** | `startWatchingActive` ne voit donc que **son propre UID** [AOSP AppOpsManager] |
| `READ_PRIVILEGED_PHONE_STATE`, `READ_NETWORK_USAGE_HISTORY`, `LOCAL_MAC_ADDRESS`, `CONTROL_VPN`, `REAL_GET_TASKS`, `CHANGE_DEVICE_IDLE_TEMP_WHITELIST` | signature\|privileged | **Non** | — |

**Autres commandes ADB utiles** [Communauté/Non revérifié pour One UI 9] :
- `adb shell cmd notification allow_listener <pkg>/<Service>` active un `NotificationListenerService`, en contournant les « paramètres restreints » des apps sideloadées.
  - **Depuis Android 15, les OTP sont masqués** pour les écouteurs « non fiables » [Doc] https://developer.android.com/about/versions/15/behavior-changes-all
  - **À éviter dans l'APK DO** : déclencheur Play Protect, voir §2.4 et §9.
- `adb shell dumpsys deviceidle whitelist +<pkg>` exempte de Doze. Pour une app ciblant 34+, `REQUEST_IGNORE_BATTERY_OPTIMIZATIONS` + dialogue fait l'équivalent.

**Ce que le DO obtient automatiquement**
- Exemption des restrictions de démarrage de FGS en arrière-plan, **et** des restrictions « while-in-use » pour les FGS location, caméra et micro [Doc] https://developer.android.com/develop/background-work/services/fgs/restrictions-bg-start
- Bucket App Standby `EXEMPTED` (`AppStandbyController`) et exemption `REASON_DEVICE_OWNER` dans `AppRestrictionController` [AOSP].
- Accès `NetworkStats` à tous les UID [Doc].
- Contrôle des permissions runtime (§3.7) et installation silencieuse via `PackageInstaller`, utile pour les **auto-mises à jour** de Vigie [Non revérifié].

---

## 5. Collecte en continu

### Foreground services
- **Types adaptés** :
  - `location`, avec `ACCESS_BACKGROUND_LOCATION` accordée par le DO ;
  - `specialUse`, avec la propriété `PROPERTY_SPECIAL_USE_FGS_SUBTYPE` et une justification ; aucune limite de durée n'est documentée ;
  - `connectedDevice` (BLE), si pertinent.
- **Éviter `dataSync`** :
  - **6 h cumulées par 24 h** quand l'app est en arrière-plan (A15+, `targetSdk ≥ 35`) ;
  - `onTimeout()` puis `stopSelf()` obligatoire ;
  - le compteur ne se réinitialise que si l'app passe au premier plan [Doc] https://developer.android.com/develop/background-work/services/fgs/timeout
- **Démarrage au boot** :
  - un récepteur `BOOT_COMPLETED` **ne peut pas** lancer les FGS `dataSync`, `camera`, `mediaPlayback`, `phoneCall`, `mediaProjection` ni `microphone` [Doc] https://developer.android.com/about/versions/15/behavior-changes-15
  - `location` et `specialUse` restent autorisés. Avec l'exemption « while-in-use » du DO, un FGS `location` peut démarrer depuis le boot [Doc, combinaison non testée].
- **Direct Boot** : `LOCKED_BOOT_COMPLETED` permet de démarrer avant le premier déverrouillage, avec `android:directBootAware="true"` et du stockage *device-protected*. Les clés Keystore liées à l'authentification et les données *credential-protected* restent indisponibles jusqu'au déverrouillage.
- **Android 15+ (toutes apps)** :
  - un « force stop » annule tous les `PendingIntent`. Le DO l'empêche via `setUserControlDisabledPackages` ;
  - **les requêtes réseau hors cycle de vie valide échouent** : faire les envois depuis le FGS ou WorkManager [Doc].
- **Android 17** : limiteur mémoire, raison `MemoryLimiter:AnonSwap` dans `ApplicationExitInfo`. Garder le service sobre.

### Localisation sans Play Services
- `LocationManager` expose `GPS_PROVIDER`, `NETWORK_PROVIDER`, `PASSIVE_PROVIDER` et, depuis l'API 31, `FUSED_PROVIDER` [Doc] https://developer.android.com/reference/android/location/LocationManager
- **Sur un appareil GMS, les fournisseurs « network » et très probablement « fused » sont implémentés par Google Play Services** (overlays `config_enableNetworkLocationOverlay` et `config_enableFusedLocationOverlay`). Ils ne fonctionnent que si « Précision de la localisation Google » est activée, et ils envoient alors des scans Wi-Fi et cellule à Google [Non vérifié sur S25].
  - Pour un profil anti-pistage : **utiliser `GPS_PROVIDER` + `PASSIVE_PROVIDER`**, et désactiver la précision Google.
- Le GNSS du S25 utilise l'assistance **Qualcomm XTRA** (`xtrapath{1,2,3}.izatcloud.net`, collecte d'identifiants techniques selon Kaspersky et Nitrokey) et SUPL (`supl.google.com` par défaut, ou un serveur de l'opérateur). La SUPL envoie IMSI et position [Presse] https://www.kaspersky.com/blog/gps-agps-supl-tracking-protection/48175/
  - Bloquer XTRA et SUPL réduit fortement le TTFF : arbitrage à exposer dans l'UI.
- `GnssStatus.Callback` (constellations, C/N0) et `GnssMeasurementsEvent` (mesures brutes, API 24+) sont publics, avec `ACCESS_FINE_LOCATION`. Utiles pour détecter un **brouillage ou une usurpation GNSS** (chute de C/N0, sauts d'horloge, AGC).

### Veille Samsung
- Listes « applications en veille », « en veille prolongée » (après 16 jours sans usage selon Samsung) et « jamais en veille » [Presse] https://www.guidingtech.com/how-to-manage-sleeping-apps-on-samsung-galaxy-phone
- Samsung affirme que, depuis One UI 6, les FGS conformes aux types d'Android 14 « fonctionnent comme prévu » [extrait de recherche de developer.samsung.com/mobile/app-management.html, non lisible directement].
- **Parades** :
  - FGS typé ;
  - `setUserControlDisabledPackages` (exemption standby) ;
  - exemption Doze ;
  - ajout manuel de Vigie dans « Jamais en veille ». **Aucune API connue pour ce dernier point : documenter la procédure.**
  - L'exemption de Samsung Device care pour un DO n'est **pas vérifiée**.
- **Redémarrage après kill** : `START_STICKY` ; alarme exacte de surveillance (`SCHEDULE_EXACT_ALARM`, accordable par `appops`/ADB) ; récepteurs `BOOT_COMPLETED`, `LOCKED_BOOT_COMPLETED` et `MY_PACKAGE_REPLACED` ; WorkManager périodique (15 min) comme filet.

---

## 6. Détection d'usage des capteurs par d'autres apps (sans privilège système)

| Mécanisme | Ce qu'on obtient | Limite | Source |
|---|---|---|---|
| `CameraManager.AvailabilityCallback` | `onCameraUnavailable(id)` / `onCameraAvailable(id)` à chaque ouverture ou fermeture, par n'importe quelle app ; aucune permission | **Pas le paquet** : `onCameraOpened(id, pkg)` est une API système | [Doc] https://developer.android.com/reference/android/hardware/camera2/CameraManager.AvailabilityCallback |
| `AudioManager.registerAudioRecordingCallback` / `getActiveRecordingConfigurations` | Source audio, format, périphérique, session, `isClientSilenced()` | **Pas d'UID ni de paquet** dans l'API publique | [Doc] https://developer.android.com/reference/android/media/AudioRecordingConfiguration |
| `AppOpsManager.startWatchingActive` | — | Sans `WATCH_APPOPS` (non accordable), ne voit que son propre UID | [AOSP] |
| `DUMP` + `Debug.dumpService("appops")` | État courant et derniers accès CAMERA, RECORD_AUDIO, FINE_LOCATION par paquet | Format texte non stable, à parser ; SELinux à vérifier | [Non vérifié] |
| Corrélation | `UsageStatsManager.queryEvents` (app au premier plan, démarrage et arrêt des FGS) **croisé** avec les callbacks caméra et micro | Attribution probabiliste | [Doc] |
| `NetworkStatsManager` par UID | Volumes par app (seaux d'environ 2 h) | DO : tous les utilisateurs | [Doc] |
| `TelephonyManager.getAllCellInfo` / `requestCellInfoUpdate`, `TelephonyCallback` (CellInfo, ServiceState, DisplayInfo) | Technologie (GSM/LTE/NR), identifiants de cellule, signal ; détection d'une **rétrogradation 2G** et de changements de LAC/TAC anormaux | `ACCESS_FINE_LOCATION` + `READ_PHONE_STATE` | [Doc, non revérifié] |
| Transparence réseau cellulaire (A15/16 : notifications chiffrement nul et divulgation d'identifiant) | — | **API système** (`MODIFY_PHONE_STATE`, `READ_PRIVILEGED_PHONE_STATE`), modem et HAL OEM requis, absente même sur Pixel au lancement d'A15 ; support Samsung inconnu. Mesure efficace côté DO : **`DISALLOW_CELLULAR_2G`** | [Presse] https://www.androidauthority.com/android-16-mobile-network-security-3571497 |
| Scans Wi-Fi | Foreground : 4 scans / 2 min ; **arrière-plan : 1 scan / 30 min (toutes apps confondues)**. Écoute passive possible de `SCAN_RESULTS_AVAILABLE_ACTION` (scans des autres apps). Option développeur « Wi-Fi scan throttling » ; la clé Global est modifiable avec `WRITE_SECURE_SETTINGS` [Non vérifié]. Exige `ACCESS_FINE_LOCATION` et la localisation activée | — | [Doc] https://developer.android.com/develop/connectivity/wifi/wifi-scan |
| Scans BLE (traceurs AirTag, SmartTag, Tile) | `BluetoothLeScanner` avec **`ScanFilter` obligatoire**, car les scans sans filtre sont suspendus écran éteint. Limite d'environ 5 `startScan` / 30 s. Filtrer sur les manufacturer data (Apple 0x004C, Samsung 0x0075…). Projet de référence : AirGuard (open source) | — | [Non revérifié] |

---

## 7. Débloatage : paquets Google et Samsung

Source principale : `uad_lists.json` d'**Universal Android Debloater NG**, branche `main`, téléchargé le 15/11/2026 : https://raw.githubusercontent.com/Universal-Debloater-Alliance/universal-android-debloater-next-generation/main/resources/assets/uad_lists.json. Les niveaux entre crochets sont ceux d'UAD-NG. Leur présence effective sur un S25 sous One UI 9 **reste à vérifier** avec `pm list packages`.

Méthode côté Vigie : `setApplicationHidden` (réversible), ou `setPackagesSuspended` quand on veut garder l'icône visible.

### 7.1 Profil « équilibré » (Play Services, Play Store, FCM et apps bancaires intacts)

**Samsung, télémétrie et publicité**
- `com.samsung.android.rubin.app` [Recommended] : Customization Service, profilage publicitaire.
- `com.samsung.android.knox.analytics.uploader` [Recommended]
- `com.samsung.android.dsms` [Recommended] : composant diagmon caché.
- `com.samsung.android.dqagent` [Advanced] : Device Quality Agent.
- `com.sec.android.diagmonagent` [Advanced] : **ne pas désactiver**, UAD signale une boucle de relance qui fait chauffer l'appareil et vide la batterie. Couper plutôt « Envoyer les données de diagnostic » dans les réglages.
- `com.samsung.android.svcagent` [Recommended] : contient la bibliothèque DiagMon.
- Collecte de logs : `com.samsung.carrier.logcollector` [Recommended], `com.sec.android.CcInfo` [Recommended], `com.samsung.logwriter` [Recommended].
- `com.samsung.attribution` [Recommended]
- `com.samsung.android.deviceidservice` [Recommended] : OAID/AAID.
- `com.samsung.android.peripheral.framework` [Recommended] : analytics Knox, selon UAD.
- `com.samsung.android.mocca` [Recommended]
- `com.samsung.sait.sohservice` [Recommended]
- Publicité et recommandations : `com.samsung.android.mfi` (Galaxy Widget) [Recommended], `com.samsung.android.app.omcagent` [Recommended], `com.samsung.android.mapsagent` [Recommended]
- `com.samsung.android.ipsgeofence` [Recommended] : géorepérage intérieur.
- Diagnostics réseau : `com.samsung.android.networkdiagnostic` [Recommended], `com.samsung.android.wifinetworkdiagnostics` [Recommended], `com.samsung.qosindicator` [Recommended].
- Bixby, optionnel (confort) : `com.samsung.android.bixby.agent`, `…bixby.wakeup`, `…bixby.service`, `…visionintelligence`, `com.samsung.android.app.spage` [Recommended].
- `com.samsung.android.app.tips` [Recommended]
- `com.samsung.android.smartsuggestions` [Recommended]

**Google, publicité et personnalisation**
- `com.google.android.adservices.api` [Recommended] : Privacy Sandbox, module mainline. Désactiver aussi les options « Confidentialité des annonces ».
- `com.google.android.ondevicepersonalization.services` [Recommended]
- `com.google.android.federatedcompute` [Recommended]
- `com.google.android.feedback` [Recommended]
- `com.google.android.partnersetup` [Advanced]
- `com.google.android.gms.location.history` [Recommended] : stub.
- Optionnels : `com.google.android.as` [Recommended], qui casse le sous-titrage instantané et Smart Reply ; `com.google.android.apps.bard` (Gemini) [Recommended].

**À conserver** dans ce profil :
- `com.google.android.gms`, `com.android.vending`, `com.google.android.gsf` ;
- `com.osp.app.signin` ;
- `com.samsung.android.fmm` (antivol) ;
- `com.samsung.android.securitylogagent` : surveille les modifications de `/system`. **Utile à Vigie, ne pas désactiver malgré [Recommended].**

### 7.2 Profil « strict » (dé-googlisation et dé-samsungisation poussées)
On y ajoute :

**Google**
- `com.google.android.gms` [Expert], `com.google.android.gsf` [Expert], `com.android.vending` [Expert].
- **Ce qui casse** : notifications push FCM (messageries, banques), Play Store et ses mises à jour, Google Wallet, **la plupart des apps bancaires** (Play Integrity), Localiser mon appareil, compte Google, mises à jour Play System et SafetyCore, sauvegarde. Selon UAD, risque de bootloop sur certains appareils.
- `com.google.android.googlequicksearchbox` [Advanced] : casse Entourer pour chercher.

**Samsung**
- `com.osp.app.signin` [Advanced] : Samsung account ; casse Galaxy Store, Samsung Cloud et Find My Mobile.
- `com.samsung.android.scloud` [Recommended]
- `com.samsung.android.mobileservice` [Advanced]
- `com.sec.spp.push` [Recommended]
- `com.samsung.android.fmm` [Recommended] : **perte de l'antivol**.
- Paiement : `com.samsung.android.spay`, `com.samsung.android.spayfw`, `com.samsung.android.samsungpass`, `com.samsung.android.authfw` [Recommended].
- `com.sec.android.app.samsungapps` [Expert] : Galaxy Store, requis par Samsung Pay.
- `com.samsung.android.app.updatecenter` [Recommended]
- `com.samsung.android.scs` [Advanced] : casse la recherche et l'OCR des apps Samsung.
- `com.samsung.android.lool` (Device care) [Advanced] et `com.samsung.android.sm.devicesecurity` (moteur McAfee) [Advanced].
- `com.samsung.klmsagent` [Advanced] : licences Knox, ce qui empêcherait le Knox SDK en v2.
- `com.samsung.android.knox.attestation` [Recommended] : peut casser Samsung Wallet ou des banques [Non vérifié].

### 7.3 Ne jamais toucher (les deux profils)
- `com.samsung.android.kgclient` [**Unsafe**] : **verrouillage plein écran persistant jusqu'au factory reset**.
- `com.samsung.android.sm.policy` [Unsafe]
- `com.sec.android.soagent` et `com.wssyncmldm` [Expert] : **OTA Samsung**.
- `com.samsung.android.cidmanager` [Expert]
- `com.samsung.android.gru` [Expert]
- `com.samsung.android.honeyboard` [Expert] : clavier ; seul clavier disponible en Direct Boot.
- `com.samsung.android.wifi.softap.resources` [Unsafe]
- `com.google.android.rkpdapp` [Unsafe] : Remote Key Provisioning. Sert à l'attestation, donc à **Play Integrity** [Non vérifié].
- `com.google.android.ext.services`, `com.google.android.networkstack`, `com.google.android.permissioncontroller` [Unsafe]
- `com.google.android.configupdater` [Expert] : pins TLS, firewall d'intents.
- `com.google.android.webview` [Expert]
- `com.samsung.android.app.routines` [Expert]
- Plus le launcher, SystemUI, le téléphone et Settings (garde-fou §3.6).

### 7.4 Domaines DNS

**Listes publiques maintenues** (URL brutes) :
- HaGeZi « Native Tracker Samsung » : 201 domaines au 13/11/2026.
  - Wildcard : https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/native.samsung-onlydomains.txt
  - Adblock : https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/native.samsung.txt
  - **HaGeZi n'a pas de liste « native Google ».**
- HaGeZi Pro : 237 247 entrées au 15/11/2026. https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/pro-onlydomains.txt
- Perflyst android-tracking : 112 lignes. https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/android-tracking.txt

**À bloquer (équilibré)**, présence vérifiée dans ces listes :
- Google, Firebase et publicité : `app-measurement.com`, `google-analytics.com`, `ssl.google-analytics.com`, `googlesyndication.com`, `www.googleadservices.com`, `googleads.g.doubleclick.net`, `crashlytics.com` (et `e.`, `reports.`, `settings.`), `firebaselogging-pa.googleapis.com`, `federatedml-pa.googleapis.com` (Perflyst).
- Samsung : `samsungads.com`, `samsungadhub.com`, `dc.dqa.samsung.com`, `dls-udc.dqa.samsung.com`, `diagmon-policy.samsungdm.com`, `diagmon-serviceapi.samsungdm.com`, `report.gras.samsungdm.com`, `analytics.samsungknox.com`, `nmetrics.samsungmobile.com`, `stats.samsungpass.com`, `api.runestone.samsung.com` (Customization Service), `smetrics.samsung.com`, `devicelog.samsungcloudsolution.net`.

**À NE PAS bloquer en équilibré** (absents de HaGeZi Pro, vérifié pour ceux marqués ✓) :
- FCM : `mtalk.google.com` ✓, `mtalk4.google.com`, `alt*-mtalk.google.com`, ports 5228-5230 ; `android.googleapis.com`, `fcmtoken.googleapis.com`, `firebaseinstallations.googleapis.com` ✓ [liste non revérifiée sur la doc FCM].
- Play Store et authentification : `play.googleapis.com` ✓, `play-fe.googleapis.com`, `android.clients.google.com`, `accounts.google.com`, `www.googleapis.com`.
- Test de connectivité : `connectivitycheck.gstatic.com` ✓, `www.google.com/generate_204`. Les URL exactes utilisées par Samsung ne sont pas vérifiées.
- Heure : `time.android.com` [Non vérifié pour Samsung].
- A-GPS : `supl.google.com` ✓, `xtrapath1-3.izatcloud.net` ✓ (sauf choix volontaire, voir §5).
- **FOTA Samsung** : `*.ospserver.net` ✓ (par ex. `fota-cloud-dn.ospserver.net`, `fota-s3-dn.ospserver.net`) et `*.samsungdm.com` sauf les sous-domaines diagmon et gras.
  - Un blocage de `ospserver.net` empêche les mises à jour [Communauté] https://discourse.pi-hole.net/t/samsung-galaxy-wont-update/74704 , https://eu.community.samsung.com/t5/samsung-lounge/security-issue-on-updates/td-p/11273721
- **Conflit** : HaGeZi Pro bloque `gld.samsungosp.com`, alors que les services du compte Samsung passent par `*.samsungosp.com`. À surveiller dans les logs.
- **Limite structurelle** : une partie de la télémétrie GMS passe par des domaines partagés (`play.googleapis.com`, `www.googleapis.com`). **Le DNS ne permet pas de la filtrer sans casser le Play Store** [Non vérifié en détail]. Seul le profil strict (désactivation de GMS) la supprime.

---

## 8. Knox SDK

**Apports pour un particulier**
- Pare-feu par app avec filtrage de domaines et **logs des domaines bloqués avec paquet** [Presse/Knox] https://docs.samsungknox.com/admin/fundamentals/whitepaper/samsung-knox-mobile-security/network-security/knox-firewall/
- Audit log Knox (`com.samsung.android.knox.log`).
- Contrôles OEM supplémentaires.

**Licence**
- La clé KPE Premium est **gratuite** et couvre les fonctions Standard. Validité de 2 ans. Depuis le portail 26.07, on ne peut plus générer de clés Standard [Presse/Knox] https://docs.samsungknox.com/dev/knox-sdk/faq/licensing/
- **Mais** : les clés développeur exigent désormais un **ticket au Knox Partner Program avec un « business use case »**, et leur génération est réservée aux comptes partenaires KPP. Adhell3 ne peut plus être activé sans clé existante [Communauté] https://github.com/hklcf/Adhell3 , https://docs.samsungknox.com/dev/knox-sdk/kbas/kba-1227-license-keys-page-unavailable-from-the-knox-developer-portal
- Depuis Android 15 (Knox 3.11), de nombreuses API Knox sont limitées aux DO et PO, ce qui ne gêne pas Vigie.
- Politique de dépréciation : 1 an de support, puis suppression possible à 2 ans.
- L'activation de licence contacte les serveurs Samsung (KLM), ce qui contredit l'objectif anti-pistage.

**Conclusion : ne pas intégrer en v1.**
- Pare-feu par app : un VPN local (§3.5) fait mieux, sans licence.
- Le reste est couvert par les API AOSP (DO).
- À réévaluer en v2 uniquement si une clé KPE est obtenue.

---

## 9. Risques

**Play Protect**
- Le bloc **DPC + NotificationListener + SMS** a déjà fait bloquer des DPC personnalisés [Communauté, §2.4].
- *Live Threat Detection* (analyse comportementale sur l'appareil, étendue à Android 17) cible, selon Google :
  - les apps qui **masquent ou changent leur icône** puis se lancent en arrière-plan ;
  - l'abus d'**accessibilité** ;
  - le transfert de SMS ;
  - les superpositions [Presse] https://blog.google/security/whats-new-in-android-security-privacy-2026/
- **Vigie doit donc :**
  - garder une icône et une notification permanentes ;
  - ne demander ni SMS, ni accessibilité, ni superposition ;
  - isoler un éventuel collecteur de notifications dans un **APK séparé et optionnel** ;
  - garder un nom et une description explicites.
- Possibilité de faire appel des classements Play Protect.

**Vérification des développeurs (sideload)**
- Obligatoire au Brésil, en Indonésie, à Singapour et en Thaïlande depuis 09/2026, puis mondialement en « 2027 et après ». Pas de date UE.
- Les comptes « limited distribution » (hobbyistes, 20 appareils, sans pièce d'identité, gratuits) existent.
- L'installation par ADB reste une voie pour les apps non vérifiées [Presse/Doc] https://support.google.com/android-developer-console/answer/16561738 , https://www.androidauthority.com/p-3679204/
- **À anticiper** : enregistrer la clé de signature de Vigie sur un compte limited distribution, ou passer par des mises à jour ADB ou silencieuses via le DO.

**Play Integrity**
- Le DO n'affecte pas `MEETS_DEVICE_INTEGRITY`.
- `MEETS_STRONG_INTEGRITY` exige des correctifs de sécurité de moins d'un an [Doc].
- Avec Play Protect désactivé, `playProtectVerdict` vaut `POSSIBLE_RISK`. Certaines banques peuvent refuser.
- Les apps avec accessibilité ou superposition donnent `*_CAPTURING`/`*_CONTROLLING` : raison de plus pour que Vigie n'en utilise pas.

**Auto Blocker et Protection avancée**
- Ils bloquent les commandes USB et le sideload. Une source unique dit que « Maximum restrictions » désactive les apps d'administration de l'appareil.
- La Protection avancée bloque aussi l'USB et la 2G.
- **Leur interaction avec un DO tiers est à tester avant tout déploiement** [Non vérifié].

**Batterie**
- Network et security logging : « low-overhead » [Doc].
- Les postes coûteux sont le GPS continu, les scans BLE et Wi-Fi, et les envois fréquents.
- Recommandations : envois groupés (lots de 15 min à 1 h, ou à chaque lot réseau), GPS en mode passif ou intervalle large, scans BLE filtrés et ponctuels.

---

## 10. Points à valider en priorité sur l'appareil
1. `dpm set-device-owner` après suppression des comptes, de Secure Folder et de Dual Messenger. Vérifier `pm list users` et `dumpsys account`.
2. Coexistence avec Auto Blocker (désactivé pendant le provisioning), puis réactivation : le DO survit-il ?
3. `setGlobalPrivateDnsModeSpecifiedHost` vers le résolveur perso. Réception de `onNetworkLogsAvailable` et `onSecurityLogsAvailable`. `retrievePreRebootSecurityLogs` est-il différent de `null` ?
4. `canUsbDataSignalingBeDisabled()`, `setMtePolicy` (exception ?), effet réel de `DISALLOW_CELLULAR_2G` sur One UI 9.
5. `Debug.dumpService("appops")` avec `DUMP` accordé (refus SELinux ?).
6. Survie du FGS `location`/`specialUse` après 24 h écran éteint et après reboot, sans ajout manuel dans « Jamais en veille ».
7. Samsung Wallet, Google Wallet et une app bancaire avec le DO actif.
