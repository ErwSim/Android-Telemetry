# Watchpost: Android / Samsung platform research (recent Galaxy devices, One UI 8 and 9)

> Scope: a self-hosted Android application running as Device Owner (DO) provisioned through ADB on a recent
> Samsung Galaxy device (stock ROM, locked bootloader, no root, no Google Play Services in the app).
> Research carried out in November 2026. No test on a physical device.

## 0. Method, reliability, limits

- **Confidence levels** used in this document:
  - **[Doc]**: official developer.android.com / source.android.com documentation, read during the research.
  - **[AOSP]**: read in the AOSP source code through the GitHub mirror `aosp-mirror/platform_frameworks_base`
    (branch `main`). This mirror is probably **frozen around Android 16** (it contains
    `QUERY_ADVANCED_PROTECTION_MODE` and `DISALLOW_THREAD_NETWORK`, but not `ACCESS_LOCAL_NETWORK`, which
    arrives with Android 17). Android 17 / One UI 9 behaviour may therefore differ.
  - **[Press]** / **[Community]**: press articles, forums, third-party GitHub projects.
  - **[Unverified]**: from memory or deduced, to be validated on the device.
- **Sites that could not be reached during the research** (DNS failure): `docs.samsungknox.com`,
  `developer.samsung.com`, `developers.google.com`, `blog.google`, `bayton.org`, `dontkillmyapp.com`,
  `android.googlesource.com`. For these sites, only search-engine excerpts were used. The Knox and Samsung points
  are therefore less solid than the AOSP points.

---

## 1. Platform versions and tooling

| Item | Value | Source |
|---|---|---|
| Android on recent Galaxy devices (EU) | **One UI 9.0 / Android 17 (API 37)**, rolling out as a stable release since autumn 2026 in waves by country and model; availability on a given device depends on the model, the region and the carrier | [Press] https://9to5google.com/2026/09/14/samsung-android-17-one-ui-9-update-list |
| Previous version | One UI 8.x / Android 16 (API 36). One UI 8 began rolling out to Galaxy devices on 2025-09-15 | [Press] https://news.samsung.com/uk/samsung-begins-official-rollout-of-one-ui-8-to-galaxy-devices |
| Android 17 stable (AOSP/Pixel) | 2026-06-16. API frozen at Beta 3 (March 2026) | [Press] https://www.androidauthority.com/android-17-3561251/ |
| Next version | One UI 9.x, then Android 18 (2027): **[Unverified]**, no reliable date | — |

**Recommended tooling** (all values [Doc] unless stated):
- **AGP 9.5.x**: the release notes page lists 9.5.1 as the latest patch. AGP 9.5 requires at least
  **Gradle 9.6.0**, JDK 17 and Build Tools 36.0.0, and supports at most API 37.
  https://developer.android.com/build/releases/gradle-plugin
- AGP 9 enables **built-in Kotlin** by default (`android.builtInKotlin=true`): the `org.jetbrains.kotlin.android`
  plugin must no longer be applied. It also enables the new DSL (`android.newDsl=true`), which removes the legacy
  variant API. https://developer.android.com/build/releases/agp-9-0-0-release-notes
- **Kotlin 2.4.21** (2026-10-08): the latest stable version. 2.5.0 is in beta. https://kotlinlang.org/docs/releases.html
- **`compileSdk = 37`, `targetSdk = 37`, `minSdk = 36`** (recommendation). `minSdk 36` lets the app still run if a
  device temporarily remains on One UI 8 (Android 16). `minSdk 37` is acceptable if the update to One UI 9 is
  confirmed on the device.
- Consequences of `targetSdk 37` for Watchpost [Doc] (https://developer.android.com/about/versions/17/behavior-changes-17):
  - **`ACCESS_LOCAL_NETWORK`** becomes mandatory: this runtime permission is needed to reach a Wazuh server located
    on RFC1918 addresses (192.168.x, 10.x, CGNAT…). The DO can pre-grant it with `setPermissionGrantState`. DNS
    traffic to a LAN resolver (port 53) is exempt.
  - Certificate Transparency is enabled by default. A self-signed certificate or a private CA on the SIEM server
    will fail unless a suitable `network_security_config` is used (pinning the private CA and disabling CT for that
    domain).
  - ECH is enabled if the networking library supports it.
  - Restrictions on background audio, `static final` fields no longer modifiable by reflection, etc.
- Android 17 for all apps: per-app memory limits (`MemoryLimiter`), a quota of 50,000 Keystore keys. [Doc]
  https://developer.android.com/about/versions/17/behavior-changes-all

---

## 2. Device Owner provisioning through ADB (without a factory reset)

### 2.1 Exact preconditions
Source: code of `DevicePolicyManagerService.checkDeviceOwnerProvisioningPreConditionLocked` [AOSP]
https://github.com/aosp-mirror/platform_frameworks_base/blob/main/services/devicepolicy/java/com/android/server/devicepolicy/DevicePolicyManagerService.java

Command: `adb shell dpm set-device-owner --user 0 <pkg>/<.Receiver>`. If the initial setup is complete, ADB allows
it provided that:
1. **No DO or PO is already set.** Otherwise: error "device owner … is already set" or "user already has a profile
   owner".
2. **No other user exists** (`nonTestNonPrecreatedUsersExist`). Otherwise: *"Not allowed to set the device owner
   because there are already several users on the device"*. On Samsung, this means removing **Secure Folder**
   (Knox user, usually id 150), **Dual Messenger** (clone profile, usually id 95), any private space or work
   profile, and guests. User ids: [Community], to be checked with `adb shell pm list users`.
3. **No "incompatible" account** exists on the device. Otherwise: *"…there are already some accounts on the
   device"*.
   - For a normal app, **any account** blocks the operation: Google, Samsung account, WhatsApp, Signal, Microsoft,
     etc. List them with `adb shell dumpsys account`.
   - For a `testOnly` app, only accounts declaring the feature `DEVICE_OR_PROFILE_OWNER_ALLOWED` are tolerated,
     which Google and Samsung accounts do not do, to our knowledge [Unverified]. **In practice, all accounts must be
     removed.**
- The error *"Cannot set the device owner if the device is already set-up"* concerns only the non-ADB path. A
  **factory reset is therefore not needed** with ADB.
- OwnDroid reports a "user limit reached" error on Samsung with no known solution [Community]
  https://github.com/BinTianqi/OwnDroid. Its versions 8.4+ bypass the account check through Shizuku or root, which
  does not apply here.
- **After provisioning**, Google and Samsung accounts can be added back: the DO forbids adding accounts only if it
  sets `DISALLOW_MODIFY_ACCOUNTS`. This is common practice among TestDPC and OwnDroid users [Community]
  [Unverified on One UI 9].

### 2.2 Automatic effects of `setDeviceOwner` (verified in the code [AOSP])
- **Android backup service disabled** (`toggleBackupServiceActive(false)`): Google Drive or Android Backup stops. It
  is re-enabled with `setBackupServiceEnabled(admin, true)` [Doc+AOSP].
- Restrictions set on all users: `DISALLOW_ADD_MANAGED_PROFILE`, `DISALLOW_ADD_CLONE_PROFILE` and
  `DISALLOW_ADD_PRIVATE_PROFILE`. Consequences:
  - **Dual Messenger, private space and work profile become impossible.**
  - **Secure Folder is very probably unavailable**: Knox KBA 1205 "Secure Folder isn't available on a device" and
    the forums point that way [Community]
    https://docs.samsungknox.com/admin/knox-platform-for-enterprise/kbas/kba-1205-secure-folder-not-available-on-a-device/
    (not readable during the research).
- Provisioned **through ADB**, the DO receives `mAdminCanGrantSensorsPermissions = true`: it can therefore grant
  the sensor permissions (location, microphone, camera) [AOSP].

### 2.3 Clean removal
- `DevicePolicyManager.clearDeviceOwnerApp(pkg)`: callable by the DO itself. It is **deprecated but still works**.
  According to the documentation, policy cleanup is "best-effort" and some policies stay in place [AOSP Javadoc].
  **Watchpost must therefore undo its own policies before the call**: hidden or suspended apps, restrictions,
  private DNS, always-on VPN, uninstall blocking.
- `adb shell dpm remove-active-admin <comp>` (`forceRemoveActiveAdmin`) **works only if the app is `testOnly`**.
  Otherwise: `SecurityException "Attempt to remove non-test admin"` [AOSP].
  - Recommendation: development builds with `android:testOnly="true"` (installed with `adb install -t`), which
    keeps an exit door through ADB.
  - Downside: a `testOnly` admin can also be removed by anyone with ADB access.
- Hidden apps (`setApplicationHidden`) stay hidden after the DO is removed if Watchpost has not shown them again.
  A possible fallback is `adb shell pm unhide <pkg>` [Unverified] (see the erratum at the end of this document).

### 2.4 QR code alternative (after a factory reset)
- Tap 6 times on the welcome screen, then scan a QR code containing:
  - `android.app.extra.PROVISIONING_DEVICE_ADMIN_COMPONENT_NAME`;
  - `…PACKAGE_DOWNLOAD_LOCATION` (APK on the personal server);
  - `…SIGNATURE_CHECKSUM` (SHA-256 of the signing certificate, base64url);
  - optionally the Wi-Fi extras.
- Since Android 12, the DPC must handle `GET_PROVISIONING_MODE` and `ADMIN_POLICY_COMPLIANCE` [Doc / not
  re-checked].
- **Major risk: since 2025, Play Protect applies a "DPC allowlist" during QR provisioning.** Unapproved custom
  DPCs are blocked ("Harmful app blocked" / "App blocked to protect your device"), with many reports on Samsung
  [Community]:
  - https://www.androidenterprise.community/android-enterprise-general-discussions-3/play-protect-blocking-custom-dpc-app-during-6-tap-qr-provisioning-appeal-submitted-2909
  - https://bayton.org/blog/2025/12/the-dpc-allowlist/
  - One developer reports having been unblocked after **removing NotificationListener and the SMS permissions**
    from their DPC.
  - **Conclusion: stay with ADB provisioning.**

### 2.5 Samsung side effects with an active DO
| Item | Effect | Confidence |
|---|---|---|
| "Device managed" notice | Bottom of the quick settings and lock screen; "Network logging" notifications (see §3) | [Doc/AOSP] |
| Secure Folder, Dual Messenger, private space | Impossible (restrictions above) | [AOSP] + [Community] |
| Google backup | Disabled by default, can be re-enabled by the DO | [AOSP] |
| Samsung Wallet / Pay / Pass | Unknown. No reliable source found. These services depend on Knox (warranty bit), which the DO does not trigger | [Unverified] |
| Google Wallet, banking apps | Play Integrity `MEETS_DEVICE_INTEGRITY` depends on the locked bootloader and the certified image, not on the presence of a DO. Indirect risks: developer options or USB debugging left on, Play Protect disabled (strict profile), a sideloaded app visible (`UNKNOWN_INSTALLED`) | [Doc] https://developer.android.com/google/play/integrity/verdicts ; the rest [Unverified] |
| Samsung OTA | Not blocked by default. `setSystemUpdatePolicy` exists, but whether Samsung honours it is not verified | [Unverified] |
| Knox / Auto Blocker | Auto Blocker (on by default since One UI 6.1.1) **blocks USB commands and sideloading**. One UI 8.5 may turn it back on after 30 min. In the One UI 9 beta, "Maximum restrictions" blocks every USB connection. A single source claims that this mode disables device administration apps, **which would be critical for Watchpost** | [Press] https://www.androidauthority.com/samsung-one-ui-9-auto-blocker-update-3666893/ , https://www.samsung.com/us/support/answer/ANS10003636 |

---

## 3. DevicePolicyManager API: real capabilities and limits

### 3.1 Cross-cutting constraint: affiliation
Network logs, security logs and `setGlobalPrivateDns*` **fail (SecurityException) or are discarded as soon as a
non-affiliated user or profile exists** [AOSP Javadoc]. Since the DO already forbids clone, private and work
profiles, the only remaining risk is a secondary or guest user created by hand. It is blocked with
`DISALLOW_ADD_USER`.

### 3.2 Network logging
Documentation: `setNetworkLoggingEnabled` / `retrieveNetworkLogs` [AOSP Javadoc + `NetworkLoggingHandler`].
https://developer.android.com/reference/android/app/admin/DevicePolicyManager#setNetworkLoggingEnabled(android.content.ComponentName,%20boolean)

**Content**
- `DnsEvent`: `hostname`, `getInetAddresses()` (possibly a subset), `getTotalResolvedAddressCount()`, `packageName`,
  `timestamp`.
- `ConnectEvent`: `inetAddress`, `port`, `packageName`, `timestamp`.

**Coverage**
- Only `getaddrinfo()`/`gethostbyname()` and `connect()` calls going through libc or netd are logged.
- **Not seen**:
  - UDP without `connect()` (QUIC, games…);
  - hard-coded IPs;
  - application-level DoH;
  - an alternative libc or direct kernel calls.
- The documentation itself points to always-on VPN for an L3 capture.

**Volume and pace**
- Batches of **at most 1200 events**, finalised at 1200 events or after **1 h 30** at the latest.
- At most 5 batches pending. A retrieved batch is discarded after 5 min.
- Retrieval through the callback `DeviceAdminReceiver.onNetworkLogsAvailable(batchToken)`. For testing:
  `adb shell dpm force-network-logs`.

**Notification**
- The system shows a "network monitored" notification at most **2 times** in total, at most once per 24 h
  (`DEF_MAXIMUM_NETWORK_LOGGING_NOTIFICATIONS_SHOWN = 2`).
- The footer of the quick settings then permanently shows "your organization may monitor traffic".

### 3.3 Security logging
- `setSecurityLoggingEnabled`, `retrieveSecurityLogs`, `retrievePreRebootSecurityLogs`.
- `retrievePreRebootSecurityLogs`: "not supported on all devices", returns `null` in that case. Samsung support
  [Unverified].
- **Pace**: the system polls logd every minute. The DO is notified at 1024 entries or every **2 h**, with a
  reminder every 30 min. Buffer of 10,240 entries; the oldest are lost beyond that [AOSP `SecurityLogMonitor`].
  For testing: `adb shell dpm force-security-logs`.
- **Public tags available** [AOSP `SecurityLog.java`], grouped by domain:
  - ADB: `ADB_SHELL_INTERACTIVE`, `ADB_SHELL_CMD`, `SYNC_RECV_FILE`, `SYNC_SEND_FILE`;
  - processes: `APP_PROCESS_START` (with the APK hash, **reserved to the DO**);
  - lock: `KEYGUARD_DISMISSED`, `KEYGUARD_DISMISS_AUTH_ATTEMPT`, `KEYGUARD_SECURED`, `KEYGUARD_DISABLED_FEATURES_SET`;
  - boot and logging: `OS_STARTUP`, `OS_SHUTDOWN`, `LOGGING_STARTED`, `LOGGING_STOPPED`, `LOG_BUFFER_SIZE_CRITICAL`;
  - storage: `MEDIA_MOUNT`, `MEDIA_UNMOUNT`;
  - passwords: `PASSWORD_EXPIRATION_SET`, `PASSWORD_COMPLEXITY_SET`, `PASSWORD_HISTORY_LENGTH_SET`,
    `MAX_SCREEN_LOCK_TIMEOUT_SET`, `MAX_PASSWORD_ATTEMPTS_SET`, `PASSWORD_COMPLEXITY_REQUIRED`, `PASSWORD_CHANGED`;
  - administration: `REMOTE_LOCK`, `WIPE_FAILURE`, `USER_RESTRICTION_ADDED`, `USER_RESTRICTION_REMOVED`,
    `CAMERA_POLICY_SET`, `BACKUP_SERVICE_TOGGLED`;
  - keys and certificates: `KEY_GENERATED`, `KEY_IMPORT`, `KEY_DESTRUCTION`, `KEY_INTEGRITY_VIOLATION`,
    `CERT_AUTHORITY_INSTALLED`, `CERT_AUTHORITY_REMOVED`, `CERT_VALIDATION_FAILURE`, `CRYPTO_SELF_TEST_COMPLETED`;
  - radios: `WIFI_CONNECTION`, `WIFI_DISCONNECTION`, `BLUETOOTH_CONNECTION`, `BLUETOOTH_DISCONNECTION`,
    `NFC_ENABLED`, `NFC_DISABLED` (this pair is behind a feature flag);
  - packages: `PACKAGE_INSTALLED`, `PACKAGE_UPDATED`, `PACKAGE_UNINSTALLED`.
  - Possible additions in Android 17 are not verified.
- The "audit log" (`setAuditLogEnabled`) is a system API, inaccessible.

### 3.4 Private DNS
- `setGlobalPrivateDnsModeSpecifiedHost(admin, host)` [AOSP Javadoc]:
  - **blocking**, because it performs a connectivity test towards the resolver: annotated `@WorkerThread`, **to be
    called off the main thread**;
  - returns `PRIVATE_DNS_SET_NO_ERROR`, `…ERROR_FAILURE_SETTING` or `…ERROR_HOST_NOT_SERVING` (the server does not
    speak RFC 7858);
  - **fails in the presence of non-affiliated users**;
  - with a VPN, the resolver must be reachable both inside and outside the VPN.
- User-side lock: `addUserRestriction(DISALLOW_CONFIG_PRIVATE_DNS)` (DO only, global scope).
- `setGlobalSetting(PRIVATE_DNS_MODE / PRIVATE_DNS_SPECIFIER)` is also in the allowlist, but without validation:
  prefer the dedicated API.

### 3.5 Always-on VPN
- `setAlwaysOnVpnPackage(admin, pkg, lockdown[, allowlist])`. The VPN must declare a `VpnService` protected by
  `BIND_VPN_SERVICE` and must not refuse always-on. Lockdown cuts the whole network if the VPN goes down [AOSP
  Javadoc].
- A local VPN in the style of NetGuard or RethinkDNS inside Watchpost would give per-app attribution of **all**
  flows, including UDP and hard-coded IPs, through `ConnectivityManager.getConnectionOwnerUid` (reserved to the
  active VPN app).
- Limit: only one VPN at a time on the device.

### 3.6 Disabling packages: hide, suspend, enable
- **`setApplicationHidden`**: very permissive [AOSP `PackageManagerService`]. It refuses only:
  - apps with an active admin;
  - the `android` package;
  - SDK or static libraries;
  - "protected" packages.
  - **It therefore accepts the Play Store, GMS, the launcher, the dialer or SystemUI.** No platform safeguard:
    Watchpost must embed its own **deny list** (default launcher, SystemUI, phone, permission controller,
    Direct Boot keyboard, `kgclient`, etc.).
  - Hiding an app makes it unusable for the user, which amounts to disabling it.
- **`setPackagesSuspended`**: safer. It refuses [AOSP `SuspendPackageHelper.canSuspendPackageForUser`]:
  - apps with an active admin and the `android` package;
  - the active launcher;
  - the required installer, uninstaller and **verifier** packages (on GMS, the verifier is in principle the Play
    Store [Unverified]);
  - the **default dialer** and the **permission controller**;
  - protected packages and those marked `OP_SYSTEM_EXEMPT_FROM_SUSPENSION`;
  - SDK or static libraries.
  - The suspended app stays visible, greyed out.
  - Both APIs go through a `listPolicyExemptApps` list defined by the OEM. Its content on Samsung is not verified.
- **`enableSystemApp`** serves only to **re-enable** a system app disabled by default, not to disable.
- **`setUserControlDisabledPackages([watchpost])`**: the user can no longer force-stop or clear data, and the app is
  **exempt from App Standby Buckets** [AOSP Javadoc]. **To be applied to Watchpost.** Complement with
  `setUninstallBlocked`.

### 3.7 Runtime permissions
Source: `setPermissionGrantState` [AOSP Javadoc + code].
- The DO can grant or deny any *runtime* permission of any app, **including system or privileged apps**: for an
  admin targeting Q+, a denial on a pre-M app sets the app-op to `IGNORED`. Unverified special case: permissions
  marked `SYSTEM_FIXED` are probably refused by the PermissionController.
- **Sensor permissions** (fine, background and approximate location, camera, microphone, activity recognition,
  body sensors): a DO provisioned through ADB can **grant** them, including to itself, which covers
  `ACCESS_FINE_LOCATION` and `ACCESS_BACKGROUND_LOCATION`. If granting is forbidden, the call throws a
  `SecurityException` when the DO targets API 35+.
- `DENIED` locks the permission in the interface. `DEFAULT` hands control back to the user without revoking.
- Only *runtime* permissions are concerned: no special app-ops (usage access, overlay, notification listener).

### 3.8 Useful user restrictions (`addUserRestriction`)
List verified in `UserManager` [AOSP]:

**Security and privacy**
- `DISALLOW_CELLULAR_2G`: DO only, global scope; emergency calls remain possible.
- `DISALLOW_CONFIG_PRIVATE_DNS`
- `DISALLOW_INSTALL_UNKNOWN_SOURCES_GLOBALLY`
- `DISALLOW_ADD_USER`
- `DISALLOW_CONFIG_VPN`
- `DISALLOW_CONFIG_CREDENTIALS`: prevents adding user CAs.
- `DISALLOW_USB_FILE_TRANSFER`
- `DISALLOW_SAFE_BOOT`
- `DISALLOW_FACTORY_RESET`: optional.
- `DISALLOW_CONTENT_CAPTURE`, `DISALLOW_CONTENT_SUGGESTIONS`, `DISALLOW_ASSIST_CONTENT`: cut the flows to AI or the
  Assistant.
- `DISALLOW_SIM_GLOBALLY`: blocks eSIM download.
- `DISALLOW_ULTRA_WIDEBAND_RADIO`, `DISALLOW_NEAR_FIELD_COMMUNICATION_RADIO`, `DISALLOW_THREAD_NETWORK`
- `DISALLOW_BLUETOOTH_SHARING`
- `DISALLOW_SHARE_LOCATION`
- `DISALLOW_AUTOFILL`

**Do NOT set**:
- `DISALLOW_DEBUGGING_FEATURES`, which cuts ADB and therefore the escape hatch;
- `setUsbDataSignalingEnabled(false)`, which also disables USB debugging [Doc]
  https://source.android.com/docs/core/interaction/accessories/disable-signaling. In addition, USB HAL support is
  not verified on every Galaxy model: call `canUsbDataSignalingBeDisabled()` first.
- `DISALLOW_OEM_UNLOCK` is a system API, inaccessible.

### 3.9 Settings (`setGlobalSetting`, `setSecureSetting`, `setSystemSetting`)
Allowlist [AOSP]:
- **Global**: `ADB_ENABLED`, `ADB_WIFI_ENABLED`, `AUTO_TIME`, `AUTO_TIME_ZONE`, `DATA_ROAMING`,
  `USB_MASS_STORAGE_ENABLED`, `WIFI_SLEEP_POLICY`, `STAY_ON_WHILE_PLUGGED_IN`, `WIFI_DEVICE_OWNER_CONFIGS_LOCKDOWN`,
  `PRIVATE_DNS_MODE`, `PRIVATE_DNS_SPECIFIER`. Any other key throws a `SecurityException`; obsolete keys are
  ignored.
- **Secure** (DO): `DEFAULT_INPUT_METHOD`, `SKIP_FIRST_USE_HINTS`, `INSTALL_NON_MARKET_APPS`, `LOCATION_MODE`.
- **System**: `SCREEN_BRIGHTNESS`, `SCREEN_BRIGHTNESS_MODE`, `SCREEN_OFF_TIMEOUT`.
- For other keys, `WRITE_SECURE_SETTINGS` granted through ADB is needed (§4).

### 3.10 Other APIs
- **`getInstalledCaCerts(admin)`**: returns the trusted CAs other than system CAs, including those added by the
  user [not re-checked word for word]. To be logged, together with the `CERT_AUTHORITY_*` events.
- **`setMtePolicy`**: a DO can force MTE on, which takes effect at reboot, or throw
  `UnsupportedOperationException` if the hardware does not support it [AOSP Javadoc]. MTE support on Galaxy
  devices is **uncertain**: one article says it arrives with One UI 9 [Press]
  https://www.webpronews.com/samsungs-quiet-security-bet-memory-tagging-extension-is-coming-to-one-ui-9-and-it-could-rewrite-androids-defense-playbook/.
  To be tested with exception handling.
- **`setSystemUpdatePolicy`**: exists; whether Samsung FOTA honours it is not verified.
- **`setPersonalAppsSuspended`**: **not relevant**, reserved to the PO of a work profile on a company-owned device
  (COPE).
- **`setAppFunctionsPolicy(APP_FUNCTIONS_DISABLED)`** (A16+) and **`setNearbyAppStreamingPolicy`** (A17, cuts
  automation by AI agents): useful on the privacy side [Doc] https://developer.android.com/work/versions/android-17
- **`setContentProtectionPolicy`**: controls the scan for deceptive apps [AOSP].
- **`setAutoTimePolicy` / `setAutoTimeZonePolicy`** (A16) [Doc] https://developer.android.com/work/versions/android-16
- **Advanced Protection**. `AdvancedProtectionManager` (API 36) is limited, in its public surface, to:
  - `isAdvancedProtectionEnabled()`;
  - `registerAdvancedProtectionCallback()`.
  - Permission `QUERY_ADVANCED_PROTECTION_MODE`, **normal** level [Doc+AOSP]
    https://developer.android.com/reference/android/security/advancedprotection/AdvancedProtectionManager
  - Watchpost can therefore **observe** the mode, not enable it. On One UI 8 it is found under Settings > Google >
    All services > Advanced Protection [Press] https://www.sammobile.com/news/android-16-one-ui-8-protect-galaxy-phone/
  - An enterprise policy to enforce Advanced Protection is announced "later in 2026" with Android 17 [Press,
    unverified].
  - **Intrusion logging**: end-to-end encrypted logs in the Google cloud, tied to the Google account, managed by the
    OS. **No public API** to read them [Press] https://thehackernews.com/2026/05/android-adds-intrusion-logging-for.html

---

## 4. Permissions that ADB can grant to a third-party app

Protection levels read in `core/res/AndroidManifest.xml` [AOSP]
https://github.com/aosp-mirror/platform_frameworks_base/blob/main/core/res/AndroidManifest.xml. **Only permissions
carrying the `development` (or `appop`) flag can be granted with `pm grant`.**

| Permission | Level | `pm grant`? | What it really unlocks |
|---|---|---|---|
| `READ_LOGS` | signature\|privileged\|**development** | Yes | Since Android 13, `LogcatManagerService` requires **consent at every access**: a dialog if the app is in the foreground (`PROCESS_STATE_TOP`), **automatic refusal in the background**, grant valid for 60 s [AOSP `LogcatManagerService.java`]. No DO exemption in the code. A `logcat` stream opened while the app is in the foreground might continue in the background [Unverified]. **Unusable for reliable continuous collection.** |
| `DUMP` | signature\|privileged\|**development** | Yes | `android.os.Debug.dumpService(name, fd, args)` (public API) on services reachable by SELinux from `untrusted_app`, e.g. `appops`, `activity`, `package`, `connectivity` [Unverified on One UI 9]. Running the `dumpsys` binary will probably not work: `servicemanager` listing denied by SELinux [Unverified]. Interesting lead: `dumpService("appops")` gives the history of microphone, camera and location accesses per app. |
| `WRITE_SECURE_SETTINGS` | …\|**development**\|role\|installer | Yes | Writing to the Global and Secure tables, e.g. `private_dns_*`, `wifi_scan_throttle_enabled`, `adb_enabled`. Since `targetSdk 31`, **reading** keys that are not `@Readable` is blocked [not re-checked]. |
| `PACKAGE_USAGE_STATS` | …\|**development**\|**appop**\|retailDemo | Yes, then `appops set <pkg> GET_USAGE_STATS allow` | `UsageStatsManager.queryEvents`; `NetworkStatsManager` for all UIDs of the user. The DO has access to the network stats of all users anyway [Doc] https://developer.android.com/reference/android/app/usage/NetworkStatsManager |
| `BATTERY_STATS` | signature\|privileged\|**development** | Yes | `BatteryStatsManager` and `dumpService("batterystats")` (the latter also requires DUMP) [Unverified] |
| `GET_APP_OPS_STATS` | signature\|privileged\|**development** | Yes | The APIs that use it (`getPackagesForOps`, `getHistoricalOps`) are **@SystemApi** and blocked by the hidden-API restrictions. Of little use alone; go through `DUMP` + `dumpService("appops")`. |
| `INTERACT_ACROSS_USERS` | …\|**development**\|role | Yes | Of little use: a single user under a DO |
| `WATCH_APPOPS` | signature\|privileged | **No** | `startWatchingActive` therefore sees only **its own UID** [AOSP AppOpsManager] |
| `READ_PRIVILEGED_PHONE_STATE`, `READ_NETWORK_USAGE_HISTORY`, `LOCAL_MAC_ADDRESS`, `CONTROL_VPN`, `REAL_GET_TASKS`, `CHANGE_DEVICE_IDLE_TEMP_WHITELIST` | signature\|privileged | **No** | — |

**Other useful ADB commands** [Community / not re-checked for One UI 9]:
- `adb shell cmd notification allow_listener <pkg>/<Service>` enables a `NotificationListenerService`, bypassing the
  "restricted settings" of sideloaded apps.
  - **Since Android 15, OTPs are masked** for "untrusted" listeners [Doc]
    https://developer.android.com/about/versions/15/behavior-changes-all
  - **To be avoided in the DO APK**: Play Protect trigger, see §2.4 and §9.
- `adb shell dumpsys deviceidle whitelist +<pkg>` exempts from Doze. For an app targeting 34+,
  `REQUEST_IGNORE_BATTERY_OPTIMIZATIONS` + dialog does the equivalent.

**What the DO gets automatically**
- Exemption from the background FGS start restrictions, **and** from the "while-in-use" restrictions for location,
  camera and microphone FGS [Doc] https://developer.android.com/develop/background-work/services/fgs/restrictions-bg-start
- App Standby bucket `EXEMPTED` (`AppStandbyController`) and `REASON_DEVICE_OWNER` exemption in
  `AppRestrictionController` [AOSP].
- `NetworkStats` access to all UIDs [Doc].
- Control of runtime permissions (§3.7) and silent installation through `PackageInstaller`, useful for Watchpost's
  **self-updates** [not re-checked].

---

## 5. Continuous collection

### Foreground services
- **Suitable types**:
  - `location`, with `ACCESS_BACKGROUND_LOCATION` granted by the DO;
  - `specialUse`, with the property `PROPERTY_SPECIAL_USE_FGS_SUBTYPE` and a justification; no duration limit is
    documented;
  - `connectedDevice` (BLE), if relevant.
- **Avoid `dataSync`**:
  - **6 h cumulative per 24 h** when the app is in the background (A15+, `targetSdk ≥ 35`);
  - `onTimeout()` followed by a mandatory `stopSelf()`;
  - the counter resets only if the app comes to the foreground [Doc]
    https://developer.android.com/develop/background-work/services/fgs/timeout
- **Start at boot**:
  - a `BOOT_COMPLETED` receiver **cannot** launch the FGS types `dataSync`, `camera`, `mediaPlayback`,
    `phoneCall`, `mediaProjection` or `microphone` [Doc]
    https://developer.android.com/about/versions/15/behavior-changes-15
  - `location` and `specialUse` remain allowed. With the DO's "while-in-use" exemption, a `location` FGS can start
    from boot [Doc, combination not tested].
- **Direct Boot**: `LOCKED_BOOT_COMPLETED` allows starting before the first unlock, with
  `android:directBootAware="true"` and *device-protected* storage. Authentication-bound Keystore keys and
  *credential-protected* data remain unavailable until unlock.
- **Android 15+ (all apps)**:
  - a "force stop" cancels all `PendingIntent`s. The DO prevents it through `setUserControlDisabledPackages`;
  - **network requests made outside a valid lifecycle fail**: do uploads from the FGS or from WorkManager [Doc].
- **Android 17**: memory limiter, reason `MemoryLimiter:AnonSwap` in `ApplicationExitInfo`. Keep the service lean.

### Location without Play Services
- `LocationManager` exposes `GPS_PROVIDER`, `NETWORK_PROVIDER`, `PASSIVE_PROVIDER` and, since API 31,
  `FUSED_PROVIDER` [Doc] https://developer.android.com/reference/android/location/LocationManager
- **On a GMS device, the "network" and very probably the "fused" providers are implemented by Google Play
  Services** (overlays `config_enableNetworkLocationOverlay` and `config_enableFusedLocationOverlay`). They work
  only if "Google Location Accuracy" is on, and they then send Wi-Fi and cell scans to Google [Unverified on One UI
  9].
  - For an anti-tracking profile: **use `GPS_PROVIDER` + `PASSIVE_PROVIDER`**, and turn off Google location
    accuracy.
- On Qualcomm-based Galaxy devices, the GNSS uses **Qualcomm XTRA** assistance (`xtrapath{1,2,3}.izatcloud.net`,
  collection of technical identifiers according to Kaspersky and Nitrokey) and SUPL (`supl.google.com` by default,
  or a carrier server). SUPL sends the IMSI and the position [Press]
  https://www.kaspersky.com/blog/gps-agps-supl-tracking-protection/48175/
  - Blocking XTRA and SUPL greatly increases TTFF: a trade-off to expose in the UI.
- `GnssStatus.Callback` (constellations, C/N0) and `GnssMeasurementsEvent` (raw measurements, API 24+) are public,
  with `ACCESS_FINE_LOCATION`. Useful to detect GNSS **jamming or spoofing** (C/N0 drop, clock jumps, AGC).

### Samsung sleep management
- Lists of "sleeping apps", "deep sleeping apps" (after 16 days without use according to Samsung) and "never
  sleeping apps" [Press] https://www.guidingtech.com/how-to-manage-sleeping-apps-on-samsung-galaxy-phone
- Samsung states that, since One UI 6, FGS that comply with the Android 14 types "work as expected" [search excerpt
  from developer.samsung.com/mobile/app-management.html, not directly readable].
- **Countermeasures**:
  - typed FGS;
  - `setUserControlDisabledPackages` (standby exemption);
  - Doze exemption;
  - manually adding Watchpost to "Never sleeping apps". **No known API for the latter: document the procedure.**
  - The exemption from Samsung Device care for a DO is **not verified**.
- **Restart after a kill**: `START_STICKY`; exact watchdog alarm (`SCHEDULE_EXACT_ALARM`, grantable through
  `appops`/ADB); `BOOT_COMPLETED`, `LOCKED_BOOT_COMPLETED` and `MY_PACKAGE_REPLACED` receivers; periodic WorkManager
  (15 min) as a safety net.

---

## 6. Detecting other apps' use of sensors (without system privilege)

| Mechanism | What you get | Limit | Source |
|---|---|---|---|
| `CameraManager.AvailabilityCallback` | `onCameraUnavailable(id)` / `onCameraAvailable(id)` at every opening or closing, by any app; no permission | **Not the package**: `onCameraOpened(id, pkg)` is a system API | [Doc] https://developer.android.com/reference/android/hardware/camera2/CameraManager.AvailabilityCallback |
| `AudioManager.registerAudioRecordingCallback` / `getActiveRecordingConfigurations` | Audio source, format, device, session, `isClientSilenced()` | **No UID or package** in the public API | [Doc] https://developer.android.com/reference/android/media/AudioRecordingConfiguration |
| `AppOpsManager.startWatchingActive` | — | Without `WATCH_APPOPS` (not grantable), sees only its own UID | [AOSP] |
| `DUMP` + `Debug.dumpService("appops")` | Current state and last accesses for CAMERA, RECORD_AUDIO, FINE_LOCATION per package | Unstable text format, must be parsed; SELinux to be checked | [Unverified] |
| Correlation | `UsageStatsManager.queryEvents` (app in the foreground, FGS start and stop) **cross-referenced** with the camera and microphone callbacks | Probabilistic attribution | [Doc] |
| `NetworkStatsManager` per UID | Volumes per app (buckets of about 2 h) | DO: all users | [Doc] |
| `TelephonyManager.getAllCellInfo` / `requestCellInfoUpdate`, `TelephonyCallback` (CellInfo, ServiceState, DisplayInfo) | Technology (GSM/LTE/NR), cell identifiers, signal; detection of a **2G downgrade** and of abnormal LAC/TAC changes | `ACCESS_FINE_LOCATION` + `READ_PHONE_STATE` | [Doc, not re-checked] |
| Cellular network transparency (A15/16: null-cipher and identifier-disclosure notifications) | — | **System API** (`MODIFY_PHONE_STATE`, `READ_PRIVILEGED_PHONE_STATE`), modem and OEM HAL required, absent even on Pixel at the launch of A15; Samsung support unknown. Effective DO-side measure: **`DISALLOW_CELLULAR_2G`** | [Press] https://www.androidauthority.com/android-16-mobile-network-security-3571497 |
| Wi-Fi scans | Foreground: 4 scans / 2 min; **background: 1 scan / 30 min (all apps combined)**. Passive listening to `SCAN_RESULTS_AVAILABLE_ACTION` is possible (scans by other apps). Developer option "Wi-Fi scan throttling"; the Global key can be modified with `WRITE_SECURE_SETTINGS` [Unverified]. Requires `ACCESS_FINE_LOCATION` and location turned on | — | [Doc] https://developer.android.com/develop/connectivity/wifi/wifi-scan |
| BLE scans (AirTag, SmartTag, Tile trackers) | `BluetoothLeScanner` with a **mandatory `ScanFilter`**, because unfiltered scans are suspended with the screen off. Limit of about 5 `startScan` per 30 s. Filter on manufacturer data (Apple 0x004C, Samsung 0x0075…). Reference project: AirGuard (open source) | — | [not re-checked] |

---

## 7. Debloating: Google and Samsung packages

Main source: `uad_lists.json` from **Universal Android Debloater NG**, branch `main`, downloaded on 2026-11-15:
https://raw.githubusercontent.com/Universal-Debloater-Alliance/universal-android-debloater-next-generation/main/resources/assets/uad_lists.json.
The levels in square brackets are those of UAD-NG. Their actual presence on a given device under One UI 9 **remains
to be verified** with `pm list packages`.

Method on the Watchpost side: `setApplicationHidden` (reversible), or `setPackagesSuspended` when the icon should
stay visible.

### 7.1 "Balanced" profile (Play Services, Play Store, FCM and banking apps untouched)

**Samsung, telemetry and advertising**
- `com.samsung.android.rubin.app` [Recommended]: Customization Service, advertising profiling.
- `com.samsung.android.knox.analytics.uploader` [Recommended]
- `com.samsung.android.dsms` [Recommended]: hidden diagmon component.
- `com.samsung.android.dqagent` [Advanced]: Device Quality Agent.
- `com.sec.android.diagmonagent` [Advanced]: **do not disable**, UAD reports a restart loop that makes the device
  hot and drains the battery. Turn off "Send diagnostic data" in the settings instead.
- `com.samsung.android.svcagent` [Recommended]: contains the DiagMon library.
- Log collection: `com.samsung.carrier.logcollector` [Recommended], `com.sec.android.CcInfo` [Recommended],
  `com.samsung.logwriter` [Recommended].
- `com.samsung.attribution` [Recommended]
- `com.samsung.android.deviceidservice` [Recommended]: OAID/AAID.
- `com.samsung.android.peripheral.framework` [Recommended]: Knox analytics, according to UAD.
- `com.samsung.android.mocca` [Recommended]
- `com.samsung.sait.sohservice` [Recommended]
- Advertising and recommendations: `com.samsung.android.mfi` (Galaxy Widget) [Recommended],
  `com.samsung.android.app.omcagent` [Recommended], `com.samsung.android.mapsagent` [Recommended]
- `com.samsung.android.ipsgeofence` [Recommended]: indoor geofencing.
- Network diagnostics: `com.samsung.android.networkdiagnostic` [Recommended],
  `com.samsung.android.wifinetworkdiagnostics` [Recommended], `com.samsung.qosindicator` [Recommended].
- Bixby, optional (convenience): `com.samsung.android.bixby.agent`, `…bixby.wakeup`, `…bixby.service`,
  `…visionintelligence`, `com.samsung.android.app.spage` [Recommended].
- `com.samsung.android.app.tips` [Recommended]
- `com.samsung.android.smartsuggestions` [Recommended]

**Google, advertising and personalisation**
- `com.google.android.adservices.api` [Recommended]: Privacy Sandbox, mainline module. Also disable the "Ad privacy"
  options.
- `com.google.android.ondevicepersonalization.services` [Recommended]
- `com.google.android.federatedcompute` [Recommended]
- `com.google.android.feedback` [Recommended]
- `com.google.android.partnersetup` [Advanced]
- `com.google.android.gms.location.history` [Recommended]: stub.
- Optional: `com.google.android.as` [Recommended], which breaks Live Caption and Smart Reply;
  `com.google.android.apps.bard` (Gemini) [Recommended].

**To keep** in this profile:
- `com.google.android.gms`, `com.android.vending`, `com.google.android.gsf`;
- `com.osp.app.signin`;
- `com.samsung.android.fmm` (anti-theft);
- `com.samsung.android.securitylogagent`: monitors changes to `/system`. **Useful to Watchpost, do not disable
  despite [Recommended].**

### 7.2 "Strict" profile (thorough de-Googling and de-Samsungising)
The following are added:

**Google**
- `com.google.android.gms` [Expert], `com.google.android.gsf` [Expert], `com.android.vending` [Expert].
- **What breaks**: FCM push notifications (messengers, banks), the Play Store and its updates, Google Wallet,
  **most banking apps** (Play Integrity), Find My Device, the Google account, Play System and SafetyCore updates,
  backup. According to UAD, bootloop risk on some devices.
- `com.google.android.googlequicksearchbox` [Advanced]: breaks Circle to Search.

**Samsung**
- `com.osp.app.signin` [Advanced]: Samsung account; breaks Galaxy Store, Samsung Cloud and Find My Mobile.
- `com.samsung.android.scloud` [Recommended]
- `com.samsung.android.mobileservice` [Advanced]
- `com.sec.spp.push` [Recommended]
- `com.samsung.android.fmm` [Recommended]: **loss of the anti-theft feature**.
- Payment: `com.samsung.android.spay`, `com.samsung.android.spayfw`, `com.samsung.android.samsungpass`,
  `com.samsung.android.authfw` [Recommended].
- `com.sec.android.app.samsungapps` [Expert]: Galaxy Store, required by Samsung Pay.
- `com.samsung.android.app.updatecenter` [Recommended]
- `com.samsung.android.scs` [Advanced]: breaks search and OCR in Samsung apps.
- `com.samsung.android.lool` (Device care) [Advanced] and `com.samsung.android.sm.devicesecurity` (McAfee engine)
  [Advanced].
- `com.samsung.klmsagent` [Advanced]: Knox licences, which would prevent a later Knox SDK integration.
- `com.samsung.android.knox.attestation` [Recommended]: may break Samsung Wallet or banks [Unverified].

### 7.3 Never touch (both profiles)
- `com.samsung.android.kgclient` [**Unsafe**]: **persistent full-screen lock until a factory reset**.
- `com.samsung.android.sm.policy` [Unsafe]
- `com.sec.android.soagent` and `com.wssyncmldm` [Expert]: **Samsung OTA**.
- `com.samsung.android.cidmanager` [Expert]
- `com.samsung.android.gru` [Expert]
- `com.samsung.android.honeyboard` [Expert]: keyboard; the only keyboard available in Direct Boot.
- `com.samsung.android.wifi.softap.resources` [Unsafe]
- `com.google.android.rkpdapp` [Unsafe]: Remote Key Provisioning. Used for attestation, therefore for **Play
  Integrity** [Unverified].
- `com.google.android.ext.services`, `com.google.android.networkstack`, `com.google.android.permissioncontroller`
  [Unsafe]
- `com.google.android.configupdater` [Expert]: TLS pins, intent firewall.
- `com.google.android.webview` [Expert]
- `com.samsung.android.app.routines` [Expert]
- Plus the launcher, SystemUI, the phone and Settings (safeguard §3.6).

### 7.4 DNS domains

**Maintained public lists** (raw URLs):
- HaGeZi "Native Tracker Samsung": 201 domains on 2026-11-13.
  - Wildcard: https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/native.samsung-onlydomains.txt
  - Adblock: https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/native.samsung.txt
  - **HaGeZi has no "native Google" list.**
- HaGeZi Pro: 237,247 entries on 2026-11-15. https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/pro-onlydomains.txt
- Perflyst android-tracking: 112 lines. https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/android-tracking.txt

**To block (balanced)**, presence verified in these lists:
- Google, Firebase and advertising: `app-measurement.com`, `google-analytics.com`, `ssl.google-analytics.com`,
  `googlesyndication.com`, `www.googleadservices.com`, `googleads.g.doubleclick.net`, `crashlytics.com` (and `e.`,
  `reports.`, `settings.`), `firebaselogging-pa.googleapis.com`, `federatedml-pa.googleapis.com` (Perflyst).
- Samsung: `samsungads.com`, `samsungadhub.com`, `dc.dqa.samsung.com`, `dls-udc.dqa.samsung.com`,
  `diagmon-policy.samsungdm.com`, `diagmon-serviceapi.samsungdm.com`, `report.gras.samsungdm.com`,
  `analytics.samsungknox.com`, `nmetrics.samsungmobile.com`, `stats.samsungpass.com`,
  `api.runestone.samsung.com` (Customization Service), `smetrics.samsung.com`,
  `devicelog.samsungcloudsolution.net`.

**Do NOT block in balanced** (absent from HaGeZi Pro, verified for those marked ✓):
- FCM: `mtalk.google.com` ✓, `mtalk4.google.com`, `alt*-mtalk.google.com`, ports 5228-5230;
  `android.googleapis.com`, `fcmtoken.googleapis.com`, `firebaseinstallations.googleapis.com` ✓ [list not
  re-checked against the FCM documentation].
- Play Store and authentication: `play.googleapis.com` ✓, `play-fe.googleapis.com`, `android.clients.google.com`,
  `accounts.google.com`, `www.googleapis.com`.
- Connectivity check: `connectivitycheck.gstatic.com` ✓, `www.google.com/generate_204`. The exact URLs used by
  Samsung are not verified.
- Time: `time.android.com` [Unverified for Samsung].
- A-GPS: `supl.google.com` ✓, `xtrapath1-3.izatcloud.net` ✓ (except by deliberate choice, see §5).
- **Samsung FOTA**: `*.ospserver.net` ✓ (e.g. `fota-cloud-dn.ospserver.net`, `fota-s3-dn.ospserver.net`) and
  `*.samsungdm.com` except the diagmon and gras sub-domains.
  - Blocking `ospserver.net` prevents updates [Community]
    https://discourse.pi-hole.net/t/samsung-galaxy-wont-update/74704 ,
    https://eu.community.samsung.com/t5/samsung-lounge/security-issue-on-updates/td-p/11273721
- **Conflict**: HaGeZi Pro blocks `gld.samsungosp.com`, while Samsung account services go through
  `*.samsungosp.com`. To be watched in the logs.
- **Structural limit**: part of the GMS telemetry goes through shared domains (`play.googleapis.com`,
  `www.googleapis.com`). **DNS cannot filter it without breaking the Play Store** [not verified in detail]. Only
  the strict profile (disabling GMS) removes it.

---

## 8. Knox SDK

**Benefits for an individual**
- Per-app firewall with domain filtering and **logs of blocked domains with the package** [Press/Knox]
  https://docs.samsungknox.com/admin/fundamentals/whitepaper/samsung-knox-mobile-security/network-security/knox-firewall/
- Knox audit log (`com.samsung.android.knox.log`).
- Additional OEM controls.

**Licence**
- The KPE Premium key is **free** and covers the Standard functions. Validity of 2 years. Since portal release
  26.07, Standard keys can no longer be generated [Press/Knox] https://docs.samsungknox.com/dev/knox-sdk/faq/licensing/
- **But**: developer keys now require a **ticket to the Knox Partner Program with a "business use case"**, and
  generating them is reserved to KPP partner accounts. Adhell3 can no longer be activated without an existing key
  [Community] https://github.com/hklcf/Adhell3 ,
  https://docs.samsungknox.com/dev/knox-sdk/kbas/kba-1227-license-keys-page-unavailable-from-the-knox-developer-portal
- Since Android 15 (Knox 3.11), many Knox APIs are limited to DOs and POs, which does not affect Watchpost.
- Deprecation policy: 1 year of support, then removal possible at 2 years.
- Licence activation contacts Samsung servers (KLM), which contradicts the anti-tracking goal.

**Conclusion: do not integrate.**
- Per-app firewall: a local VPN (§3.5) does better, without a licence.
- The rest is covered by the AOSP APIs (DO).
- To be reconsidered later only if a KPE key is obtained.

---

## 9. Risks

**Play Protect**
- The **DPC + NotificationListener + SMS** combination has already got custom DPCs blocked [Community, §2.4].
- *Live Threat Detection* (on-device behavioural analysis, extended to Android 17) targets, according to Google:
  - apps that **hide or change their icon** and then launch in the background;
  - **accessibility** abuse;
  - SMS forwarding;
  - overlays [Press] https://blog.google/security/whats-new-in-android-security-privacy-2026/
- **Watchpost must therefore:**
  - keep a permanent icon and notification;
  - request no SMS, accessibility or overlay permission;
  - isolate any notification collector in a **separate, optional APK**;
  - keep an explicit name and description.
- It is possible to appeal Play Protect classifications.

**Developer verification (sideloading)**
- Mandatory in Brazil, Indonesia, Singapore and Thailand since 09/2026, then worldwide in "2027 and after". No EU
  date.
- "Limited distribution" accounts (hobbyists, 20 devices, no identity document, free) exist.
- Installation through ADB remains a route for unverified apps [Press/Doc]
  https://support.google.com/android-developer-console/answer/16561738 , https://www.androidauthority.com/p-3679204/
- **To anticipate**: register the Watchpost signing key on a limited distribution account, or use ADB or silent
  updates through the DO.

**Play Integrity**
- The DO does not affect `MEETS_DEVICE_INTEGRITY`.
- `MEETS_STRONG_INTEGRITY` requires security patches less than one year old [Doc].
- With Play Protect disabled, `playProtectVerdict` is `POSSIBLE_RISK`. Some banks may refuse.
- Apps with accessibility or overlay produce `*_CAPTURING`/`*_CONTROLLING`: one more reason for Watchpost not to use
  them.

**Auto Blocker and Advanced Protection**
- They block USB commands and sideloading. A single source says that "Maximum restrictions" disables device
  administration apps.
- Advanced Protection also blocks USB and 2G.
- **Their interaction with a third-party DO must be tested before any deployment** [Unverified].

**Battery**
- Network and security logging: "low-overhead" [Doc].
- The costly items are continuous GPS, BLE and Wi-Fi scans, and frequent uploads.
- Recommendations: grouped uploads (batches of 15 min to 1 h, or at every network batch), GPS in passive mode or
  with a wide interval, filtered and occasional BLE scans.

---

## 10. Points to validate first on the device
1. `dpm set-device-owner` after removing the accounts, Secure Folder and Dual Messenger. Check `pm list users` and
   `dumpsys account`.
2. Coexistence with Auto Blocker (disabled during provisioning), then re-enabling it: does the DO survive?
3. `setGlobalPrivateDnsModeSpecifiedHost` towards the personal resolver. Reception of `onNetworkLogsAvailable` and
   `onSecurityLogsAvailable`. Is `retrievePreRebootSecurityLogs` different from `null`?
4. `canUsbDataSignalingBeDisabled()`, `setMtePolicy` (exception?), real effect of `DISALLOW_CELLULAR_2G` on
   One UI 9.
5. `Debug.dumpService("appops")` with `DUMP` granted (SELinux denial?).
6. Survival of the `location`/`specialUse` FGS after 24 h with the screen off and after a reboot, without manually
   adding it to "Never sleeping apps".
7. Samsung Wallet, Google Wallet and a banking app with the DO active.


## Erratum from the code review

- `pm unhide` requires `MANAGE_USERS`, which is absent from the AOSP manifest of the shell: it is **probably
  refused to the ADB shell**. Do not count on it to show a hidden package again after the Device Owner is
  removed; always "Restore everything" (or `rescue-revert --sweep`) **before** removing the role. To be verified
  on the device.
- `setGlobalPrivateDnsMode*` throws `SecurityException` as soon as a non-affiliated user exists (guest, Samsung
  maintenance mode). The agent falls back to `setGlobalSetting(private_dns_mode)`, which has no such condition.
