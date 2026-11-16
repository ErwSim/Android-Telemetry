# 02 — Build the APK

The Watchpost Agent is built on your PC (Windows, Linux or macOS). This guide installs the tools, creates the
**signing key** (to be kept for life), builds the APK and checks it. The technical reference remains
[`android/README.md`](../../android/README.md).

Time: 30 to 60 minutes, including the download of Gradle and the dependencies at the first build.
Next: [03 — the phone](03-phone.md).

> **Verification status.** The build `./gradlew lint test assembleDebug assembleRelease` succeeds in the development
> environment (Linux, JDK 21) and the release APK obtained was inspected (commands of section 6, run for this
> guide). **The build on Windows has never been run**, and neither have the PowerShell scripts.

## 1. What the project requires

| Item | Version | Remark |
|---|---|---|
| JDK | 17 minimum; 21 verified | also provided by Android Studio |
| Gradle | 9.9.1 | downloaded automatically by the wrapper (`gradlew`), nothing to install |
| Android Gradle Plugin (AGP) | 9.5.1 | Kotlin 2.4.21 built in; nothing to install |
| `compileSdk` / `targetSdk` / `minSdk` | 37 / 37 / 36 | **the phone must run Android 16 or later** (One UI 8 or later) |
| Android SDK | platform `android-37.0`, `build-tools;36.0.0`, `platform-tools` | |
| Internet access | yes, at the first build | Maven Central and Google |

The application package is `io.github.erwsim.watchpost`. You need no developer account, no Google Play and no
Firebase.

## 2. Install the tools

Two routes: **Android Studio** (graphical, installs the SDK for you) or the **command-line SDK** (lighter,
enough to build). Both work; the command line is the route described here.

### 2.1 Windows

1. **JDK**: install a JDK 17 or 21 (for example Temurin, <https://adoptium.net>), or use the one from Android
   Studio if you install it. Check, in a new PowerShell:

   ```powershell
   java -version
   keytool -help | Select-Object -First 1
   ```

   If `keytool` is not found, add the JDK's `bin` folder to the `PATH` (needed for the signing key) and set
   `JAVA_HOME` (the JDK folder, without `bin`).

2. **Android command-line tools**: download "Command line tools only" from
   <https://developer.android.com/studio#command-line-tools-only>. Unzip so that the result is
   `C:\Android\cmdline-tools\latest\bin\sdkmanager.bat` (the `latest` sub-folder is mandatory). Then:

   ```powershell
   [Environment]::SetEnvironmentVariable('ANDROID_HOME', 'C:\Android', 'User')
   $env:ANDROID_HOME = 'C:\Android'
   & 'C:\Android\cmdline-tools\latest\bin\sdkmanager.bat' --licenses
   & 'C:\Android\cmdline-tools\latest\bin\sdkmanager.bat' "platform-tools" "platforms;android-37.0" "build-tools;36.0.0"
   ```

   Accept the licences (`y`). `platform-tools` contains **`adb`**, which you will need in guide 03: add
   `C:\Android\platform-tools` to the `PATH` (Windows Settings, "environment variables"), then reopen PowerShell and
   check `adb version`.

   Android Studio variant: install it, open the repository's `android/` folder, let it synchronise; in the SDK
   Manager, tick Android SDK Platform 37.0, Build-Tools 36.0.0 and Platform-Tools. If Android Studio reports an
   incompatibility with Android Gradle Plugin 9.5.1, update it (compatibility not verified here).

3. **If Gradle cannot find the SDK** ("SDK location not found"): create `android\local.properties` with a line
   `sdk.dir=C\:\\Android` (`\` is written doubled and the `:` is preceded by a `\`). Android Studio creates this
   file by itself. It is not versioned.

4. **PowerShell scripts**: the repository's `.ps1` files are not signed and Windows refuses them under its default
   execution policy. Always run them like this, without changing the machine's configuration (the exemption applies
   only to that process):

   ```powershell
   powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\<name>.ps1 [options]
   ```

   This is the form given in all the guides. It is the one the scripts themselves document; it has never been run
   on Windows.

### 2.2 Linux and macOS

```bash
# JDK: install your distribution's package (for example openjdk-17-jdk or openjdk-21-jdk on Debian/Ubuntu,
# Temurin on macOS), then:
java -version && keytool -help | head -1

# Command-line SDK: download "Command line tools only"
# (https://developer.android.com/studio#command-line-tools-only), unzip it so that the result is
# ~/Android/Sdk/cmdline-tools/latest/bin/sdkmanager
export ANDROID_HOME=$HOME/Android/Sdk
"$ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager" --licenses
"$ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager" "platform-tools" "platforms;android-37.0" "build-tools;36.0.0"
export PATH="$ANDROID_HOME/platform-tools:$PATH"
adb version
```

Put the two `export` lines in your profile (`~/.bashrc`, `~/.zshrc`) to keep them. The `.sh` scripts are executable
in the repository (`./scripts/…`).

## 3. Clone the repository

```bash
git clone <repository address> watchpost
cd watchpost/android
```

The following commands are run from the `android/` folder (in PowerShell as in bash).

## 4. The signing key: create it once, keep it forever

### Why the signature must stay the same

Android accepts an update to an application only if it is signed by **the same key** as the installed version. For a
Device Owner application, **there is no workaround**: if you lose the key, the only way out is to remove the Device
Owner (which undoes the policy and means going through guide 03 again, with the accounts removed) or to reset the
phone. In both cases: no more updates as long as the original key is missing.

A debug APK (`assembleDebug`) is signed with a debug key specific to your PC; **never** install it on the phone you
use every day (its signature would be neither stable nor reproducible). Use only the *release* APK signed with your
key.

### Create the key

```bash
./scripts/generate-keystore.sh
```

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\generate-keystore.ps1
```

The script creates:

- `android/keystore/watchpost-release.jks`: the keystore (RSA 4096, valid for about 50 years, alias `watchpost`);
- `android/keystore.properties`: the password (random, 32 characters, or the one from the environment variable
  `WATCHPOST_KEYSTORE_PASSWORD`, 12 characters minimum) and the path, read by Gradle.

and prints the **SHA-256 fingerprint** of the signing certificate. Write it down: it is used to check the APK
(section 6). Both files are ignored by git (verified: `.gitignore` covers `*.jks` and `keystore.properties`). The
script **refuses to overwrite** an existing keystore; do not get around that.

### Back it up

Copy **together** `android/keystore/watchpost-release.jks` and `android/keystore.properties` (the password is in it
in clear text):

- into a password manager that accepts attachments, or onto a USB drive / disk that is **encrypted**;
- in at least **two** separate places, off this PC;
- never in a git repository, nor in an unencrypted cloud, nor on the VPS unencrypted.

Since the password is in `keystore.properties`, it is the encryption of the medium that protects the key. Also note
the fingerprint printed by the script. You can read it again at any time:

```bash
keytool -list -v -keystore keystore/watchpost-release.jks -alias watchpost
```

(the password is in `keystore.properties`). The signing key is **not** included in the server backups (guide 01).

## 5. Build

```bash
./gradlew assembleRelease
```

```powershell
.\gradlew.bat assembleRelease
```

The first run downloads Gradle 9.9.1 and then the dependencies; it can take several minutes (the repository's
configuration limits Gradle to 2 GB of memory and 2 processes: slow but safe; you can raise these values in
`android/gradle.properties`). Result:

```
android/app/build/outputs/apk/release/app-release.apk
```

Optional parameters (`-P…` on the command line):

| Parameter | Default | Purpose |
|---|---|---|
| `-Pwatchpost.versionCode=N` | `1` | integer, **to be increased at every update** (otherwise Android refuses: `VERSION_DOWNGRADE`) |
| `-Pwatchpost.versionName=x.y.z` | `0.1.0` | version displayed and sent to the server |
| `-Pwatchpost.testOnly=true\|false` | `true` | see section 7 |

Pitfalls:

- **Without a keystore**, `assembleRelease` succeeds but produces `app-release-unsigned.apk`, which is **not
  installable**. The `install-apk` script detects it ("The release APK is not signed") and refuses; with no argument
  it otherwise looks for `app-release.apk` and then the *debug* APK (confirmation requested before installing it).
  Always give its path explicitly in guide 03 and read the announced file ("Installing …").
- Optional checks before installing: `./gradlew lint test` (Android lint and JVM tests, 392 at the last count in
  `android/README.md`; allow several minutes).

Common build errors:

| Message | Cause and remedy |
|---|---|
| `SDK location not found` | create `local.properties` or set `ANDROID_HOME` (§2) |
| licences not accepted / missing component | `sdkmanager --licenses` then install `platforms;android-37.0` and `build-tools;36.0.0` |
| Java version too old | use a JDK 17 or 21 (`java -version`, `JAVA_HOME`) |
| `keytool` not found (key script) | add the JDK's `bin` to the `PATH` |
| download impossible | Internet access, corporate proxy: Gradle's proxy settings |

## 6. Check the APK

The tools are in the SDK's `build-tools/36.0.0/` (on Windows: `apksigner.bat` and `aapt2.exe`).

```bash
"$ANDROID_HOME/build-tools/36.0.0/apksigner" verify --verbose --print-certs app/build/outputs/apk/release/app-release.apk
"$ANDROID_HOME/build-tools/36.0.0/aapt2" dump badging app/build/outputs/apk/release/app-release.apk | grep -E "^package|testOnly|targetSdkVersion"
```

```powershell
& "$env:ANDROID_HOME\build-tools\36.0.0\apksigner.bat" verify --verbose --print-certs app\build\outputs\apk\release\app-release.apk
& "$env:ANDROID_HOME\build-tools\36.0.0\aapt2.exe" dump badging app\build\outputs\apk\release\app-release.apk | Select-String 'package:|testOnly|targetSdkVersion'
```

Expected result (observed on the APK built for this guide):

- `apksigner`: `Verifies`, **`Verified using v3 scheme (APK Signature Scheme v3): true`** (the v1 and v2 schemes are
  `false`, which is normal: with `minSdk 36`, only the v3 signature is written, which allows a future key rotation),
  a single signer (`CN=Watchpost Agent, O=Watchpost`) and a **"certificate SHA-256 digest" equal to the fingerprint
  noted when the key was created**. If it is different, it is not your key: do not install.
- `aapt2`: `package: name='io.github.erwsim.watchpost'`, the expected `versionCode` and `versionName`,
  `targetSdkVersion:'37'` and, for the default variant, **`testOnly='-1'`**.

Once installed, the phone confirms:
`adb shell dumpsys package io.github.erwsim.watchpost | grep -E "versionName|TEST_ONLY"`
(in PowerShell: `adb shell dumpsys package io.github.erwsim.watchpost | Select-String 'versionName|TEST_ONLY'`).

### 6.1 The second APK: the notification companion (optional)

Reading the title and text of notifications requires a **second APK**, **Watchpost Notifications**
(`io.github.erwsim.watchpost.notifier`, module `:notifier`), separate from the agent so as not to expose the Device
Owner APK to Play Protect (guide 03, §17). **It must be signed by the same key as the agent**: the same
`keystore.properties` (or the same `WATCHPOST_*` variables), hence **the same keystore to keep**; a companion signed
otherwise is refused at installation (`INSTALL_FAILED_DUPLICATE_PERMISSION`, both APKs declaring the local-channel
permission) and could not hand anything to the agent anyway. Same build, same variant: release with release, debug
with debug.

```bash
./gradlew :notifier:assembleRelease          # notifier/build/outputs/apk/release/notifier-release.apk
```

```powershell
.\gradlew.bat :notifier:assembleRelease
```

The parameters `-Pwatchpost.testOnly`, `-Pwatchpost.versionCode` and `-Pwatchpost.versionName` apply here too.
Check (same tools as above): the **"certificate SHA-256 digest" must be identical** to the agent's;
`aapt2 dump badging` must show `package: name='io.github.erwsim.watchpost.notifier'` and, among the permissions,
**only** `io.github.erwsim.watchpost.permission.NOTIFICATION_RELAY` (no `INTERNET` permission). Finding on the APKs
built for this guide: same signing fingerprints for the agent and the companion, `testOnly='-1'` for both, and the
companion declares only the channel permission.

```bash
"$ANDROID_HOME/build-tools/36.0.0/apksigner" verify --print-certs notifier/build/outputs/apk/release/notifier-release.apk | grep "SHA-256 digest"
"$ANDROID_HOME/build-tools/36.0.0/aapt2" dump badging notifier/build/outputs/apk/release/notifier-release.apk | grep -E "^package|uses-permission"
```

```powershell
& "$env:ANDROID_HOME\build-tools\36.0.0\apksigner.bat" verify --print-certs notifier\build\outputs\apk\release\notifier-release.apk | Select-String 'SHA-256 digest'
& "$env:ANDROID_HOME\build-tools\36.0.0\aapt2.exe" dump badging notifier\build\outputs\apk\release\notifier-release.apk | Select-String 'package:|uses-permission'
```

Without a keystore, `:notifier:assembleRelease` produces a `notifier-release-unsigned.apk` that cannot be installed
(`install-notifier` then refuses and says so). Installation is done with `install-notifier` (guide 03, §17), never
by any other means.

## 7. The `testOnly` option

`-Pwatchpost.testOnly=true` (**the default**) sets `android:testOnly="true"` in the manifest. Consequences:

- **Installation requires `adb install -t`**: the repository's scripts do it. It is impossible to install this APK by
  tapping it on the phone.
- **A last-resort exit door**: `adb shell dpm remove-active-admin` removes the Device Owner even if the application
  no longer starts. Without `testOnly`, Android refuses (`Attempt to remove non-test admin`).
- **Downside**: anyone who controls an authorised ADB access on the unlocked phone can also remove the Device
  Owner. Such a removal is seen by the agent as `agent.tamper` (Wazuh alert of level 12 on the agent, 10 for the
  loss of the Device Owner), which is the intended behaviour. The Settings › About screen shows "testOnly APK: Yes".
- Play Protect's behaviour towards a `testOnly` APK: **unverified**.

With `-Pwatchpost.testOnly=false`, only the application (Policy screen, "Remove Device Owner"), the
`remove-device-owner` script (which goes through the application's rescue) or a reset of the phone remove the role.
If the application no longer starts, only the reset remains. **Recommendation:** keep `true` during the whole trial
phase (guide 06); decide later. Switching from one variant to the other on a phone where the Device Owner is active
has not been verified: choose the variant **before** activating the Device Owner.

## 8. Updating the application later

Rebuild with **the same key** (the same `keystore.properties`) and a larger `versionCode`, then reinstall:

```bash
./gradlew assembleRelease -Pwatchpost.versionCode=2 -Pwatchpost.versionName=0.2.0
./scripts/install-apk.sh
```

```powershell
.\gradlew.bat assembleRelease -Pwatchpost.versionCode=2 -Pwatchpost.versionName=0.2.0
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\install-apk.ps1
```

The data (buffer, enrollment, settings) is kept. The companion is updated the same way, with the same key
(`:notifier:assembleRelease` then `install-notifier`). Details and the checks to make at the first trial:
[guide 05](05-operations.md) and [guide 06](06-on-device-checks.md).
