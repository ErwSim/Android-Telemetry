# 02 — Compiler l'APK

Vigie Agent se compile sur votre PC (Windows, Linux ou macOS). Ce guide installe les outils, crée la **clé de
signature** (à conserver à vie), construit l'APK et le vérifie. La référence technique reste
[`android/README.md`](../../android/README.md).

Durée : 30 à 60 minutes, dont le téléchargement de Gradle et des dépendances au premier build.
Suite : [03 — le téléphone](03-telephone.md).

> **Statut de vérification.** Le build `./gradlew lint test assembleDebug assembleRelease` réussit dans
> l'environnement de développement (Linux, JDK 21) et l'APK release obtenu a été inspecté (commandes de la section 6,
> exécutées pour ce guide). **Le build sous Windows n'a jamais été exécuté**, pas plus que les scripts PowerShell.

## 1. Ce que le projet exige

| Élément | Version | Remarque |
|---|---|---|
| JDK | 17 minimum ; 21 vérifié | fourni aussi par Android Studio |
| Gradle | 9.9.1 | téléchargé automatiquement par le wrapper (`gradlew`), rien à installer |
| Plugin Android Gradle (AGP) | 9.5.1 | Kotlin 2.4.21 intégré ; rien à installer |
| `compileSdk` / `targetSdk` / `minSdk` | 37 / 37 / 36 | **le téléphone doit être sous Android 16 ou plus** (One UI 8 ou plus) |
| SDK Android | plateforme `android-37.0`, `build-tools;36.0.0`, `platform-tools` | |
| Accès Internet | oui, au premier build | Maven Central et Google |

Le paquet de l'application est `io.github.erwsim.vigie`. Vous n'avez besoin ni d'un compte développeur, ni de Google
Play, ni de Firebase.

## 2. Installer les outils

Deux voies : **Android Studio** (graphique, installe le SDK pour vous) ou le **SDK en ligne de commande** (plus
léger, suffisant pour compiler). Les deux fonctionnent ; la ligne de commande est la voie décrite ici.

### 2.1 Windows

1. **JDK** : installez un JDK 17 ou 21 (par exemple Temurin, <https://adoptium.net>), ou utilisez celui d'Android
   Studio si vous l'installez. Vérifiez, dans un nouveau PowerShell :

   ```powershell
   java -version
   keytool -help | Select-Object -First 1
   ```

   Si `keytool` est introuvable, ajoutez le dossier `bin` du JDK au `PATH` (nécessaire pour la clé de signature) et
   définissez `JAVA_HOME` (dossier du JDK, sans `bin`).

2. **Outils de ligne de commande Android** : téléchargez « Command line tools only » sur
   <https://developer.android.com/studio#command-line-tools-only>. Dézippez de façon que le résultat soit
   `C:\Android\cmdline-tools\latest\bin\sdkmanager.bat` (le sous-dossier `latest` est obligatoire). Puis :

   ```powershell
   [Environment]::SetEnvironmentVariable('ANDROID_HOME', 'C:\Android', 'User')
   $env:ANDROID_HOME = 'C:\Android'
   & 'C:\Android\cmdline-tools\latest\bin\sdkmanager.bat' --licenses
   & 'C:\Android\cmdline-tools\latest\bin\sdkmanager.bat' "platform-tools" "platforms;android-37.0" "build-tools;36.0.0"
   ```

   Acceptez les licences (`y`). `platform-tools` contient **`adb`**, dont vous aurez besoin au guide 03 : ajoutez
   `C:\Android\platform-tools` au `PATH` (Paramètres Windows, « variables d'environnement »), puis rouvrez PowerShell
   et vérifiez `adb version`.

   Variante Android Studio : installez-le, ouvrez le dossier `android/` du dépôt, laissez-le synchroniser ; dans le
   SDK Manager, cochez Android SDK Platform 37.0, Build-Tools 36.0.0 et Platform-Tools. Si Android Studio signale une
   incompatibilité avec le plugin Android Gradle 9.5.1, mettez-le à jour (compatibilité non vérifiée ici).

3. **Si Gradle ne trouve pas le SDK** (« SDK location not found ») : créez `android\local.properties` avec une ligne
   `sdk.dir=C\:\\Android` (les `\` s'écrivent doublés et le `:` précédé d'un `\`). Android Studio crée ce fichier
   tout seul. Il n'est pas versionné.

4. **Scripts PowerShell** : les `.ps1` du dépôt ne sont pas signés et Windows les refuse avec sa politique d'exécution par
   défaut. Lancez-les toujours ainsi, sans rien changer à la configuration de la machine (la dérogation ne vaut que pour ce
   processus) :

   ```powershell
   powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\<nom>.ps1 [options]
   ```

   C'est la forme donnée dans tous les guides. Elle est celle que documentent les scripts eux-mêmes ; elle n'a jamais été
   exécutée sous Windows.

### 2.2 Linux et macOS

```bash
# JDK : installez le paquet de votre distribution (par exemple openjdk-17-jdk ou openjdk-21-jdk sous Debian/Ubuntu,
# Temurin sous macOS), puis :
java -version && keytool -help | head -1

# SDK en ligne de commande : télécharger « Command line tools only »
# (https://developer.android.com/studio#command-line-tools-only), le dézipper de façon que le résultat soit
# ~/Android/Sdk/cmdline-tools/latest/bin/sdkmanager
export ANDROID_HOME=$HOME/Android/Sdk
"$ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager" --licenses
"$ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager" "platform-tools" "platforms;android-37.0" "build-tools;36.0.0"
export PATH="$ANDROID_HOME/platform-tools:$PATH"
adb version
```

Placez les deux `export` dans votre profil (`~/.bashrc`, `~/.zshrc`) pour les conserver. Les scripts `.sh` sont
exécutables dans le dépôt (`./scripts/…`).

## 3. Cloner le dépôt

```bash
git clone <adresse du dépôt> Android-Telemetry
cd Android-Telemetry/android
```

Les commandes suivantes se lancent depuis le dossier `android/` (dans PowerShell comme en bash).

## 4. La clé de signature : à créer une fois, à conserver toujours

### Pourquoi la signature doit rester la même

Android n'accepte une mise à jour d'une application que si elle est signée par **la même clé** que la version
installée. Pour une application Device Owner, **il n'y a pas de contournement** : si vous perdez la clé, la seule
issue est de retirer le Device Owner (ce qui défait la politique et demande de repasser par le guide 03, comptes
retirés) ou de réinitialiser le téléphone. Dans les deux cas : plus de mise à jour tant que la clé d'origine
manque.

Un APK de débogage (`assembleDebug`) est signé avec une clé de débogage propre à votre PC ; ne l'installez **jamais**
sur le téléphone de tous les jours (sa signature ne serait ni stable, ni reproductible). N'utilisez que l'APK
*release* signé avec votre clé.

### Créer la clé

```bash
./scripts/generate-keystore.sh
```

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\generate-keystore.ps1
```

Le script crée :

- `android/keystore/vigie-release.jks` : le keystore (RSA 4096, validité d'environ 50 ans, alias `vigie`) ;
- `android/keystore.properties` : le mot de passe (aléatoire, 32 caractères, ou celui de la variable d'environnement
  `VIGIE_KEYSTORE_PASSWORD`, 12 caractères au minimum) et le chemin, lus par Gradle.

et affiche l'**empreinte SHA-256** du certificat de signature. Notez-la : elle sert à contrôler l'APK (section 6).
Les deux fichiers sont ignorés par git (vérifié : `.gitignore` couvre `*.jks` et `keystore.properties`). Le script
**refuse d'écraser** un keystore existant ; ne le contournez pas.

### La sauvegarder

Copiez **ensemble** `android/keystore/vigie-release.jks` et `android/keystore.properties` (le mot de passe y est en
clair) :

- dans un gestionnaire de mots de passe qui accepte les pièces jointes, ou sur une clé USB / un disque **chiffré** ;
- en au moins **deux** endroits distincts, hors de ce PC ;
- jamais dans un dépôt git, ni dans un nuage non chiffré, ni sur le VPS non chiffré.

Puisque le mot de passe est dans `keystore.properties`, c'est le chiffrement du support qui protège la clé. Notez
aussi l'empreinte affichée par le script. Vous pouvez la relire à tout moment :

```bash
keytool -list -v -keystore keystore/vigie-release.jks -alias vigie
```

(le mot de passe est dans `keystore.properties`). La clé de signature n'est **pas** incluse dans les sauvegardes du
serveur (guide 01).

## 5. Construire

```bash
./gradlew assembleRelease
```

```powershell
.\gradlew.bat assembleRelease
```

Le premier lancement télécharge Gradle 9.9.1 puis les dépendances ; il peut durer plusieurs minutes (la configuration
du dépôt limite Gradle à 2 Go de mémoire et à 2 processus : lent mais sûr ; vous pouvez augmenter ces valeurs dans
`android/gradle.properties`). Résultat :

```
android/app/build/outputs/apk/release/app-release.apk
```

Paramètres facultatifs (`-P…` sur la ligne de commande) :

| Paramètre | Défaut | Rôle |
|---|---|---|
| `-Pvigie.versionCode=N` | `1` | entier, **à augmenter à chaque mise à jour** (sinon Android refuse : `VERSION_DOWNGRADE`) |
| `-Pvigie.versionName=x.y.z` | `0.1.0` | version affichée et envoyée au serveur |
| `-Pvigie.testOnly=true\|false` | `true` | voir section 7 |

Pièges :

- **Sans keystore**, `assembleRelease` réussit mais produit `app-release-unsigned.apk`, qui n'est **pas installable**.
  Le script `install-apk` cherche `app-release.apk` puis, à défaut, l'APK *debug* (il demande alors confirmation avant de
  l'installer) : donnez toujours son chemin explicitement au guide 03 et lisez le fichier annoncé (« Installation de … »).
- Vérifications facultatives avant d'installer : `./gradlew lint test` (lint Android et tests JVM ; compter plusieurs
  minutes).

Erreurs fréquentes du build :

| Message | Cause et remède |
|---|---|
| `SDK location not found` | créer `local.properties` ou définir `ANDROID_HOME` (§2) |
| licences non acceptées / composant manquant | `sdkmanager --licenses` puis installer `platforms;android-37.0` et `build-tools;36.0.0` |
| version de Java insuffisante | utiliser un JDK 17 ou 21 (`java -version`, `JAVA_HOME`) |
| `keytool` introuvable (script de clé) | ajouter le `bin` du JDK au `PATH` |
| téléchargement impossible | accès Internet, proxy d'entreprise : réglages proxy de Gradle |

## 6. Vérifier l'APK

Les outils sont dans `build-tools/36.0.0/` du SDK (sous Windows : `apksigner.bat` et `aapt2.exe`).

```bash
"$ANDROID_HOME/build-tools/36.0.0/apksigner" verify --verbose --print-certs app/build/outputs/apk/release/app-release.apk
"$ANDROID_HOME/build-tools/36.0.0/aapt2" dump badging app/build/outputs/apk/release/app-release.apk | grep -E "^package|testOnly|targetSdkVersion"
```

```powershell
& "$env:ANDROID_HOME\build-tools\36.0.0\apksigner.bat" verify --verbose --print-certs app\build\outputs\apk\release\app-release.apk
& "$env:ANDROID_HOME\build-tools\36.0.0\aapt2.exe" dump badging app\build\outputs\apk\release\app-release.apk | Select-String 'package:|testOnly|targetSdkVersion'
```

Résultat attendu (observé sur l'APK construit pour ce guide) :

- `apksigner` : `Verifies`, **`Verified using v3 scheme (APK Signature Scheme v3): true`** (les schémas v1 et v2 sont
  à `false`, c'est normal : avec `minSdk 36`, seule la signature v3 est écrite, ce qui permet une rotation de clé
  future), un seul signataire (`CN=Vigie Agent, O=Vigie (personnel)`) et un **« certificate SHA-256 digest » égal à
  l'empreinte notée à la création de la clé**. S'il est différent, ce n'est pas votre clé : n'installez pas.
- `aapt2` : `package: name='io.github.erwsim.vigie'`, le `versionCode` et le `versionName` attendus,
  `targetSdkVersion:'37'` et, pour la variante par défaut, **`testOnly='-1'`**.

Une fois installé, le téléphone confirme : `adb shell dumpsys package io.github.erwsim.vigie | grep -E "versionName|TEST_ONLY"`
(sous PowerShell : `adb shell dumpsys package io.github.erwsim.vigie | Select-String 'versionName|TEST_ONLY'`).

## 7. L'option `testOnly`

`-Pvigie.testOnly=true` (**par défaut**) pose `android:testOnly="true"` dans le manifeste. Conséquences :

- **L'installation exige `adb install -t`** : les scripts du dépôt le font. Impossible d'installer cet APK en le
  touchant depuis le téléphone.
- **Une porte de sortie de dernier recours** : `adb shell dpm remove-active-admin` retire le Device Owner même si
  l'application ne démarre plus. Sans `testOnly`, Android refuse (`Attempt to remove non-test admin`).
- **Contrepartie** : quiconque contrôle un accès ADB autorisé sur le téléphone déverrouillé peut aussi retirer le
  Device Owner. Un tel retrait est vu par l'agent comme `agent.tamper` (alerte Wazuh de niveau 12 sur l'agent, 10 pour la
  perte du Device Owner), ce qui est le comportement voulu. L'écran Réglages › À propos affiche « APK testOnly : Oui ».
- Comportement de Play Protect face à un APK `testOnly` : **non vérifié**.

Avec `-Pvigie.testOnly=false`, seuls l'application (écran Politique, « Retirer le Device Owner »), le script
`remove-device-owner` (qui passe par l'issue de secours de l'application) ou une réinitialisation du téléphone
retirent le rôle. Si l'application ne démarre plus, il n'y a plus que la réinitialisation. **Recommandation :** gardez
`true` pendant toute la phase d'essai (guide 06) ; décidez plus tard. Le passage d'une variante à l'autre sur un
téléphone où le Device Owner est actif n'a pas été vérifié : choisissez la variante **avant** l'activation du Device
Owner.

## 8. Mettre à jour l'application plus tard

Reconstruisez avec **la même clé** (le même `keystore.properties`) et un `versionCode` plus grand, puis réinstallez :

```bash
./gradlew assembleRelease -Pvigie.versionCode=2 -Pvigie.versionName=0.2.0
./scripts/install-apk.sh
```

```powershell
.\gradlew.bat assembleRelease -Pvigie.versionCode=2 -Pvigie.versionName=0.2.0
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\install-apk.ps1
```

Les données (tampon, enrôlement, réglages) sont conservées. Le détail et les contrôles à faire au premier essai :
[guide 05](05-exploitation.md) et [guide 06](06-verifications-sur-appareil.md).
