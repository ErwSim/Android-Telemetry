import java.util.Properties

// Watchpost Notifications: separate, optional companion APK holding the project's only
// NotificationListenerService (kept out of the Device Owner APK: principle 4, Play Protect).
// No INTERNET permission, no library besides the channel's protocol (no AndroidX, no network,
// nothing from Google).
plugins {
    alias(libs.plugins.android.application)
}

// Same build parameters as :app (gradle.properties, -P...): testOnly, version.
val watchpostTestOnly: Boolean = providers.gradleProperty("watchpost.testOnly").map { it.toBoolean() }.getOrElse(true)
val watchpostVersionCode: Int = providers.gradleProperty("watchpost.versionCode").map { it.toInt() }.getOrElse(1)
val watchpostVersionName: String = providers.gradleProperty("watchpost.versionName").getOrElse("0.1.0")

// Release signing: the SAME key as the agent, read from the same place as :app (environment
// variables first, then android/keystore.properties, never versioned): no secret is duplicated.
// The channel's permission has protection level "signature": a companion signed by another key
// cannot talk to the agent (and Android refuses to install it next to the agent, both APKs declaring
// the same permission: INSTALL_FAILED_DUPLICATE_PERMISSION).
val keystoreProperties = Properties().apply {
    providers.fileContents(rootProject.layout.projectDirectory.file("keystore.properties")).asText.orNull
        ?.let { load(it.reader()) }
}

fun signingValue(env: String, key: String): String? =
    providers.environmentVariable(env).orNull?.takeIf { it.isNotBlank() } ?: keystoreProperties.getProperty(key)

val releaseStoreFile = signingValue("WATCHPOST_KEYSTORE_FILE", "storeFile")
val releaseStorePassword = signingValue("WATCHPOST_KEYSTORE_PASSWORD", "storePassword")
val releaseKeyAlias = signingValue("WATCHPOST_KEY_ALIAS", "keyAlias")
val releaseKeyPassword = signingValue("WATCHPOST_KEY_PASSWORD", "keyPassword")
val hasReleaseSigning = listOf(releaseStoreFile, releaseStorePassword, releaseKeyAlias, releaseKeyPassword).all { it != null }

android {
    namespace = "io.github.erwsim.watchpost.notifier"
    compileSdk = 37

    defaultConfig {
        applicationId = "io.github.erwsim.watchpost.notifier"
        minSdk = 36
        targetSdk = 37
        versionCode = watchpostVersionCode
        versionName = watchpostVersionName
        manifestPlaceholders["testOnly"] = watchpostTestOnly.toString()
    }

    signingConfigs {
        if (hasReleaseSigning) {
            create("release") {
                storeFile = rootProject.file(releaseStoreFile!!)
                storePassword = releaseStorePassword
                keyAlias = releaseKeyAlias
                keyPassword = releaseKeyPassword
                enableV3Signing = true
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            // Without a keystore the release APK is produced unsigned (notifier-release-unsigned.apk).
            signingConfig = signingConfigs.findByName("release")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    testOptions {
        unitTests.isReturnDefaultValues = true
    }

    lint {
        abortOnError = true
        checkDependencies = true
    }
}

dependencies {
    implementation(project(":notifier:protocol"))
}
