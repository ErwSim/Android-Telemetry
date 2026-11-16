import java.util.Properties

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.compose)
}

// Build parameters (gradle.properties, overridable with -P...).
val vigieTestOnly: Boolean = providers.gradleProperty("vigie.testOnly").map { it.toBoolean() }.getOrElse(true)
val vigieVersionCode: Int = providers.gradleProperty("vigie.versionCode").map { it.toInt() }.getOrElse(1)
val vigieVersionName: String = providers.gradleProperty("vigie.versionName").getOrElse("0.1.0")

// Release signing: environment variables first, then android/keystore.properties (never versioned).
// The signing key must stay the same for every update: a Device Owner app cannot be replaced by an
// APK signed with another key (see README).
val keystoreProperties = Properties().apply {
    providers.fileContents(rootProject.layout.projectDirectory.file("keystore.properties")).asText.orNull
        ?.let { load(it.reader()) }
}

fun signingValue(env: String, key: String): String? =
    providers.environmentVariable(env).orNull?.takeIf { it.isNotBlank() } ?: keystoreProperties.getProperty(key)

val releaseStoreFile = signingValue("VIGIE_KEYSTORE_FILE", "storeFile")
val releaseStorePassword = signingValue("VIGIE_KEYSTORE_PASSWORD", "storePassword")
val releaseKeyAlias = signingValue("VIGIE_KEY_ALIAS", "keyAlias")
val releaseKeyPassword = signingValue("VIGIE_KEY_PASSWORD", "keyPassword")
val hasReleaseSigning = listOf(releaseStoreFile, releaseStorePassword, releaseKeyAlias, releaseKeyPassword).all { it != null }

android {
    namespace = "io.github.erwsim.vigie"
    compileSdk = 37

    defaultConfig {
        applicationId = "io.github.erwsim.vigie"
        minSdk = 36
        targetSdk = 37
        versionCode = vigieVersionCode
        versionName = vigieVersionName
        // android:testOnly in the manifest: true keeps "dpm remove-active-admin" usable.
        manifestPlaceholders["testOnly"] = vigieTestOnly.toString()
    }

    signingConfigs {
        if (hasReleaseSigning) {
            create("release") {
                storeFile = rootProject.file(releaseStoreFile!!)
                storePassword = releaseStorePassword
                keyAlias = releaseKeyAlias
                keyPassword = releaseKeyPassword
                // v3 (Android 9+) makes a future key rotation possible (signing certificate lineage).
                // With minSdk 36 apksigner then omits v2, which is not needed.
                enableV3Signing = true
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            // Without a keystore the release APK is produced unsigned (app-release-unsigned.apk).
            signingConfig = signingConfigs.findByName("release")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    testOptions {
        // Plain JVM unit tests (contract conformance of every module): Android stubs return default values.
        unitTests.isReturnDefaultValues = true
    }

    lint {
        abortOnError = true
        checkDependencies = true
        // Lint baseline intentionally absent: errors must be fixed, not hidden.
    }

    packaging {
        resources.excludes += setOf("/META-INF/{AL2.0,LGPL2.1}", "/META-INF/versions/9/OSGI-INF/MANIFEST.MF")
    }
}

dependencies {
    implementation(project(":core"))
    implementation(project(":collectors"))
    implementation(project(":policy"))

    implementation(platform(libs.compose.bom))
    implementation(libs.compose.ui)
    implementation(libs.compose.material3)
    implementation(libs.compose.material.icons)
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.lifecycle.runtime.compose)
    implementation(libs.androidx.lifecycle.runtime)

    testImplementation(testFixtures(project(":core")))
    testImplementation(libs.junit)
}
