// Local channel between the notification companion (:notifier) and the agent (:collectors):
// constants, payload codec and validation, content filtering (code masking, truncation, package
// lists) and noise reduction. Pure Kotlin on the Android framework only: no AndroidX, no network,
// no Google library, because it is packaged into the companion APK, which must stay minimal.
plugins {
    alias(libs.plugins.android.library)
}

android {
    namespace = "io.github.erwsim.vigie.notifier.protocol"
    compileSdk = 37

    defaultConfig {
        minSdk = 36
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    testOptions {
        unitTests.isReturnDefaultValues = true
    }
}
