plugins {
    alias(libs.plugins.android.library)
}

android {
    namespace = "io.github.erwsim.vigie.collectors"
    compileSdk = 37

    defaultConfig {
        minSdk = 36
        consumerProguardFiles("consumer-rules.pro")
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    testOptions {
        // Plain JVM unit tests: Android stubs return default values.
        unitTests.isReturnDefaultValues = true
    }
}

dependencies {
    implementation(project(":core"))
    // Channel with the notification companion APK (pure code, no dependency): see notifications/.
    // api: NotificationEvents.data(NotificationPayload) is public, for the APK's contract tests.
    api(project(":notifier:protocol"))

    testImplementation(testFixtures(project(":core")))
    testImplementation(libs.junit)
    testImplementation(libs.kotlinx.coroutines.test)
}
