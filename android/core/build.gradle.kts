plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.serialization)
    alias(libs.plugins.ksp)
}

android {
    namespace = "io.github.erwsim.vigie.core"
    compileSdk = 37

    defaultConfig {
        minSdk = 36
        consumerProguardFiles("consumer-rules.pro")
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    // Shared JVM test helpers (FakeClock, MemoryPrefs, CollectorHarness…) for :collectors and :policy tests.
    testFixtures {
        enable = true
    }

    testOptions {
        // Plain JVM unit tests (no emulator, no Robolectric): Android stubs return defaults,
        // Room runs on the bundled JVM SQLite driver.
        unitTests.isReturnDefaultValues = true
    }
}

ksp {
    arg("room.schemaLocation", "$projectDir/schemas")
    arg("room.generateKotlin", "true")
}

dependencies {
    api(libs.kotlinx.coroutines.android)
    api(libs.kotlinx.serialization.json)
    api(libs.androidx.core.ktx)
    api(libs.work.runtime)
    implementation(libs.okhttp)
    implementation(libs.room.runtime)
    ksp(libs.room.compiler)

    testFixturesImplementation(libs.junit)
    testFixturesImplementation(libs.sqlite.bundled.jvm)
    testFixturesImplementation(libs.room.runtime)

    testImplementation(libs.junit)
    testImplementation(libs.kotlinx.coroutines.test)
    testImplementation(libs.okhttp.mockwebserver)
    testImplementation(libs.okhttp.tls)
    testImplementation(libs.sqlite.bundled.jvm)
}
