plugins {
    alias(libs.plugins.android.library)
    // Applied state and the package catalog (res/raw/policy_catalog.json) are (de)serialized with kotlinx.serialization.
    alias(libs.plugins.kotlin.serialization)
}

android {
    namespace = "io.github.erwsim.vigie.policy"
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

    testImplementation(testFixtures(project(":core")))
    testImplementation(libs.junit)
    testImplementation(libs.kotlinx.coroutines.test)
}
