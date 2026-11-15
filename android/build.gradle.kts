// Root build file: plugin versions only. Kotlin is built into AGP 9; declaring the Kotlin
// Gradle plugin here (apply false) pins the Kotlin compiler version used by the built-in support.
plugins {
    alias(libs.plugins.android.application) apply false
    alias(libs.plugins.android.library) apply false
    alias(libs.plugins.kotlin.android) apply false
    alias(libs.plugins.kotlin.compose) apply false
    alias(libs.plugins.kotlin.serialization) apply false
    alias(libs.plugins.ksp) apply false
}
