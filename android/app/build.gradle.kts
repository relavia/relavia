plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

// Release version identity (Step 15): the repo-root VERSION file
// is the single source of truth for every artifact. versionCode
// follows the project encoding MAJOR*10000 + MINOR*100 + PATCH
// (docs/relavia-update-v1.md §2 — the same value the Go client's
// ClientVersionCode carries). Release builds may override both
// via -PrelaviaVersionName / -PrelaviaVersionCode
// (scripts/release/build.sh passes them from VERSION).
val relaviaVersionFile = rootProject.file("../VERSION")
val relaviaVersionRaw: String = if (relaviaVersionFile.exists()) {
    relaviaVersionFile.readText().trim().removePrefix("v")
} else {
    "0.1.0"
}
val relaviaVersionParts: List<Int> =
    relaviaVersionRaw.substringBefore("-").split(".").map { it.toIntOrNull() ?: 0 }
val relaviaDerivedVersionCode: Int =
    (relaviaVersionParts.getOrElse(0) { 0 } * 10000) +
        (relaviaVersionParts.getOrElse(1) { 0 } * 100) +
        (relaviaVersionParts.getOrElse(2) { 0 })
val relaviaVersionName: String =
    (findProperty("relaviaVersionName") as String?) ?: relaviaVersionRaw
val relaviaVersionCode: Int =
    (findProperty("relaviaVersionCode") as String?)?.toIntOrNull() ?: relaviaDerivedVersionCode

android {
    namespace = "org.relavia.client"
    compileSdk = 34

    defaultConfig {
        // Identifier string only; it does not imply ownership of
        // any domain (see docs/step10-Android客户端MVP.md).
        applicationId = "org.relavia.client"
        minSdk = 24
        targetSdk = 34
        versionCode = relaviaVersionCode
        versionName = relaviaVersionName
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.13.1")
    // The libbox data-plane binding (docs/libbox绑定.md): a
    // gomobile AAR built from the Go package app/libboxbind by
    // `scripts/build-android.sh bind` (CI android job, before
    // this Gradle build). The AAR is a build artifact — it is
    // gitignored and never committed. Its absence is a BUILD
    // ERROR by design (the Kotlin shell references the
    // generated org.relavia.libboxbind facade): a shell APK
    // without the data plane must never be producible by
    // accident.
    implementation(files("libs/libboxbind.aar"))
}
