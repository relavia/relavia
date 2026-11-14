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

// Optional ABI restriction for the merged APK, e.g.
// -PrelaviaAbis=arm64-v8a (comma-separated for several).
// Unset (the default) leaves the ndk configuration untouched
// and the build packages every ABI the inputs carry — the
// long-standing behavior. When set, the list is applied as
// ndk.abiFilters in defaultConfig below.
//
// Why abiFilters, not splits: abiFilters is a packaging-time
// filter over native libraries from EVERY source — the
// gomobile AAR's jni/<abi>/ directories and src/main/jniLibs
// alike — so the three unneeded libgojni.so copies (each one
// embedding the full bundled CJK font collection, KI-21) are
// dropped without rebuilding the AAR, and the build still
// emits the single app-debug.apk at the usual path. Splits
// would instead emit several APKs under new names (plus a
// universal APK), changing the artifact surface every
// consumer and verify step keys on. First consumer: the CI
// android job's additional arm64-v8a-only artifact
// (KI-18); the all-ABI build remains the default product.
val relaviaAbis: List<String> =
    (findProperty("relaviaAbis") as String?)
        ?.split(",")
        ?.map { it.trim() }
        ?.filter { it.isNotEmpty() }
        ?: emptyList()

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
        if (relaviaAbis.isNotEmpty()) {
            ndk {
                abiFilters.addAll(relaviaAbis)
            }
        }
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
