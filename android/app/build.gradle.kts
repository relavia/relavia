plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "org.relavia.client"
    compileSdk = 34

    defaultConfig {
        // Identifier string only; it does not imply ownership of
        // any domain (see docs/step10-Android客户端MVP.md).
        applicationId = "org.relavia.client"
        minSdk = 24
        targetSdk = 34
        versionCode = 1
        versionName = "0.1.0-dev"
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
