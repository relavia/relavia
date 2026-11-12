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
}
