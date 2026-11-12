// Relavia Android shell (Step 10). Versions are pinned so CI and
// local builds agree; the shell is intentionally thin — all
// product logic lives in the Go module under app/.
plugins {
    id("com.android.application") version "8.5.2" apply false
    id("org.jetbrains.kotlin.android") version "2.0.20" apply false
}
