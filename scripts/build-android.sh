#!/usr/bin/env bash
# Relavia Android build (Step 10).
#
# Two artifacts, one script:
#
#   1. Kotlin VpnService shell APK (android/) — the production
#      shell. Built with Gradle; needs JDK 17 + Android SDK
#      (platform 34, build-tools) on PATH / ANDROID_HOME.
#   2. Gio logic-build APK (app/cmd/relavia-android) — the Go
#      service/UI validation shell. Built with gogio; needs the
#      same SDK plus an NDK and Go.
#
# Usage:
#   ./scripts/build-android.sh check   # Go-side GOOS=android cross-compile gate only (no SDK needed)
#   ./scripts/build-android.sh shell   # Gradle assembleDebug for the Kotlin shell
#   ./scripts/build-android.sh gio     # gogio APK for the Go logic build
#   ./scripts/build-android.sh all     # check + shell + gio
#
# The script fails loudly listing exactly which tools are
# missing; it never skips a build silently. CI runs the same
# entry points (.github/workflows/ci.yml, job "android").
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PATH="$HOME/tools/go/bin:$PATH"

GO_TAGS="with_quic with_utls with_wireguard with_gvisor"

check_go_android() {
    echo "== GOOS=android cross-compile gate (CGO off) =="
    (cd "$ROOT/app" && CGO_ENABLED=0 GOOS=android GOARCH=arm64 \
        go build ./i18n/ ./locales/ ./platform/ ./service/ ./android/)
    (cd "$ROOT/app" && CGO_ENABLED=0 GOOS=android GOARCH=arm64 \
        go vet ./platform/ ./android/)
    echo "OK: service layer, i18n and the VPN bridge compile for android/arm64"
}

require_shell_tools() {
    local missing=()
    command -v java >/dev/null 2>&1 || missing+=("java (JDK 17)")
    if [ -z "${ANDROID_HOME:-}" ] && [ -z "${ANDROID_SDK_ROOT:-}" ] && ! command -v sdkmanager >/dev/null 2>&1; then
        missing+=("Android SDK (set ANDROID_HOME)")
    fi
    if [ "${#missing[@]}" -gt 0 ]; then
        echo "build-android: cannot build the Kotlin shell; missing: ${missing[*]}" >&2
        echo "Install JDK 17 and the Android SDK (platform 34 + build-tools), or use the CI android job." >&2
        exit 3
    fi
}

build_shell() {
    require_shell_tools
    echo "== Kotlin VpnService shell (Gradle assembleDebug) =="
    (cd "$ROOT/android" && gradle :app:assembleDebug --console=plain)
    local apk="$ROOT/android/app/build/outputs/apk/debug/app-debug.apk"
    ls -l "$apk"
    sha256sum "$apk"
}

build_gio() {
    require_shell_tools
    command -v gogio >/dev/null 2>&1 || {
        echo "build-android: gogio not found; install with: go install gioui.org/cmd/gogio@v0.10.3" >&2
        exit 3
    }
    if [ -z "${ANDROID_NDK_HOME:-}" ] && [ -z "${ANDROID_NDK_ROOT:-}" ]; then
        echo "build-android: gogio needs an Android NDK (set ANDROID_NDK_HOME)" >&2
        exit 3
    fi
    # gogio -version must be major.minor.patch.versioncode ("0.1.0.1"
    # = versionName 0.1.0 + versionCode 1, matching the Gradle shell);
    # a bare "1" is rejected as invalid semver (CI run 43290011677).
    echo "== Gio logic-build APK (gogio) =="
    mkdir -p "$ROOT/app/dist"
    (cd "$ROOT/app" && gogio -target android -appid org.relavia.client \
        -version 0.1.0.1 -tags "$GO_TAGS" -o dist/relavia-logic.apk ./cmd/relavia-android)
    ls -l "$ROOT/app/dist/relavia-logic.apk"
    sha256sum "$ROOT/app/dist/relavia-logic.apk"
}

case "${1:-all}" in
    check) check_go_android ;;
    shell) build_shell ;;
    gio) build_gio ;;
    all) check_go_android; build_shell; build_gio ;;
    *) echo "usage: $0 [check|shell|gio|all]" >&2; exit 2 ;;
esac
