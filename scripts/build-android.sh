#!/usr/bin/env bash
# Relavia Android build (Step 10; libbox binding added later).
#
# Three artifacts, one script:
#
#   1. libboxbind AAR (app/libboxbind) — the gomobile binding of
#      the Go data plane (sing-box libbox) for the shell. Built
#      with the SagerNet gomobile fork pinned by sing-box
#      v1.14.4's own Makefile (v0.1.13); needs Go + an NDK.
#   2. Kotlin VpnService shell APK (android/) — the production
#      shell; with the AAR in android/app/libs/ this is the
#      MERGED APK (shell + real data plane). Built with Gradle;
#      needs JDK 17 + Android SDK (platform 34, build-tools).
#   3. Gio logic-build APK (app/cmd/relavia-android) — the Go
#      service/UI validation shell. Built with gogio; needs the
#      same SDK plus an NDK and Go.
#
# Usage:
#   ./scripts/build-android.sh check   # Go-side GOOS=android cross-compile gate only (no SDK needed)
#   ./scripts/build-android.sh bind    # gomobile bind -> android/app/libs/libboxbind.aar
#   ./scripts/build-android.sh shell   # Gradle assembleDebug for the Kotlin shell (needs the AAR for the merged APK)
#   ./scripts/build-android.sh gio     # gogio APK for the Go logic build
#   ./scripts/build-android.sh all     # check + bind + shell + gio
#
# The script fails loudly listing exactly which tools are
# missing; it never skips a build silently. CI runs the same
# entry points (.github/workflows/ci.yml, job "android").
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PATH="$HOME/tools/go/bin:$PATH"

GO_TAGS="with_quic with_utls with_wireguard with_gvisor"
# Binding-only additions (docs/libbox绑定.md §6): upstream's
# own libbox build carries these two tags plus
# -checklinkname=0 because libbox's internals use //go:linkname
# into restricted runtime symbols (link fails without them).
# They enable no protocol features; the feature set above is
# Step 7's official set, unchanged.
BIND_TAGS="$GO_TAGS badlinkname tfogo_checklinkname0"
BIND_LDFLAGS="-checklinkname=0"
# Toolchain pinned by sing-box v1.14.4's Makefile (lib_install).
GOMOBILE_VERSION="v0.1.13"

check_go_android() {
    echo "== GOOS=android cross-compile gate (CGO off) =="
    (cd "$ROOT/app" && CGO_ENABLED=0 GOOS=android GOARCH=arm64 \
        go build -ldflags="$BIND_LDFLAGS" ./i18n/ ./locales/ ./platform/ ./service/ ./android/ ./libboxbind/)
    (cd "$ROOT/app" && CGO_ENABLED=0 GOOS=android GOARCH=arm64 \
        go vet ./platform/ ./android/ ./libboxbind/)
    echo "OK: service layer, i18n, the VPN bridge and the libbox binding compile for android/arm64"
}

build_bind() {
    command -v gomobile >/dev/null 2>&1 || {
        echo "build-android: gomobile not found; install the pinned SagerNet fork:" >&2
        echo "  go install github.com/sagernet/gomobile/cmd/gomobile@$GOMOBILE_VERSION" >&2
        echo "  go install github.com/sagernet/gomobile/cmd/gobind@$GOMOBILE_VERSION" >&2
        exit 3
    }
    if [ -z "${ANDROID_NDK_HOME:-}" ] && [ -z "${ANDROID_NDK_ROOT:-}" ]; then
        # Same NDK discovery the CI gio step uses (runner image layout).
        if [ -n "${ANDROID_HOME:-}" ] && ls -d "$ANDROID_HOME"/ndk/* >/dev/null 2>&1; then
            export ANDROID_NDK_HOME="$(ls -d "$ANDROID_HOME"/ndk/* | sort -V | tail -1)"
        else
            echo "build-android: gomobile bind needs an Android NDK (set ANDROID_NDK_HOME)" >&2
            exit 3
        fi
    fi
    echo "== libbox binding AAR (gomobile bind, sing-box v1.14.4 / gomobile $GOMOBILE_VERSION) =="
    mkdir -p "$ROOT/android/app/libs"
    (cd "$ROOT/app" && gomobile bind -target android -androidapi 24 \
        -javapkg org.relavia -tags "$BIND_TAGS" -ldflags "$BIND_LDFLAGS" \
        -o "$ROOT/android/app/libs/libboxbind.aar" ./libboxbind)
    ls -l "$ROOT/android/app/libs/libboxbind.aar"
    sha256sum "$ROOT/android/app/libs/libboxbind.aar"
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
    # The Gradle build references libs/libboxbind.aar (see
    # android/app/build.gradle.kts): run `bind` first. Without
    # the AAR this step fails at Kotlin compilation BY DESIGN —
    # a shell APK without the data plane is not a producible
    # artifact (docs/libbox绑定.md §5).
    echo "== Kotlin VpnService shell + libbox AAR = merged APK (Gradle assembleDebug) =="
    (cd "$ROOT/android" && gradle :app:assembleDebug --console=plain)
    local apk="$ROOT/android/app/build/outputs/apk/debug/app-debug.apk"
    ls -l "$apk"
    sha256sum "$apk"
}

build_gio() {
    # Since Step 15 the gogio build lives in scripts/release/build.sh
    # (single implementation: VERSION-derived gogio version
    # MAJOR.MINOR.PATCH.CODE — a bare "1" is rejected as invalid
    # semver, CI run 43290011677 — plus -trimpath/-buildvcs=false
    # via GOFLAGS and the ClientVersion -X stamp). This entry point
    # stays as the CI/dev facade and delegates.
    echo "== Gio logic-build APK (gogio, via scripts/release/build.sh) =="
    mkdir -p "$ROOT/app/dist"
    "$ROOT/scripts/release/build.sh" gio "$ROOT/app/dist/relavia-logic.apk"
}

case "${1:-all}" in
    check) check_go_android ;;
    bind) build_bind ;;
    shell) build_shell ;;
    gio) build_gio ;;
    all) check_go_android; build_bind; build_shell; build_gio ;;
    *) echo "usage: $0 [check|bind|shell|gio|all]" >&2; exit 2 ;;
esac
