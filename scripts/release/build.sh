#!/usr/bin/env bash
# Relavia deterministic release builds (Step 15).
#
#   scripts/release/build.sh windows <output-file>   Windows client exe
#   scripts/release/build.sh shell   <output-file>   Android shell APK (Gradle release, UNSIGNED)
#   scripts/release/build.sh gio     <output-file>   Android Gio logic APK (gogio)
#
# Reproducibility discipline applied here (see
# docs/step15-签名与可复现构建.md for the per-artifact analysis):
#
#   - Go toolchain is pinned by the go directive in app/go.mod
#     (1.25.5) and the CI setup-go step; the module graph is locked
#     by go.sum.
#   - All Go builds use -trimpath (no build-machine paths in the
#     binary) and -buildvcs=false (no VCS stamp — the checkout a
#     third party builds from may be an archive export with no
#     .git). For gogio, which shells out to `go build` itself,
#     the same flags are exported via GOFLAGS so its build
#     inherits them (verified against gogio v0.10.3 source: it
#     appends os.Environ() to its go build environment).
#   - The Windows exe additionally gets -buildid= (empty) so no
#     linker build ID can vary.
#   - Client version identity is asserted against the source
#     defaults in app/service/update.go and stamped via
#     -ldflags -X (string var ClientVersion). ClientVersionCode
#     is an int var and CANNOT be set with -X (verified:
#     "cannot set with -X: not a var of type string"); the build
#     therefore refuses to proceed when the release version's
#     code differs from the source default — bump the defaults
#     in update.go as part of the version-bump commit instead.
#
# Signing is NOT done here except where the builder owns it
# (gogio signs its APK; see the gio notes in release.sh). This
# script produces the exact bytes that release.sh then signs.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=version.sh
source "$(dirname "${BASH_SOURCE[0]}")/version.sh"

GO_TAGS="with_quic with_utls with_wireguard with_gvisor"
export PATH="$HOME/tools/go/bin:$PATH"

target="${1:-}"
out="${2:-}"
if [ -z "$target" ] || [ -z "$out" ]; then
    echo "usage: $0 <windows|shell|gio> <output-file>" >&2
    exit 2
fi
mkdir -p "$(dirname "$out")"
out="$(cd "$(dirname "$out")" && pwd)/$(basename "$out")"

# Assert the client's compiled-in version defaults match the
# version being built (see header note on ClientVersionCode).
assert_client_version() {
    local src="$ROOT/app/service/update.go"
    local def_version def_code
    def_version="$(grep -o 'ClientVersion[[:space:]]*=[[:space:]]*"[^"]*"' "$src" | head -1 | sed 's/.*"\([^"]*\)"/\1/')"
    def_code="$(grep -o 'ClientVersionCode[[:space:]]*=[[:space:]]*[0-9]*' "$src" | head -1 | grep -o '[0-9]*$')"
    if [ "$def_version" != "$RELAVIA_VERSION" ] || [ "$def_code" != "$RELAVIA_VERSION_CODE" ]; then
        echo "build.sh: app/service/update.go defaults are ClientVersion=$def_version / ClientVersionCode=$def_code," >&2
        echo "but the release version is $RELAVIA_VERSION / $RELAVIA_VERSION_CODE." >&2
        echo "Bump the defaults in update.go as part of the version-bump commit, then rebuild." >&2
        echo "(ClientVersionCode is an int var; -ldflags -X cannot stamp it — see docs/step15.)" >&2
        exit 4
    fi
}

stamp_ldflags() {
    echo "-X openproxy/app/service.ClientVersion=$RELAVIA_VERSION"
}

build_windows() {
    assert_client_version
    echo "== Windows client (deterministic) =="
    echo "version $RELAVIA_VERSION (code $RELAVIA_VERSION_CODE), tags: $GO_TAGS"
    (cd "$ROOT/app" && CGO_ENABLED=0 GOOS=windows GOARCH=amd64 \
        go build -trimpath -buildvcs=false -tags "$GO_TAGS" \
        -ldflags "-s -w -buildid= $(stamp_ldflags)" \
        -o "$out" ./cmd/relavia)
    ls -l "$out"
    sha256sum "$out"
}

require_android_tools() {
    local missing=()
    command -v java >/dev/null 2>&1 || missing+=("java (JDK 17)")
    if [ -z "${ANDROID_HOME:-}" ] && [ -z "${ANDROID_SDK_ROOT:-}" ] && ! command -v sdkmanager >/dev/null 2>&1; then
        missing+=("Android SDK (set ANDROID_HOME)")
    fi
    if [ "${#missing[@]}" -gt 0 ]; then
        echo "build.sh: missing tools: ${missing[*]}" >&2
        exit 3
    fi
}

build_shell() {
    require_android_tools
    command -v gradle >/dev/null 2>&1 || { echo "build.sh: gradle not found" >&2; exit 3; }
    echo "== Android shell APK (Gradle assembleRelease, unsigned) =="
    echo "versionName $RELAVIA_VERSION, versionCode $RELAVIA_VERSION_CODE"
    (cd "$ROOT/android" && gradle :app:assembleRelease --console=plain \
        -PrelaviaVersionName="$RELAVIA_VERSION" \
        -PrelaviaVersionCode="$RELAVIA_VERSION_CODE")
    local apk="$ROOT/android/app/build/outputs/apk/release/app-release-unsigned.apk"
    cp "$apk" "$out"
    ls -l "$out"
    sha256sum "$out"
}

build_gio() {
    require_android_tools
    command -v gogio >/dev/null 2>&1 || {
        echo "build.sh: gogio not found; install with: go install gioui.org/cmd/gogio@v0.10.3" >&2
        exit 3
    }
    if [ -z "${ANDROID_NDK_HOME:-}" ] && [ -z "${ANDROID_NDK_ROOT:-}" ]; then
        echo "build.sh: gogio needs an Android NDK (set ANDROID_NDK_HOME)" >&2
        exit 3
    fi
    assert_client_version
    echo "== Android Gio logic APK (gogio) =="
    echo "gogio -version $RELAVIA_GOGIO_VERSION, tags: $GO_TAGS"
    # gogio's internal `go build` inherits GOFLAGS (see header).
    export GOFLAGS="-trimpath -buildvcs=false"
    local sign_args=()
    if [ -n "${RELAVIA_ANDROID_KEYSTORE:-}" ]; then
        # Release signing at build time: gogio signs with the
        # injected keystore; the password comes from
        # RELAVIA_ANDROID_KEYSTORE_PASS via gogio's own
        # GOGIO_SIGNPASS environment variable (never a CLI arg,
        # so it does not land in process listings).
        sign_args=(-signkey "$RELAVIA_ANDROID_KEYSTORE")
        export GOGIO_SIGNPASS="${RELAVIA_ANDROID_KEYSTORE_PASS:-}"
        echo "signing: injected keystore $RELAVIA_ANDROID_KEYSTORE"
    else
        echo "WARNING: RELAVIA_ANDROID_KEYSTORE not set — gogio will sign with" >&2
        echo "~/.android/debug.keystore if present, else a RANDOM throwaway" >&2
        echo "keystore. The result is NOT release-signed and is NOT" >&2
        echo "byte-reproducible across machines. Drill/CI use only." >&2
    fi
    (cd "$ROOT/app" && gogio -target android -appid org.relavia.client \
        -version "$RELAVIA_GOGIO_VERSION" -tags "$GO_TAGS" \
        -ldflags "$(stamp_ldflags)" \
        "${sign_args[@]}" \
        -o "$out" ./cmd/relavia-android)
    ls -l "$out"
    sha256sum "$out"
}

case "$target" in
    windows) build_windows ;;
    shell) build_shell ;;
    gio) build_gio ;;
    *) echo "usage: $0 <windows|shell|gio> <output-file>" >&2; exit 2 ;;
esac
