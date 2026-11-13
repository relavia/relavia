#!/usr/bin/env bash
# Relavia reproducibility check (Step 15).
#
#   scripts/release/repro-check.sh [windows|shell|gio|all] [--report FILE] [--worktree]
#
# Builds the chosen artifacts TWICE, each time from a fresh
# `git archive` export into its own isolated directory (no
# .git, different absolute paths — the two conditions under which
# path-embedding and VCS-stamping bugs show up), then compares
# SHA-256 of the outputs.
#
# The default export source is HEAD (the commit being released).
# --worktree exports the current working tree instead (via a
# temporary git index + write-tree, so untracked and modified
# files are included exactly as they would be committed, and
# .gitignore still applies). --worktree exists to verify the
# release pipeline itself before its own commit lands; release
# verification proper always uses HEAD.
#
# Verdicts per target:
#   REPRODUCIBLE        both builds byte-identical
#   NOT REPRODUCIBLE    hashes differ (zipdiff / byte-diff detail
#                       is printed to localize the difference)
#   UNVERIFIED (env)    a build tool is unavailable here; the
#                       target must be checked where the tool
#                       exists (the CI `repro` job provides the
#                       full environment)
#
# Gio note: byte-identity of a SIGNED apk across two builds
# requires the same signing key. When RELAVIA_ANDROID_KEYSTORE is
# not injected, this script generates a throwaway TEST-ONLY
# keystore (alias relavia-repro-test, password relavia-test-only)
# inside the check's temp directory, uses it for both builds, and
# deletes it with the temp directory. It is never written into
# the repository and must never be used for a real release.
#
# Exit code: 1 if any attempted target is NOT REPRODUCIBLE, else 0.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TARGET="all"
REPORT=""
FROM_WORKTREE=0
while [ $# -gt 0 ]; do
    case "$1" in
        windows|shell|gio|all) TARGET="$1"; shift ;;
        --report) REPORT="${2:-}"; shift 2 ;;
        --worktree) FROM_WORKTREE=1; shift ;;
        *) echo "usage: $0 [windows|shell|gio|all] [--report FILE] [--worktree]" >&2; exit 2 ;;
    esac
done

if [ -n "$REPORT" ] && [ "${REPRO_TEE:-}" != "1" ]; then
    # Re-run self through tee so the console and the report file
    # see the same output; propagate the real exit code.
    if [ "$FROM_WORKTREE" = "1" ]; then
        REPRO_TEE=1 "$0" "$TARGET" --worktree 2>&1 | tee "$REPORT"
    else
        REPRO_TEE=1 "$0" "$TARGET" 2>&1 | tee "$REPORT"
    fi
    exit "${PIPESTATUS[0]}"
fi

WORK="$(mktemp -d /tmp/relavia-repro-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

echo "=== Relavia reproducibility check ==="
echo "commit: $(git -C "$ROOT" rev-parse HEAD)"
echo "date (UTC): $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "go: $(go version 2>/dev/null || echo unavailable)"

FAILURES=0

# The tree object both exports are taken from: HEAD normally,
# or (with --worktree) a write-tree of the working tree staged
# through a throwaway index (the real index is never touched).
SOURCE_TREE="HEAD"
if [ "$FROM_WORKTREE" = "1" ]; then
    TMPINDEX="$WORK/tmp-index"
    GIT_INDEX_FILE="$TMPINDEX" git -C "$ROOT" add -A
    SOURCE_TREE="$(GIT_INDEX_FILE="$TMPINDEX" git -C "$ROOT" write-tree)"
    echo "source: working tree (temporary-index tree $SOURCE_TREE)"
else
    echo "source: HEAD"
fi

# Export $SOURCE_TREE into $1 (fresh directory, no .git).
export_tree() {
    mkdir -p "$1"
    git -C "$ROOT" archive "$SOURCE_TREE" | tar -x -C "$1"
}

# build_in <tree> <target> <outfile-name> -> build.sh exit code
build_in() {
    local tree="$1" target="$2" name="$3"
    "$tree/scripts/release/build.sh" "$target" "$tree/out/$name" > "$tree/build-$target.log" 2>&1
    return $?
}

check_target() {
    local target="$1" name="$2"
    echo ""
    echo "--- target: $target ---"
    local A="$WORK/A-$target" B="$WORK/B-$target"
    export_tree "$A"
    export_tree "$B"
    if [ "$target" = "shell" ]; then
        # The Gradle shell build requires android/app/libs/
        # libboxbind.aar as an input (absence is a build error by
        # design — docs/libbox绑定.md §5), and the AAR is a
        # gitignored build artifact, so no source export contains
        # it. Inject the checkout's AAR into BOTH trees as a
        # shared, identical input: the check then verifies that
        # the Gradle packaging is reproducible GIVEN that input
        # (the AAR's own reproducibility is a separate question,
        # tracked in docs/step15-签名与可复现构建.md).
        local aar="$ROOT/android/app/libs/libboxbind.aar"
        if [ ! -f "$aar" ]; then
            echo "shell: UNVERIFIED (env) — $aar not present in this checkout"
            echo "  (build it with: scripts/build-android.sh bind — needs gomobile + an Android NDK;"
            echo "   the CI repro job does exactly that before running this check)"
            return 0
        fi
        mkdir -p "$A/android/app/libs" "$B/android/app/libs"
        cp "$aar" "$A/android/app/libs/libboxbind.aar"
        cp "$aar" "$B/android/app/libs/libboxbind.aar"
        echo "shell: injected shared input libboxbind.aar (sha256 $(sha256sum "$aar" | cut -d' ' -f1)) into both trees"
        # Same shared-input treatment for the OpenVPN 3 build
        # products: the SWIG bindings (net.openvpn.ovpn3) and
        # libovpn3android.so are gitignored outputs of
        # android/openvpn3/build-openvpn3-android.sh, and the
        # Kotlin sources do not compile without them (branch
        # run 43494569302 failed on exactly that). When the
        # checkout carries them (CI downloads them from the
        # openvpn3-android job), inject identical copies into
        # both trees; when absent, say so — the Gradle build
        # then fails honestly instead of passing on a tree
        # that silently lacks the OpenVPN sources.
        local ovpn3_so="$ROOT/android/app/src/main/jniLibs/arm64-v8a/libovpn3android.so"
        local ovpn3_java="$ROOT/android/app/src/main/java/net/openvpn/ovpn3"
        if [ -f "$ovpn3_so" ] && [ -d "$ovpn3_java" ]; then
            mkdir -p "$A/android/app/src/main/jniLibs/arm64-v8a" "$B/android/app/src/main/jniLibs/arm64-v8a"
            mkdir -p "$A/android/app/src/main/java/net/openvpn" "$B/android/app/src/main/java/net/openvpn"
            cp "$ovpn3_so" "$A/android/app/src/main/jniLibs/arm64-v8a/libovpn3android.so"
            cp "$ovpn3_so" "$B/android/app/src/main/jniLibs/arm64-v8a/libovpn3android.so"
            cp -r "$ovpn3_java" "$A/android/app/src/main/java/net/openvpn/"
            cp -r "$ovpn3_java" "$B/android/app/src/main/java/net/openvpn/"
            echo "shell: injected shared OpenVPN 3 inputs (libovpn3android.so sha256 $(sha256sum "$ovpn3_so" | cut -d' ' -f1) + SWIG bindings) into both trees"
        else
            echo "shell: NOTE — OpenVPN 3 build inputs absent in this checkout; the shell build will fail on the net.openvpn.ovpn3 references (produce them with android/openvpn3/build-openvpn3-android.sh)"
        fi
    fi
    local rc_a rc_b
    build_in "$A" "$target" "$name"; rc_a=$?
    build_in "$B" "$target" "$name"; rc_b=$?
    if [ $rc_a -eq 3 ] || [ $rc_b -eq 3 ]; then
        echo "$target: UNVERIFIED (env) — build tool unavailable (A rc=$rc_a, B rc=$rc_b); see build logs"
        return 0
    fi
    if [ $rc_a -ne 0 ] || [ $rc_b -ne 0 ]; then
        echo "$target: BUILD FAILED (A rc=$rc_a, B rc=$rc_b)"
        tail -5 "$A/build-$target.log" "$B/build-$target.log" 2>/dev/null
        FAILURES=$((FAILURES + 1))
        return 0
    fi
    local hash_a hash_b
    hash_a="$(sha256sum "$A/out/$name" | cut -d' ' -f1)"
    hash_b="$(sha256sum "$B/out/$name" | cut -d' ' -f1)"
    echo "build A: $hash_a"
    echo "build B: $hash_b"
    if [ "$hash_a" = "$hash_b" ]; then
        echo "$target: REPRODUCIBLE (byte-identical)"
        return 0
    fi
    echo "$target: NOT REPRODUCIBLE"
    FAILURES=$((FAILURES + 1))
    case "$name" in
        *.apk)
            python3 "$ROOT/scripts/release/zipdiff.py" "$A/out/$name" "$B/out/$name" || true
            ;;
        *)
            local nbytes
            nbytes="$(cmp -l "$A/out/$name" "$B/out/$name" 2>/dev/null | wc -l)"
            echo "differing bytes: $nbytes (sizes: $(stat -c%s "$A/out/$name") vs $(stat -c%s "$B/out/$name"))"
            ;;
    esac
}

setup_gio_test_keystore() {
    if [ -n "${RELAVIA_ANDROID_KEYSTORE:-}" ]; then
        return 0
    fi
    local test_ks="$WORK/repro-test-only.keystore"
    if command -v keytool >/dev/null 2>&1; then
        keytool -genkeypair -keystore "$test_ks" -alias relavia-repro-test \
            -keyalg RSA -keysize 2048 -validity 3650 \
            -storepass relavia-test-only -keypass relavia-test-only \
            -dname "CN=Relavia Repro TEST ONLY, O=Relavia" >/dev/null 2>&1
        export RELAVIA_ANDROID_KEYSTORE="$test_ks"
        export RELAVIA_ANDROID_KEYSTORE_PASS="relavia-test-only"
        export RELAVIA_ANDROID_KEY_ALIAS="relavia-repro-test"
        export RELAVIA_ANDROID_KEY_PASS="relavia-test-only"
        echo "gio: using a throwaway TEST-ONLY keystore for both builds (deleted with the temp dir)"
    else
        echo "gio: no keystore injected and keytool unavailable — gogio fallback keys will differ per build"
    fi
}

case "$TARGET" in
    windows) check_target windows relavia-windows-amd64.exe ;;
    shell) check_target shell relavia-android-shell.apk ;;
    gio)
        setup_gio_test_keystore
        check_target gio relavia-android-arm64.apk
        ;;
    all)
        check_target windows relavia-windows-amd64.exe
        check_target shell relavia-android-shell.apk
        setup_gio_test_keystore
        check_target gio relavia-android-arm64.apk
        ;;
    *) echo "usage: $0 [windows|shell|gio|all] [--report FILE] [--worktree]" >&2; exit 2 ;;
esac

echo ""
if [ $FAILURES -gt 0 ]; then
    echo "=== RESULT: $FAILURES target(s) NOT REPRODUCIBLE ==="
    exit 1
fi
echo "=== RESULT: all attempted targets REPRODUCIBLE or UNVERIFIED (env) ==="
exit 0
