#!/usr/bin/env bash
# Relavia release assembly (Step 15).
#
#   scripts/release/release.sh [--version V] [--channel stable|beta]
#                              [--seq N] [--out DIR] [--notes FILE]
#                              [--allow-unsigned] [--require-all]
#
# Assembles dist/release/v<VERSION>/ with:
#
#   relavia-windows-amd64.exe   Windows client (deterministic build)
#   relavia-android-arm64.apk   Android client — the Gio logic APK;
#                               this is the android-arm64 artifact of
#                               the update manifest (spec example name)
#   relavia-android-shell.apk   Android VpnService shell APK (Gradle);
#                               a release asset + SHA256SUMS entry but
#                               NOT an update-manifest artifact — it is
#                               a component shell, not the updatable
#                               client (see docs/step15)
#   update-<channel>.json       relavia-update/v1 manifest, signed
#   SHA256SUMS                  sha256 of every artifact + manifest
#   RELEASE-NOTES.txt           provenance + per-artifact signing status
#
# Keys are INJECTED, never stored in the repo (see
# docs/step15-签名与可复现构建.md §密钥注入点清单):
#
#   RELAVIA_RELEASE_KEY           path to base64 Ed25519 release private key
#   RELAVIA_ANDROID_KEYSTORE      path to the Android release keystore
#   RELAVIA_ANDROID_KEYSTORE_PASS keystore password
#   RELAVIA_ANDROID_KEY_ALIAS     key alias (default: relavia)
#   RELAVIA_ANDROID_KEY_PASS      key password (default: keystore password)
#   RELAVIA_WIN_PFX               path to the Windows code-signing .pfx
#   RELAVIA_WIN_PFX_PASS          .pfx password
#
# Missing keys degrade LOUDLY, never silently:
#   - no RELAVIA_RELEASE_KEY  -> abort before the manifest step
#     (pass --allow-unsigned for a clearly-labelled unsigned draft);
#   - no Android keystore     -> shell APK stays UNSIGNED, Gio APK
#     keeps gogio's fallback key; both are flagged in RELEASE-NOTES
#     and are NOT distributable;
#   - no Windows cert         -> exe stays unsigned, flagged in
#     RELEASE-NOTES. Per the 2026-11-13 release-policy ruling
#     this is the STANDING arrangement, not a stopgap: SignPath
#     Foundation does not accept security-circumvention tools,
#     and paid certificates require real-name identity
#     verification, so Windows releases ship unsigned and are
#     authenticated by the Ed25519-signed update manifest +
#     published SHA-256 sums instead (docs/step15-签名与可复现构建.md).
#     The Authenticode segment below stays available if a
#     certificate is ever injected.
#
# A missing BUILD TOOL (gradle, NDK, ...) marks that artifact
# MISSING in the notes and the release continues, unless
# --require-all is given.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

VERSION_OVERRIDE=""
CHANNEL="stable"
SEQ=""
OUT_DIR=""
NOTES_FILE=""
ALLOW_UNSIGNED=0
REQUIRE_ALL=0
while [ $# -gt 0 ]; do
    case "$1" in
        --version) VERSION_OVERRIDE="$2"; shift 2 ;;
        --channel) CHANNEL="$2"; shift 2 ;;
        --seq) SEQ="$2"; shift 2 ;;
        --out) OUT_DIR="$2"; shift 2 ;;
        --notes) NOTES_FILE="$2"; shift 2 ;;
        --allow-unsigned) ALLOW_UNSIGNED=1; shift ;;
        --require-all) REQUIRE_ALL=1; shift ;;
        *) echo "release.sh: unknown argument $1" >&2; exit 2 ;;
    esac
done

if [ -n "$VERSION_OVERRIDE" ]; then
    export RELAVIA_VERSION="$VERSION_OVERRIDE"
fi
# shellcheck source=version.sh
source "$(dirname "${BASH_SOURCE[0]}")/version.sh"

if [ -z "$SEQ" ]; then
    SEQ="${RELAVIA_UPDATE_SEQ:-}"
fi
if [ -z "$SEQ" ]; then
    echo "release.sh: --seq N (or RELAVIA_UPDATE_SEQ) is required." >&2
    echo "seq is the per-channel, strictly increasing release counter (docs/relavia-update-v1.md §5);" >&2
    echo "its source of truth is the seq of the last manifest published for this channel." >&2
    exit 2
fi
if [ -z "$OUT_DIR" ]; then
    OUT_DIR="$ROOT/dist/release/v$RELAVIA_VERSION"
fi
mkdir -p "$OUT_DIR"
OUT_DIR="$(cd "$OUT_DIR" && pwd)"

BUILD="$ROOT/scripts/release/build.sh"
STATUS_FILE="$(mktemp)"
trap 'rm -f "$STATUS_FILE"' EXIT
# Callers pass <key> <message...>; BOTH halves must be recorded —
# writing $1 alone drops the message and get_status (which greps
# "^<key> " and cuts from field 2) can never match (Step 15
# completion audit: the status section came out empty).
note_status() { local key="$1"; shift; echo "$key $*" >> "$STATUS_FILE"; }
get_status() { grep "^$1 " "$STATUS_FILE" 2>/dev/null | tail -1 | cut -d' ' -f2- || true; }

# build_one <target> <outfile> -> 0 built, 3 tool-missing
build_one() {
    local target="$1" outfile="$2"
    set +e
    "$BUILD" "$target" "$OUT_DIR/$outfile"
    local rc=$?
    set -e
    if [ $rc -eq 3 ]; then
        note_status "$target" "MISSING (build tool unavailable in this environment)"
        if [ $REQUIRE_ALL -eq 1 ]; then
            echo "release.sh: $target could not be built and --require-all was given" >&2
            exit 1
        fi
        echo "release.sh: WARNING: $target skipped (tool unavailable); continuing" >&2
        return 3
    elif [ $rc -ne 0 ]; then
        echo "release.sh: build of $target FAILED (exit $rc)" >&2
        exit 1
    fi
    return 0
}

echo "=== Relavia release assembly: v$RELAVIA_VERSION (code $RELAVIA_VERSION_CODE), channel $CHANNEL, seq $SEQ ==="
echo "output: $OUT_DIR"

# ---------------------------------------------------------------- artifacts
build_one windows relavia-windows-amd64.exe && note_status windows "built"
build_one gio relavia-android-arm64.apk && note_status gio "built"
build_one shell relavia-android-shell.apk && note_status shell "built"

# ---------------------------------------------------------------- android signing
BT_DIR=""
if [ -n "${ANDROID_HOME:-}" ]; then
    BT_DIR="$(ls -d "$ANDROID_HOME"/build-tools/* 2>/dev/null | sort -V | tail -1 || true)"
fi
APKSIGNER=""
ZIPALIGN=""
# NOTE: these must be if-statements, not bare && lists — under
# `set -e` a standalone && list whose first test is false returns
# 1 and kills the script silently (this bit in environments
# without ANDROID_HOME; found in the Step 15 completion audit).
if [ -n "$BT_DIR" ] && [ -x "$BT_DIR/apksigner" ]; then APKSIGNER="$BT_DIR/apksigner"; fi
if [ -n "$BT_DIR" ] && [ -x "$BT_DIR/zipalign" ]; then ZIPALIGN="$BT_DIR/zipalign"; fi

sign_android() {
    if [ -n "${RELAVIA_ANDROID_KEYSTORE:-}" ]; then
        note_status android-signing "release keystore: $RELAVIA_ANDROID_KEYSTORE"
        # Gio APK was already signed by gogio with this keystore
        # (build.sh passes -signkey). Verify and record the signer.
        if [ -f "$OUT_DIR/relavia-android-arm64.apk" ] && [ -n "$APKSIGNER" ]; then
            if "$APKSIGNER" verify "$OUT_DIR/relavia-android-arm64.apk" 2>/dev/null; then
                note_status gio "built; signature verified (release keystore, via gogio -signkey)"
            else
                note_status gio "built; WARNING: apksigner verify FAILED on the gogio APK"
            fi
        fi
        # Shell APK: built unsigned; align + sign here.
        if [ -f "$OUT_DIR/relavia-android-shell.apk" ]; then
            if [ -n "$APKSIGNER" ] && [ -n "$ZIPALIGN" ]; then
                local tmp="$OUT_DIR/.shell-aligned.apk"
                "$ZIPALIGN" -f -p 4 "$OUT_DIR/relavia-android-shell.apk" "$tmp"
                RELAVIA_ANDROID_KEY_PASS="${RELAVIA_ANDROID_KEY_PASS:-${RELAVIA_ANDROID_KEYSTORE_PASS:-}}"
                "$APKSIGNER" sign \
                    --ks "$RELAVIA_ANDROID_KEYSTORE" \
                    --ks-pass "env:RELAVIA_ANDROID_KEYSTORE_PASS" \
                    --ks-key-alias "${RELAVIA_ANDROID_KEY_ALIAS:-relavia}" \
                    --key-pass "env:RELAVIA_ANDROID_KEY_PASS" \
                    --out "$OUT_DIR/relavia-android-shell.apk.signed" "$tmp"
                mv "$OUT_DIR/relavia-android-shell.apk.signed" "$OUT_DIR/relavia-android-shell.apk"
                rm -f "$tmp"
                "$APKSIGNER" verify "$OUT_DIR/relavia-android-shell.apk"
                local cert
                cert="$("$APKSIGNER" verify --print-certs "$OUT_DIR/relavia-android-shell.apk" 2>/dev/null | grep -i 'SHA-256 digest' | head -1 || true)"
                note_status shell "built; signed with release keystore (apksigner). $cert"
            else
                note_status shell "built; WARNING: keystore set but apksigner/zipalign not found — left UNSIGNED"
            fi
        fi
    else
        note_status android-signing "NO RELEASE KEYSTORE INJECTED — Android artifacts are NOT release-signed"
        # if-guards, not && lists (set -e — see the APKSIGNER note).
        if [ -f "$OUT_DIR/relavia-android-arm64.apk" ]; then note_status gio "built; signed by gogio fallback key (debug or random) — NOT the release key"; fi
        if [ -f "$OUT_DIR/relavia-android-shell.apk" ]; then note_status shell "built; UNSIGNED"; fi
    fi
}
sign_android

# ---------------------------------------------------------------- windows signing
sign_windows() {
    local exe="$OUT_DIR/relavia-windows-amd64.exe"
    [ -f "$exe" ] || return 0
    if [ -z "${RELAVIA_WIN_PFX:-}" ]; then
        note_status windows "built; UNSIGNED (standing release policy: unsigned exe + Ed25519-signed manifest — 2026-11-13 ruling, docs/step15)"
        return 0
    fi
    local signer=""
    if command -v osslsigncode >/dev/null 2>&1; then
        signer="osslsigncode"
    elif [ "${OSTYPE:-}" = "msys" ] || [ "${OSTYPE:-}" = "cygwin" ]; then
        # Only on Windows is `signtool` the Authenticode tool. On
        # Linux the same name is Mono's JAR signer — never use it
        # for Authenticode (see docs/step15).
        signer="signtool"
    fi
    if [ -z "$signer" ]; then
        note_status windows "built; UNSIGNED (RELAVIA_WIN_PFX set but no Authenticode tool: install osslsigncode, or run on Windows for signtool)"
        echo "release.sh: WARNING: RELAVIA_WIN_PFX is set but no Authenticode signing tool is available" >&2
        return 0
    fi
    if [ "$signer" = "osslsigncode" ]; then
        osslsigncode sign -pkcs12 "$RELAVIA_WIN_PFX" -pass "${RELAVIA_WIN_PFX_PASS:-}" \
            -n "Relavia" -i "https://relavia.github.io" -h sha256 \
            -t "http://timestamp.digicert.com" \
            -in "$exe" -out "$exe.signed"
        mv "$exe.signed" "$exe"
        osslsigncode verify "$exe" >/dev/null
    else
        signtool sign /f "$RELAVIA_WIN_PFX" /p "${RELAVIA_WIN_PFX_PASS:-}" \
            /fd SHA256 /tr "http://timestamp.digicert.com" /td SHA256 "$exe"
    fi
    note_status windows "built; Authenticode-signed ($signer, RFC 3161 timestamp)"
}
sign_windows

# ---------------------------------------------------------------- manifest
TOOL_BIN="$(mktemp -d)/releasetool"
(cd "$ROOT/tools/releasetool" && go build -o "$TOOL_BIN" .)

MANIFEST_ARGS=()
# if-guards, not && lists (set -e — see the APKSIGNER note).
if [ -f "$OUT_DIR/relavia-windows-amd64.exe" ]; then MANIFEST_ARGS+=(--artifact "windows-amd64=$OUT_DIR/relavia-windows-amd64.exe"); fi
if [ -f "$OUT_DIR/relavia-android-arm64.apk" ]; then MANIFEST_ARGS+=(--artifact "android-arm64=$OUT_DIR/relavia-android-arm64.apk"); fi
if [ "${#MANIFEST_ARGS[@]}" -eq 0 ]; then
    echo "release.sh: no updatable artifacts were built; cannot emit a manifest" >&2
    exit 1
fi
if [ -z "${RELAVIA_RELEASE_KEY:-}" ] && [ $ALLOW_UNSIGNED -eq 0 ]; then
    echo "release.sh: RELAVIA_RELEASE_KEY is not set — refusing to emit an unsigned manifest." >&2
    echo "Inject the release private key, or pass --allow-unsigned for a labelled draft." >&2
    exit 1
fi
MANIFEST_FILE="$OUT_DIR/update-$CHANNEL.json"
BASE_URL="https://github.com/relavia/relavia/releases/download/v$RELAVIA_VERSION"
"$TOOL_BIN" manifest \
    --version "$RELAVIA_VERSION" \
    --channel "$CHANNEL" \
    --seq "$SEQ" \
    --base-url "$BASE_URL" \
    ${NOTES_FILE:+--notes "$NOTES_FILE"} \
    "${MANIFEST_ARGS[@]}" \
    --out "$MANIFEST_FILE"
if [ -n "${RELAVIA_RELEASE_KEY:-}" ]; then
    PUBKEY_OUT="$OUT_DIR/release-pubkey.txt"
    # Derive the public key file for verifiers from the manifest
    # verification step below; releasetool verify needs the pubkey
    # explicitly, so require the releaser to also provide it.
    if [ -n "${RELAVIA_RELEASE_PUBKEY:-}" ]; then
        cp "$RELAVIA_RELEASE_PUBKEY" "$PUBKEY_OUT"
        "$TOOL_BIN" verify --manifest "$MANIFEST_FILE" --pubkey "$RELAVIA_RELEASE_PUBKEY" --dir "$OUT_DIR"
        note_status manifest "signed with the injected release key; self-verification passed (incl. file re-hash)"
    else
        note_status manifest "signed with the injected release key; self-verification SKIPPED (RELAVIA_RELEASE_PUBKEY not provided)"
        echo "release.sh: WARNING: set RELAVIA_RELEASE_PUBKEY (path to the base64 public key file) to self-verify the manifest" >&2
    fi
else
    note_status manifest "UNSIGNED DRAFT (--allow-unsigned): clients will reject this manifest"
fi

# ---------------------------------------------------------------- checksums + notes
(cd "$OUT_DIR" && ls relavia-* update-*.json 2>/dev/null | sort | xargs sha256sum > SHA256SUMS)

{
    echo "Relavia release v$RELAVIA_VERSION (channel $CHANNEL, seq $SEQ)"
    echo "git commit: $(git -C "$ROOT" rev-parse HEAD 2>/dev/null || echo unknown)"
    echo "assembled at (UTC): $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    # go version is taken from inside the app module: with a
    # toolchain-switching launcher this reports the EFFECTIVE
    # toolchain (e.g. 1.25.5), not the launcher's own version.
    echo "go: $(cd "$ROOT/app" && go version 2>/dev/null || echo unavailable)"
    if command -v java >/dev/null 2>&1; then
        echo "java: $(java -version 2>&1 | head -1)"
    else
        echo "java: unavailable"
    fi
    echo "gradle: $(gradle -v 2>/dev/null | grep '^Gradle' || echo unavailable)"
    echo ""
    echo "Artifacts:"
    while IFS= read -r line; do echo "  $line"; done < <(cd "$OUT_DIR" && sha256sum relavia-* 2>/dev/null || true)
    echo ""
    echo "Per-artifact status:"
    for k in windows gio shell android-signing manifest; do
        s="$(get_status "$k")"
        [ -n "$s" ] && echo "  [$k] $s"
    done
    echo ""
    echo "Update manifest: update-$CHANNEL.json (format relavia-update/v1)"
    echo "Verify with: tools/releasetool verify --manifest update-$CHANNEL.json --pubkey <release pubkey> --dir ."
    echo "Reproducibility: see docs/step15-签名与可复现构建.md and docs/复现构建验证指南.md"
} > "$OUT_DIR/RELEASE-NOTES.txt"

echo ""
echo "=== release assembled in $OUT_DIR ==="
ls -l "$OUT_DIR"
cat "$OUT_DIR/RELEASE-NOTES.txt"
