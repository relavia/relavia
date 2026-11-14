#!/usr/bin/env bash
# Build libovpn3android.so + the net.openvpn.ovpn3 Java bindings
# for Relavia's Android app (docs/openvpn3构建尖峰.md).
#
# What this produces (under android/app/src/main/):
#   jniLibs/<abi>/libovpn3android.so   (generated; git-ignored)
#   java/net/openvpn/ovpn3/*.java      (SWIG output; git-ignored)
#
# Toolchain: Android NDK (pinned below), CMake >= 3.22, SWIG 4,
# vcpkg for the C++ dependencies (asio/fmt/jsoncpp/lz4/xxhash/
# openssl) built for the vcpkg arm64-android family of triplets.
# No LZO anywhere (license red line, docs/openvpn3许可证审查.md).
#
# Usage:
#   ANDROID_NDK_HOME=/path/to/ndk VCPKG_ROOT=/path/to/vcpkg \
#     android/openvpn3/build-openvpn3-android.sh [abi ...]
# Default ABI: arm64-v8a. Extra ABIs (armeabi-v7a, x86_64) use
# the matching vcpkg triplet + NDK ABI name.
set -euo pipefail

OPENVPN3_COMMIT=0c1ce172fe918b05463d71e682a0c2f2d8fe7899   # master, vcpkg.json version-string 3.12
NDK_MIN_API=24                                            # matches the app's minSdk

REPO_ROOT=$(cd "$(dirname "$0")/../.." && pwd)
WORK=${OPENVPN3_WORK:-$(mktemp -d /tmp/ovpn3-build.XXXXXX)}
SRC=$WORK/openvpn3
ABIS=("${@:-arm64-v8a}")

: "${ANDROID_NDK_HOME:?set ANDROID_NDK_HOME to the pinned NDK}"
: "${VCPKG_ROOT:?set VCPKG_ROOT to a vcpkg checkout}"

triplet_for() {
  case "$1" in
    arm64-v8a)   echo arm64-android ;;
    armeabi-v7a) echo arm-neon-android ;;
    x86_64)      echo x64-android ;;
    *) echo "unknown ABI $1" >&2; exit 2 ;;
  esac
}

echo "== fetch openvpn3 @ $OPENVPN3_COMMIT =="
if [ ! -d "$SRC" ]; then
  git clone -q https://github.com/OpenVPN/openvpn3.git "$SRC"
fi
git -C "$SRC" checkout -q "$OPENVPN3_COMMIT"

echo "== apply Relavia downstream patches =="
# Downstream patches live in android/openvpn3/patches/ (see
# the header of each patch for what it changes and why — e.g.
# 0001 makes the core honor the tls-version-max directive for
# VPN Gate pool sessions, diagnosis §10). The reverse check
# keeps re-runs over a reused $WORK idempotent; a patch that
# neither applies nor is already applied fails the build
# loudly rather than silently shipping an unpatched core.
for p in "$REPO_ROOT/android/openvpn3/patches/"*.patch; do
  [ -e "$p" ] || continue
  if git -C "$SRC" apply --check "$p" 2>/dev/null; then
    git -C "$SRC" apply "$p"
    echo "applied $(basename "$p")"
  elif git -C "$SRC" apply --reverse --check "$p" 2>/dev/null; then
    echo "already applied $(basename "$p")"
  else
    echo "downstream patch does not apply: $p" >&2
    exit 2
  fi
done

for ABI in "${ABIS[@]}"; do
  TRIPLET=$(triplet_for "$ABI")
  echo "== vcpkg deps ($TRIPLET) =="
  # Manifest mode would pull tap-windows6/gtest from upstream's
  # vcpkg.json; install the Android subset explicitly instead.
  "$VCPKG_ROOT/vcpkg" install --triplet "$TRIPLET" \
    asio fmt jsoncpp lz4 xxhash openssl
  INSTALLED=$VCPKG_ROOT/installed/$TRIPLET

  echo "== SWIG Java bindings (package net.openvpn.ovpn3) =="
  GEN=$WORK/gen-$ABI
  mkdir -p "$GEN/java"
  swig -c++ -java -package net.openvpn.ovpn3 \
    -outdir "$GEN/java" -o "$GEN/ovpncli_wrap.cpp" \
    -I"$SRC" -I"$SRC/client" "$SRC/client/ovpncli.i"

  echo "== CMake build ($ABI) =="
  # The NDK toolchain alone roots every find_* inside the NDK
  # sysroot (CMAKE_FIND_ROOT_PATH_MODE_* = ONLY), so the vcpkg
  # installed tree is invisible to FindOpenSSL / config packages
  # even via CMAKE_PREFIX_PATH — configure died at
  # find_package(OpenSSL) in CI (run 43499776194). The vcpkg
  # toolchain chainloading the NDK one is the documented fix:
  # vcpkg.cmake adds its installed dir to CMAKE_FIND_ROOT_PATH,
  # which re-roots those searches into the vcpkg tree.
  ls "$INSTALLED/lib" | head -20
  cmake -S "$REPO_ROOT/android/openvpn3" -B "$WORK/build-$ABI" \
    -DCMAKE_TOOLCHAIN_FILE="$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake" \
    -DVCPKG_CHAINLOAD_TOOLCHAIN_FILE="$ANDROID_NDK_HOME/build/cmake/android.toolchain.cmake" \
    -DVCPKG_TARGET_TRIPLET="$TRIPLET" \
    -DANDROID_ABI="$ABI" -DANDROID_PLATFORM=android-$NDK_MIN_API \
    -DCMAKE_BUILD_TYPE=Release \
    -DOPENVPN3_SRC="$SRC" -DVCPKG_INSTALLED_DIR="$VCPKG_ROOT/installed"
  # NOTE: VCPKG_INSTALLED_DIR above is the vcpkg *parent* installed
  # dir — vcpkg.cmake appends /<triplet> itself when building its
  # search roots. Passing the triplet dir here (as this script
  # originally did) made vcpkg search installed/<triplet>/<triplet>
  # and FindOpenSSL still missed (CI run 43500654298). The glue
  # CMakeLists resolves the triplet subdir from this parent.
  # The generated wrapper is a build input of our CMakeLists;
  # stage it where the build expects it.
  cp "$GEN/ovpncli_wrap.cpp" "$GEN/ovpncli_wrap.h" "$WORK/build-$ABI/"
  cmake --build "$WORK/build-$ABI" -j

  echo "== stage into the app tree =="
  OUT_JNI="$REPO_ROOT/android/app/src/main/jniLibs/$ABI"
  mkdir -p "$OUT_JNI"
  cp "$WORK/build-$ABI/libovpn3android.so" "$OUT_JNI/"
  "${ANDROID_NDK_HOME}/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-strip" \
    "$OUT_JNI/libovpn3android.so"
  OUT_JAVA="$REPO_ROOT/android/app/src/main/java/net/openvpn/ovpn3"
  mkdir -p "$OUT_JAVA"
  cp "$GEN/java/"*.java "$OUT_JAVA/"
  ls -la "$OUT_JNI/libovpn3android.so"
done

echo "Done. Generated outputs are git-ignored; the pinned commit"
echo "and this script are the reproducible source of truth."
