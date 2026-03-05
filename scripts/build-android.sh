#!/usr/bin/env bash
set -euo pipefail

# ── Android cross-compilation build script ───────────────────────────────
# Prerequisites: ANDROID_NDK_HOME set, linkers configured in .cargo/config.toml
# See: docs/build-android.md and scripts/setup-ndk.sh

TARGETS=(
    "aarch64-linux-android"
    "armv7-linux-androideabi"
)

ABI_MAP_aarch64_linux_android="arm64-v8a"
ABI_MAP_armv7_linux_androideabi="armeabi-v7a"

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
DIST_DIR="$ROOT_DIR/dist/android"
JNILIBS_DIR="$ROOT_DIR/android/secure-core-android/src/main/jniLibs"

echo "==> Checking ANDROID_NDK_HOME"
if [ -z "${ANDROID_NDK_HOME:-}" ]; then
    echo "ERROR: ANDROID_NDK_HOME is not set. See scripts/setup-ndk.sh"
    exit 1
fi

echo "==> Installing Rust targets"
for target in "${TARGETS[@]}"; do
    rustup target add "$target" 2>/dev/null || true
done

echo "==> Building for Android targets"
for target in "${TARGETS[@]}"; do
    echo "--- Building $target (release)"
    cargo build --release --features jni --target "$target"
done

echo "==> Copying artifacts to dist/"
rm -rf "$DIST_DIR"

for target in "${TARGETS[@]}"; do
    # Map target to Android ABI directory name
    abi_var="ABI_MAP_${target//-/_}"
    abi="${!abi_var}"

    mkdir -p "$DIST_DIR/$abi"

    so_path="target/$target/release/libsecure_core.so"
    if [ -f "$so_path" ]; then
        cp "$so_path" "$DIST_DIR/$abi/"
        echo "  $abi/libsecure_core.so"
    else
        echo "  WARNING: $so_path not found"
    fi
done

echo ""
echo "==> Copying .so files to Android module jniLibs/"
rm -rf "$JNILIBS_DIR"

for target in "${TARGETS[@]}"; do
    abi_var="ABI_MAP_${target//-/_}"
    abi="${!abi_var}"

    so_path="target/$target/release/libsecure_core.so"
    if [ -f "$so_path" ]; then
        mkdir -p "$JNILIBS_DIR/$abi"
        cp "$so_path" "$JNILIBS_DIR/$abi/"
        hash=$(sha256sum "$JNILIBS_DIR/$abi/libsecure_core.so" | cut -d' ' -f1)
        echo "Copied libsecure_core.so to Android module — SHA256: $hash ($abi)"
    fi
done

echo ""
echo "==> SHA-256 checksums"
find "$DIST_DIR" -name '*.so' -exec sha256sum {} \;

echo ""
echo "==> Done. Artifacts in $DIST_DIR/ and $JNILIBS_DIR/"
