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

DIST_DIR="$(cd "$(dirname "$0")/.." && pwd)/dist/android"

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
    cargo build --release --target "$target"
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
echo "==> SHA-256 checksums"
find "$DIST_DIR" -name '*.so' -exec sha256sum {} \;

echo ""
echo "==> Done. Artifacts in $DIST_DIR/"
