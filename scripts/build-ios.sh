#!/usr/bin/env bash
set -euo pipefail

# ── iOS cross-compilation build script ───────────────────────────────────
# Prerequisites: macOS, Xcode 15+, Rust stable
# See: docs/build-ios.md

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
DIST_DIR="$ROOT_DIR/dist/ios"
INCLUDE_DIR="$ROOT_DIR/include"
XCFRAMEWORK_OUT="$DIST_DIR/secure_core.xcframework"

# ── Preflight checks ────────────────────────────────────────────────────

if [[ "$(uname)" != "Darwin" ]]; then
    echo "ERROR: This script must be run on macOS."
    exit 1
fi

if ! command -v xcodebuild &>/dev/null; then
    echo "ERROR: Xcode command-line tools not found. Install Xcode 15+."
    exit 1
fi

if [ ! -f "$INCLUDE_DIR/secure_core.h" ]; then
    echo "ERROR: include/secure_core.h not found. Run the header generation first."
    exit 1
fi

# ── Install targets ─────────────────────────────────────────────────────

echo "==> Installing Rust iOS targets"
rustup target add aarch64-apple-ios 2>/dev/null || true
rustup target add aarch64-apple-ios-sim 2>/dev/null || true
rustup target add x86_64-apple-ios 2>/dev/null || true

# ── Build ────────────────────────────────────────────────────────────────

echo "==> Building for aarch64-apple-ios (device)"
cargo build --release --target aarch64-apple-ios

echo "==> Building for aarch64-apple-ios-sim (simulator arm64)"
cargo build --release --target aarch64-apple-ios-sim

echo "==> Building for x86_64-apple-ios (simulator Intel)"
cargo build --release --target x86_64-apple-ios

# ── Create fat lib for simulator (arm64 + x86_64) ───────────────────────

echo "==> Creating fat simulator library"
mkdir -p "$DIST_DIR/sim"

lipo -create \
    "$ROOT_DIR/target/aarch64-apple-ios-sim/release/libsecure_core.a" \
    "$ROOT_DIR/target/x86_64-apple-ios/release/libsecure_core.a" \
    -output "$DIST_DIR/sim/libsecure_core.a"

# ── Create xcframework ──────────────────────────────────────────────────

echo "==> Creating xcframework"
rm -rf "$XCFRAMEWORK_OUT"

xcodebuild -create-xcframework \
    -library "$ROOT_DIR/target/aarch64-apple-ios/release/libsecure_core.a" \
    -headers "$INCLUDE_DIR" \
    -library "$DIST_DIR/sim/libsecure_core.a" \
    -headers "$INCLUDE_DIR" \
    -output "$XCFRAMEWORK_OUT"

# ── Add module.modulemap for Swift import ────────────────────────────────

echo "==> Adding module.modulemap to each slice"
MODULEMAP_CONTENT='module secure_core {
    header "secure_core.h"
    export *
}'
for slice_dir in "$XCFRAMEWORK_OUT"/*/Headers; do
    echo "$MODULEMAP_CONTENT" > "$slice_dir/module.modulemap"
    echo "  Created modulemap in $(basename "$(dirname "$slice_dir")")"
done

# ── Checksums ────────────────────────────────────────────────────────────

echo ""
echo "==> SHA-256 checksums"
find "$XCFRAMEWORK_OUT" -name '*.a' -exec shasum -a 256 {} \;

echo ""
echo "==> Done. xcframework at $XCFRAMEWORK_OUT"
