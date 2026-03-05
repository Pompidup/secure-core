#!/usr/bin/env bash
set -euo pipefail

# ── Android NDK setup helper ────────────────────────────────────────────
# This script prints the configuration needed for cross-compiling to Android.
# It does NOT modify your system — copy the output to your shell profile
# and .cargo/config.toml manually.

echo "=== Android NDK Setup for secure-core ==="
echo ""

# ── Step 1: Install NDK ─────────────────────────────────────────────────

echo "1. Install Android NDK r27+ via Android Studio SDK Manager or:"
echo "   sdkmanager --install 'ndk;27.2.12479018'"
echo ""

# ── Step 2: Set ANDROID_NDK_HOME ─────────────────────────────────────────

echo "2. Set ANDROID_NDK_HOME in your shell profile (~/.zshrc or ~/.bashrc):"
echo ""
echo '   export ANDROID_NDK_HOME="$HOME/Library/Android/sdk/ndk/27.2.12479018"'
echo ""

# ── Step 3: Locate toolchain binaries ────────────────────────────────────

echo "3. The NDK provides prebuilt toolchain binaries at:"
echo '   $ANDROID_NDK_HOME/toolchains/llvm/prebuilt/<host>/bin/'
echo ""
echo "   Host values:"
echo "     macOS:  darwin-x86_64"
echo "     Linux:  linux-x86_64"
echo ""

# ── Step 4: Configure .cargo/config.toml ─────────────────────────────────

PREBUILT="\$ANDROID_NDK_HOME/toolchains/llvm/prebuilt"

echo "4. Add the following to secure-core/.cargo/config.toml:"
echo ""
cat <<'TOML'
[target.aarch64-linux-android]
ar = "$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin/llvm-ar"
linker = "$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin/aarch64-linux-android24-clang"

[target.armv7-linux-androideabi]
ar = "$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin/llvm-ar"
linker = "$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin/armv7a-linux-androideabi24-clang"
TOML
echo ""
echo "   Replace 'darwin-x86_64' with 'linux-x86_64' on Linux."
echo "   Replace '24' with your minimum Android API level."
echo ""

# ── Step 5: Environment variables (alternative to config.toml) ───────────

echo "5. Alternative: set per-target env vars before building:"
echo ""
echo '   # aarch64 (arm64-v8a)'
echo '   export CC_aarch64_linux_android="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin/aarch64-linux-android24-clang"'
echo '   export AR_aarch64_linux_android="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin/llvm-ar"'
echo ""
echo '   # armv7 (armeabi-v7a)'
echo '   export CC_armv7_linux_androideabi="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin/armv7a-linux-androideabi24-clang"'
echo '   export AR_armv7_linux_androideabi="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin/llvm-ar"'
echo ""

echo "=== Setup complete. Run scripts/build-android.sh to build. ==="
