# Building secure-core for Android

## Prerequisites

| Requirement | Version | Notes |
| ----------- | ------- | ----- |
| Rust stable | 1.75+ | Via `rustup` (managed by `rust-toolchain.toml`) |
| Android NDK | r27+ | Provides the cross-compilation toolchain |
| Android API level | 24+ | Minimum supported (Android 7.0 Nougat) |

## Environment Setup

### 1. Install the NDK

Via Android Studio SDK Manager, or CLI:

```bash
sdkmanager --install 'ndk;27.2.12479018'
```

### 2. Set `ANDROID_NDK_HOME`

```bash
# ~/.zshrc or ~/.bashrc
export ANDROID_NDK_HOME="$HOME/Library/Android/sdk/ndk/27.2.12479018"
```

### 3. Configure Cargo linkers

Run the setup helper for detailed instructions:

```bash
bash scripts/setup-ndk.sh
```

Or add directly to `secure-core/.cargo/config.toml`:

```toml
[target.aarch64-linux-android]
ar = "$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin/llvm-ar"
linker = "$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin/aarch64-linux-android24-clang"

[target.armv7-linux-androideabi]
ar = "$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin/llvm-ar"
linker = "$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin/armv7a-linux-androideabi24-clang"
```

Replace `darwin-x86_64` with `linux-x86_64` on Linux hosts.

## Building

### Quick build (both targets)

```bash
bash scripts/build-android.sh
```

### Manual build (single target)

```bash
rustup target add aarch64-linux-android
cargo build --release --target aarch64-linux-android
```

## Output

Build artifacts are placed in:

```
dist/android/
├── arm64-v8a/
│   └── libsecure_core.so
└── armeabi-v7a/
    └── libsecure_core.so
```

## Integrating into Android Studio

### Option A: Copy to `jniLibs`

Copy the `.so` files into your Android project:

```
app/src/main/jniLibs/
├── arm64-v8a/
│   └── libsecure_core.so
└── armeabi-v7a/
    └── libsecure_core.so
```

Gradle will automatically package them into the APK.

### Option B: Configure in `build.gradle.kts`

```kotlin
android {
    sourceSets {
        getByName("main") {
            jniLibs.srcDirs("path/to/dist/android")
        }
    }
}
```

## Loading from Kotlin

```kotlin
companion object {
    init {
        System.loadLibrary("secure_core")
    }
}
```

Then declare JNI native methods that call the C FFI functions.

## Verification

After building, verify the shared library:

```bash
file dist/android/arm64-v8a/libsecure_core.so
# Expected: ELF 64-bit LSB shared object, ARM aarch64

nm -D dist/android/arm64-v8a/libsecure_core.so | grep secure_core
# Should list: secure_core_encrypt_bytes, secure_core_decrypt_bytes, etc.
```
