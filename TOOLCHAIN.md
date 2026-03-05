# Toolchain Requirements

## Rust

| Component | Version | Notes |
| --------- | ------- | ----- |
| Rust stable | 1.75+ | Managed by `rust-toolchain.toml` |
| rustfmt | stable | Required for CI |
| clippy | stable | Required for CI |

## Android Cross-Compilation

| Component | Version | Notes |
| --------- | ------- | ----- |
| Android NDK | r27+ (27.2.12479018 tested) | Provides clang cross-compiler |
| Min API level | 24 (Android 7.0 Nougat) | Set in linker suffix (e.g. `android24-clang`) |

### Supported Targets — V1

| Rust target | Android ABI | Architecture | Priority |
| ----------- | ----------- | ------------ | -------- |
| `aarch64-linux-android` | `arm64-v8a` | ARMv8-A 64-bit | Primary |
| `armv7-linux-androideabi` | `armeabi-v7a` | ARMv7-A 32-bit | Secondary |

### Not Yet Supported

| Rust target | Android ABI | Notes |
| ----------- | ----------- | ----- |
| `x86_64-linux-android` | `x86_64` | Emulators only, planned for V2 |
| `i686-linux-android` | `x86` | Legacy emulators, low priority |

## iOS Cross-Compilation

| Component | Version | Notes |
| --------- | ------- | ----- |
| macOS | Ventura 13+ | Required for iOS builds |
| Xcode | 15+ | Provides `xcodebuild`, `lipo` |

### Supported Targets — V1

| Rust target | Architecture | Priority |
| ----------- | ------------ | -------- |
| `aarch64-apple-ios` | ARM64 device | Primary |
| `aarch64-apple-ios-sim` | ARM64 simulator (Apple Silicon) | Primary |
| `x86_64-apple-ios` | x86_64 simulator (Intel) | Secondary |

### Build Command

```bash
./scripts/build-ios.sh
```

Output: `dist/ios/secure_core.xcframework`

## CI Environment

- Ubuntu latest (GitHub Actions) — lint, test, Android cross-check
- macOS latest (GitHub Actions) — iOS xcframework build (tag `v*` only)
- Cross-compilation check: `cargo check --target <target>` (no NDK required)
- Full build: requires NDK (local or dedicated CI runner)
