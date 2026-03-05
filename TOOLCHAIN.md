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

## iOS Cross-Compilation (Planned)

| Rust target | Architecture | Notes |
| ----------- | ------------ | ----- |
| `aarch64-apple-ios` | ARM64 device | Planned V2 |
| `aarch64-apple-ios-sim` | ARM64 simulator | Planned V2 |

## CI Environment

- Ubuntu latest (GitHub Actions)
- Cross-compilation check: `cargo check --target <target>` (no NDK required)
- Full build: requires NDK (local or dedicated CI runner)
