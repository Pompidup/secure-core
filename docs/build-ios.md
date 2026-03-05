# Build iOS — secure_core.xcframework

## Prerequisites

- **macOS** (Ventura 13+ recommended)
- **Xcode 15+** with command-line tools (`xcode-select --install`)
- **Rust stable** 1.75+ (`rustup update stable`)

## Build

```bash
chmod +x scripts/build-ios.sh
./scripts/build-ios.sh
```

The script will:
1. Install iOS Rust targets (`aarch64-apple-ios`, `aarch64-apple-ios-sim`, `x86_64-apple-ios`)
2. Build the static library for device and simulators
3. Create a fat simulator lib (arm64 + x86_64) via `lipo`
4. Package everything into `dist/ios/secure_core.xcframework`

## Output

```
dist/ios/secure_core.xcframework/
  ios-arm64/
    libsecure_core.a
    Headers/secure_core.h
  ios-arm64_x86_64-simulator/
    libsecure_core.a
    Headers/secure_core.h
```

## Integrate in Xcode

1. Drag `secure_core.xcframework` into your Xcode project navigator
2. In target > **General** > **Frameworks, Libraries, and Embedded Content**, set to **Do Not Embed** (static lib)
3. In **Build Settings** > **Header Search Paths**, add the path to the xcframework headers if needed
4. Add `#import "secure_core.h"` in your bridging header (Swift) or source file (ObjC)

## Integrate in React Native iOS (Podfile)

Add to your `ios/Podfile`:

```ruby
pod 'SecureCore', :path => '../path/to/secure-core', :modular_headers => true
```

Or manual linking:
1. Copy `secure_core.xcframework` into `ios/Frameworks/`
2. In Xcode, add it via **Build Phases** > **Link Binary With Libraries**
3. Set **Framework Search Paths** to `$(PROJECT_DIR)/Frameworks`

## Checksum Validation

After building, verify the output checksums:

```bash
find dist/ios/secure_core.xcframework -name '*.a' -exec shasum -a 256 {} \;
```

Compare with the checksums printed at the end of `build-ios.sh`.
