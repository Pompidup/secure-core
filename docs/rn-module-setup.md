# React Native Module Setup

## Linking the Native Module

### 1. Register the package in MainApplication

In your RN app's `MainApplication.kt`:

```kotlin
import com.securecore.rn.SecureCorePackage
import com.securecore.rn.SecureCoreServiceLocator

class MainApplication : Application(), ReactApplication {

    override fun onCreate() {
        super.onCreate()

        // Initialize DocumentService (see secure-core-android setup)
        val documentService = // ... build your DocumentService instance
        SecureCoreServiceLocator.documentService = documentService
    }

    override val reactNativeHost = object : DefaultReactNativeHost(this) {
        override fun getPackages() = PackageList(this).packages.apply {
            add(SecureCorePackage())
        }
    }
}
```

### 2. Add secure-core-android as a dependency

In `android/app/build.gradle`:

```groovy
dependencies {
    implementation project(':secure-core-android')
}
```

In `android/settings.gradle`:

```groovy
include ':secure-core-android'
project(':secure-core-android').projectDir = new File(rootProject.projectDir, 'secure-core-android')
```

### 3. Import in JavaScript/TypeScript

```typescript
import { SecureCoreAPI } from './src/native/SecureCore';

const { docId } = await SecureCoreAPI.importDocument(uri);
```

## Running Smoke Tests

```bash
# Install dependencies
npm install

# Run smoke tests (mocked, no device needed)
npm run test:smoke
```

The smoke tests mock `NativeModules.SecureCore` and validate:
- Each method forwards calls correctly
- Native error codes are mapped to `SecureCoreError`
- Return types match the API contract

## Running Integration Tests

Integration tests require an Android emulator or device:

```bash
# Build and install the app
npx react-native run-android

# Run with Detox (when configured)
detox test --configuration android.emu.debug

# Or run manually with Jest (skipped by default)
jest --testPathPattern integration --no-skip
```

## Known Limitations (v1)

- **Android only** — iOS native module is not yet implemented
- **No Turbo Module** — Uses the legacy bridge (`NativeModules`), not the new architecture. Migration to TurboModules planned for v2.
- **Base64 for binary data** — React Native's bridge cannot transfer raw bytes. `decryptToMemory` returns base64-encoded content. For large files, prefer `decryptToTempFile`.
- **No streaming** — Documents are fully decrypted into memory or to a temp file. No chunked/streaming API yet.
