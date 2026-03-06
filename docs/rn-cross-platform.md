# React Native Cross-Platform Contract

## Principle

The TypeScript API (`SecureCoreAPI` in `src/native/SecureCore.ts`) is **identical on Android and iOS**. Application code should never contain `Platform.OS` branches for SecureCore operations.

## API Surface

| Method | Params | Returns |
|---|---|---|
| `importDocument` | `uri: string` | `{ docId: string }` |
| `decryptToMemory` | `docId: string` | `{ bytes: string, mimeType: string }` |
| `decryptToTempFile` | `docId: string` | `{ uri: string }` |
| `listDocuments` | (none) | `DocumentMeta[]` |
| `deleteDocument` | `docId: string` | `{ deleted: boolean }` |

## Error Codes (same on both platforms)

| Code | When |
|---|---|
| `CRYPTO_ERROR` | Encryption/decryption failure, invalid format, unsupported version |
| `NOT_FOUND` | Document ID does not exist |
| `INVALID_PARAM` | Invalid document ID or parameter |
| `IO_ERROR` | File system read/write failure, storage full |
| `KEY_ERROR` | Keychain/Keystore error, key not found, key invalidated |
| `AUTH_REQUIRED` | Biometric auth needed, cancelled, failed, or locked out |
| `UNSUPPORTED_TYPE` | MIME type not allowed (Android import validation) |
| `FILE_TOO_LARGE` | File exceeds size limit (Android import validation) |
| `URI_ERROR` | Cannot access the provided URI |

## Platform Differences (handled in native code)

| Aspect | Android | iOS |
|---|---|---|
| URI format | `content://` provider URIs | `file://` paths (from document picker) |
| Import input | `ContentResolver.openInputStream(uri)` | `URL.startAccessingSecurityScopedResource()` then `Data(contentsOf:)` |
| Temp file location | `context.cacheDir/previews/` | `NSTemporaryDirectory/previews/` |
| Key storage | Android Keystore | iOS Keychain |
| Biometrics | BiometricPrompt | LAContext (via Keychain access control) |

These differences are **entirely abstracted** by the native modules. The JS layer sees the same interface.

## Testing

### Unit tests (no device required)
```bash
# Cross-platform contract tests
npx jest SecureCore.crossplatform.test.ts

# Smoke tests (mocked native bridge)
npx jest SecureCore.smoke.test.ts
```

### Integration tests (device required)
```bash
# Android
detox test --configuration android.emu.debug

# iOS
detox test --configuration ios.sim.debug
```

### Manual smoke tests
See `docs/smoke-test-ios.md` for iOS-specific manual testing.

## Guidelines

- **JS code** should never use `Platform.OS` for SecureCore logic. UI-only branching (e.g. navigation, styling) is fine.
- **New error codes** must be added to both `SecureCoreModule.kt` and `SecureCoreModule.swift`, and to `SecureCoreErrorCode` in TypeScript.
- **New methods** must be added to both native modules and to the `SecureCoreAPI` object, then covered in `SecureCore.crossplatform.test.ts`.
