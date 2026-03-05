# Authentication Policy

## V1 Mode: App-Level Biometric Gate

Authentication is enforced at the application layer via `BiometricAuthManager` and `AuthGate`, not at the Keystore key level.

### How It Works

1. User attempts a sensitive operation (decrypt)
2. `AuthGate` checks if the session is active
3. If expired, `BiometricPrompt` is shown
4. On success, a session timer starts (5 minutes)
5. Subsequent operations within the session window proceed without re-authentication

### Session Duration

- Default: **5 minutes** (configurable via `BiometricAuthManager` constructor)
- Timer starts from the last successful authentication
- Session is invalidated:
  - After timeout
  - Explicitly via `invalidateSession()`
  - On app process death

### Authenticators

`BiometricPrompt` is configured with:

```
BIOMETRIC_STRONG | DEVICE_CREDENTIAL
```

- **BIOMETRIC_STRONG**: Fingerprint, face (Class 3 biometric)
- **DEVICE_CREDENTIAL**: PIN, pattern, password (mandatory fallback)

This means the user can always authenticate even if no biometric is enrolled, as long as a device lock is set.

### Protected Operations

| Operation | Auth Required |
|-----------|:------------:|
| `importDocument` | No |
| `listDocuments` | No |
| `deleteDocument` | No |
| `decryptToMemory` | Yes |
| `decryptToTempFile` | Yes |

Rationale: only operations that reveal plaintext require authentication. Import, list, and delete operate on ciphertext/metadata only.

### Error Codes (JS side)

| Error Code | Meaning |
|-----------|---------|
| `AUTH_REQUIRED` | Session expired or user cancelled authentication |

The JS layer should navigate to an unlock screen when receiving `AUTH_REQUIRED`.

### Error Mapping

| BiometricPrompt Error | AuthError | JS Code |
|----------------------|-----------|---------|
| `ERROR_USER_CANCELED` | `UserCancelled` | `AUTH_REQUIRED` |
| `ERROR_LOCKOUT` | `LockedOut` | `AUTH_REQUIRED` |
| `ERROR_NO_BIOMETRICS` | `NoBiometrics` | `AUTH_REQUIRED` |
| `ERROR_HW_NOT_PRESENT` | `NotAvailable` | `AUTH_REQUIRED` |

## Known Limitations (V1)

- Authentication is app-level only; the Keystore KEK is not bound to biometric authentication
- Session state is in-memory (`@Volatile`); a process death resets it (secure by default)
- Lockout duration is estimated (30s), not queried from the system

## Roadmap V2

- Bind the KEK to `KeyProperties.PURPOSE_DECRYPT` with `setUserAuthenticationRequired(true)` and `setUserAuthenticationParameters(300, AUTH_BIOMETRIC_STRONG)`
- This moves auth enforcement from app code to hardware, making it tamper-resistant
- Requires handling `UserNotAuthenticatedException` from `Cipher.init()` and triggering `BiometricPrompt` with `CryptoObject`
