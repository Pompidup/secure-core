# Android Keystore Policy

## V1: UserAuthenticationRequired = false

In the initial release, the Device Master Key (DMK) stored in the Android
Keystore does **not** require user authentication at the key level.

### Rationale

- Authentication is enforced at the **application layer** (PIN, biometric
  unlock screen) before any crypto operation is triggered.
- Setting `UserAuthenticationRequired = true` ties the key to the lockscreen
  credential and/or biometric enrollment. Any change (new fingerprint, PIN
  reset) **invalidates the key**, making all encrypted data irrecoverable
  unless a re-wrap migration is performed first.
- For V1, keeping key access unconditional simplifies the migration story and
  avoids data-loss scenarios during early adoption.

### Consequences of app reinstallation

When the app is uninstalled, the Android Keystore entry is **deleted by the OS**.
On reinstall:

1. `isKeyAvailable()` returns `false`.
2. Any previously wrapped DEKs are **permanently unrecoverable** because the
   DMK that encrypted them no longer exists.
3. The user must re-provision documents from the server (re-download + re-encrypt
   with a new DMK).

This is by design: local-only keys ensure that a compromised backup cannot
be used to recover plaintext on another device.

## V2 Roadmap: UserAuthenticationRequired = true

In a future release the DMK will be upgraded to require biometric or
lockscreen authentication:

```kotlin
KeyGenParameterSpec.Builder(alias, PURPOSE_ENCRYPT or PURPOSE_DECRYPT)
    .setUserAuthenticationRequired(true)
    .setUserAuthenticationParameters(0, AUTH_BIOMETRIC_STRONG or AUTH_DEVICE_CREDENTIAL)
    .setInvalidatedByBiometricEnrollment(true)
    .build()
```

This adds a second layer: even if an attacker gains code execution, they
cannot use the DMK without the user's biometric or PIN.

### Migration path

1. Detect existing V1 key (`alias = "secure_core_master_key_v1"`).
2. Unwrap all DEKs with the V1 key.
3. Generate a V2 key (`"secure_core_master_key_v2"`) with auth required.
4. Re-wrap all DEKs with the V2 key.
5. Delete the V1 key.

The migration must be atomic per-document to avoid partial states.
