# iOS Keychain Policy

## V1: kSecAttrAccessibleWhenUnlockedThisDeviceOnly

The Device Master Key (DMK) is stored in the iOS Keychain with the
`kSecAttrAccessibleWhenUnlockedThisDeviceOnly` accessibility attribute.

### Why this accessibility level

- **No iCloud Keychain sync**: The key never leaves the device, preventing
  extraction from a compromised iCloud account or a secondary device.
- **No unencrypted backup**: Even in an iTunes/Finder backup, these items
  are not included unless the backup itself is encrypted. On restore to a
  different device, the key is not present.
- **Available only when unlocked**: The key material is accessible only
  after the user has unlocked the device (first unlock or subsequent), which
  aligns with the app's foreground usage pattern.

### V1: No biometric gate at key level

In V1, biometric authentication is enforced at the **application layer**
(session-based), not via `SecAccessControl` on the Keychain item.

Rationale (same as Android):

- Setting `.userPresence` or `.biometryCurrentSet` on the access control
  ties the key to the current biometric enrollment. Any change (new
  fingerprint, Face ID re-enrollment) **invalidates the key**, making all
  encrypted data irrecoverable without a re-wrap migration.
- For V1, keeping Keychain access unconditional simplifies the migration
  story and avoids data-loss during early adoption.

## Reinstallation behavior

When the app is deleted and reinstalled:

1. Keychain items with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` **may
   persist** on iOS (unlike Android Keystore, which deletes keys on
   uninstall). However, this behavior is not guaranteed by Apple.
2. If the key survives reinstall, previously wrapped DEKs remain usable.
3. If the key is deleted (e.g., device wipe, Keychain reset), wrapped DEKs
   are **permanently unrecoverable**.
4. The user must re-provision documents from the server (re-download +
   re-encrypt with a new DMK).

This is by design: local-only keys ensure that a compromised backup cannot
be used to recover plaintext on another device.

## V2 Roadmap: Secure Enclave binding

In a future release, the DMK will be upgraded to use the Secure Enclave
for stronger hardware binding:

```swift
let accessControl = SecAccessControlCreateWithFlags(
    nil,
    kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
    [.privateKeyUsage, .biometryCurrentSet],
    nil
)
```

Benefits:

- Key material never leaves the Secure Enclave hardware.
- Biometric gate enforced at the hardware level.
- Resistant to jailbreak-based key extraction.

### Migration path

1. Detect existing V1 key (alias `"secure_core_master_key_v1"`).
2. Unwrap all DEKs with the V1 key.
3. Generate a V2 Secure Enclave key (`"secure_core_master_key_v2"`).
4. Re-wrap all DEKs with the V2 key.
5. Delete the V1 key from Keychain.

The migration must be atomic per-document to avoid partial states.
