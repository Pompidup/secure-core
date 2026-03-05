# WrapsEnvelope Error Codes

Error codes related to DEK wrapping/unwrapping operations. These codes are used
across all platforms (Rust core, Android, iOS) for consistent error reporting.

## Error Table

| Code | Name | Description | Cause |
|------|------|-------------|-------|
| `WRAP_DEVICE_KEY_INVALIDATED` | Device Key Invalidated | The OS keystore master key has been invalidated. | User enrolled new biometrics, factory reset, app reinstall, or OS-level key revocation. The wrapped DEK is permanently unrecoverable unless recovery wrap exists. |
| `WRAP_RECOVERY_NOT_CONFIGURED` | Recovery Not Configured | Recovery unwrap was requested but `recovery` is null. | Client tried to unwrap via recovery path, but no recovery wrap was stored (V1 default). |
| `WRAP_FORMAT_INVALID` | Format Invalid | The WrapsEnvelope JSON is malformed or has missing/invalid fields. | Corrupted database, manual tampering, or schema mismatch. Validation checks: non-null `device`, non-empty `algo`, non-empty `key_alias`, valid base64 for `iv`/`tag`/`ciphertext`. |
| `WRAP_ALGO_UNSUPPORTED` | Algorithm Unsupported | The `algo` string in the envelope is not recognized. | File produced by a newer platform version with an algorithm this build doesn't support. |
| `WRAP_VERSION_TOO_NEW` | Version Too New | The `schema_version` is higher than what this build supports. | File produced by a newer platform version. User must update the app. |

## Platform Mapping

### Rust (`SecureCoreError`)

| Error Code | Variant |
|------------|---------|
| `WRAP_FORMAT_INVALID` | `SecureCoreError::InvalidParameter(...)` |
| `WRAP_ALGO_UNSUPPORTED` | `SecureCoreError::InvalidParameter(...)` |
| `WRAP_VERSION_TOO_NEW` | `SecureCoreError::InvalidParameter(...)` |

### Android (`KeyManagerError`)

| Error Code | Class |
|------------|-------|
| `WRAP_DEVICE_KEY_INVALIDATED` | `KeyManagerError.KeyInvalidated` |
| `WRAP_RECOVERY_NOT_CONFIGURED` | `KeyManagerError.RecoveryNotConfigured` (new) |
| `WRAP_FORMAT_INVALID` | `KeyManagerError.WrapFormatInvalid` (new) |
| `WRAP_ALGO_UNSUPPORTED` | `KeyManagerError.AlgoUnsupported` (new) |
| `WRAP_VERSION_TOO_NEW` | `KeyManagerError.VersionTooNew` (new) |

### iOS (future)

Will mirror Android error mapping with Swift `enum SecureCoreError` cases.

## Recovery Scenarios

| Scenario | Error | User-Facing Action |
|----------|-------|-------------------|
| New biometric enrolled | `WRAP_DEVICE_KEY_INVALIDATED` | Re-authenticate via recovery or re-import documents |
| App reinstall | `WRAP_DEVICE_KEY_INVALIDATED` | Same as above |
| Old app reads new schema | `WRAP_VERSION_TOO_NEW` | Prompt user to update app |
| Database corruption | `WRAP_FORMAT_INVALID` | Report error, attempt recovery from backup |
| Future algo on old build | `WRAP_ALGO_UNSUPPORTED` | Prompt user to update app |
