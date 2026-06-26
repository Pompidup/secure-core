## Why

When `recovery::unwrap_dek_with_passphrase` rejects a recovery wrap whose
`schema_version` is not supported by the current build, it returns
`SecureCoreError::InvalidParameter` → FFI status `5`. But status `5` is a
grab-bag: malformed base64, wrong IV/tag length, and an empty passphrase all
map to it too. Mobile clients therefore cannot tell "incompatible bundle —
ask the user to update the app" apart from "corrupted bundle" using the
numeric code, so both apps currently **string-match the message substring**
`"unsupported recovery schema_version"` (Android `ExportService.kt:213`, iOS
`ExportService.swift:202`). If that human-readable string ever changes, both
apps silently reclassify an incompatible bundle as a wrong-passphrase error
and tell the user the wrong thing. This is the highest-value contract fix the
mobile team has asked for, and the FFI is still safe to extend additively
because no real users have produced recovery bundles yet.

## What Changes

- Add a dedicated, structured error case for an unsupported recovery
  schema version, carrying the offending `schema_version` value, distinct
  from the generic invalid-parameter case.
- Map it to a **new** FFI status code (additive: existing codes `0`–`5` are
  unchanged), exported in `include/secure_core.h` and the C ABI types.
- Propagate the same status through the JNI bridge so Android/iOS read a
  stable numeric code instead of matching the message text.
- `recovery::unwrap_dek_with_passphrase` returns the new case (instead of
  `InvalidParameter`) when `wrap.schema_version` is not the supported value.
- The error message becomes purely diagnostic — no longer load-bearing for
  client control flow.
- This is **additive, not breaking**: no existing FFI signature, status code,
  `.enc` format byte, or golden file changes.

## Capabilities

### New Capabilities
- `recovery-error-reporting`: How `unwrap_dek_with_passphrase` classifies and
  surfaces failures across the Rust API, the C FFI, and the JNI bridge — in
  particular, distinguishing an unsupported recovery schema version from other
  failures via a stable, structured code rather than a message substring.

### Modified Capabilities
<!-- None: openspec/specs/ is empty; no existing requirement is being changed. -->

## Impact

- **Code**: `src/error.rs` (new error case), `src/recovery.rs` (return it from
  `unwrap_dek_with_passphrase`), `src/ffi/types.rs` (new status constant +
  `FfiResult::from_error` mapping), `src/jni_bridge.rs` (`error_to_status`
  mapping).
- **ABI / public contract**: `include/secure_core.h` gains one new status
  constant; kept in sync (CI `check-ffi-header.sh`). No signature changes.
- **Docs**: `docs/recovery-format-v1.md` (and any error-code reference, e.g.
  `docs/wraps-error-codes.md` / `docs/api-overview.md`) updated to document the
  new code and to state that clients should match on the code, not the message.
- **Tests**: new assertions that a bad `schema_version` yields the new
  structured error / FFI status, at both the Rust and FFI layers.
- **Downstream**: unblocks the mobile apps to drop the `"unsupported recovery
  schema_version"` substring match in favor of the numeric code.
- **No new dependencies.**
