## Context

`secure-core` reports failures through `SecureCoreError` (5 variants), which is
mapped to numeric status codes at two boundaries:

- C FFI: `FfiResult::from_error` (`src/ffi/types.rs`) → `FFI_OK = 0`,
  `FFI_ERROR_INVALID_FORMAT = 1`, `FFI_ERROR_UNSUPPORTED_VERSION = 2`,
  `FFI_ERROR_CRYPTO = 3`, `FFI_ERROR_IO = 4`, `FFI_ERROR_INVALID_PARAM = 5`.
- JNI: `jni_bridge::error_to_status` produces the same numeric codes.

`recovery::unwrap_dek_with_passphrase` validates `wrap.schema_version` first and,
on mismatch, returns `SecureCoreError::InvalidParameter(...)` → status `5`. That
code is shared with base64/length/empty-passphrase failures, so the two mobile
clients string-match the message substring `"unsupported recovery
schema_version"` to isolate "incompatible bundle, update the app" from
"corrupted bundle / wrong passphrase". The message is therefore load-bearing —
a fragile, undocumented coupling.

The FFI/ABI is contractual (CLAUDE.md invariant #2), but no real users have
produced recovery bundles yet, so an **additive** extension (a new status code,
no signature or existing-code change) is safe now and cheap to consume because
the same author controls the only client.

There is an existing structured variant `UnsupportedVersion { found: u16,
max_supported: u16 }` (status `2`) but it is `.enc`-header-specific and its
`u16` shape does not fit the recovery `schema_version`, which is a `String`
(e.g. `"1.0"`).

## Goals / Non-Goals

**Goals:**
- Give the recovery-schema mismatch its own structured error case and a
  dedicated, additive FFI/JNI status code.
- Let clients classify the failure by code; make the message diagnostic-only.
- Keep `include/secure_core.h` in sync (CI-enforced) and document the new code.

**Non-Goals:**
- No change to existing status codes, FFI signatures, the `.enc` binary format,
  or golden files.
- No change to recovery cryptography (Argon2id params, AES-GCM, wrap layout).
- Not moving bundle assembly/zip into `secure-core` (deferred change #2).
- No restructuring of the other `InvalidParameter` failure sub-cases.

## Decisions

### Decision 1: New `SecureCoreError` variant rather than reusing `UnsupportedVersion`

Add a dedicated variant, e.g. `UnsupportedRecoverySchema { found: String }`.

- **Why not reuse `UnsupportedVersion { found: u16, max_supported }`**: its
  numeric `u16` shape misrepresents a string schema like `"1.0"`, and it is
  already semantically bound to the `.enc` header version. Overloading it would
  blur two distinct contracts and force a lossy parse.
- **Why a String payload**: the recovery `schema_version` is a free-form string
  per `recovery-format-v1`; carrying it verbatim keeps the diagnostic faithful.
- A new variant keeps the `Display` impl and FFI/JNI mappings exhaustive and
  forces the compiler to surface every match site that must be updated.

### Decision 2: New additive FFI status code

Introduce a new constant (e.g. `FFI_ERROR_UNSUPPORTED_RECOVERY_SCHEMA = 6`) in
`src/ffi/types.rs`, mirrored in `include/secure_core.h`, mapped in
`FfiResult::from_error` and `jni_bridge::error_to_status`.

- **Why `6` (next free value)**: purely additive; codes `0`–`5` keep their
  meaning, so existing clients that don't yet know `6` simply see an
  unrecognized non-zero error — they already treat any non-zero status as a
  failure, so nothing breaks.
- **Alternative considered — a sub-code/tag inside the message**: rejected;
  that perpetuates message-as-contract, the very coupling we remove.

### Decision 3: `unwrap_dek_with_passphrase` returns the new variant on schema mismatch

The schema-version check stays first (before any base64 decode or KDF work);
only its error type changes from `InvalidParameter` to the new variant. Message
text is preserved as diagnostic but is no longer relied upon for classification.

### Decision 4: Message stops being load-bearing; document the code

Update `docs/recovery-format-v1.md` (and the error-code reference, e.g.
`docs/wraps-error-codes.md` / `docs/api-overview.md`) to document the new code
and instruct clients to branch on the status code, not the message. This lets
the apps drop the substring match in a follow-up on their side.

## Risks / Trade-offs

- **A client still on the old code path treats `6` as generic failure** → For
  the schema-mismatch case it would lose the "please update" distinction until
  updated. Mitigation: additive change, single controlled client, and the
  apps update to branch on `6` as the immediate downstream follow-up. Until
  then the old substring match keeps working (message text is preserved).
- **Header / FFI drift** → CI `check-ffi-header.sh` fails the PR if
  `include/secure_core.h` and the Rust exports disagree; updating both is part
  of the tasks.
- **Coverage of `jni_bridge.rs` is excluded from llvm-cov (no JVM harness)** →
  The JNI mapping is one line via `error_to_status`; cover the mapping function
  itself with a unit test at the Rust level and rely on the existing FFI test
  for the end-to-end status value.
- **Future real bundles with `schema_version` other than `"1.0"`** → unchanged
  policy: still rejected, just with a cleaner code; no migration implication.
