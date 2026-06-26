## 1. Tests first (TDD — write failing tests before code)

- [x] 1.1 Add a Rust unit/integration test asserting `unwrap_dek_with_passphrase` on a `RecoveryWrap` with an unsupported `schema_version` (e.g. `"2.0"`) returns the new `UnsupportedRecoverySchema` variant (not `InvalidParameter`).
- [x] 1.2 Add a regression test asserting malformed input (bad base64, wrong IV/tag length, empty passphrase) with a supported `schema_version` still returns `InvalidParameter`, and that a wrong passphrase still returns `CryptoError`.
- [x] 1.3 Add an FFI test (in `tests/ffi_tests.rs`) asserting `secure_core_unwrap_dek_with_passphrase` returns the new status code (`6`) for an unsupported `schema_version`, with a non-null diagnostic `error_msg`.
- [x] 1.4 Add a unit test for the status-mapping function(s) (`FfiResult::from_error` and the JNI `error_to_status`) confirming the new variant maps to the new code and that codes `0`–`5` are unchanged.
- [x] 1.5 Run the suite and confirm the new tests fail for the right reason.

## 2. Core error type

- [x] 2.1 Add `SecureCoreError::UnsupportedRecoverySchema { found: String }` in `src/error.rs`.
- [x] 2.2 Extend the `Display` impl with a diagnostic message that includes `found` (preserve a clear, non-load-bearing string).
- [x] 2.3 Return the new variant from `recovery::unwrap_dek_with_passphrase` on `schema_version` mismatch (replace the current `InvalidParameter`), keeping the check first (before base64/KDF work).

## 3. FFI surface

- [x] 3.1 Add `pub const FFI_ERROR_UNSUPPORTED_RECOVERY_SCHEMA: i32 = 6;` in `src/ffi/types.rs`.
- [x] 3.2 Map the new variant to the new status in `FfiResult::from_error`.
- [x] 3.3 Map the new variant to the new status in `jni_bridge::error_to_status`.
- [x] 3.4 Add the matching `#define SECURE_CORE_ERROR_UNSUPPORTED_RECOVERY_SCHEMA 6` to `include/secure_core.h`.

## 4. Verification & sync

- [x] 4.1 Run `./scripts/check-ffi-header.sh` and confirm the header is in sync with the Rust exports.
- [x] 4.2 Run `cargo test --all-features` and confirm all tests (including the new ones) pass.
- [x] 4.3 Run `cargo clippy --all-targets --all-features -- -D warnings` and `cargo fmt --all -- --check`.
- [x] 4.4 Run the FFI harness (`./scripts/run-ffi-harness.sh`) to confirm the C ABI surface still loads and behaves.
- [x] 4.5 Confirm no `.enc` golden files changed: `git diff --quiet testdata/compat/`.

## 5. Documentation

- [x] 5.1 Document the new status code in `docs/recovery-format-v1.md` and the error-code reference (`docs/wraps-error-codes.md` / `docs/api-overview.md` as applicable).
- [x] 5.2 State explicitly that clients SHALL branch on the status code, not the message substring, and note the new code for the mobile teams (so they can drop the `"unsupported recovery schema_version"` match in a follow-up).
- [x] 5.3 Update `CHANGELOG.md` with the additive FFI status code under the appropriate version heading.
