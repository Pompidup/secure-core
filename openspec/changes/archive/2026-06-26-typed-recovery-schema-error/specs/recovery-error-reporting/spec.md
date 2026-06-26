## ADDED Requirements

### Requirement: Unsupported recovery schema version is a distinct, structured error

`recovery::unwrap_dek_with_passphrase` SHALL return a structured error case —
distinct from the generic invalid-parameter case used for malformed input (bad
base64, wrong IV/tag length, empty passphrase) — when it is asked to unwrap a
`RecoveryWrap` whose `schema_version` is not the version supported by the current
build. The structured error SHALL carry the offending `schema_version` value for
diagnostics.

The classification SHALL be carried by a structured field (the error case and
its mapped status code), NOT by the human-readable error message. The message
SHALL be diagnostic only and callers SHALL NOT be required to parse it to
determine the failure category.

#### Scenario: Unwrap rejects an unknown schema version

- **WHEN** `unwrap_dek_with_passphrase` receives a `RecoveryWrap` with a
  `schema_version` other than the supported value (e.g. `"2.0"`)
- **THEN** it returns the unsupported-recovery-schema error case carrying the
  offending value, and does NOT return the generic invalid-parameter case

#### Scenario: Malformed input stays a generic invalid-parameter error

- **WHEN** `unwrap_dek_with_passphrase` receives a wrap with the supported
  `schema_version` but with malformed base64, a wrong-length IV/tag, or an
  empty passphrase
- **THEN** it returns the generic invalid-parameter error case, NOT the
  unsupported-recovery-schema case

#### Scenario: Wrong passphrase stays a crypto error

- **WHEN** `unwrap_dek_with_passphrase` receives a structurally valid wrap with
  the supported `schema_version` but the passphrase is wrong or the ciphertext
  was tampered with
- **THEN** it returns the crypto-error case, distinct from both the
  unsupported-recovery-schema case and the invalid-parameter case

### Requirement: Unsupported recovery schema maps to a stable, additive FFI status code

The unsupported-recovery-schema error SHALL map to a dedicated C FFI status
code that is distinct from every existing status code. The new code SHALL be
additive: the existing status codes (`OK = 0`, `INVALID_FORMAT = 1`,
`UNSUPPORTED_VERSION = 2`, `CRYPTO = 3`, `IO = 4`, `INVALID_PARAM = 5`) SHALL
keep their current numeric values. The new constant SHALL be declared in
`include/secure_core.h` and kept in sync with the Rust FFI exports (enforced by
`check-ffi-header.sh`).

#### Scenario: FFI returns the new status for an unknown schema version

- **WHEN** a caller invokes `secure_core_unwrap_dek_with_passphrase` with a
  recovery JSON whose `schema_version` is unsupported
- **THEN** the returned `FfiResult.status` is the new unsupported-recovery-schema
  status code, and the populated `error_msg` is informational only

#### Scenario: Existing status codes are unchanged

- **WHEN** the C header and FFI types are inspected after this change
- **THEN** the status codes `0` through `5` retain their existing names and
  numeric values, and the new code occupies a previously unused value

### Requirement: JNI bridge surfaces the same structured status

The JNI bridge SHALL map the unsupported-recovery-schema error to the same
numeric status code as the C FFI, so that Android and iOS clients can classify
the failure by code without matching the error message text.

#### Scenario: JNI unwrap reports the structured status

- **WHEN** `Java_com_securecore_SecureCoreLib_nativeUnwrapDekWithPassphrase`
  processes a wrap with an unsupported `schema_version`
- **THEN** the native result's status field equals the new
  unsupported-recovery-schema status code (the same value exposed by the C FFI)
