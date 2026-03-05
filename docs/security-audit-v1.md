# Security Audit — secure-core V1

**Date**: 2026-03-05
**Scope**: `secure-core 0.1.0` — all modules, FFI surface, streaming, metadata
**Auditor**: Internal (pre-release)

---

## 1. Dependency Audit

```
cargo audit — 0 vulnerabilities found
75 crate dependencies scanned
```

All dependencies are from the RustCrypto ecosystem (`aes-gcm 0.10`, `zeroize 1.x`) or well-established crates (`rand 0.8`, `serde 1.x`).

A weekly `cargo audit` CI workflow (`.github/workflows/audit.yml`) is in place.

## 2. Secret Leakage Review

| Check | Result |
|---|---|
| `Dek` Debug impl | Prints `Dek([REDACTED])` — no key bytes exposed |
| `log_operation()` | Only logs operation name + doc_id, never DEK or plaintext |
| `log` feature gate | Logging is opt-in (`log` feature flag), no-op by default |
| FFI error messages | Never contain key material |
| Metadata serialization | `wrapped_dek` is hex-encoded; raw DEK never serialized |

**Grep verification**: No occurrences of raw key logging found outside test code.

## 3. Zeroize Guarantees

- `Dek` derives `Zeroize` + `ZeroizeOnDrop` — key bytes are zeroed when the struct is dropped.
- Verified by unit test `test_dek_zeroize_on_drop`.
- Intermediate plaintext buffers in `encrypt_bytes` / `decrypt_bytes` are owned `Vec<u8>` returned to the caller — core does not retain copies.

## 4. Cryptographic Review

| Property | Status |
|---|---|
| Algorithm | AES-256-GCM (NIST approved, AEAD) |
| Nonce generation | 96-bit random via `rand::thread_rng()` (OS CSPRNG) |
| Nonce uniqueness (streaming) | Base nonce XOR chunk index — unique per chunk |
| AAD binding | Full header (25 bytes) used as AAD — tamper-evident |
| Max plaintext | 4 GB hard limit enforced before encryption |
| Tag size | 128-bit (16 bytes) — full GCM tag |

### Nonce collision risk

With 96-bit random nonces and a single key, the birthday bound is ~2^48 encryptions before a 50% collision probability. For typical mobile usage (thousands of documents per device), this margin is extremely safe.

## 5. FFI Safety

- All `extern "C"` functions validate inputs (null pointers, slice lengths) before any unsafe operation.
- Every `unsafe` block has a `// SAFETY:` comment documenting the invariant.
- `FfiResult` ownership model: caller must call `secure_core_free_result()` / `secure_core_free_buffer()`.
- 7 FFI integration tests cover encrypt, decrypt, file operations, version, and free functions.

## 6. Format Integrity

- Magic bytes `SENC` prevent accidental misinterpretation.
- Version field enables future format evolution without breaking existing blobs.
- `header_length` is validated against actual header size on parse.
- 7 format unit tests + integration test with `testdata/v1_reference.enc` frozen reference blob.

## 7. Benchmark Results

Environment: macOS, Apple Silicon (single-threaded, criterion 0.5)

| Operation | Size | Throughput |
|---|---|---|
| `encrypt_bytes` | 1 KB | ~157 MiB/s |
| `encrypt_bytes` | 1 MB | ~193 MiB/s |
| `decrypt_bytes` | 1 MB | ~194 MiB/s |
| `encrypt_stream` | 50 MB | ~185 MiB/s |
| `decrypt_stream` | 50 MB | ~187 MiB/s |

Streaming overhead vs in-memory is < 5%, confirming the 64 KB chunk size is well-suited.

## 8. Test Coverage Summary

| Test suite | Count |
|---|---|
| `crypto.rs` unit tests | 12 |
| `format.rs` unit tests | 7 |
| `validation.rs` unit tests | 6 |
| Integration: crypto_tests | 14 |
| Integration: streaming_tests | 4 |
| Integration: metadata_tests | 8 |
| Integration: ffi_tests | 7 |
| Integration: validation_tests | 5 |
| **Total** | **63** |

## 9. CI Pipeline

- `cargo fmt --check` — formatting enforcement
- `cargo clippy -- -D warnings` — lint enforcement
- `cargo test` + `cargo test --features _test-vectors` — full test suite
- Cross-compilation check: `aarch64-linux-android`, `armv7-linux-androideabi`
- Weekly `cargo audit` — dependency vulnerability scanning

## 10. Conclusion

**secure-core 0.1.0 is approved for V1 release.**

No critical or high-severity issues found. The library meets the security guarantees defined in the platform contract and threat model. Ongoing monitoring via CI (audit, clippy, tests) provides continuous assurance.

### Recommendations for V1.1+

- Add `cargo-fuzz` harness for format parsing and decrypt paths.
- Consider HKDF-based key derivation if multi-context key usage is needed.
- Evaluate `mlock` / platform-specific memory protection for DEK storage.
