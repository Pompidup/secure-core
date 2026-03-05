# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-03-05

### Added
- **Format `.enc` V1**: Custom binary format with 25-byte header (magic `SENC`, version, algorithm, nonce, flags, header_length). Header authenticated as AAD.
- **AES-256-GCM encryption**: In-memory `encrypt_bytes` / `decrypt_bytes` with random 96-bit nonces and full 128-bit auth tags.
- **Chunked streaming**: `encrypt_stream` / `decrypt_stream` with 64 KB chunks and per-chunk nonce derivation (XOR base nonce with chunk index).
- **File API**: `encrypt_file` / `decrypt_file` with partial `DocumentMetadata` generation.
- **Document metadata**: `DocumentMetadata` + `WrappedDek` with JSON serialization (hex-encoded byte fields).
- **C-compatible FFI**: 7 `extern "C"` functions for Kotlin/JNI and Swift integration (`secure_core_encrypt_bytes`, `secure_core_decrypt_bytes`, `secure_core_encrypt_file`, `secure_core_decrypt_file`, `secure_core_version`, `secure_core_free_buffer`, `secure_core_free_result`).
- **Android cross-compilation**: Build scripts and CI for `aarch64-linux-android` and `armv7-linux-androideabi`.
- **Security guarantees**: `Dek` with `ZeroizeOnDrop`, redacted `Debug` impl, safe logging (no secrets), input validation.
- **Test suite**: 63 tests (unit + integration) including test vectors, tamper detection, streaming roundtrips, FFI harness, and frozen reference blob.
- **Criterion benchmarks**: In-memory and streaming performance measurements.
- **CI pipeline**: fmt, clippy, test, unsafe audit, Android cross-check, weekly `cargo audit`.
- **Documentation**: Threat model, platform contract, format spec, FFI API reference, ADRs, security audit, FAQ.

### Compatibility
- All `.enc` V1 files will remain readable by future versions of secure-core.
