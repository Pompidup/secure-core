# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

### Changed

### Security


## [0.3.0] - 2026-04-21

### Added
- **Streaming truncation detection (V1.1)**: `encrypt_stream` now sets `FLAG_STREAM_FINAL_CHUNK` (bit 0 of the header `flags` field) and authenticates the last chunk with a marker bit in its AAD. `decrypt_stream` rejects streams whose terminal chunk was stripped. Backward-compatible: blobs produced before this change (`flags == 0`) continue to decrypt via the legacy code path. See `docs/enc-format-v1.md` for the semantics and `docs/compat-promises.md` for the compat posture.
- `Dek::take(&mut [u8; 32]) -> Dek`: preferred constructor at FFI/JNI boundaries. Copies the bytes into the returned `Dek` and zeroes the caller's source buffer so no stack copy of the key lingers.
- **`RecoveryWrap` schema versioning.** New field `schema_version` (current value `"1.0"`) stamped on every wrap, validated at unwrap. Blobs without the field (produced before this change) deserialize as `"1.0"` so existing recovery bundles keep working. Rejecting unknown versions gives future param bumps (e.g. Argon2 m/t/p or KDF change) a clean migration path — older clients surface a clear `InvalidParameter("unsupported recovery schema_version: ...")` instead of attempting to decrypt with stale params. See `docs/recovery-format-v1.md#recoverywrap-schema` for the evolution policy.
- **Public size limits.** `crypto::MAX_PLAINTEXT_SIZE` (formerly private) and the new `streaming::MAX_STREAM_PLAINTEXT_SIZE` are both exposed. Doc-comments and `docs/enc-format-v1.md` now cross-reference them so callers can pick the right API for their payload size (in-memory vs streaming). A sanity test asserts the in-memory limit stays strictly below the streaming limit to prevent future drift.
- **Parser robustness test suite** (`tests/parser_robustness.rs`). Fuzz-lite, no new dep: 8 tests feed `EncHeader::from_bytes`, `decrypt_bytes`, `decrypt_stream` with seeded random bytes, exhaustive bit-flips of valid blobs, every truncation prefix, and pathological streaming length prefixes. Asserts no panic / abort / UB across ~6 000 hostile inputs per run. Seeded for reproducibility.
- **V1.1 streaming compat pack** (`testdata/compat/v1_1/stream/`). Two deterministic golden streams (`stream_single_chunk` 2 KiB / 1 chunk, `stream_multi_chunk` ~128.8 KiB / 3 chunks) freeze the V1.1 on-disk layout cross-platform. Produced via `encrypt_stream_with_nonce_test` (new `_test-vectors` helper that forces the base nonce for reproducibility). Verified by 5 new tests in `compat_tests.rs`: decryption, header flag presence, truncation rejection, byte-for-byte regeneration. The `compat-tests` CI job now diffs the entire `testdata/compat/` tree (V1 and V1.1) to catch any unintentional format drift.
- **Platform contract update** (`docs/platform-contract.md`). New §4 "Cycle de vie de la passphrase" (Android/iOS/C zeroize guidance) and §5 "Gestion des erreurs de version recovery" (UX on unsupported `schema_version`). "Ce que le core ne fera JAMAIS" table now enumerates: no silent streaming truncation, no panic across FFI/JNI, no unknown-schema `RecoveryWrap`.

### Removed
- `tests/generate_reference.rs`. Its sole output, `testdata/v1_reference.enc`, is now produced by `tests/generate_compat_pack.rs` alongside the compat pack. One binary, one command (`cargo test --test generate_compat_pack --features _test-vectors -- --ignored`) to rebuild every committed test fixture. The produced `v1_reference.enc` is byte-for-byte identical; regression tests in `crypto_tests.rs` are unchanged.

### Changed
- **`Dek` inner field is now private.** Previously `pub struct Dek(pub [u8; 32])`, now `pub struct Dek([u8; 32])`. Access the bytes via `Dek::as_bytes()`. This removes a footgun where callers could read the key without going through the typed accessor. No FFI/ABI impact (the type is Rust-internal).
- `ffi/functions.rs` and `jni_bridge.rs` now build `Dek` via `Dek::take(&mut key)` across all code paths (encrypt/decrypt bytes, wrap-dek-with-passphrase, encrypt/decrypt file) so the transient 32-byte stack buffer is zeroed immediately after construction.
- **`api::encrypt_file` now returns `PartialDocumentMetadata`, not `DocumentMetadata`.** The old result stamped `doc_id: ""` and `wrapped_dek.device: None` as placeholders — a footgun where forgetting to replace them would pass `validate()` only at runtime. The new `PartialDocumentMetadata` type simply does not carry those fields; callers must call `.finalize(doc_id, wrapped_dek)` to obtain a `DocumentMetadata`, which is enforced at compile time. `EncryptResult.document_metadata` was renamed to `EncryptResult.partial_metadata`. FFI/JNI ABI unchanged (neither boundary ever serialized `document_metadata`).

### Security
- Mitigates a silent-truncation attack on streaming `.enc` files: previously, an attacker who stripped the final chunk of a streamed blob would see `decrypt_stream` return success with a shortened plaintext. V1.1 blobs now detect this.
- Removes the "unzeroed stack copy" of the DEK at all FFI/JNI entry points. A process-memory snapshot taken after an FFI call can no longer recover the key from the bridge's stack frame.
- **JNI bridge no longer aborts the JVM on allocation failure.** `jni_bridge.rs` previously used `.expect()` on fallible JNI calls (`find_class`, `new_byte_array`, `new_string`, `new_object`); a JVM `OutOfMemoryError` or a missing class entry would unwind Rust across the FFI boundary and abort the Android process. Every fallible JNI call now early-returns with `JObject::null()` (or the `JString` equivalent) so the pending JVM exception surfaces cleanly to Kotlin.
- **FFI error messages are preserved across NUL bytes.** `FfiResult::from_error` previously called `CString::new(msg).unwrap_or_default()`, which returned an *empty* C string whenever the source message contained an embedded NUL byte — destroying all diagnostic context (most visibly for I/O errors that embed caller-controlled paths). NUL bytes are now replaced with `?` before `CString::new`, so the entire message is transmitted to the caller. No ABI change.
- **JNI passphrase is zeroized after use.** `Java_com_securecore_SecureCoreLib_nativeWrapDekWithPassphrase` and `nativeUnwrapDekWithPassphrase` used to copy the JVM `String` into a plain Rust `String`, whose heap buffer was deallocated but not wiped — the passphrase bytes survived in freed memory until the allocator reused the block. The Rust-owned copy is now wrapped in `zeroize::Zeroizing<String>`, which overwrites the backing allocation on drop. The C FFI path was already clean (it only borrows the caller's `const char*`); documented in `docs/security-considerations.md`.
- **DoS-resistant chunk-length parsing in `decrypt_stream`.** The chunk-length prefix (`u32` before each encrypted chunk) was used verbatim to size a `vec![0u8; chunk_len]`, letting a malicious blob declare `chunk_len = 0xFFFF_FFFF` and force a 4 GiB allocation — enough to abort the process on a low-memory mobile device. `chunk_len > CHUNK_SIZE + TAG_SIZE` (65 552 bytes) now returns `InvalidFormat` before any allocation happens.

## [0.1.0-core] - 2026-03-10

### Changed
- **Repo separation**: `secure-core` is now a pure Rust cryptographic library. All mobile code (Android Kotlin adapter, iOS Swift adapter, React Native bridge) has been moved to the `secure-vault-mobile` repository.
- **GitHub Release workflow**: Prebuilt binaries (.so for Android ABIs, .xcframework for iOS) are published as GitHub Release assets on tag push.
- Build scripts updated to output only to `dist/` (removed jniLibs copy).
- CI cleaned up: removed Android JNI integration tests and hardening workflow (now in mobile repo).

### Added
- `release.yml` workflow: builds and publishes Android + iOS binaries on `v*` tags.

## [1.0.0-ios] - 2026-03-06

### Added

- Support iOS via Swift Package (SecureCore framework)
- Same API as Android: importDocument, decryptDocument, listDocuments, deleteDocument
- Same security guarantees: AES-256-GCM encryption, per-document DEK, zeroization
- FaceID / TouchID authentication with passcode fallback (via Keychain access control)
- Secure preview management: in-memory for images/text, temp file for PDF with auto-purge
- React Native bridge module (SecureCoreModule.swift + ObjC bridge) with identical JS contract
- Privacy Manifest (PrivacyInfo.xcprivacy) for App Store compliance
- Hardening test suite: anti-leak, anti-loss, tamper detection, performance (50MB budget)
- Preview lifecycle observer: auto-purge on app background and foreground
- ReconciliationService for filesystem/database consistency at startup
- Backup exclusion on all stored files (.isExcludedFromBackupKey)

### Known Limitations (V1 iOS)

- Recovery after reinstallation not available (Keychain keys lost on device reset)
- No streaming encryption (files loaded fully into memory, max 50MB)
- Biometric testing requires physical device (simulator uses mock key manager)
- iCloud restore results in inaccessible documents (expected -- Keychain not restored)

## [1.0.0] - 2026-03-05

### Features

- Import de documents (images JPEG/PNG/WebP, PDF, texte brut)
- Chiffrement local AES-256-GCM via secure-core Rust v0.1.0
- Cles de chiffrement par document (DEK), wrappees par le Keystore Android (KEK)
- Previsualisation securisee avec purge automatique (RAM pour images/texte, fichier temporaire pour PDF)
- Verrouillage biometrique avec session de 5 minutes (fallback PIN/pattern)
- Module React Native avec bridge TypeScript type
- Validation a l'import : types MIME V1, taille max 50 Mo
- Reconciliation au demarrage (orphelins .enc et metadata)

### Security

- Aucune donnee en clair sur disque a aucun moment du cycle de vie
- Aucune donnee envoyee sur des serveurs externes (zero reseau)
- Backup Android desactive intentionnellement (allowBackup=false + XML rules + noBackupFilesDir)
- Detection de falsification : toute modification du fichier chiffre provoque une erreur crypto
- Purge automatique des previews au background, au release et au demarrage
- Suite de tests de hardening (anti-leak, anti-loss, tamper, performance)

### Known Limitations (V1)

- Android uniquement (iOS prevu V2)
- Recuperation apres reinstallation non disponible : les cles sont liees a l'installation (prevu V2)
- Partage de documents non disponible (prevu V2)
- Pas de streaming : les fichiers sont charges entierement en memoire (limite a 50 Mo)
- Authentification au niveau applicatif, pas au niveau Keystore (Keystore-bound auth prevu V2)

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
