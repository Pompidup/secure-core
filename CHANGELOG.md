# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
