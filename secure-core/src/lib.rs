//! # secure-core
//!
//! Core cryptographic primitives for the Pompidup secure document platform.
//!
//! This crate provides AES-256-GCM encryption (in-memory and streaming),
//! a custom `.enc` V1 binary format, document metadata, and a C-compatible
//! FFI for integration with Kotlin/JNI and Swift.
//!
//! ## Design guarantees
//!
//! - **No plaintext on disk**: the core never writes cleartext to persistent storage.
//! - **No secret logging**: the `log` feature only emits operation names and document IDs.
//! - **Zeroize on drop**: the [`crypto::Dek`] type erases key bytes when dropped.

/// High-level file encryption/decryption API.
pub mod api;

/// Core AES-256-GCM encrypt/decrypt and [`Dek`](crypto::Dek) key type.
pub mod crypto;

/// Error types used throughout the crate.
pub mod error;

/// C-compatible FFI surface for mobile platform integration.
pub mod ffi;

/// JNI bridge for Android (enabled via the `jni` feature).
#[cfg(feature = "jni")]
pub mod jni_bridge;

/// `.enc` V1 binary format: header parsing and serialization.
pub mod format;

/// Safe logging helpers (no secrets emitted).
pub mod logging;

/// Document metadata and wrapped-DEK structures.
pub mod metadata;

/// Chunked streaming encryption/decryption (64 KB chunks).
pub mod streaming;

/// Passphrase-based DEK recovery (Argon2id + AES-256-GCM).
pub mod recovery;

/// Input validation helpers (DEK length, nonce length).
pub mod validation;
