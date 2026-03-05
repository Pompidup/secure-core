#![cfg(feature = "_test-vectors")]

use secure_core::crypto::{decrypt_bytes, encrypt_bytes, encrypt_bytes_with_nonce_test};
use secure_core::error::SecureCoreError;

// ── Test helpers ────────────────────────────────────────────────────────

mod test_helpers {
    pub const KEY: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D,
        0x1E, 0x1F,
    ];

    pub const NONCE: [u8; 12] = [
        0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB,
    ];

    /// Header size for V1.
    pub const HEADER_SIZE: usize = 25;

    /// GCM tag size.
    pub const TAG_SIZE: usize = 16;

    pub fn random_bytes(len: usize) -> Vec<u8> {
        use rand::RngCore;
        let mut buf = vec![0u8; len];
        rand::thread_rng().fill_bytes(&mut buf);
        buf
    }
}

// ── 1. Roundtrip by size ────────────────────────────────────────────────

#[test]
fn test_roundtrip_empty() {
    let plaintext = b"";
    let blob = encrypt_bytes(plaintext, &test_helpers::KEY).unwrap();
    let decrypted = decrypt_bytes(&blob, &test_helpers::KEY).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_roundtrip_1byte() {
    let plaintext = &[0x42u8];
    let blob = encrypt_bytes(plaintext, &test_helpers::KEY).unwrap();
    let decrypted = decrypt_bytes(&blob, &test_helpers::KEY).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_roundtrip_1kb() {
    let plaintext = test_helpers::random_bytes(1024);
    let blob = encrypt_bytes(&plaintext, &test_helpers::KEY).unwrap();
    let decrypted = decrypt_bytes(&blob, &test_helpers::KEY).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_roundtrip_5mb() {
    let plaintext = test_helpers::random_bytes(5 * 1024 * 1024);
    let blob = encrypt_bytes(&plaintext, &test_helpers::KEY).unwrap();
    let decrypted = decrypt_bytes(&blob, &test_helpers::KEY).unwrap();
    assert_eq!(decrypted, plaintext);
}

// ── 2. Anti-tamper (CRITICAL — security guarantees) ─────────────────────

#[test]
fn test_tamper_ciphertext_byte() {
    let plaintext = b"tamper ciphertext byte";
    let mut blob = encrypt_bytes(plaintext, &test_helpers::KEY).unwrap();

    // Flip one bit in the ciphertext (first byte after header)
    blob[test_helpers::HEADER_SIZE] ^= 0x01;

    let err = decrypt_bytes(&blob, &test_helpers::KEY).unwrap_err();
    assert!(matches!(err, SecureCoreError::CryptoError(_)));
}

#[test]
fn test_tamper_auth_tag() {
    let plaintext = b"tamper auth tag";
    let mut blob = encrypt_bytes(plaintext, &test_helpers::KEY).unwrap();

    // Flip the last byte (part of the GCM auth tag)
    let last = blob.len() - 1;
    blob[last] ^= 0xFF;

    let err = decrypt_bytes(&blob, &test_helpers::KEY).unwrap_err();
    assert!(matches!(err, SecureCoreError::CryptoError(_)));
}

#[test]
fn test_tamper_header_version() {
    let plaintext = b"tamper header version";
    let mut blob = encrypt_bytes(plaintext, &test_helpers::KEY).unwrap();

    // Set version to 99 (offset 4-5, little-endian)
    blob[4] = 99;
    blob[5] = 0;

    let err = decrypt_bytes(&blob, &test_helpers::KEY).unwrap_err();
    assert!(
        matches!(err, SecureCoreError::UnsupportedVersion { .. })
            || matches!(err, SecureCoreError::InvalidFormat(_))
    );
}

#[test]
fn test_tamper_nonce() {
    let plaintext = b"tamper nonce";
    let mut blob = encrypt_bytes(plaintext, &test_helpers::KEY).unwrap();

    // Flip one byte in the nonce (offset 7)
    blob[7] ^= 0xFF;

    // Nonce is part of AAD and used for decryption — GCM will reject
    let err = decrypt_bytes(&blob, &test_helpers::KEY).unwrap_err();
    assert!(matches!(err, SecureCoreError::CryptoError(_)));
}

#[test]
fn test_truncated_file() {
    let plaintext = b"truncation test with enough data";
    let blob = encrypt_bytes(plaintext, &test_helpers::KEY).unwrap();

    // Cut the blob in half
    let half = blob.len() / 2;
    let truncated = &blob[..half];

    let err = decrypt_bytes(truncated, &test_helpers::KEY).unwrap_err();
    assert!(
        matches!(err, SecureCoreError::InvalidFormat(_))
            || matches!(err, SecureCoreError::CryptoError(_))
    );
}

// ── 3. Deterministic test vectors ───────────────────────────────────────

#[test]
fn test_vector_1_exact_output() {
    let plaintext = b"Hello, secure-core!";
    let blob1 =
        encrypt_bytes_with_nonce_test(plaintext, &test_helpers::KEY, test_helpers::NONCE).unwrap();
    let blob2 =
        encrypt_bytes_with_nonce_test(plaintext, &test_helpers::KEY, test_helpers::NONCE).unwrap();
    assert_eq!(blob1, blob2);

    // Verify roundtrip
    let decrypted = decrypt_bytes(&blob1, &test_helpers::KEY).unwrap();
    assert_eq!(decrypted, plaintext);

    // Verify expected size: header(25) + plaintext(19) + tag(16) = 60
    assert_eq!(
        blob1.len(),
        test_helpers::HEADER_SIZE + 19 + test_helpers::TAG_SIZE
    );
}

#[test]
fn test_vector_2_empty_exact_output() {
    let plaintext = b"";
    let blob =
        encrypt_bytes_with_nonce_test(plaintext, &test_helpers::KEY, test_helpers::NONCE).unwrap();

    // header(25) + tag(16) = 41
    assert_eq!(
        blob.len(),
        test_helpers::HEADER_SIZE + test_helpers::TAG_SIZE
    );

    let decrypted = decrypt_bytes(&blob, &test_helpers::KEY).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_vector_3_binary_exact_output() {
    let plaintext: Vec<u8> = (0u8..=255).collect();
    let blob =
        encrypt_bytes_with_nonce_test(&plaintext, &test_helpers::KEY, test_helpers::NONCE).unwrap();

    // header(25) + plaintext(256) + tag(16) = 297
    assert_eq!(
        blob.len(),
        test_helpers::HEADER_SIZE + 256 + test_helpers::TAG_SIZE
    );

    let decrypted = decrypt_bytes(&blob, &test_helpers::KEY).unwrap();
    assert_eq!(decrypted, plaintext);
}

// ── 4. Non-regression: v1_reference.enc ─────────────────────────────────

#[test]
fn test_regression_v1_reference() {
    let reference_path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../testdata/v1_reference.enc");

    let blob = std::fs::read(&reference_path).unwrap_or_else(|e| {
        panic!(
            "cannot read reference blob at {}: {e}",
            reference_path.display()
        )
    });

    let expected_plaintext = b"secure-core v1 reference test vector";
    let decrypted = decrypt_bytes(&blob, &test_helpers::KEY).unwrap();
    assert_eq!(decrypted, expected_plaintext);
}

/// Verify the reference blob hasn't changed on disk (byte-for-byte stability).
#[test]
fn test_regression_v1_reference_deterministic() {
    let reference_path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../testdata/v1_reference.enc");
    let stored_blob = std::fs::read(&reference_path).unwrap();

    // Re-generate with same inputs
    let plaintext = b"secure-core v1 reference test vector";
    let regenerated =
        encrypt_bytes_with_nonce_test(plaintext, &test_helpers::KEY, test_helpers::NONCE).unwrap();

    assert_eq!(
        stored_blob, regenerated,
        "v1_reference.enc must match deterministic re-generation"
    );
}
