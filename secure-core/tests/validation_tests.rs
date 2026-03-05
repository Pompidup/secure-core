use secure_core::crypto::{decrypt_bytes, encrypt_bytes};
use secure_core::error::SecureCoreError;
use secure_core::validation::{validate_dek, validate_nonce};

const VALID_KEY: [u8; 32] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
];

// ── DEK validation ──────────────────────────────────────────────────────

#[test]
fn test_invalid_dek_length() {
    let short_dek = [0u8; 16];
    let err = validate_dek(&short_dek).unwrap_err();
    assert!(matches!(err, SecureCoreError::InvalidParameter(_)));
}

#[test]
fn test_invalid_dek_length_64() {
    let long_dek = [0u8; 64];
    let err = validate_dek(&long_dek).unwrap_err();
    assert!(matches!(err, SecureCoreError::InvalidParameter(_)));
}

#[test]
fn test_null_plaintext_allowed() {
    let plaintext: &[u8] = &[];
    let blob = encrypt_bytes(plaintext, &VALID_KEY).unwrap();
    let decrypted = decrypt_bytes(&blob, &VALID_KEY).unwrap();
    assert_eq!(decrypted, plaintext);
}

// ── Nonce validation ────────────────────────────────────────────────────

#[test]
fn test_valid_nonce() {
    assert!(validate_nonce(&[0u8; 12]).is_ok());
}

#[test]
fn test_invalid_nonce_length() {
    let err = validate_nonce(&[0u8; 8]).unwrap_err();
    assert!(matches!(err, SecureCoreError::InvalidParameter(_)));
}
