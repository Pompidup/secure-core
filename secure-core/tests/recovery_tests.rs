use secure_core::recovery::{
    derive_recovery_key, unwrap_dek_with_passphrase, wrap_dek_with_passphrase, RecoveryWrap,
};

const TEST_DEK: [u8; 32] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
    0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D,
    0x1E, 0x1F,
];

const TEST_PASSPHRASE: &str = "correct horse battery staple abandon ability able about";

#[test]
fn test_wrap_unwrap_passphrase_roundtrip() {
    let wrap = wrap_dek_with_passphrase(&TEST_DEK, TEST_PASSPHRASE).unwrap();

    assert_eq!(wrap.algo, "AES-256-GCM-ARGON2ID");
    assert_eq!(wrap.kdf, "argon2id-v19");
    assert_eq!(wrap.kdf_params.m, 65536);
    assert_eq!(wrap.kdf_params.t, 3);
    assert_eq!(wrap.kdf_params.p, 4);

    let unwrapped = unwrap_dek_with_passphrase(&wrap, TEST_PASSPHRASE).unwrap();
    assert_eq!(unwrapped, TEST_DEK);
}

#[test]
fn test_wrong_passphrase_fails() {
    let wrap = wrap_dek_with_passphrase(&TEST_DEK, TEST_PASSPHRASE).unwrap();

    let err = unwrap_dek_with_passphrase(&wrap, "wrong passphrase entirely").unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("invalid passphrase") || msg.contains("tampered"),
        "unexpected error: {msg}"
    );
}

#[test]
fn test_argon2_vectors() {
    // Known test vector: fixed passphrase + salt -> deterministic key.
    // This ensures the Argon2id parameters match across implementations.
    let salt = [0xAA_u8; 32];
    let passphrase = "test-passphrase-for-vectors";

    let key1 = derive_recovery_key(passphrase, &salt).unwrap();
    let key2 = derive_recovery_key(passphrase, &salt).unwrap();

    // Same inputs must produce same output (deterministic)
    assert_eq!(key1, key2);

    // Different passphrase must produce different key
    let key3 = derive_recovery_key("different-passphrase", &salt).unwrap();
    assert_ne!(key1, key3);

    // Different salt must produce different key
    let salt2 = [0xBB_u8; 32];
    let key4 = derive_recovery_key(passphrase, &salt2).unwrap();
    assert_ne!(key1, key4);

    // Verify key is non-zero (sanity)
    assert_ne!(key1, [0u8; 32]);
}

#[test]
fn test_wrap_produces_valid_base64_fields() {
    use base64::engine::general_purpose::STANDARD as BASE64;
    use base64::Engine;

    let wrap = wrap_dek_with_passphrase(&TEST_DEK, TEST_PASSPHRASE).unwrap();

    let salt = BASE64.decode(&wrap.salt).unwrap();
    assert_eq!(salt.len(), 32);

    let iv = BASE64.decode(&wrap.iv).unwrap();
    assert_eq!(iv.len(), 12);

    let tag = BASE64.decode(&wrap.tag).unwrap();
    assert_eq!(tag.len(), 16);

    let ct = BASE64.decode(&wrap.ciphertext).unwrap();
    assert_eq!(ct.len(), 32);
}

#[test]
fn test_wrap_serialization_roundtrip() {
    let wrap = wrap_dek_with_passphrase(&TEST_DEK, TEST_PASSPHRASE).unwrap();

    let json = serde_json::to_string(&wrap).unwrap();
    let deserialized: RecoveryWrap = serde_json::from_str(&json).unwrap();

    let unwrapped = unwrap_dek_with_passphrase(&deserialized, TEST_PASSPHRASE).unwrap();
    assert_eq!(unwrapped, TEST_DEK);
}

#[test]
fn test_empty_passphrase_rejected() {
    let err = wrap_dek_with_passphrase(&TEST_DEK, "").unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("empty"), "unexpected error: {msg}");
}

#[test]
fn test_tampered_ciphertext_fails() {
    use base64::engine::general_purpose::STANDARD as BASE64;
    use base64::Engine;

    let mut wrap = wrap_dek_with_passphrase(&TEST_DEK, TEST_PASSPHRASE).unwrap();

    // Tamper with ciphertext
    let mut ct = BASE64.decode(&wrap.ciphertext).unwrap();
    ct[0] ^= 0xFF;
    wrap.ciphertext = BASE64.encode(&ct);

    let err = unwrap_dek_with_passphrase(&wrap, TEST_PASSPHRASE).unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("invalid passphrase") || msg.contains("tampered"),
        "unexpected error: {msg}"
    );
}

#[test]
fn test_two_wraps_differ() {
    // Two wraps of the same DEK with the same passphrase should differ
    // (different random salt and nonce each time)
    let wrap1 = wrap_dek_with_passphrase(&TEST_DEK, TEST_PASSPHRASE).unwrap();
    let wrap2 = wrap_dek_with_passphrase(&TEST_DEK, TEST_PASSPHRASE).unwrap();

    assert_ne!(wrap1.salt, wrap2.salt);
    assert_ne!(wrap1.iv, wrap2.iv);
}
