#![cfg(feature = "_test-vectors")]

use secure_core::crypto::encrypt_bytes_with_nonce_test;

/// One-shot helper to generate testdata/v1_reference.enc.
/// Run with: cargo test --test generate_reference --features _test-vectors -- --ignored
#[test]
#[ignore]
fn generate_v1_reference_blob() {
    let key: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D,
        0x1E, 0x1F,
    ];
    let nonce: [u8; 12] = [
        0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB,
    ];
    let plaintext = b"secure-core v1 reference test vector";

    let blob = encrypt_bytes_with_nonce_test(plaintext, &key, nonce).unwrap();

    let out_path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../testdata/v1_reference.enc");
    std::fs::write(&out_path, &blob).unwrap();
    eprintln!("wrote {} bytes to {}", blob.len(), out_path.display());
}
