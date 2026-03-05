use std::io::Write;

use secure_core::api::{decrypt_file, encrypt_file};
use secure_core::crypto::Dek;
use secure_core::error::SecureCoreError;
use secure_core::streaming::CHUNK_SIZE;
use tempfile::NamedTempFile;

const TEST_KEY: [u8; 32] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
];

fn random_bytes(len: usize) -> Vec<u8> {
    use rand::RngCore;
    let mut buf = vec![0u8; len];
    rand::thread_rng().fill_bytes(&mut buf);
    buf
}

fn write_temp_file(data: &[u8]) -> NamedTempFile {
    let mut f = NamedTempFile::new().unwrap();
    f.write_all(data).unwrap();
    f.flush().unwrap();
    f
}

// ── Roundtrip tests ─────────────────────────────────────────────────────

#[test]
fn test_stream_roundtrip_small() {
    let dek = Dek::new(TEST_KEY);
    let plaintext = b"small file, less than one chunk";

    let input_file = write_temp_file(plaintext);
    let encrypted_file = NamedTempFile::new().unwrap();
    let decrypted_file = NamedTempFile::new().unwrap();

    let enc_meta = encrypt_file(input_file.path(), encrypted_file.path(), &dek).unwrap();
    assert_eq!(enc_meta.chunks, 1);
    assert_eq!(enc_meta.total_plaintext_bytes, plaintext.len() as u64);

    let dec_meta = decrypt_file(encrypted_file.path(), decrypted_file.path(), &dek).unwrap();
    assert_eq!(dec_meta.chunks, 1);
    assert_eq!(dec_meta.total_plaintext_bytes, plaintext.len() as u64);

    let result = std::fs::read(decrypted_file.path()).unwrap();
    assert_eq!(result, plaintext);
}

#[test]
fn test_stream_roundtrip_multi_chunk() {
    let dek = Dek::new(TEST_KEY);
    // 5.5 chunks worth of data
    let plaintext = random_bytes(CHUNK_SIZE * 5 + CHUNK_SIZE / 2);

    let input_file = write_temp_file(&plaintext);
    let encrypted_file = NamedTempFile::new().unwrap();
    let decrypted_file = NamedTempFile::new().unwrap();

    let enc_meta = encrypt_file(input_file.path(), encrypted_file.path(), &dek).unwrap();
    assert_eq!(enc_meta.chunks, 6);
    assert_eq!(enc_meta.total_plaintext_bytes, plaintext.len() as u64);

    let dec_meta = decrypt_file(encrypted_file.path(), decrypted_file.path(), &dek).unwrap();
    assert_eq!(dec_meta.chunks, 6);

    let result = std::fs::read(decrypted_file.path()).unwrap();
    assert_eq!(result, plaintext);
}

// ── Tamper tests ────────────────────────────────────────────────────────

#[test]
fn test_stream_tamper_middle_chunk() {
    let dek = Dek::new(TEST_KEY);
    let plaintext = random_bytes(CHUNK_SIZE * 4);

    let input_file = write_temp_file(&plaintext);
    let encrypted_file = NamedTempFile::new().unwrap();

    encrypt_file(input_file.path(), encrypted_file.path(), &dek).unwrap();

    // Read the encrypted blob and corrupt a byte in the middle
    let mut blob = std::fs::read(encrypted_file.path()).unwrap();
    let mid = blob.len() / 2;
    blob[mid] ^= 0xFF;
    std::fs::write(encrypted_file.path(), &blob).unwrap();

    let decrypted_file = NamedTempFile::new().unwrap();
    let err = decrypt_file(encrypted_file.path(), decrypted_file.path(), &dek).unwrap_err();
    assert!(
        matches!(err, SecureCoreError::CryptoError(_))
            || matches!(err, SecureCoreError::InvalidFormat(_))
    );
}

#[test]
fn test_stream_tamper_last_chunk() {
    let dek = Dek::new(TEST_KEY);
    let plaintext = random_bytes(CHUNK_SIZE * 3 + 100);

    let input_file = write_temp_file(&plaintext);
    let encrypted_file = NamedTempFile::new().unwrap();

    encrypt_file(input_file.path(), encrypted_file.path(), &dek).unwrap();

    // Corrupt the last byte (part of the last chunk's tag)
    let mut blob = std::fs::read(encrypted_file.path()).unwrap();
    let last = blob.len() - 1;
    blob[last] ^= 0xFF;
    std::fs::write(encrypted_file.path(), &blob).unwrap();

    let decrypted_file = NamedTempFile::new().unwrap();
    let err = decrypt_file(encrypted_file.path(), decrypted_file.path(), &dek).unwrap_err();
    assert!(matches!(err, SecureCoreError::CryptoError(_)));
}
