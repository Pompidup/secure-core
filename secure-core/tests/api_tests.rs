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
fn test_api_roundtrip_1kb() {
    let dek = Dek::new(TEST_KEY);
    let plaintext = random_bytes(1024);

    let input_file = write_temp_file(&plaintext);
    let encrypted_file = NamedTempFile::new().unwrap();
    let decrypted_file = NamedTempFile::new().unwrap();

    encrypt_file(input_file.path(), encrypted_file.path(), &dek).unwrap();
    decrypt_file(encrypted_file.path(), decrypted_file.path(), &dek).unwrap();

    let result = std::fs::read(decrypted_file.path()).unwrap();
    assert_eq!(result, plaintext);
}

#[test]
fn test_api_roundtrip_200kb() {
    let dek = Dek::new(TEST_KEY);
    let size = 200 * 1024;
    let plaintext = random_bytes(size);

    let input_file = write_temp_file(&plaintext);
    let encrypted_file = NamedTempFile::new().unwrap();
    let decrypted_file = NamedTempFile::new().unwrap();

    let enc_result = encrypt_file(input_file.path(), encrypted_file.path(), &dek).unwrap();

    // 200 KB / 64 KB = 3.125 → 4 chunks
    assert!(
        enc_result.stream_metadata.chunks >= 4,
        "expected >= 4 chunks for 200KB, got {}",
        enc_result.stream_metadata.chunks
    );

    decrypt_file(encrypted_file.path(), decrypted_file.path(), &dek).unwrap();

    let result = std::fs::read(decrypted_file.path()).unwrap();
    assert_eq!(result, plaintext);
}

#[test]
fn test_api_empty_file() {
    let dek = Dek::new(TEST_KEY);
    let plaintext: &[u8] = &[];

    let input_file = write_temp_file(plaintext);
    let encrypted_file = NamedTempFile::new().unwrap();
    let decrypted_file = NamedTempFile::new().unwrap();

    let enc_result = encrypt_file(input_file.path(), encrypted_file.path(), &dek).unwrap();
    assert_eq!(enc_result.stream_metadata.total_plaintext_bytes, 0);

    let dec_meta = decrypt_file(encrypted_file.path(), decrypted_file.path(), &dek).unwrap();
    assert_eq!(dec_meta.total_plaintext_bytes, 0);

    let result = std::fs::read(decrypted_file.path()).unwrap();
    assert!(result.is_empty());
}

// ── Error tests ─────────────────────────────────────────────────────────

#[test]
fn test_api_decrypt_corrupted_blob() {
    let dek = Dek::new(TEST_KEY);
    let plaintext = random_bytes(1024);

    let input_file = write_temp_file(&plaintext);
    let encrypted_file = NamedTempFile::new().unwrap();

    encrypt_file(input_file.path(), encrypted_file.path(), &dek).unwrap();

    // Overwrite the encrypted file with random garbage
    let garbage = random_bytes(512);
    std::fs::write(encrypted_file.path(), &garbage).unwrap();

    let decrypted_file = NamedTempFile::new().unwrap();
    let err = decrypt_file(encrypted_file.path(), decrypted_file.path(), &dek).unwrap_err();
    assert!(
        matches!(
            err,
            SecureCoreError::InvalidFormat(_) | SecureCoreError::CryptoError(_)
        ),
        "expected InvalidFormat or CryptoError, got: {err:?}"
    );
}

// ── Metadata tests ──────────────────────────────────────────────────────

#[test]
fn test_api_encrypt_result_metadata() {
    let dek = Dek::new(TEST_KEY);
    let plaintext = random_bytes(1024);

    let input_file = write_temp_file(&plaintext);
    let encrypted_file = NamedTempFile::new().unwrap();

    let enc_result = encrypt_file(input_file.path(), encrypted_file.path(), &dek).unwrap();

    // 1024 bytes fits in a single 64KB chunk
    assert_eq!(enc_result.stream_metadata.chunks, 1);
    assert_eq!(enc_result.stream_metadata.total_plaintext_bytes, 1024);

    // Ciphertext includes header + nonce + chunk length + ciphertext + GCM tag
    assert!(
        enc_result.document_metadata.ciphertext_size > 1024,
        "ciphertext_size ({}) should exceed plaintext_size (1024)",
        enc_result.document_metadata.ciphertext_size
    );

    assert_eq!(enc_result.document_metadata.plaintext_size, Some(1024));

    // Filename should be extracted from the temp file path
    assert!(
        !enc_result.document_metadata.filename.is_empty(),
        "filename should not be empty"
    );
}

#[test]
fn test_api_roundtrip_exact_chunk_boundary() {
    let dek = Dek::new(TEST_KEY);
    // Exactly 1 chunk boundary — tests edge case of no partial last chunk
    let plaintext = random_bytes(CHUNK_SIZE);

    let input_file = write_temp_file(&plaintext);
    let encrypted_file = NamedTempFile::new().unwrap();
    let decrypted_file = NamedTempFile::new().unwrap();

    let enc_result = encrypt_file(input_file.path(), encrypted_file.path(), &dek).unwrap();
    assert_eq!(enc_result.stream_metadata.chunks, 1);
    assert_eq!(
        enc_result.stream_metadata.total_plaintext_bytes,
        CHUNK_SIZE as u64
    );

    decrypt_file(encrypted_file.path(), decrypted_file.path(), &dek).unwrap();

    let result = std::fs::read(decrypted_file.path()).unwrap();
    assert_eq!(result, plaintext);
}
