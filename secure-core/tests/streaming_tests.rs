use std::io::Write;

use secure_core::api::{decrypt_file, encrypt_file};
use secure_core::crypto::Dek;
use secure_core::error::SecureCoreError;
use secure_core::format::{EncHeader, FLAG_STREAM_FINAL_CHUNK};
use secure_core::streaming::CHUNK_SIZE;
use tempfile::NamedTempFile;

const TEST_KEY: [u8; 32] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
];

fn random_bytes(len: usize) -> Vec<u8> {
    use rand::RngCore;
    let mut buf = vec![0u8; len];
    rand::rng().fill_bytes(&mut buf);
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

    let enc_result = encrypt_file(input_file.path(), encrypted_file.path(), &dek).unwrap();
    assert_eq!(enc_result.stream_metadata.chunks, 1);
    assert_eq!(
        enc_result.stream_metadata.total_plaintext_bytes,
        plaintext.len() as u64
    );

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

    let enc_result = encrypt_file(input_file.path(), encrypted_file.path(), &dek).unwrap();
    assert_eq!(enc_result.stream_metadata.chunks, 6);
    assert_eq!(
        enc_result.stream_metadata.total_plaintext_bytes,
        plaintext.len() as u64
    );

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

// ── V1.1: stream truncation detection ───────────────────────────────────

/// Walks chunk-length-prefixed framing and returns the offset at which the
/// last chunk starts (i.e. the cut point to strip it).
fn last_chunk_offset(blob: &[u8]) -> usize {
    let mut offset = 25; // header
    let mut last_chunk_start = offset;
    while offset + 4 <= blob.len() {
        last_chunk_start = offset;
        let len = u32::from_le_bytes([
            blob[offset],
            blob[offset + 1],
            blob[offset + 2],
            blob[offset + 3],
        ]) as usize;
        offset += 4 + len;
    }
    last_chunk_start
}

#[test]
fn test_stream_header_marks_final_chunk_flag() {
    let dek = Dek::new(TEST_KEY);
    let plaintext = b"tiny";
    let input_file = write_temp_file(plaintext);
    let encrypted_file = NamedTempFile::new().unwrap();

    encrypt_file(input_file.path(), encrypted_file.path(), &dek).unwrap();

    let blob = std::fs::read(encrypted_file.path()).unwrap();
    let header = EncHeader::from_bytes(&blob).unwrap();
    assert_eq!(
        header.flags & FLAG_STREAM_FINAL_CHUNK,
        FLAG_STREAM_FINAL_CHUNK,
        "new streams must opt in to final-chunk detection"
    );
}

#[test]
fn test_stream_empty_input_still_has_final_marker() {
    let dek = Dek::new(TEST_KEY);
    let input_file = write_temp_file(b"");
    let encrypted_file = NamedTempFile::new().unwrap();

    encrypt_file(input_file.path(), encrypted_file.path(), &dek).unwrap();

    let blob = std::fs::read(encrypted_file.path()).unwrap();
    let header = EncHeader::from_bytes(&blob).unwrap();
    assert_ne!(header.flags & FLAG_STREAM_FINAL_CHUNK, 0);

    let decrypted_file = NamedTempFile::new().unwrap();
    decrypt_file(encrypted_file.path(), decrypted_file.path(), &dek).unwrap();
    assert!(std::fs::read(decrypted_file.path()).unwrap().is_empty());
}

#[test]
fn test_stream_truncation_of_last_chunk_is_detected() {
    let dek = Dek::new(TEST_KEY);
    // Ensure at least 3 chunks so stripping one still leaves valid framing.
    let plaintext = random_bytes(CHUNK_SIZE * 3 + 42);
    let input_file = write_temp_file(&plaintext);
    let encrypted_file = NamedTempFile::new().unwrap();

    encrypt_file(input_file.path(), encrypted_file.path(), &dek).unwrap();

    let mut blob = std::fs::read(encrypted_file.path()).unwrap();
    let cut = last_chunk_offset(&blob);
    assert!(cut > 25, "must have at least one chunk before the last");
    blob.truncate(cut);
    std::fs::write(encrypted_file.path(), &blob).unwrap();

    let decrypted_file = NamedTempFile::new().unwrap();
    let err = decrypt_file(encrypted_file.path(), decrypted_file.path(), &dek).unwrap_err();
    assert!(
        matches!(
            err,
            SecureCoreError::InvalidFormat(_) | SecureCoreError::CryptoError(_)
        ),
        "truncated stream must be rejected, got: {err:?}"
    );
}

#[cfg(feature = "_test-vectors")]
#[test]
fn test_legacy_stream_without_flag_still_decrypts() {
    use std::io::Cursor;

    let dek = Dek::new(TEST_KEY);
    let plaintext = random_bytes(CHUNK_SIZE * 2 + 123);

    // Produce a blob with the pre-V1.1 layout (flags=0, legacy AAD).
    let mut encrypted = Vec::new();
    secure_core::streaming::encrypt_stream_legacy_v1_test(
        Cursor::new(&plaintext),
        &mut encrypted,
        &dek,
    )
    .unwrap();

    let header = EncHeader::from_bytes(&encrypted).unwrap();
    assert_eq!(header.flags & FLAG_STREAM_FINAL_CHUNK, 0);

    let mut decrypted = Vec::new();
    secure_core::streaming::decrypt_stream(Cursor::new(&encrypted), &mut decrypted, &dek).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_stream_truncation_to_single_chunk_is_detected() {
    let dek = Dek::new(TEST_KEY);
    let plaintext = random_bytes(CHUNK_SIZE * 4);
    let input_file = write_temp_file(&plaintext);
    let encrypted_file = NamedTempFile::new().unwrap();

    encrypt_file(input_file.path(), encrypted_file.path(), &dek).unwrap();

    // Keep only header + first chunk, drop everything after.
    let blob = std::fs::read(encrypted_file.path()).unwrap();
    let first_chunk_len = u32::from_le_bytes([blob[25], blob[26], blob[27], blob[28]]) as usize;
    let kept_end = 25 + 4 + first_chunk_len;
    let truncated = &blob[..kept_end];
    std::fs::write(encrypted_file.path(), truncated).unwrap();

    let decrypted_file = NamedTempFile::new().unwrap();
    let err = decrypt_file(encrypted_file.path(), decrypted_file.path(), &dek).unwrap_err();
    assert!(
        matches!(
            err,
            SecureCoreError::InvalidFormat(_) | SecureCoreError::CryptoError(_)
        ),
        "heavily truncated stream must be rejected, got: {err:?}"
    );
}
