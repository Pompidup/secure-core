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
fn test_legacy_stream_without_flag_decrypts_with_allow_legacy() {
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
    secure_core::streaming::decrypt_stream_allow_legacy(
        Cursor::new(&encrypted),
        &mut decrypted,
        &dek,
    )
    .unwrap();
    assert_eq!(decrypted, plaintext);
}

#[cfg(feature = "_test-vectors")]
#[test]
fn test_decrypt_file_allow_legacy_migrates_legacy_file() {
    let dek = Dek::new(TEST_KEY);
    let plaintext = random_bytes(CHUNK_SIZE * 2 + 9);
    let mut legacy = Vec::new();
    secure_core::streaming::encrypt_stream_legacy_v1_test(
        std::io::Cursor::new(&plaintext),
        &mut legacy,
        &dek,
    )
    .unwrap();
    let legacy_file = write_temp_file(&legacy);

    // Default reader refuses it...
    let out = NamedTempFile::new().unwrap();
    let err = decrypt_file(legacy_file.path(), out.path(), &dek).unwrap_err();
    assert!(
        matches!(err, SecureCoreError::InvalidFormat(_)),
        "got: {err:?}"
    );

    // ...the explicit migration path decrypts it, and re-encryption yields V1.1.
    secure_core::api::decrypt_file_allow_legacy(legacy_file.path(), out.path(), &dek).unwrap();
    assert_eq!(std::fs::read(out.path()).unwrap(), plaintext);

    let migrated = NamedTempFile::new().unwrap();
    encrypt_file(out.path(), migrated.path(), &dek).unwrap();
    let roundtrip = NamedTempFile::new().unwrap();
    decrypt_file(migrated.path(), roundtrip.path(), &dek).unwrap();
    assert_eq!(std::fs::read(roundtrip.path()).unwrap(), plaintext);
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

// ── Downgrade protection ────────────────────────────────────────────
// The stream header is not part of the chunk AAD, so an attacker can clear
// FLAG_STREAM_FINAL_CHUNK. Non-final V1.1 chunks are indistinguishable from
// V1.0 legacy chunks, so a reader that trusts the flag would accept a
// truncated stream as a valid legacy one. The default reader must refuse
// streams without the flag.

fn encrypt_to_vec(plaintext: &[u8], dek: &Dek) -> Vec<u8> {
    let mut blob = Vec::new();
    secure_core::streaming::encrypt_stream(std::io::Cursor::new(plaintext), &mut blob, dek)
        .unwrap();
    blob
}

/// Clears FLAG_STREAM_FINAL_CHUNK (bit 0 of the little-endian flags at offset 19).
fn clear_final_flag(blob: &mut [u8]) {
    blob[19] &= !(FLAG_STREAM_FINAL_CHUNK as u8);
}

#[test]
fn test_stream_truncation_with_final_flag_cleared_is_rejected() {
    let dek = Dek::new(TEST_KEY);
    let plaintext = random_bytes(CHUNK_SIZE * 3 - 100);
    let mut blob = encrypt_to_vec(&plaintext, &dek);

    blob.truncate(last_chunk_offset(&blob));
    clear_final_flag(&mut blob);

    let mut out = Vec::new();
    let err = secure_core::streaming::decrypt_stream(std::io::Cursor::new(&blob), &mut out, &dek)
        .unwrap_err();
    assert!(
        matches!(err, SecureCoreError::InvalidFormat(_)),
        "downgraded truncated stream must be rejected, got: {err:?}"
    );
    assert!(
        out.is_empty(),
        "no plaintext may be emitted before rejection"
    );
}

#[test]
fn test_stream_header_only_with_final_flag_cleared_is_rejected() {
    let dek = Dek::new(TEST_KEY);
    let blob = encrypt_to_vec(&random_bytes(CHUNK_SIZE + 1), &dek);
    let mut header_only = blob[..25].to_vec();
    clear_final_flag(&mut header_only);

    let mut out = Vec::new();
    let err =
        secure_core::streaming::decrypt_stream(std::io::Cursor::new(&header_only), &mut out, &dek)
            .unwrap_err();
    assert!(
        matches!(err, SecureCoreError::InvalidFormat(_)),
        "a stream stripped of every chunk must be rejected, got: {err:?}"
    );
    assert!(out.is_empty());
}

#[test]
fn test_decrypt_file_rejects_downgraded_stream_and_writes_no_plaintext() {
    let dek = Dek::new(TEST_KEY);
    let plaintext = random_bytes(CHUNK_SIZE * 3 + 7);
    let input_file = write_temp_file(&plaintext);
    let encrypted_file = NamedTempFile::new().unwrap();
    encrypt_file(input_file.path(), encrypted_file.path(), &dek).unwrap();

    let mut blob = std::fs::read(encrypted_file.path()).unwrap();
    blob.truncate(last_chunk_offset(&blob));
    clear_final_flag(&mut blob);
    std::fs::write(encrypted_file.path(), &blob).unwrap();

    let decrypted_file = NamedTempFile::new().unwrap();
    let err = decrypt_file(encrypted_file.path(), decrypted_file.path(), &dek).unwrap_err();
    assert!(
        matches!(err, SecureCoreError::InvalidFormat(_)),
        "got: {err:?}"
    );
    assert_eq!(std::fs::metadata(decrypted_file.path()).unwrap().len(), 0);
}

#[test]
fn test_allow_legacy_decrypts_v1_1_streams() {
    let dek = Dek::new(TEST_KEY);
    let plaintext = random_bytes(CHUNK_SIZE * 2 + 1);
    let blob = encrypt_to_vec(&plaintext, &dek);

    let mut out = Vec::new();
    secure_core::streaming::decrypt_stream_allow_legacy(
        std::io::Cursor::new(&blob),
        &mut out,
        &dek,
    )
    .unwrap();
    assert_eq!(out, plaintext);
}

#[test]
fn test_allow_legacy_still_detects_truncation_of_flagged_stream() {
    let dek = Dek::new(TEST_KEY);
    let mut blob = encrypt_to_vec(&random_bytes(CHUNK_SIZE * 3), &dek);
    blob.truncate(last_chunk_offset(&blob));

    let err = secure_core::streaming::decrypt_stream_allow_legacy(
        std::io::Cursor::new(&blob),
        &mut Vec::new(),
        &dek,
    )
    .unwrap_err();
    assert!(
        matches!(
            err,
            SecureCoreError::InvalidFormat(_) | SecureCoreError::CryptoError(_)
        ),
        "got: {err:?}"
    );
}

#[cfg(feature = "_test-vectors")]
#[test]
fn test_legacy_stream_without_flag_is_rejected_by_default() {
    let dek = Dek::new(TEST_KEY);
    let plaintext = random_bytes(CHUNK_SIZE + 5);
    let mut legacy = Vec::new();
    secure_core::streaming::encrypt_stream_legacy_v1_test(
        std::io::Cursor::new(&plaintext),
        &mut legacy,
        &dek,
    )
    .unwrap();

    let err = secure_core::streaming::decrypt_stream(
        std::io::Cursor::new(&legacy),
        &mut Vec::new(),
        &dek,
    )
    .unwrap_err();
    assert!(
        matches!(err, SecureCoreError::InvalidFormat(_)),
        "got: {err:?}"
    );
}

// ── Header version must be one this build knows ──────────────────────
// No writer ever produced version 0. Accepting it widened the set of
// malformed inputs, and in streaming the version byte is not authenticated.

#[test]
fn test_header_version_0_is_rejected() {
    let mut bytes = EncHeader::new_v1([0u8; 12]).to_bytes();
    bytes[4] = 0;
    bytes[5] = 0;
    let err = EncHeader::from_bytes(&bytes).unwrap_err();
    assert!(
        matches!(err, SecureCoreError::UnsupportedVersion { found: 0, .. }),
        "got: {err:?}"
    );
}

#[test]
fn test_stream_with_header_version_0_is_rejected() {
    let dek = Dek::new(TEST_KEY);
    let mut blob = encrypt_to_vec(&random_bytes(CHUNK_SIZE + 3), &dek);
    blob[4] = 0;
    let mut out = Vec::new();
    let err = secure_core::streaming::decrypt_stream(std::io::Cursor::new(&blob), &mut out, &dek)
        .unwrap_err();
    assert!(
        matches!(err, SecureCoreError::UnsupportedVersion { found: 0, .. }),
        "got: {err:?}"
    );
    assert!(out.is_empty());
}

#[test]
fn test_bytes_blob_with_header_version_0_is_rejected_as_unsupported() {
    let key = TEST_KEY;
    let mut blob = secure_core::crypto::encrypt_bytes(b"version zero", &key).unwrap();
    blob[4] = 0;
    let err = secure_core::crypto::decrypt_bytes(&blob, &key).unwrap_err();
    assert!(
        matches!(err, SecureCoreError::UnsupportedVersion { found: 0, .. }),
        "got: {err:?}"
    );
}
