#![cfg(feature = "_test-vectors")]

//! Compatibility tests for the .enc V1 format.
//!
//! These tests load pre-generated golden files from `testdata/compat/v1/` and verify
//! that decryption produces the expected plaintext (by SHA-256 comparison).
//! Any failure here means a FORMAT REGRESSION — the .enc binary format has changed
//! in a way that breaks cross-platform compatibility.

use std::collections::HashMap;
use std::io::Cursor;
use std::path::{Path, PathBuf};

use secure_core::crypto::{decrypt_bytes, encrypt_bytes_with_nonce_test, Dek};
use secure_core::error::SecureCoreError;
use secure_core::format::{EncHeader, FLAG_STREAM_FINAL_CHUNK};
use secure_core::streaming::{decrypt_stream, encrypt_stream_with_nonce_test};
use sha2::{Digest, Sha256};

// ── Helpers ────────────────────────────────────────────────────────────

fn compat_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../testdata/compat/v1")
}

fn sha256_hex(data: &[u8]) -> String {
    let hash = Sha256::digest(data);
    hash.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

#[derive(serde::Deserialize)]
struct VectorsFile {
    vectors: Vec<VectorEntry>,
}

#[derive(serde::Deserialize)]
struct VectorEntry {
    id: String,
    dek_ref: String,
    plain_sha256: String,
    cipher_sha256: String,
    header: HeaderEntry,
}

#[derive(serde::Deserialize)]
struct HeaderEntry {
    version: u16,
    algo: String,
    nonce: String,
}

fn load_vectors() -> VectorsFile {
    let path = compat_dir().join("vectors.json");
    let data = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    serde_json::from_str(&data).unwrap()
}

fn load_deks() -> HashMap<String, Vec<u8>> {
    let path = compat_dir().join("test_deks.json");
    let data = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    let raw: serde_json::Value = serde_json::from_str(&data).unwrap();
    let obj = raw.as_object().unwrap();
    obj.iter()
        .filter(|(k, _)| k.starts_with("dek_"))
        .map(|(k, v)| (k.clone(), hex_to_bytes(v.as_str().unwrap())))
        .collect()
}

fn decrypt_vector(vector: &VectorEntry, deks: &HashMap<String, Vec<u8>>) -> Vec<u8> {
    let enc_path = compat_dir().join(&vector.id).join("encrypted.enc");
    let enc_data = std::fs::read(&enc_path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", enc_path.display()));

    // Verify cipher SHA-256
    assert_eq!(
        sha256_hex(&enc_data),
        vector.cipher_sha256,
        "cipher_sha256 mismatch for {} — golden file may have been modified",
        vector.id,
    );

    let dek_bytes = deks
        .get(&vector.dek_ref)
        .unwrap_or_else(|| panic!("DEK {} not found in test_deks.json", vector.dek_ref));

    let dek: [u8; 32] = dek_bytes.as_slice().try_into().unwrap();
    decrypt_bytes(&enc_data, &dek).unwrap()
}

// ── Success: decrypt and verify plaintext SHA-256 ──────────────────────

fn test_compat_decrypt(vector_id: &str) {
    let vectors = load_vectors();
    let deks = load_deks();
    let vector = vectors
        .vectors
        .iter()
        .find(|v| v.id == vector_id)
        .unwrap_or_else(|| panic!("vector {vector_id} not found in vectors.json"));

    let plaintext = decrypt_vector(vector, &deks);

    assert_eq!(
        sha256_hex(&plaintext),
        vector.plain_sha256,
        "FORMAT REGRESSION DETECTED: plaintext SHA-256 mismatch for {vector_id}"
    );

    // Also verify against plain.bin on disk
    let plain_path = compat_dir().join(vector_id).join("plain.bin");
    let expected_plain = std::fs::read(&plain_path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", plain_path.display()));
    assert_eq!(
        plaintext, expected_plain,
        "decrypted plaintext does not match plain.bin for {vector_id}"
    );
}

#[test]
fn test_compat_decrypt_image_small() {
    test_compat_decrypt("image_small");
}

#[test]
fn test_compat_decrypt_image_medium() {
    test_compat_decrypt("image_medium");
}

#[test]
fn test_compat_decrypt_pdf_large() {
    test_compat_decrypt("pdf_large");
}

#[test]
fn test_compat_decrypt_text_small() {
    test_compat_decrypt("text_small");
}

// ── Header parsing ─────────────────────────────────────────────────────

fn test_compat_header_parse(vector_id: &str) {
    let vectors = load_vectors();
    let vector = vectors.vectors.iter().find(|v| v.id == vector_id).unwrap();

    let enc_path = compat_dir().join(vector_id).join("encrypted.enc");
    let enc_data = std::fs::read(&enc_path).unwrap();

    let header = EncHeader::from_bytes(&enc_data).unwrap();
    assert_eq!(header.version, vector.header.version);
    assert_eq!(vector.header.algo, "AES-256-GCM");
    assert_eq!(
        header
            .nonce
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>(),
        vector.header.nonce,
    );
}

#[test]
fn test_compat_header_parse_image_small() {
    test_compat_header_parse("image_small");
}

#[test]
fn test_compat_header_parse_image_medium() {
    test_compat_header_parse("image_medium");
}

#[test]
fn test_compat_header_parse_pdf_large() {
    test_compat_header_parse("pdf_large");
}

#[test]
fn test_compat_header_parse_text_small() {
    test_compat_header_parse("text_small");
}

// ── Deterministic re-generation ────────────────────────────────────────

#[test]
fn test_compat_deterministic_regeneration() {
    let vectors = load_vectors();
    let deks = load_deks();

    for vector in &vectors.vectors {
        let dek_bytes = deks.get(&vector.dek_ref).unwrap();
        let dek: [u8; 32] = dek_bytes.as_slice().try_into().unwrap();
        let nonce: [u8; 12] = hex_to_bytes(&vector.header.nonce).try_into().unwrap();

        // Read original plaintext
        let plain_path = compat_dir().join(&vector.id).join("plain.bin");
        let plaintext = std::fs::read(&plain_path).unwrap();

        // Re-encrypt with same key + nonce
        let regenerated = encrypt_bytes_with_nonce_test(&plaintext, &dek, nonce).unwrap();

        // Must match stored encrypted.enc byte-for-byte
        let enc_path = compat_dir().join(&vector.id).join("encrypted.enc");
        let stored = std::fs::read(&enc_path).unwrap();

        assert_eq!(
            stored, regenerated,
            "FORMAT REGRESSION: re-encryption of {} does not match golden file",
            vector.id,
        );
    }
}

// ── Error vectors ──────────────────────────────────────────────────────

#[test]
fn test_compat_error_tampered() {
    let deks = load_deks();
    let dek_bytes = deks.get("dek_image_small").unwrap();
    let dek: [u8; 32] = dek_bytes.as_slice().try_into().unwrap();

    let enc_path = compat_dir().join("error_tampered/encrypted.enc");
    let enc_data = std::fs::read(&enc_path).unwrap();

    let err = decrypt_bytes(&enc_data, &dek).unwrap_err();
    assert!(
        matches!(err, SecureCoreError::CryptoError(_)),
        "expected CryptoError for tampered data, got: {err:?}"
    );
}

#[test]
fn test_compat_error_truncated() {
    let deks = load_deks();
    let dek_bytes = deks.get("dek_image_small").unwrap();
    let dek: [u8; 32] = dek_bytes.as_slice().try_into().unwrap();

    let enc_path = compat_dir().join("error_truncated/encrypted.enc");
    let enc_data = std::fs::read(&enc_path).unwrap();

    let err = decrypt_bytes(&enc_data, &dek).unwrap_err();
    assert!(
        matches!(
            err,
            SecureCoreError::InvalidFormat(_) | SecureCoreError::CryptoError(_)
        ),
        "expected InvalidFormat or CryptoError for truncated data, got: {err:?}"
    );
}

#[test]
fn test_compat_error_future_version() {
    let deks = load_deks();
    let dek_bytes = deks.get("dek_image_small").unwrap();
    let dek: [u8; 32] = dek_bytes.as_slice().try_into().unwrap();

    let enc_path = compat_dir().join("error_future_version/encrypted.enc");
    let enc_data = std::fs::read(&enc_path).unwrap();

    let err = decrypt_bytes(&enc_data, &dek).unwrap_err();
    assert!(
        matches!(
            err,
            SecureCoreError::UnsupportedVersion {
                found: 99,
                max_supported: 1
            }
        ),
        "expected UnsupportedVersion(99, 1) for future version, got: {err:?}"
    );
}

// ── V1.1 streaming compat pack ─────────────────────────────────────────
//
// The V1.1 format (opt-in header flag FLAG_STREAM_FINAL_CHUNK) is frozen
// by golden files under testdata/compat/v1_1/stream/. Each vector must
// round-trip, decrypt to the expected plaintext, carry the flag, detect
// truncation, and regenerate byte-for-byte — the compat posture mirrors
// the V1 in-memory pack above.

fn compat_v1_1_stream_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../testdata/compat/v1_1/stream")
}

#[derive(serde::Deserialize)]
struct StreamVectorsFile {
    vectors: Vec<StreamVectorEntry>,
}

#[derive(serde::Deserialize)]
struct StreamVectorEntry {
    id: String,
    dek_ref: String,
    plain_sha256: String,
    cipher_sha256: String,
    chunks: u32,
    header: StreamHeaderEntry,
}

#[derive(serde::Deserialize)]
struct StreamHeaderEntry {
    base_nonce: String,
}

fn load_v1_1_stream_vectors() -> StreamVectorsFile {
    let path = compat_v1_1_stream_dir().join("vectors.json");
    let data = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    serde_json::from_str(&data).unwrap()
}

fn load_v1_1_stream_deks() -> HashMap<String, Vec<u8>> {
    let path = compat_v1_1_stream_dir().join("test_deks.json");
    let data = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    let raw: serde_json::Value = serde_json::from_str(&data).unwrap();
    raw.as_object()
        .unwrap()
        .iter()
        .filter(|(k, _)| k.starts_with("dek_"))
        .map(|(k, v)| (k.clone(), hex_to_bytes(v.as_str().unwrap())))
        .collect()
}

fn find_stream_vector<'a>(vectors: &'a StreamVectorsFile, id: &str) -> &'a StreamVectorEntry {
    vectors
        .vectors
        .iter()
        .find(|v| v.id == id)
        .unwrap_or_else(|| panic!("V1.1 stream vector {id} not found"))
}

fn decrypt_stream_vector(vector: &StreamVectorEntry) -> Vec<u8> {
    let enc_path = compat_v1_1_stream_dir()
        .join(&vector.id)
        .join("encrypted.enc");
    let enc_data = std::fs::read(&enc_path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", enc_path.display()));

    assert_eq!(
        sha256_hex(&enc_data),
        vector.cipher_sha256,
        "cipher_sha256 mismatch for V1.1 stream vector {} — golden file drift",
        vector.id,
    );

    let deks = load_v1_1_stream_deks();
    let dek_bytes = deks
        .get(&vector.dek_ref)
        .unwrap_or_else(|| panic!("DEK {} not found in V1.1 test_deks.json", vector.dek_ref));
    let dek_arr: [u8; 32] = dek_bytes.as_slice().try_into().unwrap();
    let dek = Dek::new(dek_arr);

    let mut plaintext = Vec::new();
    decrypt_stream(Cursor::new(&enc_data), &mut plaintext, &dek)
        .unwrap_or_else(|e| panic!("decrypt_stream failed on {}: {e}", vector.id));
    plaintext
}

#[test]
fn test_compat_v1_1_stream_single_chunk_decrypts() {
    let vectors = load_v1_1_stream_vectors();
    let vector = find_stream_vector(&vectors, "stream_single_chunk");

    let plaintext = decrypt_stream_vector(vector);
    assert_eq!(
        sha256_hex(&plaintext),
        vector.plain_sha256,
        "FORMAT REGRESSION: stream_single_chunk plaintext SHA mismatch"
    );

    let expected =
        std::fs::read(compat_v1_1_stream_dir().join(&vector.id).join("plain.bin")).unwrap();
    assert_eq!(plaintext, expected);
}

#[test]
fn test_compat_v1_1_stream_multi_chunk_decrypts() {
    let vectors = load_v1_1_stream_vectors();
    let vector = find_stream_vector(&vectors, "stream_multi_chunk");
    assert_eq!(vector.chunks, 3, "fixture expected to span 3 chunks");

    let plaintext = decrypt_stream_vector(vector);
    assert_eq!(
        sha256_hex(&plaintext),
        vector.plain_sha256,
        "FORMAT REGRESSION: stream_multi_chunk plaintext SHA mismatch"
    );

    let expected =
        std::fs::read(compat_v1_1_stream_dir().join(&vector.id).join("plain.bin")).unwrap();
    assert_eq!(plaintext, expected);
}

#[test]
fn test_compat_v1_1_stream_header_carries_final_flag() {
    let vectors = load_v1_1_stream_vectors();
    for vector in &vectors.vectors {
        let enc_path = compat_v1_1_stream_dir()
            .join(&vector.id)
            .join("encrypted.enc");
        let enc_data = std::fs::read(&enc_path).unwrap();
        let header = EncHeader::from_bytes(&enc_data).unwrap();
        assert_ne!(
            header.flags & FLAG_STREAM_FINAL_CHUNK,
            0,
            "vector {} is a V1.1 golden but its flag is not set",
            vector.id
        );
    }
}

#[test]
fn test_compat_v1_1_stream_multi_chunk_truncation_is_detected() {
    let vectors = load_v1_1_stream_vectors();
    let vector = find_stream_vector(&vectors, "stream_multi_chunk");

    let enc_path = compat_v1_1_stream_dir()
        .join(&vector.id)
        .join("encrypted.enc");
    let enc_data = std::fs::read(&enc_path).unwrap();

    // Walk the chunk-length framing to find where the last chunk starts,
    // then truncate the blob to drop it. The V1.1 final-chunk marker must
    // make decrypt_stream reject this.
    let mut offset = 25usize;
    let mut last_chunk_start = offset;
    while offset + 4 <= enc_data.len() {
        last_chunk_start = offset;
        let len = u32::from_le_bytes([
            enc_data[offset],
            enc_data[offset + 1],
            enc_data[offset + 2],
            enc_data[offset + 3],
        ]) as usize;
        offset += 4 + len;
    }
    assert!(
        last_chunk_start > 25,
        "need at least one chunk before the last"
    );
    let truncated = &enc_data[..last_chunk_start];

    let deks = load_v1_1_stream_deks();
    let dek_arr: [u8; 32] = deks
        .get(&vector.dek_ref)
        .unwrap()
        .as_slice()
        .try_into()
        .unwrap();
    let dek = Dek::new(dek_arr);

    let mut sink = Vec::new();
    let err = decrypt_stream(Cursor::new(truncated), &mut sink, &dek).unwrap_err();
    assert!(
        matches!(
            err,
            SecureCoreError::InvalidFormat(_) | SecureCoreError::CryptoError(_)
        ),
        "truncated V1.1 stream must be rejected, got: {err:?}"
    );
}

#[test]
fn test_compat_v1_1_stream_deterministic_regeneration() {
    let vectors = load_v1_1_stream_vectors();
    let deks = load_v1_1_stream_deks();

    for vector in &vectors.vectors {
        let dek_arr: [u8; 32] = deks
            .get(&vector.dek_ref)
            .unwrap()
            .as_slice()
            .try_into()
            .unwrap();
        let dek = Dek::new(dek_arr);

        let base_nonce: [u8; 12] = hex_to_bytes(&vector.header.base_nonce).try_into().unwrap();

        let plaintext =
            std::fs::read(compat_v1_1_stream_dir().join(&vector.id).join("plain.bin")).unwrap();

        let mut regenerated = Vec::new();
        encrypt_stream_with_nonce_test(Cursor::new(&plaintext), &mut regenerated, &dek, base_nonce)
            .unwrap();

        let stored = std::fs::read(
            compat_v1_1_stream_dir()
                .join(&vector.id)
                .join("encrypted.enc"),
        )
        .unwrap();

        assert_eq!(
            stored, regenerated,
            "FORMAT REGRESSION: V1.1 stream vector {} does not regenerate byte-for-byte",
            vector.id
        );
    }
}
