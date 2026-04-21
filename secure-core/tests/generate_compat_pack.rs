#![cfg(feature = "_test-vectors")]

//! One-shot generator for all committed test data.
//! Run with: cargo test --test generate_compat_pack --features _test-vectors -- --ignored
//!
//! Produces two deterministic outputs, both committed to git:
//! - `testdata/compat/v1/` : the cross-platform compat pack (4 success
//!   vectors + 3 error vectors + `vectors.json` + `test_deks.json`),
//!   consumed by `tests/compat_tests.rs`.
//! - `testdata/v1_reference.enc` : a single small reference blob used by
//!   the regression tests in `tests/crypto_tests.rs`.
//!
//! Previously these two outputs were produced by separate ignored tests
//! (`generate_compat_pack.rs` and `generate_reference.rs`). They used the
//! same primitive and the same feature gate; splitting them gave us two
//! sources of truth for "how do we rebuild the test corpus?". Now there
//! is one.
//!
//! Also produces the V1.1 streaming compat pack in
//! `testdata/compat/v1_1/stream/` — two deterministic streaming vectors
//! (single-chunk and multi-chunk) that freeze the V1.1 format across
//! platforms. See docs/compat-promises.md.

use secure_core::crypto::{encrypt_bytes_with_nonce_test, Dek};
use secure_core::streaming::{encrypt_stream_with_nonce_test, CHUNK_SIZE};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};

// ── DEKs (NEVER USE IN PRODUCTION) ─────────────────────────────────────

const DEK_IMAGE_SMALL: [u8; 32] = [
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
];

const DEK_IMAGE_MEDIUM: [u8; 32] = [
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
];

const DEK_PDF_LARGE: [u8; 32] = [
    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
    0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F,
];

const DEK_TEXT_SMALL: [u8; 32] = [
    0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F,
    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F,
];

// V1.1 streaming DEKs (distinct byte ranges from V1 to avoid any
// confusion when inspecting fixtures). NEVER USE IN PRODUCTION.
const DEK_STREAM_SINGLE: [u8; 32] = [
    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F,
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
];

const DEK_STREAM_MULTI: [u8; 32] = [
    0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF,
    0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF,
];

// V1.1 streaming base nonces (one per vector, fixed to keep regeneration
// byte-for-byte stable).
const STREAM_NONCE_SINGLE: [u8; 12] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
];
const STREAM_NONCE_MULTI: [u8; 12] = [
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
];

// Reference blob constants (testdata/v1_reference.enc). Must match the
// values used by tests/crypto_tests.rs::test_regression_v1_reference* —
// changing them breaks regression tests without any crypto change.
const REFERENCE_KEY: [u8; 32] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
];
const REFERENCE_NONCE: [u8; 12] = [
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB,
];
const REFERENCE_PLAINTEXT: &[u8] = b"secure-core v1 reference test vector";

// ── Nonces (one per vector) ────────────────────────────────────────────

const NONCE_IMAGE_SMALL: [u8; 12] = [
    0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB,
];
const NONCE_IMAGE_MEDIUM: [u8; 12] = [
    0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB,
];
const NONCE_PDF_LARGE: [u8; 12] = [
    0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB,
];
const NONCE_TEXT_SMALL: [u8; 12] = [
    0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xEB,
];

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn sha256_hex(data: &[u8]) -> String {
    let hash = Sha256::digest(data);
    hex(&hash)
}

fn compat_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../testdata/compat/v1")
}

fn compat_v1_1_stream_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../testdata/compat/v1_1/stream")
}

/// Generate a repeating-pattern plaintext of the given size.
fn make_plaintext(size: usize, seed: u8) -> Vec<u8> {
    (0..size)
        .map(|i| seed.wrapping_add((i % 256) as u8))
        .collect()
}

/// Generate a UTF-8 text plaintext.
fn make_text_plaintext() -> Vec<u8> {
    // Repeating readable ASCII pattern, exactly 256 bytes
    let base = "The quick brown fox jumps over the lazy dog. ";
    let mut out = String::new();
    while out.len() < 256 {
        out.push_str(base);
    }
    out.truncate(256);
    out.into_bytes()
}

struct VectorResult {
    id: String,
    dek_ref: String,
    plain_sha256: String,
    cipher_sha256: String,
    nonce_hex: String,
    plaintext_size: usize,
    mime_type: String,
}

struct StreamVectorResult {
    id: String,
    dek_ref: String,
    plain_sha256: String,
    cipher_sha256: String,
    base_nonce_hex: String,
    plaintext_size: usize,
    ciphertext_size: usize,
    chunks: u32,
    mime_type: String,
}

fn generate_vector(
    id: &str,
    dek: &[u8; 32],
    nonce: [u8; 12],
    plaintext: &[u8],
    mime_type: &str,
) -> VectorResult {
    let dir = compat_dir().join(id);
    fs::create_dir_all(&dir).unwrap();

    // Write plaintext
    fs::write(dir.join("plain.bin"), plaintext).unwrap();

    // Encrypt
    let encrypted = encrypt_bytes_with_nonce_test(plaintext, dek, nonce).unwrap();
    fs::write(dir.join("encrypted.enc"), &encrypted).unwrap();

    let plain_sha = sha256_hex(plaintext);
    let cipher_sha = sha256_hex(&encrypted);

    // Write metadata.json
    let metadata = serde_json::json!({
        "mimeType": mime_type,
        "plaintextSize": plaintext.len(),
        "contentHash": plain_sha,
        "headerParsed": {
            "version": 1,
            "algorithm": "AES-256-GCM",
            "algorithmId": "0x01",
            "nonce": hex(&nonce),
            "flags": "0x0000",
            "headerLength": 25
        }
    });
    fs::write(
        dir.join("metadata.json"),
        serde_json::to_string_pretty(&metadata).unwrap(),
    )
    .unwrap();

    eprintln!(
        "  {id}: plain={} bytes, enc={} bytes, plain_sha={}",
        plaintext.len(),
        encrypted.len(),
        &plain_sha[..16]
    );

    VectorResult {
        id: id.to_string(),
        dek_ref: format!("dek_{id}"),
        plain_sha256: plain_sha,
        cipher_sha256: cipher_sha,
        nonce_hex: hex(&nonce),
        plaintext_size: plaintext.len(),
        mime_type: mime_type.to_string(),
    }
}

/// Produces a single V1.1 streaming vector on disk and returns its summary.
/// Writes `plain.bin`, `encrypted.enc`, and `metadata.json` under
/// `<stream-dir>/<id>/`. The encrypted output is produced with a fixed
/// base nonce so re-runs are byte-for-byte reproducible.
fn generate_stream_vector(
    id: &str,
    dek_bytes: &[u8; 32],
    base_nonce: [u8; 12],
    plaintext: &[u8],
    mime_type: &str,
) -> StreamVectorResult {
    let dir = compat_v1_1_stream_dir().join(id);
    fs::create_dir_all(&dir).unwrap();

    fs::write(dir.join("plain.bin"), plaintext).unwrap();

    // Build a temporary Dek; encrypt_stream_with_nonce_test forces the base
    // nonce so successive runs against the same inputs emit identical bytes.
    let dek = Dek::new(*dek_bytes);
    let mut encrypted = Vec::new();
    let stream_meta =
        encrypt_stream_with_nonce_test(Cursor::new(plaintext), &mut encrypted, &dek, base_nonce)
            .unwrap();
    fs::write(dir.join("encrypted.enc"), &encrypted).unwrap();

    let plain_sha = sha256_hex(plaintext);
    let cipher_sha = sha256_hex(&encrypted);

    let metadata = serde_json::json!({
        "mimeType": mime_type,
        "plaintextSize": plaintext.len(),
        "ciphertextSize": encrypted.len(),
        "contentHash": plain_sha,
        "chunks": stream_meta.chunks,
        "headerParsed": {
            "version": 1,
            "algorithm": "AES-256-GCM",
            "algorithmId": "0x01",
            "baseNonce": hex(&base_nonce),
            "flags": "0x0001",
            "flagsMeaning": "FLAG_STREAM_FINAL_CHUNK set; last chunk's AAD carries the terminal marker",
            "headerLength": 25
        }
    });
    fs::write(
        dir.join("metadata.json"),
        serde_json::to_string_pretty(&metadata).unwrap(),
    )
    .unwrap();

    eprintln!(
        "  {id}: plain={} bytes, enc={} bytes, chunks={}, plain_sha={}",
        plaintext.len(),
        encrypted.len(),
        stream_meta.chunks,
        &plain_sha[..16]
    );

    StreamVectorResult {
        id: id.to_string(),
        dek_ref: format!("dek_{id}"),
        plain_sha256: plain_sha,
        cipher_sha256: cipher_sha,
        base_nonce_hex: hex(&base_nonce),
        plaintext_size: plaintext.len(),
        ciphertext_size: encrypted.len(),
        chunks: stream_meta.chunks,
        mime_type: mime_type.to_string(),
    }
}

#[test]
#[ignore]
fn generate_compat_pack_v1() {
    let base = compat_dir();
    fs::create_dir_all(&base).unwrap();
    eprintln!("Generating compat pack in {}", base.display());

    // ── Success vectors ────────────────────────────────────────────

    let v1 = generate_vector(
        "image_small",
        &DEK_IMAGE_SMALL,
        NONCE_IMAGE_SMALL,
        &make_plaintext(1024, 0x00),
        "image/jpeg",
    );

    let v2 = generate_vector(
        "image_medium",
        &DEK_IMAGE_MEDIUM,
        NONCE_IMAGE_MEDIUM,
        &make_plaintext(500 * 1024, 0x40),
        "image/png",
    );

    let v3 = generate_vector(
        "pdf_large",
        &DEK_PDF_LARGE,
        NONCE_PDF_LARGE,
        &make_plaintext(5 * 1024 * 1024, 0x80),
        "application/pdf",
    );

    let v4 = generate_vector(
        "text_small",
        &DEK_TEXT_SMALL,
        NONCE_TEXT_SMALL,
        &make_text_plaintext(),
        "text/plain",
    );

    let vectors = [v1, v2, v3, v4];

    // ── Error vectors ──────────────────────────────────────────────

    // error_tampered: take image_small's enc and flip 1 byte in ciphertext
    {
        let dir = base.join("error_tampered");
        fs::create_dir_all(&dir).unwrap();
        let mut enc = fs::read(base.join("image_small/encrypted.enc")).unwrap();
        // Flip byte at offset 30 (in ciphertext area, past 25-byte header)
        enc[30] ^= 0xFF;
        fs::write(dir.join("encrypted.enc"), &enc).unwrap();
        eprintln!("  error_tampered: {} bytes (flipped byte 30)", enc.len());
    }

    // error_truncated: take image_small's enc and truncate to 50%
    {
        let dir = base.join("error_truncated");
        fs::create_dir_all(&dir).unwrap();
        let enc = fs::read(base.join("image_small/encrypted.enc")).unwrap();
        let truncated = &enc[..enc.len() / 2];
        fs::write(dir.join("encrypted.enc"), truncated).unwrap();
        eprintln!(
            "  error_truncated: {} bytes (from {})",
            truncated.len(),
            enc.len()
        );
    }

    // error_future_version: valid header but version=99
    {
        let dir = base.join("error_future_version");
        fs::create_dir_all(&dir).unwrap();
        let mut enc = fs::read(base.join("image_small/encrypted.enc")).unwrap();
        // Version is at offset 4-5, little-endian
        enc[4] = 99;
        enc[5] = 0;
        fs::write(dir.join("encrypted.enc"), &enc).unwrap();
        eprintln!("  error_future_version: version=99");
    }

    // ── test_deks.json ─────────────────────────────────────────────

    let test_deks = serde_json::json!({
        "_WARNING": "NEVER USE THESE KEYS IN PRODUCTION. Test-only keys for compat vectors.",
        "dek_image_small": hex(&DEK_IMAGE_SMALL),
        "dek_image_medium": hex(&DEK_IMAGE_MEDIUM),
        "dek_pdf_large": hex(&DEK_PDF_LARGE),
        "dek_text_small": hex(&DEK_TEXT_SMALL)
    });
    fs::write(
        base.join("test_deks.json"),
        serde_json::to_string_pretty(&test_deks).unwrap(),
    )
    .unwrap();

    // ── vectors.json ───────────────────────────────────────────────

    let vectors_json = serde_json::json!({
        "version": "1",
        "produced_by": "secure-core v0.1.0 / Rust",
        "produced_at": "2026-03-05",
        "vectors": vectors.iter().map(|v| serde_json::json!({
            "id": v.id,
            "dek_ref": v.dek_ref,
            "plain_sha256": v.plain_sha256,
            "cipher_sha256": v.cipher_sha256,
            "plaintext_size": v.plaintext_size,
            "mime_type": v.mime_type,
            "header": {
                "version": 1,
                "algo": "AES-256-GCM",
                "nonce": v.nonce_hex
            }
        })).collect::<Vec<_>>()
    });
    fs::write(
        base.join("vectors.json"),
        serde_json::to_string_pretty(&vectors_json).unwrap(),
    )
    .unwrap();

    // ── V1.1 streaming compat pack ─────────────────────────────────
    //
    // Two deterministic streaming vectors, written to
    // testdata/compat/v1_1/stream/. These freeze the V1.1 on-disk format
    // (FLAG_STREAM_FINAL_CHUNK set, last chunk's AAD carrying the terminal
    // marker). compat_tests.rs verifies that decrypt_stream reproduces the
    // plaintext and that regeneration is byte-for-byte stable.
    {
        let stream_base = compat_v1_1_stream_dir();
        fs::create_dir_all(&stream_base).unwrap();
        eprintln!(
            "Generating V1.1 stream compat pack in {}",
            stream_base.display()
        );

        let single = generate_stream_vector(
            "stream_single_chunk",
            &DEK_STREAM_SINGLE,
            STREAM_NONCE_SINGLE,
            &make_plaintext(2048, 0xA0),
            "application/octet-stream",
        );

        // Exactly CHUNK_SIZE * 2 + 777 bytes: exercises two full non-final
        // chunks followed by a partial final chunk. The "+ 777" (vs a
        // round number) is intentional — it makes the final chunk visibly
        // shorter in hex dumps so reviewers can eyeball the boundary.
        let multi = generate_stream_vector(
            "stream_multi_chunk",
            &DEK_STREAM_MULTI,
            STREAM_NONCE_MULTI,
            &make_plaintext(CHUNK_SIZE * 2 + 777, 0xB0),
            "application/octet-stream",
        );

        let stream_vectors = [single, multi];

        let stream_test_deks = serde_json::json!({
            "_WARNING": "NEVER USE THESE KEYS IN PRODUCTION. Test-only keys for V1.1 stream compat vectors.",
            "dek_stream_single_chunk": hex(&DEK_STREAM_SINGLE),
            "dek_stream_multi_chunk": hex(&DEK_STREAM_MULTI)
        });
        fs::write(
            stream_base.join("test_deks.json"),
            serde_json::to_string_pretty(&stream_test_deks).unwrap(),
        )
        .unwrap();

        let stream_vectors_json = serde_json::json!({
            "version": "1.1",
            "format": "streaming",
            "produced_by": format!("secure-core v{} / Rust", env!("CARGO_PKG_VERSION")),
            "produced_at": "2026-04-21",
            "vectors": stream_vectors.iter().map(|v| serde_json::json!({
                "id": v.id,
                "dek_ref": v.dek_ref,
                "plain_sha256": v.plain_sha256,
                "cipher_sha256": v.cipher_sha256,
                "plaintext_size": v.plaintext_size,
                "ciphertext_size": v.ciphertext_size,
                "chunks": v.chunks,
                "mime_type": v.mime_type,
                "header": {
                    "version": 1,
                    "algo": "AES-256-GCM",
                    "base_nonce": v.base_nonce_hex,
                    "flags": "0x0001"
                }
            })).collect::<Vec<_>>()
        });
        fs::write(
            stream_base.join("vectors.json"),
            serde_json::to_string_pretty(&stream_vectors_json).unwrap(),
        )
        .unwrap();

        eprintln!("V1.1 stream compat pack generated successfully.");
    }

    // ── testdata/v1_reference.enc ──────────────────────────────────
    //
    // A single small reference blob used by the regression tests in
    // crypto_tests.rs. Kept alongside the compat pack so there is one
    // canonical place to regenerate every committed test fixture.
    {
        let blob =
            encrypt_bytes_with_nonce_test(REFERENCE_PLAINTEXT, &REFERENCE_KEY, REFERENCE_NONCE)
                .unwrap();
        let out_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../testdata/v1_reference.enc");
        fs::write(&out_path, &blob).unwrap();
        eprintln!("  v1_reference.enc: {} bytes", blob.len());
    }

    eprintln!("Compat pack V1 + V1.1 generated successfully.");
}
