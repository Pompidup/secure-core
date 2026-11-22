//! Since 1.0.0 the core has no reader for legacy V1.0 streams (`flags == 0`,
//! written before 0.3.0): they carry no end-of-stream authentication, and a
//! truncated V1.1 stream whose flag was cleared looks exactly like one.
//!
//! These tests build a genuine V1.0 stream by hand (independently of the
//! library's writer) and check that every entry point rejects it, and that
//! no legacy reader symbol survives in the sources or the C header.

use std::ffi::CString;
use std::io::Cursor;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};

use secure_core::api::decrypt_file;
use secure_core::crypto::Dek;
use secure_core::error::SecureCoreError;
use secure_core::ffi::functions::{secure_core_decrypt_file, secure_core_free_result};
use secure_core::ffi::types::FFI_ERROR_INVALID_FORMAT;
use secure_core::format::{EncHeader, FLAG_STREAM_FINAL_CHUNK};
use secure_core::streaming::{decrypt_stream, CHUNK_SIZE};

const KEY: [u8; 32] = [0x3C; 32];
const BASE_NONCE: [u8; 12] = [0x5A; 12];

/// Encodes `plaintext` with the documented streaming layout. `v1_1 = false`
/// produces the legacy V1.0 layout: flags 0 and AAD = chunk index for every
/// chunk. `v1_1 = true` sets FLAG_STREAM_FINAL_CHUNK and marks the last
/// chunk's AAD (top bit), which validates the builder against the reader.
fn handmade_stream(plaintext: &[u8], v1_1: bool) -> Vec<u8> {
    let mut header = EncHeader::new_v1(BASE_NONCE);
    if v1_1 {
        header.flags |= FLAG_STREAM_FINAL_CHUNK;
    }
    let mut out = header.to_bytes();
    let cipher = Aes256Gcm::new_from_slice(&KEY).unwrap();
    let chunks: Vec<&[u8]> = plaintext.chunks(CHUNK_SIZE).collect();
    for (i, chunk) in chunks.iter().enumerate() {
        let index = i as u32;
        let mut nonce = BASE_NONCE;
        for (n, b) in nonce[8..].iter_mut().zip(index.to_be_bytes()) {
            *n ^= b;
        }
        let last = v1_1 && i + 1 == chunks.len();
        let aad = (index | if last { 0x8000_0000 } else { 0 }).to_be_bytes();
        let ct = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: chunk,
                    aad: &aad,
                },
            )
            .unwrap();
        out.extend_from_slice(&(ct.len() as u32).to_le_bytes());
        out.extend_from_slice(&ct);
    }
    out
}

fn plaintext() -> Vec<u8> {
    (0..CHUNK_SIZE * 2 + 321).map(|i| (i % 253) as u8).collect()
}

#[test]
fn test_handmade_v1_1_stream_is_accepted_so_the_builder_is_correct() {
    let data = plaintext();
    let mut out = Vec::new();
    decrypt_stream(
        Cursor::new(handmade_stream(&data, true)),
        &mut out,
        &Dek::new(KEY),
    )
    .unwrap();
    assert_eq!(out, data);
}

#[test]
fn test_genuine_legacy_v1_0_stream_is_rejected_by_decrypt_stream() {
    let mut out = Vec::new();
    let err = decrypt_stream(
        Cursor::new(handmade_stream(&plaintext(), false)),
        &mut out,
        &Dek::new(KEY),
    )
    .unwrap_err();
    assert!(
        matches!(err, SecureCoreError::InvalidFormat(_)),
        "got {err:?}"
    );
    assert!(out.is_empty(), "no plaintext may be emitted");
}

#[test]
fn test_genuine_legacy_v1_0_stream_is_rejected_by_file_apis() {
    let dir = tempfile::tempdir().unwrap();
    let (enc, out) = (dir.path().join("legacy.enc"), dir.path().join("out.bin"));
    std::fs::write(&enc, handmade_stream(&plaintext(), false)).unwrap();

    let err = decrypt_file(&enc, &out, &Dek::new(KEY)).unwrap_err();
    assert!(
        matches!(err, SecureCoreError::InvalidFormat(_)),
        "got {err:?}"
    );
    assert!(!out.exists());

    let (enc_c, out_c) = (
        CString::new(enc.to_str().unwrap()).unwrap(),
        CString::new(out.to_str().unwrap()).unwrap(),
    );
    let (in_ptr, out_ptr) = (enc_c.as_ptr(), out_c.as_ptr());
    // SAFETY: NUL-terminated paths and a 32-byte key that outlive the call.
    let r = unsafe { secure_core_decrypt_file(in_ptr, out_ptr, KEY.as_ptr(), 32) };
    assert_eq!(r.status, FFI_ERROR_INVALID_FORMAT);
    // SAFETY: returned by secure_core_decrypt_file and freed exactly once.
    unsafe { secure_core_free_result(r) };
    assert!(!out.exists());
}

#[test]
fn test_no_legacy_reader_remains_in_the_sources_or_the_c_header() {
    // Built with concat! so this file does not match itself.
    let needles = [concat!("allow", "_legacy"), concat!("Allow", "Legacy")];
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let files = [
        "src/streaming.rs",
        "src/api.rs",
        "src/ffi/functions.rs",
        "src/jni_bridge.rs",
        "../include/secure_core.h",
    ];
    let mut hits = Vec::new();
    for rel in files {
        let src = std::fs::read_to_string(root.join(rel)).unwrap();
        for needle in needles {
            if src.contains(needle) {
                hits.push(format!("{rel}: {needle}"));
            }
        }
    }
    assert!(hits.is_empty(), "legacy reader still present: {hits:?}");
}
