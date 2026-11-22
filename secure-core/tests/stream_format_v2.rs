//! `.enc` V2 streaming format (docs/enc-format-v2.md, ADR-003).
//!
//! The streams used here are built by hand from the spec with `aes_gcm`,
//! independently of the library's writer, so the tests check the library
//! against the specification rather than against itself.

use std::io::Cursor;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};

use secure_core::crypto::{decrypt_bytes, encrypt_bytes, Dek};
use secure_core::error::SecureCoreError;
use secure_core::format::{EncHeader, FLAG_STREAM_FINAL_CHUNK};
use secure_core::streaming::{decrypt_stream, encrypt_stream, StreamMetadata, CHUNK_SIZE};

const KEY: [u8; 32] = [0x6B; 32];
const BASE_NONCE: [u8; 12] = [
    0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC,
];
const HEADER_LEN: usize = 25;

/// Builds a stream exactly as the spec describes. `version = 1` produces
/// V1.1 (AAD = BE32(index | marker)); `version = 2` produces V2
/// (AAD = header || BE32(index | marker)).
fn spec_stream(plaintext: &[u8], key: &[u8; 32], base_nonce: [u8; 12], version: u16) -> Vec<u8> {
    let mut header = EncHeader::new_v1(base_nonce);
    header.version = version;
    header.flags = FLAG_STREAM_FINAL_CHUNK;
    let header_bytes = header.to_bytes();
    assert_eq!(header_bytes.len(), HEADER_LEN);

    let cipher = Aes256Gcm::new_from_slice(key).unwrap();
    let mut chunks: Vec<&[u8]> = plaintext.chunks(CHUNK_SIZE).collect();
    if chunks.is_empty() {
        chunks.push(&[]);
    }
    let mut out = header_bytes.clone();
    for (i, chunk) in chunks.iter().enumerate() {
        let index = i as u32;
        let mut nonce = base_nonce;
        for (n, b) in nonce[8..].iter_mut().zip(index.to_be_bytes()) {
            *n ^= b;
        }
        let marker = if i + 1 == chunks.len() {
            0x8000_0000
        } else {
            0
        };
        let mut aad = Vec::new();
        if version == 2 {
            aad.extend_from_slice(&header_bytes);
        }
        aad.extend_from_slice(&(index | marker).to_be_bytes());
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

fn data(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 7 % 251) as u8).collect()
}

fn decrypt(blob: &[u8]) -> (Result<StreamMetadata, SecureCoreError>, Vec<u8>) {
    let mut out = Vec::new();
    let r = decrypt_stream(Cursor::new(blob), &mut out, &Dek::new(KEY));
    (r, out)
}

/// (start, end) of every chunk frame (length prefix included).
fn frames(blob: &[u8]) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut off = HEADER_LEN;
    while off < blob.len() {
        let len = u32::from_le_bytes(blob[off..off + 4].try_into().unwrap()) as usize;
        out.push((off, off + 4 + len));
        off += 4 + len;
    }
    out
}

// ── Writer ──────────────────────────────────────────────────────────

#[test]
fn test_encrypt_stream_writes_a_v2_header() {
    let mut blob = Vec::new();
    encrypt_stream(Cursor::new(data(1000)), &mut blob, &Dek::new(KEY)).unwrap();
    let header = EncHeader::from_bytes(&blob).unwrap();
    assert_eq!(header.version, 2);
    assert_eq!(header.flags, FLAG_STREAM_FINAL_CHUNK);
    assert_eq!(header.header_length as usize, HEADER_LEN);
}

#[test]
fn test_v2_roundtrip_at_chunk_boundaries() {
    for len in [
        0,
        1,
        CHUNK_SIZE - 1,
        CHUNK_SIZE,
        CHUNK_SIZE + 1,
        CHUNK_SIZE * 3 + 5,
    ] {
        let plaintext = data(len);
        let mut blob = Vec::new();
        encrypt_stream(Cursor::new(&plaintext), &mut blob, &Dek::new(KEY)).unwrap();
        let (r, out) = decrypt(&blob);
        r.unwrap_or_else(|e| panic!("len {len}: {e:?}"));
        assert_eq!(out, plaintext, "len {len}");
    }
}

#[cfg(feature = "_test-vectors")]
#[test]
fn test_writer_matches_the_spec_byte_for_byte() {
    for len in [0, 10, CHUNK_SIZE, CHUNK_SIZE * 2 + 3] {
        let plaintext = data(len);
        let mut blob = Vec::new();
        secure_core::streaming::encrypt_stream_with_nonce_test(
            Cursor::new(&plaintext),
            &mut blob,
            &Dek::new(KEY),
            BASE_NONCE,
        )
        .unwrap();
        assert_eq!(
            blob,
            spec_stream(&plaintext, &KEY, BASE_NONCE, 2),
            "len {len}"
        );
    }
}

#[cfg(feature = "_test-vectors")]
#[test]
fn test_v1_1_test_writer_still_produces_v1_1() {
    let plaintext = data(CHUNK_SIZE + 9);
    let mut blob = Vec::new();
    secure_core::streaming::encrypt_stream_v1_1_with_nonce_test(
        Cursor::new(&plaintext),
        &mut blob,
        &Dek::new(KEY),
        BASE_NONCE,
    )
    .unwrap();
    assert_eq!(blob, spec_stream(&plaintext, &KEY, BASE_NONCE, 1));
}

// ── Reader ──────────────────────────────────────────────────────────

#[test]
fn test_reader_accepts_a_spec_built_v2_stream() {
    let plaintext = data(CHUNK_SIZE * 2 + 77);
    let (r, out) = decrypt(&spec_stream(&plaintext, &KEY, BASE_NONCE, 2));
    assert_eq!(r.unwrap().chunks, 3);
    assert_eq!(out, plaintext);
}

#[test]
fn test_v1_1_streams_remain_readable() {
    let plaintext = data(CHUNK_SIZE * 2 + 77);
    let (r, out) = decrypt(&spec_stream(&plaintext, &KEY, BASE_NONCE, 1));
    r.unwrap();
    assert_eq!(out, plaintext);
}

#[test]
fn test_every_header_bit_flip_of_a_v2_stream_is_rejected_without_output() {
    let blob = spec_stream(&data(CHUNK_SIZE + 3), &KEY, BASE_NONCE, 2);
    for byte in 0..HEADER_LEN {
        for bit in 0..8 {
            let mut tampered = blob.clone();
            tampered[byte] ^= 1 << bit;
            let (r, out) = decrypt(&tampered);
            assert!(r.is_err(), "header byte {byte} bit {bit} accepted");
            assert!(
                out.is_empty(),
                "header byte {byte} bit {bit}: plaintext emitted"
            );
        }
    }
}

#[test]
fn test_downgrading_a_v2_stream_to_v1_1_fails_authentication() {
    let mut blob = spec_stream(&data(CHUNK_SIZE * 2), &KEY, BASE_NONCE, 2);
    blob[4] = 1; // version 2 -> 1, everything else left as a valid V1.1 header
    let (r, out) = decrypt(&blob);
    assert!(
        matches!(r, Err(SecureCoreError::CryptoError(_))),
        "got {r:?}"
    );
    assert!(out.is_empty());
}

#[test]
fn test_upgrading_a_v1_1_stream_to_v2_fails_authentication() {
    let mut blob = spec_stream(&data(CHUNK_SIZE * 2), &KEY, BASE_NONCE, 1);
    blob[4] = 2;
    let (r, out) = decrypt(&blob);
    assert!(
        matches!(r, Err(SecureCoreError::CryptoError(_))),
        "got {r:?}"
    );
    assert!(out.is_empty());
}

#[test]
fn test_v2_truncation_reordering_and_splicing_are_detected() {
    let blob = spec_stream(&data(CHUNK_SIZE * 3), &KEY, BASE_NONCE, 2);
    let fr = frames(&blob);
    assert_eq!(fr.len(), 3);

    // Last chunk dropped.
    let (r, _) = decrypt(&blob[..fr[2].0]);
    assert!(r.is_err(), "truncation accepted");

    // Every chunk dropped.
    let (r, _) = decrypt(&blob[..HEADER_LEN]);
    assert!(
        matches!(r, Err(SecureCoreError::InvalidFormat(_))),
        "got {r:?}"
    );

    // Chunks 0 and 1 swapped.
    let mut swapped = blob[..HEADER_LEN].to_vec();
    swapped.extend_from_slice(&blob[fr[1].0..fr[1].1]);
    swapped.extend_from_slice(&blob[fr[0].0..fr[0].1]);
    swapped.extend_from_slice(&blob[fr[2].0..fr[2].1]);
    let (r, out) = decrypt(&swapped);
    assert!(r.is_err(), "reordering accepted");
    assert!(out.is_empty());

    // Chunk 1 replaced by chunk 1 of another stream under the same key.
    let mut other_nonce = BASE_NONCE;
    other_nonce[0] ^= 0xFF;
    let other = spec_stream(&data(CHUNK_SIZE * 3), &KEY, other_nonce, 2);
    let ofr = frames(&other);
    let mut spliced = blob[..fr[1].0].to_vec();
    spliced.extend_from_slice(&other[ofr[1].0..ofr[1].1]);
    spliced.extend_from_slice(&blob[fr[2].0..]);
    let (r, _) = decrypt(&spliced);
    assert!(r.is_err(), "splice accepted");
}

#[test]
fn test_v2_stream_without_the_final_flag_is_rejected_before_crypto() {
    let mut blob = spec_stream(&data(100), &KEY, BASE_NONCE, 2);
    blob[19] &= !(FLAG_STREAM_FINAL_CHUNK as u8);
    let (r, out) = decrypt(&blob);
    assert!(
        matches!(r, Err(SecureCoreError::InvalidFormat(_))),
        "got {r:?}"
    );
    assert!(out.is_empty());
}

// ── Header parser and in-memory format ──────────────────────────────

#[test]
fn test_header_parser_accepts_v2_and_rejects_v3() {
    let mut bytes = EncHeader::new_v1(BASE_NONCE).to_bytes();
    bytes[4] = 2;
    assert_eq!(EncHeader::from_bytes(&bytes).unwrap().version, 2);
    bytes[4] = 3;
    assert!(matches!(
        EncHeader::from_bytes(&bytes),
        Err(SecureCoreError::UnsupportedVersion {
            found: 3,
            max_supported: 2
        })
    ));
}

#[test]
fn test_in_memory_blobs_stay_version_1() {
    let blob = encrypt_bytes(b"small document", &KEY).unwrap();
    assert_eq!(EncHeader::from_bytes(&blob).unwrap().version, 1);
    assert_eq!(decrypt_bytes(&blob, &KEY).unwrap(), b"small document");
}

#[test]
fn test_decrypt_bytes_rejects_a_v2_stream() {
    let blob = spec_stream(&data(100), &KEY, BASE_NONCE, 2);
    let err = decrypt_bytes(&blob, &KEY).unwrap_err();
    assert!(
        matches!(err, SecureCoreError::InvalidFormat(_)),
        "got {err:?}"
    );
}
