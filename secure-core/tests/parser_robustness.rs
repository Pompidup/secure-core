//! Fuzz-lite parser robustness tests.
//!
//! These tests bombard the binary parsers (`EncHeader::from_bytes`,
//! `decrypt_bytes`, `decrypt_stream`) with hostile inputs and assert two
//! invariants:
//! 1. The parsers never panic, abort, or exhibit UB — any return value is
//!    acceptable as long as the process stays alive.
//! 2. When a parser returns `Ok`, the parsed value round-trips back to an
//!    equivalent byte representation (where applicable).
//!
//! The RNG is seeded for reproducibility; any regression surfaces
//! deterministically on the same iteration.

use std::io::Cursor;

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use secure_core::crypto::{decrypt_bytes, encrypt_bytes, Dek};
use secure_core::format::EncHeader;
use secure_core::streaming::{decrypt_stream, encrypt_stream, CHUNK_SIZE};

/// Iterations per random-input test. Kept modest so the whole suite stays
/// under a minute in dev mode; CI can expand it by exporting
/// SECURE_CORE_FUZZ_ITER if deeper coverage is ever wanted.
const FUZZ_ITERATIONS: usize = 2_000;
const FUZZ_SEED: u64 = 0x5EC0_C0DE_BAD5_5EED;

/// Bit-flip stride on the multi-chunk streaming blob. Flipping every single
/// byte would be ~130 k decrypt_stream calls and blow CI budget; sampling
/// every 32 bytes keeps coverage of header, chunk-length, ciphertext, and
/// tag regions while staying fast.
const MULTICHUNK_BITFLIP_STRIDE: usize = 32;

const TEST_KEY: [u8; 32] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
];

fn random_bytes(rng: &mut StdRng, max_len: usize) -> Vec<u8> {
    let len = rng.random_range(0..=max_len);
    let mut buf = vec![0u8; len];
    rng.fill(&mut buf[..]);
    buf
}

// ── Random input ────────────────────────────────────────────────────────

#[test]
fn test_header_from_bytes_never_panics_on_random_input() {
    let mut rng = StdRng::seed_from_u64(FUZZ_SEED);
    for i in 0..FUZZ_ITERATIONS {
        let input = random_bytes(&mut rng, 256);
        // The assertion is the absence of panic. If from_bytes happens to
        // accept the random blob, the header must at minimum round-trip.
        if let Ok(header) = EncHeader::from_bytes(&input) {
            let reserialized = header.to_bytes();
            let reparsed = EncHeader::from_bytes(&reserialized)
                .unwrap_or_else(|e| panic!("iter {i}: re-parse of serialized header failed: {e}"));
            assert_eq!(header, reparsed, "iter {i}: header did not round-trip");
        }
    }
}

#[test]
fn test_decrypt_bytes_never_panics_on_random_input() {
    let mut rng = StdRng::seed_from_u64(FUZZ_SEED ^ 0x1111);
    for _ in 0..FUZZ_ITERATIONS {
        let blob = random_bytes(&mut rng, 256);
        // Ignore the result; success on random bytes is astronomically
        // unlikely, we only care that no panic escapes.
        let _ = decrypt_bytes(&blob, &TEST_KEY);
    }
}

#[test]
fn test_decrypt_stream_never_panics_on_random_input() {
    let dek = Dek::new(TEST_KEY);
    let mut rng = StdRng::seed_from_u64(FUZZ_SEED ^ 0x2222);
    for _ in 0..FUZZ_ITERATIONS {
        let blob = random_bytes(&mut rng, 512);
        let mut sink = Vec::new();
        let _ = decrypt_stream(Cursor::new(&blob), &mut sink, &dek);
    }
}

// ── Bit-flip of a valid blob ────────────────────────────────────────────

#[test]
fn test_decrypt_bytes_never_panics_on_bitflipped_valid_blob() {
    let plaintext = b"robustness-fuzz-plaintext";
    let valid = encrypt_bytes(plaintext, &TEST_KEY).expect("base encrypt");

    for byte_idx in 0..valid.len() {
        for bit in 0..8u8 {
            let mut corrupted = valid.clone();
            corrupted[byte_idx] ^= 1 << bit;
            // Must not panic regardless of which bit we flipped.
            let _ = decrypt_bytes(&corrupted, &TEST_KEY);
        }
    }
}

#[test]
fn test_decrypt_stream_never_panics_on_bitflipped_multichunk_blob() {
    let dek = Dek::new(TEST_KEY);
    // Two full chunks + a small tail: exercises header, non-final, and
    // final chunk AAD paths.
    let plaintext = vec![0x42u8; CHUNK_SIZE * 2 + 123];

    let mut valid = Vec::new();
    encrypt_stream(Cursor::new(&plaintext), &mut valid, &dek).expect("base encrypt_stream");

    let mut byte_idx = 0;
    while byte_idx < valid.len() {
        let mut corrupted = valid.clone();
        corrupted[byte_idx] ^= 0x01;
        let mut sink = Vec::new();
        let _ = decrypt_stream(Cursor::new(&corrupted), &mut sink, &dek);
        byte_idx += MULTICHUNK_BITFLIP_STRIDE;
    }
}

// ── Truncation at every byte boundary ───────────────────────────────────

#[test]
fn test_decrypt_bytes_never_panics_on_any_truncation() {
    let plaintext = b"truncation-fuzz-data-here-ok";
    let valid = encrypt_bytes(plaintext, &TEST_KEY).expect("base encrypt");

    for cut in 0..valid.len() {
        let truncated = &valid[..cut];
        let _ = decrypt_bytes(truncated, &TEST_KEY);
    }
}

#[test]
fn test_decrypt_stream_never_panics_on_any_truncation() {
    let dek = Dek::new(TEST_KEY);
    // Single chunk blob: small enough that testing every prefix is cheap.
    let plaintext = b"streaming truncation fuzz";
    let mut valid = Vec::new();
    encrypt_stream(Cursor::new(plaintext.as_ref()), &mut valid, &dek).expect("base encrypt_stream");

    for cut in 0..valid.len() {
        let truncated = &valid[..cut];
        let mut sink = Vec::new();
        let _ = decrypt_stream(Cursor::new(truncated), &mut sink, &dek);
    }
}

// ── Targeted corruption of length prefix in streaming ───────────────────

#[test]
fn test_decrypt_stream_never_panics_on_oversized_chunk_len() {
    let dek = Dek::new(TEST_KEY);
    // Build a valid single-chunk blob, then overwrite the 4-byte chunk_len
    // prefix (at offset 25, right after the header) with pathological
    // values. The parser must not OOM-abort or panic on a huge declared
    // length — it must bail with an error once the read fails or the cap
    // is enforced.
    let mut valid = Vec::new();
    encrypt_stream(Cursor::new(&b"payload"[..]), &mut valid, &dek).expect("base");
    assert!(valid.len() > 25 + 4);

    let pathological = [
        0x00_00_00_00_u32, // zero len
        0x00_00_00_10_u32, // too small to hold a tag
        0x80_00_00_00_u32, // huge
        0xFF_FF_FF_FF_u32, // max u32
    ];

    for &len in &pathological {
        let mut corrupted = valid.clone();
        corrupted[25..29].copy_from_slice(&len.to_le_bytes());
        let mut sink = Vec::new();
        let _ = decrypt_stream(Cursor::new(&corrupted), &mut sink, &dek);
    }
}
