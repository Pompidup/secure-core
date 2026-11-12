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
        enc_result.partial_metadata.ciphertext_size > 1024,
        "ciphertext_size ({}) should exceed plaintext_size (1024)",
        enc_result.partial_metadata.ciphertext_size
    );

    assert_eq!(enc_result.partial_metadata.plaintext_size, Some(1024));

    // Filename should be extracted from the temp file path
    assert!(
        !enc_result.partial_metadata.filename.is_empty(),
        "filename should not be empty"
    );
}

#[test]
fn test_api_partial_metadata_finalize_yields_valid_document() {
    use secure_core::metadata::WrapsEnvelope;

    let dek = Dek::new(TEST_KEY);
    let plaintext = random_bytes(2048);

    let input_file = write_temp_file(&plaintext);
    let encrypted_file = NamedTempFile::new().unwrap();

    let enc_result = encrypt_file(input_file.path(), encrypted_file.path(), &dek).unwrap();

    let envelope = WrapsEnvelope::new_device(
        "AES-256-GCM-KEYSTORE".into(),
        "secure_core_master_key_v1".into(),
        vec![0xA0; 12],
        vec![0xB0; 16],
        vec![0x01, 0x02, 0x03, 0x04],
    );

    let doc = enc_result
        .partial_metadata
        .finalize("550e8400-e29b-41d4-a716-446655440000".into(), envelope);

    assert_eq!(doc.doc_id, "550e8400-e29b-41d4-a716-446655440000");
    assert_eq!(doc.plaintext_size, Some(2048));
    assert!(!doc.filename.is_empty());
    doc.validate().expect("finalized document must validate");
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

// ── No plaintext left behind on failure ──────────────────────────────
// decrypt_file must never leave decrypted bytes on disk when it fails: the
// output is written to a temporary sibling and only moved into place once
// the whole stream has been authenticated.

/// Encrypts `plaintext` to `<dir>/doc.enc` and flips one bit in the tag of
/// the last chunk, so that every chunk but the last one decrypts.
fn tampered_last_chunk(dir: &std::path::Path, plaintext: &[u8], dek: &Dek) -> std::path::PathBuf {
    let plain = dir.join("plain.bin");
    let enc = dir.join("doc.enc");
    std::fs::write(&plain, plaintext).unwrap();
    encrypt_file(&plain, &enc, dek).unwrap();
    let mut blob = std::fs::read(&enc).unwrap();
    let last = blob.len() - 1;
    blob[last] ^= 0x01;
    std::fs::write(&enc, &blob).unwrap();
    enc
}

/// Entries of `dir` other than the ones the test created itself.
fn leftovers(dir: &std::path::Path, known: &[&str]) -> Vec<String> {
    std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| !known.contains(&n.as_str()))
        .collect()
}

#[test]
fn test_decrypt_file_failure_leaves_no_plaintext_on_disk() {
    let dek = Dek::new(TEST_KEY);
    let dir = tempfile::tempdir().unwrap();
    let enc = tampered_last_chunk(dir.path(), &random_bytes(CHUNK_SIZE * 3 - 50), &dek);
    let out = dir.path().join("out.pdf");

    let err = decrypt_file(&enc, &out, &dek).unwrap_err();
    assert!(
        matches!(err, SecureCoreError::CryptoError(_)),
        "got: {err:?}"
    );
    assert!(
        !out.exists(),
        "no output file may exist after a failed decryption"
    );
    assert_eq!(
        leftovers(dir.path(), &["plain.bin", "doc.enc"]),
        Vec::<String>::new(),
        "no temporary file may be left behind"
    );
}

#[test]
fn test_decrypt_file_failure_keeps_existing_output_untouched() {
    let dek = Dek::new(TEST_KEY);
    let dir = tempfile::tempdir().unwrap();
    let enc = tampered_last_chunk(dir.path(), &random_bytes(CHUNK_SIZE * 2 + 9), &dek);
    let out = dir.path().join("out.pdf");
    std::fs::write(&out, b"previous content").unwrap();

    decrypt_file(&enc, &out, &dek).unwrap_err();
    assert_eq!(std::fs::read(&out).unwrap(), b"previous content");
}

#[test]
fn test_decrypt_file_success_replaces_existing_output() {
    let dek = Dek::new(TEST_KEY);
    let dir = tempfile::tempdir().unwrap();
    let plaintext = random_bytes(CHUNK_SIZE + 3);
    let (plain, enc, out) = (
        dir.path().join("plain.bin"),
        dir.path().join("doc.enc"),
        dir.path().join("out.pdf"),
    );
    std::fs::write(&plain, &plaintext).unwrap();
    std::fs::write(&out, b"stale").unwrap();
    encrypt_file(&plain, &enc, &dek).unwrap();

    decrypt_file(&enc, &out, &dek).unwrap();
    assert_eq!(std::fs::read(&out).unwrap(), plaintext);
    assert_eq!(
        leftovers(dir.path(), &["plain.bin", "doc.enc", "out.pdf"]),
        Vec::<String>::new()
    );
}

#[test]
fn test_encrypt_file_failure_leaves_no_partial_ciphertext() {
    let dek = Dek::new(TEST_KEY);
    let dir = tempfile::tempdir().unwrap();
    // A directory as input: opening succeeds on unix but reading fails.
    let input = dir.path().join("not-a-file");
    std::fs::create_dir(&input).unwrap();
    let out = dir.path().join("doc.enc");

    encrypt_file(&input, &out, &dek).unwrap_err();
    assert!(!out.exists());
    assert_eq!(leftovers(dir.path(), &["not-a-file"]), Vec::<String>::new());
}

// ── Input and output must be different files ─────────────────────────
// Encrypting or decrypting a file onto itself used to truncate it before it
// was read, destroying the document while reporting success. Even with
// atomic outputs, "in place" encryption would leave the old plaintext in the
// storage blocks, so the core refuses it explicitly: same path, symlink and
// hard link alike.

#[cfg(unix)]
fn same_file_cases(
    dir: &std::path::Path,
) -> Vec<(&'static str, std::path::PathBuf, std::path::PathBuf)> {
    let doc = dir.join("doc.pdf");
    std::fs::write(&doc, random_bytes(CHUNK_SIZE + 10)).unwrap();
    let symlink = dir.join("link.pdf");
    std::os::unix::fs::symlink(&doc, &symlink).unwrap();
    let hardlink = dir.join("hard.pdf");
    std::fs::hard_link(&doc, &hardlink).unwrap();
    let dotted = dir.join(".").join("doc.pdf");
    vec![
        ("same path", doc.clone(), doc.clone()),
        ("symlink", doc.clone(), symlink),
        ("hard link", doc.clone(), hardlink),
        ("equivalent path", doc.clone(), dotted),
    ]
}

#[cfg(unix)]
#[test]
fn test_encrypt_file_rejects_output_that_is_the_input() {
    let dek = Dek::new(TEST_KEY);
    let dir = tempfile::tempdir().unwrap();
    for (case, input, output) in same_file_cases(dir.path()) {
        let before = std::fs::read(&input).unwrap();
        let err = encrypt_file(&input, &output, &dek).unwrap_err();
        assert!(
            matches!(err, SecureCoreError::InvalidParameter(_)),
            "{case}: expected InvalidParameter, got {err:?}"
        );
        assert_eq!(
            std::fs::read(&input).unwrap(),
            before,
            "{case}: input must be intact"
        );
    }
}

#[cfg(unix)]
#[test]
fn test_decrypt_file_rejects_output_that_is_the_input() {
    let dek = Dek::new(TEST_KEY);
    let dir = tempfile::tempdir().unwrap();
    let plain = dir.path().join("plain.bin");
    std::fs::write(&plain, random_bytes(CHUNK_SIZE + 10)).unwrap();
    let enc = dir.path().join("doc.enc");
    encrypt_file(&plain, &enc, &dek).unwrap();
    let before = std::fs::read(&enc).unwrap();
    let link = dir.path().join("link.enc");
    std::os::unix::fs::symlink(&enc, &link).unwrap();

    for output in [enc.clone(), link] {
        let err = decrypt_file(&enc, &output, &dek).unwrap_err();
        assert!(
            matches!(err, SecureCoreError::InvalidParameter(_)),
            "got {err:?}"
        );
        assert_eq!(
            std::fs::read(&enc).unwrap(),
            before,
            "ciphertext must be intact"
        );
    }
}

#[test]
fn test_file_apis_accept_distinct_files_in_the_same_directory() {
    let dek = Dek::new(TEST_KEY);
    let dir = tempfile::tempdir().unwrap();
    let (plain, enc, out) = (
        dir.path().join("a"),
        dir.path().join("b"),
        dir.path().join("c"),
    );
    let data = random_bytes(1000);
    std::fs::write(&plain, &data).unwrap();
    encrypt_file(&plain, &enc, &dek).unwrap();
    decrypt_file(&enc, &out, &dek).unwrap();
    assert_eq!(std::fs::read(&out).unwrap(), data);
}
