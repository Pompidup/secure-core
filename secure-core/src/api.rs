use std::fs::{self, File};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::crypto::Dek;
use crate::error::SecureCoreError;
use crate::metadata::PartialDocumentMetadata;
use crate::streaming::{decrypt_stream, encrypt_stream, StreamMetadata};

/// Result of a file encryption operation.
///
/// Contains the streaming metadata and a [`PartialDocumentMetadata`] holding
/// everything the core can compute on its own. The caller (platform) must
/// call [`PartialDocumentMetadata::finalize`] with its `doc_id` and the
/// `wrapped_dek` produced by the OS keystore to obtain a complete
/// `DocumentMetadata`.
#[derive(Debug)]
pub struct EncryptResult {
    pub stream_metadata: StreamMetadata,
    pub partial_metadata: PartialDocumentMetadata,
}

/// Encrypts a file at `input_path` and writes the encrypted output to `output_path`.
///
/// Returns an [`EncryptResult`]. The caller must finalize the
/// [`PartialDocumentMetadata`] with its `doc_id` and `wrapped_dek` before
/// persisting anything — the types enforce this at compile time.
pub fn encrypt_file(
    input_path: &Path,
    output_path: &Path,
    dek: &Dek,
) -> Result<EncryptResult, SecureCoreError> {
    let input = File::open(input_path)?;
    let output = File::create(output_path)?;
    let stream_meta = encrypt_stream(input, output, dek)?;

    let ciphertext_size = fs::metadata(output_path)?.len();

    let filename = input_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown")
        .to_string();

    let created_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let partial = PartialDocumentMetadata {
        filename,
        mime_type: None,
        created_at,
        plaintext_size: Some(stream_meta.total_plaintext_bytes),
        ciphertext_size,
        content_hash: None,
        tags: None,
        folder_id: None,
    };

    Ok(EncryptResult {
        stream_metadata: stream_meta,
        partial_metadata: partial,
    })
}

/// Decrypts a file at `input_path` and writes the plaintext to `output_path`.
pub fn decrypt_file(
    input_path: &Path,
    output_path: &Path,
    dek: &Dek,
) -> Result<StreamMetadata, SecureCoreError> {
    let input = File::open(input_path)?;
    let output = File::create(output_path)?;
    decrypt_stream(input, output, dek)
}
