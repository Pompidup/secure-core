use std::fs::{self, File};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::crypto::Dek;
use crate::error::SecureCoreError;
use crate::metadata::{DocumentMetadata, WrapsEnvelope};
use crate::streaming::{decrypt_stream, encrypt_stream, StreamMetadata};

/// Result of a file encryption operation.
///
/// Contains the streaming metadata and a partial [`DocumentMetadata`]
/// pre-filled with everything the core knows. The caller (platform) must
/// supply `doc_id`, `wrapped_dek`, and optionally `content_hash`.
#[derive(Debug)]
pub struct EncryptResult {
    pub stream_metadata: StreamMetadata,
    pub document_metadata: DocumentMetadata,
}

/// Encrypts a file at `input_path` and writes the encrypted output to `output_path`.
///
/// Returns an [`EncryptResult`] containing a partial [`DocumentMetadata`].
/// The `wrapped_dek` field is set to a placeholder — the platform must replace it
/// with the actual wrapped DEK from the OS keystore.
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

    let doc_metadata = DocumentMetadata {
        doc_id: String::new(),
        filename,
        mime_type: None,
        created_at,
        plaintext_size: Some(stream_meta.total_plaintext_bytes),
        ciphertext_size,
        content_hash: None,
        tags: None,
        folder_id: None,
        wrapped_dek: WrapsEnvelope {
            schema_version: crate::metadata::WRAPS_SCHEMA_VERSION.to_string(),
            device: None,
            recovery: None,
        },
    };

    Ok(EncryptResult {
        stream_metadata: stream_meta,
        document_metadata: doc_metadata,
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
