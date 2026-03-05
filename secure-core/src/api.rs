use std::fs::File;
use std::path::Path;

use crate::crypto::Dek;
use crate::error::SecureCoreError;
use crate::streaming::{decrypt_stream, encrypt_stream, StreamMetadata};

/// Encrypts a file at `input_path` and writes the encrypted output to `output_path`.
///
/// Uses chunked AES-256-GCM streaming to avoid loading the entire file in memory.
pub fn encrypt_file(
    input_path: &Path,
    output_path: &Path,
    dek: &Dek,
) -> Result<StreamMetadata, SecureCoreError> {
    let input = File::open(input_path)?;
    let output = File::create(output_path)?;
    encrypt_stream(input, output, dek)
}

/// Decrypts a file at `input_path` and writes the plaintext to `output_path`.
///
/// Uses chunked AES-256-GCM streaming to avoid loading the entire file in memory.
pub fn decrypt_file(
    input_path: &Path,
    output_path: &Path,
    dek: &Dek,
) -> Result<StreamMetadata, SecureCoreError> {
    let input = File::open(input_path)?;
    let output = File::create(output_path)?;
    decrypt_stream(input, output, dek)
}
