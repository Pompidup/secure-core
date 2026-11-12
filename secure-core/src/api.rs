use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::crypto::Dek;
use crate::error::SecureCoreError;
use crate::metadata::PartialDocumentMetadata;
use crate::streaming::{
    decrypt_stream, decrypt_stream_allow_legacy, encrypt_stream, StreamMetadata,
};

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
///
/// The ciphertext is written to a temporary file next to `output_path` and
/// moved into place only once complete, so a failure never leaves a
/// truncated `.enc` behind (see [`decrypt_file`]).
pub fn encrypt_file(
    input_path: &Path,
    output_path: &Path,
    dek: &Dek,
) -> Result<EncryptResult, SecureCoreError> {
    let input = File::open(input_path)?;
    let (stream_meta, ciphertext_size) =
        write_atomically(output_path, |output| encrypt_stream(input, output, dek))?;

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

/// Decrypts a V1.1 file at `input_path` and writes the plaintext to `output_path`.
///
/// Legacy V1.0 streams (no final-chunk flag) are rejected; see
/// [`decrypt_stream`].
///
/// The plaintext is written to a temporary file next to `output_path`
/// (hidden name, created exclusively, owner-only permissions on unix) and
/// renamed onto `output_path` only after the whole stream authenticated. On
/// any error the temporary file is deleted and a pre-existing `output_path`
/// is left untouched, so a failed call leaves no plaintext on disk.
pub fn decrypt_file(
    input_path: &Path,
    output_path: &Path,
    dek: &Dek,
) -> Result<StreamMetadata, SecureCoreError> {
    let input = File::open(input_path)?;
    write_atomically(output_path, |output| decrypt_stream(input, output, dek)).map(|(m, _)| m)
}

/// Like [`decrypt_file`], but also accepts legacy V1.0 streams.
///
/// **Security:** truncation of legacy input is not detected. Reserved for a
/// one-time migration of pre-0.3.0 files; see [`decrypt_stream_allow_legacy`].
pub fn decrypt_file_allow_legacy(
    input_path: &Path,
    output_path: &Path,
    dek: &Dek,
) -> Result<StreamMetadata, SecureCoreError> {
    let input = File::open(input_path)?;
    write_atomically(output_path, |output| {
        decrypt_stream_allow_legacy(input, output, dek)
    })
    .map(|(m, _)| m)
}

/// Runs `write` against a fresh temporary file next to `output_path`, then
/// syncs it and renames it onto `output_path`. If anything fails, the
/// temporary file is removed and `output_path` is not touched. Returns the
/// value produced by `write` and the final file size.
fn write_atomically<T>(
    output_path: &Path,
    write: impl FnOnce(&mut File) -> Result<T, SecureCoreError>,
) -> Result<(T, u64), SecureCoreError> {
    let (temp_path, mut file) = create_temp_sibling(output_path)?;
    let outcome = write(&mut file).and_then(|value| {
        file.sync_all()?;
        Ok((value, file.metadata()?.len()))
    });
    drop(file);

    let committed = outcome.and_then(|done| {
        fs::rename(&temp_path, output_path)?;
        Ok(done)
    });
    if committed.is_err() {
        // Best effort: the original error is what the caller needs to see.
        let _ = fs::remove_file(&temp_path);
    }
    committed
}

/// Creates `.<name>.<random>.tmp` in the directory of `output_path`, failing
/// rather than reusing an existing file (`create_new`), readable by the owner
/// only on unix. Same directory = same filesystem, so the final `rename` is
/// atomic.
fn create_temp_sibling(output_path: &Path) -> Result<(PathBuf, File), SecureCoreError> {
    let name = output_path
        .file_name()
        .ok_or_else(|| SecureCoreError::InvalidParameter("output_path must name a file".into()))?;
    let dir = match output_path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };

    for _ in 0..16 {
        let mut suffix = [0u8; 8];
        rand::RngCore::fill_bytes(&mut rand::rng(), &mut suffix);
        let mut temp_name = OsString::from(".");
        temp_name.push(name);
        temp_name.push(format!(".{}.tmp", hex(&suffix)));
        let temp_path = dir.join(temp_name);

        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&temp_path) {
            Ok(file) => return Ok((temp_path, file)),
            Err(e) if e.kind() == ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Err(SecureCoreError::IoError(std::io::Error::new(
        ErrorKind::AlreadyExists,
        "could not create a unique temporary file next to output_path",
    )))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
