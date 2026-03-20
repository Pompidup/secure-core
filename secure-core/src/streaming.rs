use std::io::{Read, Write};

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};

use serde::Serialize;

use crate::crypto::{generate_nonce, Dek};
use crate::error::SecureCoreError;
use crate::format::EncHeader;

/// Default chunk size: 64 KB of plaintext per chunk.
pub const CHUNK_SIZE: usize = 64 * 1024;

/// GCM auth tag size in bytes.
const TAG_SIZE: usize = 16;

/// Metadata returned after a streaming encrypt/decrypt operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StreamMetadata {
    pub chunks: u32,
    pub total_plaintext_bytes: u64,
    pub total_ciphertext_bytes: u64,
}

/// Derives a per-chunk nonce by XORing the chunk index into the last 4 bytes of the base nonce.
fn nonce_for_chunk(base_nonce: &[u8; 12], chunk_index: u32) -> [u8; 12] {
    let mut nonce = *base_nonce;
    let idx_bytes = chunk_index.to_be_bytes();
    nonce[8] ^= idx_bytes[0];
    nonce[9] ^= idx_bytes[1];
    nonce[10] ^= idx_bytes[2];
    nonce[11] ^= idx_bytes[3];
    nonce
}

/// Encrypts data from `input` into `output` using chunked AES-256-GCM.
///
/// Writes a V1 header followed by individually encrypted chunks.
/// Each chunk is `CHUNK_SIZE` bytes of plaintext (last chunk may be smaller),
/// encrypted with a nonce derived from the header's base nonce + chunk index.
pub fn encrypt_stream<R: Read, W: Write>(
    mut input: R,
    mut output: W,
    dek: &Dek,
) -> Result<StreamMetadata, SecureCoreError> {
    let base_nonce = generate_nonce();
    let header = EncHeader::new_v1(base_nonce);
    let header_bytes = header.to_bytes();

    output.write_all(&header_bytes)?;

    let cipher = Aes256Gcm::new_from_slice(dek.as_bytes())
        .map_err(|e| SecureCoreError::CryptoError(e.to_string()))?;

    let mut buf = vec![0u8; CHUNK_SIZE];
    let mut chunk_index: u32 = 0;
    let mut total_plaintext: u64 = 0;
    let mut total_ciphertext: u64 = header_bytes.len() as u64;

    loop {
        let bytes_read = read_exact_or_eof(&mut input, &mut buf)?;
        if bytes_read == 0 && chunk_index > 0 {
            break;
        }

        let chunk_nonce = nonce_for_chunk(&base_nonce, chunk_index);
        let gcm_nonce = Nonce::from_slice(&chunk_nonce);

        // AAD includes chunk index to prevent reordering
        let aad = chunk_index.to_be_bytes();
        let ciphertext_with_tag = cipher
            .encrypt(
                gcm_nonce,
                aes_gcm::aead::Payload {
                    msg: &buf[..bytes_read],
                    aad: &aad,
                },
            )
            .map_err(|e| SecureCoreError::CryptoError(e.to_string()))?;

        // Write chunk length (u32 LE) + ciphertext + tag
        let chunk_len = ciphertext_with_tag.len() as u32;
        output.write_all(&chunk_len.to_le_bytes())?;
        output.write_all(&ciphertext_with_tag)?;

        total_plaintext += bytes_read as u64;
        total_ciphertext += 4 + ciphertext_with_tag.len() as u64;

        chunk_index = chunk_index
            .checked_add(1)
            .ok_or_else(|| SecureCoreError::InvalidParameter("too many chunks".into()))?;

        if bytes_read < CHUNK_SIZE {
            break;
        }
    }

    output.flush()?;

    Ok(StreamMetadata {
        chunks: chunk_index,
        total_plaintext_bytes: total_plaintext,
        total_ciphertext_bytes: total_ciphertext,
    })
}

/// Decrypts chunked data from `input` into `output`.
pub fn decrypt_stream<R: Read, W: Write>(
    mut input: R,
    mut output: W,
    dek: &Dek,
) -> Result<StreamMetadata, SecureCoreError> {
    let mut header_buf = vec![0u8; 25];
    input
        .read_exact(&mut header_buf)
        .map_err(|_| SecureCoreError::InvalidFormat("failed to read stream header".into()))?;

    let header = EncHeader::from_bytes(&header_buf)?;
    let base_nonce = header.nonce;

    let cipher = Aes256Gcm::new_from_slice(dek.as_bytes())
        .map_err(|e| SecureCoreError::CryptoError(e.to_string()))?;

    let mut chunk_index: u32 = 0;
    let mut total_plaintext: u64 = 0;
    let mut total_ciphertext: u64 = header_buf.len() as u64;

    loop {
        // Read chunk length (u32 LE)
        let mut len_buf = [0u8; 4];
        match input.read_exact(&mut len_buf) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e.into()),
        }

        let chunk_len = u32::from_le_bytes(len_buf) as usize;
        if chunk_len < TAG_SIZE {
            return Err(SecureCoreError::InvalidFormat(
                "chunk too small to contain auth tag".into(),
            ));
        }

        let mut chunk_buf = vec![0u8; chunk_len];
        input.read_exact(&mut chunk_buf).map_err(|_| {
            SecureCoreError::InvalidFormat("unexpected EOF while reading chunk data".into())
        })?;

        let chunk_nonce = nonce_for_chunk(&base_nonce, chunk_index);
        let gcm_nonce = Nonce::from_slice(&chunk_nonce);

        let aad = chunk_index.to_be_bytes();
        let plaintext = cipher
            .decrypt(
                gcm_nonce,
                aes_gcm::aead::Payload {
                    msg: &chunk_buf,
                    aad: &aad,
                },
            )
            .map_err(|_| {
                SecureCoreError::CryptoError(format!(
                    "decryption failed on chunk {chunk_index}: invalid key or tampered data"
                ))
            })?;

        output.write_all(&plaintext)?;

        total_plaintext += plaintext.len() as u64;
        total_ciphertext += 4 + chunk_len as u64;

        chunk_index = chunk_index
            .checked_add(1)
            .ok_or_else(|| SecureCoreError::InvalidParameter("too many chunks".into()))?;
    }

    output.flush()?;

    Ok(StreamMetadata {
        chunks: chunk_index,
        total_plaintext_bytes: total_plaintext,
        total_ciphertext_bytes: total_ciphertext,
    })
}

/// Reads exactly `buf.len()` bytes, or fewer if EOF is reached.
/// Returns the number of bytes actually read.
fn read_exact_or_eof<R: Read>(reader: &mut R, buf: &mut [u8]) -> Result<usize, std::io::Error> {
    let mut total = 0;
    while total < buf.len() {
        match reader.read(&mut buf[total..]) {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    const TEST_KEY: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D,
        0x1E, 0x1F,
    ];

    #[test]
    fn test_nonce_derivation_unique() {
        let base = [0u8; 12];
        let n0 = nonce_for_chunk(&base, 0);
        let n1 = nonce_for_chunk(&base, 1);
        let n2 = nonce_for_chunk(&base, 2);
        assert_ne!(n0, n1);
        assert_ne!(n1, n2);
        assert_eq!(n0, base); // XOR with 0 is identity
    }

    #[test]
    fn test_nonce_derivation_deterministic() {
        let base = [0xAA; 12];
        let n1 = nonce_for_chunk(&base, 42);
        let n2 = nonce_for_chunk(&base, 42);
        assert_eq!(n1, n2);
    }

    #[test]
    fn test_stream_roundtrip_unit() {
        let dek = Dek::new(TEST_KEY);
        let plaintext = b"hello streaming";

        let mut encrypted = Vec::new();
        let enc_meta = encrypt_stream(Cursor::new(plaintext), &mut encrypted, &dek).unwrap();
        assert_eq!(enc_meta.chunks, 1);
        assert_eq!(enc_meta.total_plaintext_bytes, plaintext.len() as u64);

        let mut decrypted = Vec::new();
        let dec_meta = decrypt_stream(Cursor::new(&encrypted), &mut decrypted, &dek).unwrap();
        assert_eq!(decrypted, plaintext);
        assert_eq!(dec_meta.chunks, 1);
        assert_eq!(dec_meta.total_plaintext_bytes, plaintext.len() as u64);
    }

    #[test]
    fn test_stream_empty() {
        let dek = Dek::new(TEST_KEY);
        let plaintext = b"";

        let mut encrypted = Vec::new();
        let enc_meta = encrypt_stream(Cursor::new(plaintext), &mut encrypted, &dek).unwrap();
        // Empty input still produces 1 chunk (with 0 bytes of plaintext)
        assert_eq!(enc_meta.chunks, 1);
        assert_eq!(enc_meta.total_plaintext_bytes, 0);

        let mut decrypted = Vec::new();
        decrypt_stream(Cursor::new(&encrypted), &mut decrypted, &dek).unwrap();
        assert_eq!(decrypted, plaintext);
    }
}
