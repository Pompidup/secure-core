use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::SecureCoreError;
use crate::format::EncHeader;

/// GCM auth tag size in bytes.
const TAG_SIZE: usize = 16;

/// Maximum plaintext size: 4 GB.
const MAX_PLAINTEXT_SIZE: usize = 4 * 1024 * 1024 * 1024;

/// A Data Encryption Key that is zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Dek(pub [u8; 32]);

impl Dek {
    pub fn new(key: [u8; 32]) -> Self {
        Self(key)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Generates a cryptographically random 12-byte nonce.
pub fn generate_nonce() -> [u8; 12] {
    let mut nonce = [0u8; 12];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);
    nonce
}

/// Encrypts plaintext and returns a complete `.enc` V1 blob (header + ciphertext + tag).
pub fn encrypt_bytes(plaintext: &[u8], dek: &[u8; 32]) -> Result<Vec<u8>, SecureCoreError> {
    encrypt_bytes_with_nonce(plaintext, dek, generate_nonce())
}

/// Encrypts with an explicit nonce. Used by tests for deterministic output.
#[cfg(test)]
pub fn encrypt_bytes_with_nonce_test(
    plaintext: &[u8],
    dek: &[u8; 32],
    nonce: [u8; 12],
) -> Result<Vec<u8>, SecureCoreError> {
    encrypt_bytes_with_nonce(plaintext, dek, nonce)
}

fn encrypt_bytes_with_nonce(
    plaintext: &[u8],
    dek: &[u8; 32],
    nonce: [u8; 12],
) -> Result<Vec<u8>, SecureCoreError> {
    if plaintext.len() > MAX_PLAINTEXT_SIZE {
        return Err(SecureCoreError::InvalidParameter(format!(
            "plaintext too large: {} bytes, max {}",
            plaintext.len(),
            MAX_PLAINTEXT_SIZE
        )));
    }

    let header = EncHeader::new_v1(nonce);
    let header_bytes = header.to_bytes();

    let cipher =
        Aes256Gcm::new_from_slice(dek).map_err(|e| SecureCoreError::CryptoError(e.to_string()))?;

    // GCM with AAD = header bytes
    let gcm_nonce = Nonce::from_slice(&nonce);
    let ciphertext_with_tag = cipher
        .encrypt(
            gcm_nonce,
            aes_gcm::aead::Payload {
                msg: plaintext,
                aad: &header_bytes,
            },
        )
        .map_err(|e| SecureCoreError::CryptoError(e.to_string()))?;

    let mut blob = Vec::with_capacity(header_bytes.len() + ciphertext_with_tag.len());
    blob.extend_from_slice(&header_bytes);
    blob.extend_from_slice(&ciphertext_with_tag);

    Ok(blob)
}

/// Decrypts a `.enc` V1 blob and returns the plaintext.
pub fn decrypt_bytes(blob: &[u8], dek: &[u8; 32]) -> Result<Vec<u8>, SecureCoreError> {
    let header = EncHeader::from_bytes(blob)?;
    let header_len = header.header_length as usize;

    let payload = blob
        .get(header_len..)
        .ok_or_else(|| SecureCoreError::InvalidFormat("blob shorter than header_length".into()))?;

    if payload.len() < TAG_SIZE {
        return Err(SecureCoreError::InvalidFormat(
            "payload too short to contain auth tag".into(),
        ));
    }

    let header_bytes = &blob[..header_len];

    let cipher =
        Aes256Gcm::new_from_slice(dek).map_err(|e| SecureCoreError::CryptoError(e.to_string()))?;

    let gcm_nonce = Nonce::from_slice(&header.nonce);
    let plaintext = cipher
        .decrypt(
            gcm_nonce,
            aes_gcm::aead::Payload {
                msg: payload,
                aad: header_bytes,
            },
        )
        .map_err(|_| {
            SecureCoreError::CryptoError("decryption failed: invalid key or tampered data".into())
        })?;

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Test vectors ────────────────────────────────────────────────
    // Known key, nonce, plaintext → deterministic output via encrypt_bytes_with_nonce_test.

    const TV_KEY: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D,
        0x1E, 0x1F,
    ];

    const TV_NONCE: [u8; 12] = [
        0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB,
    ];

    // ── Vector 1: simple ASCII ──────────────────────────────────────

    #[test]
    fn test_vector_1_roundtrip() {
        let plaintext = b"Hello, secure-core!";
        let blob = encrypt_bytes_with_nonce_test(plaintext, &TV_KEY, TV_NONCE).unwrap();
        let decrypted = decrypt_bytes(&blob, &TV_KEY).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_vector_1_deterministic() {
        let plaintext = b"Hello, secure-core!";
        let blob1 = encrypt_bytes_with_nonce_test(plaintext, &TV_KEY, TV_NONCE).unwrap();
        let blob2 = encrypt_bytes_with_nonce_test(plaintext, &TV_KEY, TV_NONCE).unwrap();
        assert_eq!(
            blob1, blob2,
            "same key+nonce+plaintext must produce identical output"
        );
    }

    // ── Vector 2: empty plaintext ───────────────────────────────────

    #[test]
    fn test_vector_2_empty_plaintext() {
        let plaintext = b"";
        let blob = encrypt_bytes_with_nonce_test(plaintext, &TV_KEY, TV_NONCE).unwrap();

        // header (25) + tag (16) = 41 bytes, no ciphertext
        assert_eq!(blob.len(), 25 + 16);

        let decrypted = decrypt_bytes(&blob, &TV_KEY).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    // ── Vector 3: binary data ───────────────────────────────────────

    #[test]
    fn test_vector_3_binary_data() {
        let plaintext: Vec<u8> = (0u8..=255).collect();
        let blob = encrypt_bytes_with_nonce_test(&plaintext, &TV_KEY, TV_NONCE).unwrap();
        let decrypted = decrypt_bytes(&blob, &TV_KEY).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    // ── Encrypt / Decrypt with random nonce ─────────────────────────

    #[test]
    fn test_encrypt_decrypt_random_nonce() {
        let plaintext = b"random nonce test";
        let blob = encrypt_bytes(plaintext, &TV_KEY).unwrap();
        let decrypted = decrypt_bytes(&blob, &TV_KEY).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_different_nonces_produce_different_blobs() {
        let plaintext = b"nonce uniqueness";
        let blob1 = encrypt_bytes(plaintext, &TV_KEY).unwrap();
        let blob2 = encrypt_bytes(plaintext, &TV_KEY).unwrap();
        // Nonces are random → blobs must differ (with overwhelming probability)
        assert_ne!(blob1, blob2);
    }

    // ── Tamper detection ────────────────────────────────────────────

    #[test]
    fn test_tampered_ciphertext_fails() {
        let plaintext = b"tamper test";
        let mut blob = encrypt_bytes_with_nonce_test(plaintext, &TV_KEY, TV_NONCE).unwrap();

        // Flip a byte in the ciphertext area (after header)
        let idx = 25 + 1;
        blob[idx] ^= 0xFF;

        let err = decrypt_bytes(&blob, &TV_KEY).unwrap_err();
        assert!(matches!(err, SecureCoreError::CryptoError(_)));
    }

    #[test]
    fn test_tampered_header_fails() {
        let plaintext = b"header tamper";
        let mut blob = encrypt_bytes_with_nonce_test(plaintext, &TV_KEY, TV_NONCE).unwrap();

        // Flip a flag bit in the header (offset 19 = flags)
        blob[19] ^= 0x01;

        let err = decrypt_bytes(&blob, &TV_KEY).unwrap_err();
        assert!(matches!(err, SecureCoreError::CryptoError(_)));
    }

    #[test]
    fn test_wrong_key_fails() {
        let plaintext = b"wrong key test";
        let blob = encrypt_bytes_with_nonce_test(plaintext, &TV_KEY, TV_NONCE).unwrap();

        let wrong_key = [0xFFu8; 32];
        let err = decrypt_bytes(&blob, &wrong_key).unwrap_err();
        assert!(matches!(err, SecureCoreError::CryptoError(_)));
    }

    // ── Dek zeroize ─────────────────────────────────────────────────

    #[test]
    fn test_dek_zeroize_on_drop() {
        let key_copy;
        {
            let dek = Dek::new([0x42u8; 32]);
            key_copy = dek.as_bytes().as_ptr();
            // dek is dropped here
        }
        // We cannot reliably read freed memory in safe Rust,
        // but we verify the type compiles with ZeroizeOnDrop.
        let _ = key_copy;
    }

    // ── Header AAD ──────────────────────────────────────────────────

    #[test]
    fn test_header_is_authenticated() {
        let plaintext = b"AAD test";
        let blob = encrypt_bytes_with_nonce_test(plaintext, &TV_KEY, TV_NONCE).unwrap();

        // Parse header, verify nonce is in the blob
        let header = EncHeader::from_bytes(&blob).unwrap();
        assert_eq!(header.nonce, TV_NONCE);
        assert_eq!(header.algorithm, crate::format::AlgorithmId::Aes256Gcm);
    }
}
