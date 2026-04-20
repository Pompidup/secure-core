use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::SecureCoreError;
use crate::format::EncHeader;
use crate::validation::validate_dek;

/// GCM auth tag size in bytes.
const TAG_SIZE: usize = 16;

/// Maximum plaintext size accepted by [`encrypt_bytes`]: 4 GiB on 64-bit
/// targets, 2 GiB on 32-bit. This is a conservative cap well below the
/// NIST SP 800-38D per-invocation limit for GCM (~64 GiB); it reflects the
/// practical ceiling for in-memory operations on mobile devices.
///
/// For plaintexts that exceed this bound, use
/// [`streaming::encrypt_stream`](crate::streaming::encrypt_stream), which
/// processes 64 KiB chunks and can handle up to
/// [`streaming::MAX_STREAM_PLAINTEXT_SIZE`](crate::streaming::MAX_STREAM_PLAINTEXT_SIZE).
#[cfg(target_pointer_width = "64")]
pub const MAX_PLAINTEXT_SIZE: usize = 4 * 1024 * 1024 * 1024;
#[cfg(not(target_pointer_width = "64"))]
pub const MAX_PLAINTEXT_SIZE: usize = 2 * 1024 * 1024 * 1024;

/// A Data Encryption Key that is zeroized on drop.
///
/// `Debug` is intentionally implemented to NOT print the key bytes,
/// preventing accidental secret leakage in logs or error messages.
///
/// The inner byte array is private: callers read it via [`Dek::as_bytes`].
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Dek([u8; 32]);

impl std::fmt::Debug for Dek {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Dek([REDACTED])")
    }
}

impl Dek {
    /// Builds a `Dek` from an owned key array.
    ///
    /// The caller is responsible for zeroizing any upstream copy of `key`.
    /// Prefer [`Dek::take`] when the source is a mutable buffer that holds
    /// sensitive material — it wipes the source after copying.
    pub fn new(key: [u8; 32]) -> Self {
        Self(key)
    }

    /// Builds a `Dek` by moving bytes out of `src` and zeroizing it.
    ///
    /// After this call, `src` is guaranteed to be all zeros, so any stack
    /// copy the caller holds cannot leak the key. This is the preferred
    /// constructor at FFI/JNI boundaries where a temporary `[u8; 32]`
    /// buffer has just been populated from caller memory.
    pub fn take(src: &mut [u8; 32]) -> Self {
        let mut key = [0u8; 32];
        key.copy_from_slice(src);
        src.zeroize();
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
///
/// Rejects any plaintext larger than [`MAX_PLAINTEXT_SIZE`]; use
/// [`crate::streaming::encrypt_stream`] for larger payloads.
pub fn encrypt_bytes(plaintext: &[u8], dek: &[u8; 32]) -> Result<Vec<u8>, SecureCoreError> {
    validate_dek(dek)?;
    encrypt_bytes_with_nonce(plaintext, dek, generate_nonce())
}

/// Encrypts with an explicit nonce. Available under `#[cfg(test)]` or the `_test-vectors` feature.
#[cfg(any(test, feature = "_test-vectors"))]
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
    validate_dek(dek)?;
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
        use zeroize::Zeroize;

        // Verify explicit zeroize clears the key
        let mut dek = Dek::new([0x42u8; 32]);
        assert_eq!(dek.as_bytes(), &[0x42u8; 32]);
        dek.zeroize();
        assert_eq!(
            dek.as_bytes(),
            &[0u8; 32],
            "DEK must be zeroed after zeroize()"
        );
    }

    #[test]
    fn test_dek_debug_redacted() {
        let dek = Dek::new([0xFFu8; 32]);
        let debug_output = format!("{dek:?}");
        assert_eq!(debug_output, "Dek([REDACTED])");
        assert!(
            !debug_output.contains("ff") && !debug_output.contains("FF"),
            "Debug must not contain key bytes"
        );
    }

    #[test]
    fn test_dek_take_zeroes_source() {
        let mut src = [0x5Au8; 32];
        let _dek = Dek::take(&mut src);
        assert_eq!(src, [0u8; 32], "Dek::take must zero the caller's buffer");
    }

    #[test]
    fn test_dek_take_preserves_value_in_dek() {
        let original = [0x5Au8; 32];
        let mut src = original;
        let dek = Dek::take(&mut src);
        assert_eq!(
            dek.as_bytes(),
            &original,
            "Dek must hold the original key bytes"
        );
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
