use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::Argon2;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::error::SecureCoreError;

/// Argon2id V1 parameters.
const ARGON2_M_COST: u32 = 65536; // 64 MiB
const ARGON2_T_COST: u32 = 3;
const ARGON2_P_COST: u32 = 4;
const SALT_LEN: usize = 32;
const NONCE_LEN: usize = 12;

/// A passphrase-derived recovery wrap for a DEK.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RecoveryWrap {
    pub algo: String,
    pub kdf: String,
    pub kdf_params: KdfParams,
    /// Base64-encoded 32-byte salt.
    pub salt: String,
    /// Base64-encoded 12-byte nonce/IV.
    pub iv: String,
    /// Base64-encoded 16-byte authentication tag.
    pub tag: String,
    /// Base64-encoded 32-byte ciphertext (wrapped DEK).
    pub ciphertext: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KdfParams {
    pub m: u32,
    pub t: u32,
    pub p: u32,
}

/// Derives a 256-bit key from a passphrase and salt using Argon2id.
pub fn derive_recovery_key(passphrase: &str, salt: &[u8]) -> Result<[u8; 32], SecureCoreError> {
    if salt.len() < 16 {
        return Err(SecureCoreError::InvalidParameter(
            "salt must be at least 16 bytes".into(),
        ));
    }

    let params = argon2::Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, Some(32))
        .map_err(|e| SecureCoreError::CryptoError(format!("argon2 params: {e}")))?;

    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

    let mut key = [0u8; 32];
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| SecureCoreError::CryptoError(format!("argon2 derivation: {e}")))?;

    Ok(key)
}

/// Wraps a DEK with a passphrase using Argon2id + AES-256-GCM.
///
/// Generates a random salt and nonce, derives a key from the passphrase,
/// and encrypts the DEK. Returns a `RecoveryWrap` suitable for JSON serialization.
pub fn wrap_dek_with_passphrase(
    dek: &[u8; 32],
    passphrase: &str,
) -> Result<RecoveryWrap, SecureCoreError> {
    use base64::engine::general_purpose::STANDARD as BASE64;
    use base64::Engine;

    if passphrase.is_empty() {
        return Err(SecureCoreError::InvalidParameter(
            "passphrase must not be empty".into(),
        ));
    }

    // Generate random salt and nonce
    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut salt);
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);

    // Derive key
    let mut recovery_key = derive_recovery_key(passphrase, &salt)?;

    // Encrypt DEK with recovery key
    let cipher = Aes256Gcm::new_from_slice(&recovery_key)
        .map_err(|e| SecureCoreError::CryptoError(e.to_string()))?;

    recovery_key.zeroize();

    let gcm_nonce = Nonce::from_slice(&nonce);
    let ciphertext_with_tag = cipher
        .encrypt(gcm_nonce, dek.as_ref())
        .map_err(|e| SecureCoreError::CryptoError(format!("wrap encrypt: {e}")))?;

    // Split ciphertext and tag (GCM appends 16-byte tag)
    let ct_len = ciphertext_with_tag.len() - 16;
    let ciphertext = &ciphertext_with_tag[..ct_len];
    let tag = &ciphertext_with_tag[ct_len..];

    Ok(RecoveryWrap {
        algo: "AES-256-GCM-ARGON2ID".to_string(),
        kdf: "argon2id-v19".to_string(),
        kdf_params: KdfParams {
            m: ARGON2_M_COST,
            t: ARGON2_T_COST,
            p: ARGON2_P_COST,
        },
        salt: BASE64.encode(salt),
        iv: BASE64.encode(nonce),
        tag: BASE64.encode(tag),
        ciphertext: BASE64.encode(ciphertext),
    })
}

/// Unwraps a DEK from a recovery wrap using the passphrase.
pub fn unwrap_dek_with_passphrase(
    wrap: &RecoveryWrap,
    passphrase: &str,
) -> Result<[u8; 32], SecureCoreError> {
    use base64::engine::general_purpose::STANDARD as BASE64;
    use base64::Engine;

    // Validate algo
    if wrap.algo != "AES-256-GCM-ARGON2ID" {
        return Err(SecureCoreError::InvalidParameter(format!(
            "unsupported recovery algo: {}",
            wrap.algo
        )));
    }

    // Decode fields
    let salt = BASE64
        .decode(&wrap.salt)
        .map_err(|e| SecureCoreError::InvalidParameter(format!("salt: invalid base64: {e}")))?;
    let nonce = BASE64
        .decode(&wrap.iv)
        .map_err(|e| SecureCoreError::InvalidParameter(format!("iv: invalid base64: {e}")))?;
    let tag = BASE64
        .decode(&wrap.tag)
        .map_err(|e| SecureCoreError::InvalidParameter(format!("tag: invalid base64: {e}")))?;
    let ciphertext = BASE64.decode(&wrap.ciphertext).map_err(|e| {
        SecureCoreError::InvalidParameter(format!("ciphertext: invalid base64: {e}"))
    })?;

    if nonce.len() != NONCE_LEN {
        return Err(SecureCoreError::InvalidParameter(format!(
            "iv must be {} bytes, got {}",
            NONCE_LEN,
            nonce.len()
        )));
    }
    if tag.len() != 16 {
        return Err(SecureCoreError::InvalidParameter(format!(
            "tag must be 16 bytes, got {}",
            tag.len()
        )));
    }

    // Derive key
    let mut recovery_key = derive_recovery_key(passphrase, &salt)?;

    let cipher = Aes256Gcm::new_from_slice(&recovery_key)
        .map_err(|e| SecureCoreError::CryptoError(e.to_string()))?;

    recovery_key.zeroize();

    // Reassemble ciphertext + tag for GCM
    let mut ct_with_tag = Vec::with_capacity(ciphertext.len() + tag.len());
    ct_with_tag.extend_from_slice(&ciphertext);
    ct_with_tag.extend_from_slice(&tag);

    let gcm_nonce = Nonce::from_slice(&nonce);
    let plaintext = cipher.decrypt(gcm_nonce, ct_with_tag.as_ref()).map_err(|_| {
        SecureCoreError::CryptoError(
            "recovery unwrap failed: invalid passphrase or tampered data".into(),
        )
    })?;

    if plaintext.len() != 32 {
        return Err(SecureCoreError::CryptoError(format!(
            "unwrapped DEK must be 32 bytes, got {}",
            plaintext.len()
        )));
    }

    let mut dek = [0u8; 32];
    dek.copy_from_slice(&plaintext);
    Ok(dek)
}
