use serde::{Deserialize, Serialize};

use crate::error::SecureCoreError;

/// Metadata associated with an encrypted document.
///
/// This struct is designed to be serialized to JSON and stored by the platform
/// alongside the encrypted file. The core never persists it — that is the
/// platform's responsibility (see `docs/platform-contract.md`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DocumentMetadata {
    /// Unique document identifier (UUID recommended).
    pub doc_id: String,

    /// Original filename.
    pub filename: String,

    /// MIME type of the original file (e.g. "image/jpeg").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,

    /// Unix timestamp (seconds) when the document was encrypted.
    pub created_at: u64,

    /// Size of the original plaintext in bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plaintext_size: Option<u64>,

    /// Size of the encrypted output in bytes.
    pub ciphertext_size: u64,

    /// SHA-256 hash of the plaintext (optional integrity check).
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_optional_hash",
        deserialize_with = "deserialize_optional_hash",
        default
    )]
    pub content_hash: Option<[u8; 32]>,

    /// The wrapped (encrypted) DEK, managed by the platform's keystore.
    pub wrapped_dek: WrappedDek,
}

/// A DEK wrapped (encrypted) by the platform's key management system.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WrappedDek {
    /// The DEK encrypted by the OS keystore (Keychain / KeyStore).
    #[serde(with = "hex_bytes")]
    pub device_wrap: Vec<u8>,

    /// Reserved for V2: recovery-wrapped DEK (e.g. for account recovery).
    #[serde(
        skip_serializing_if = "Option::is_none",
        with = "optional_hex_bytes",
        default
    )]
    pub recovery_wrap: Option<Vec<u8>>,

    /// Algorithm used for wrapping (e.g. "AES-KWP", "RSA-OAEP").
    pub wrap_algorithm: String,
}

impl DocumentMetadata {
    /// Validates that all required fields are present and well-formed.
    pub fn validate(&self) -> Result<(), SecureCoreError> {
        if self.doc_id.is_empty() {
            return Err(SecureCoreError::InvalidParameter(
                "doc_id must not be empty".into(),
            ));
        }
        if self.filename.is_empty() {
            return Err(SecureCoreError::InvalidParameter(
                "filename must not be empty".into(),
            ));
        }
        if self.wrapped_dek.device_wrap.is_empty() {
            return Err(SecureCoreError::InvalidParameter(
                "wrapped_dek.device_wrap must not be empty".into(),
            ));
        }
        if self.wrapped_dek.wrap_algorithm.is_empty() {
            return Err(SecureCoreError::InvalidParameter(
                "wrapped_dek.wrap_algorithm must not be empty".into(),
            ));
        }
        Ok(())
    }
}

// ── Hex serialization helpers ───────────────────────────────────────────

mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        s.serialize_str(&hex)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let hex = String::deserialize(d)?;
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).map_err(serde::de::Error::custom))
            .collect()
    }
}

mod optional_hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(val: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
        match val {
            Some(bytes) => {
                let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
                s.serialize_some(&hex)
            }
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<u8>>, D::Error> {
        let opt: Option<String> = Option::deserialize(d)?;
        match opt {
            Some(hex) => {
                let bytes: Result<Vec<u8>, _> = (0..hex.len())
                    .step_by(2)
                    .map(|i| {
                        u8::from_str_radix(&hex[i..i + 2], 16).map_err(serde::de::Error::custom)
                    })
                    .collect();
                bytes.map(Some)
            }
            None => Ok(None),
        }
    }
}

fn serialize_optional_hash<S: serde::Serializer>(
    val: &Option<[u8; 32]>,
    s: S,
) -> Result<S::Ok, S::Error> {
    match val {
        Some(hash) => {
            let hex: String = hash.iter().map(|b| format!("{b:02x}")).collect();
            s.serialize_some(&hex)
        }
        None => s.serialize_none(),
    }
}

fn deserialize_optional_hash<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Option<[u8; 32]>, D::Error> {
    let opt: Option<String> = Option::deserialize(d)?;
    match opt {
        Some(hex) => {
            if hex.len() != 64 {
                return Err(serde::de::Error::custom(
                    "content_hash must be 64 hex chars",
                ));
            }
            let bytes: Vec<u8> = (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).map_err(serde::de::Error::custom))
                .collect::<Result<_, _>>()?;
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            Ok(Some(arr))
        }
        None => Ok(None),
    }
}
