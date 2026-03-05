use crate::error::SecureCoreError;

/// Magic bytes identifying the `.enc` format: ASCII "SENC".
pub const MAGIC: [u8; 4] = [0x53, 0x45, 0x4E, 0x43];

/// Current format version.
pub const FORMAT_VERSION_V1: u16 = 1;

/// Total header size in bytes for V1.
const HEADER_SIZE_V1: u32 = 25;

/// Size of an AES-256-GCM nonce in bytes.
const NONCE_SIZE: usize = 12;

/// Supported encryption algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AlgorithmId {
    Aes256Gcm = 0x01,
}

impl AlgorithmId {
    fn from_byte(b: u8) -> Result<Self, SecureCoreError> {
        match b {
            0x01 => Ok(Self::Aes256Gcm),
            other => Err(SecureCoreError::InvalidFormat(format!(
                "unknown algorithm id: 0x{other:02X}"
            ))),
        }
    }
}

/// Header of the `.enc` V1 binary format.
///
/// ```text
/// magic (4) | version (2) | algo (1) | nonce (12) | flags (2) | header_length (4)
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncHeader {
    pub version: u16,
    pub algorithm: AlgorithmId,
    pub nonce: [u8; NONCE_SIZE],
    pub flags: u16,
    pub header_length: u32,
}

impl EncHeader {
    /// Creates a new V1 header with the given nonce.
    pub fn new_v1(nonce: [u8; NONCE_SIZE]) -> Self {
        Self {
            version: FORMAT_VERSION_V1,
            algorithm: AlgorithmId::Aes256Gcm,
            nonce,
            flags: 0,
            header_length: HEADER_SIZE_V1,
        }
    }

    /// Serializes the header to its binary representation.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.header_length as usize);
        buf.extend_from_slice(&MAGIC);
        buf.extend_from_slice(&self.version.to_le_bytes());
        buf.push(self.algorithm as u8);
        buf.extend_from_slice(&self.nonce);
        buf.extend_from_slice(&self.flags.to_le_bytes());
        buf.extend_from_slice(&self.header_length.to_le_bytes());
        buf
    }

    /// Parses a header from a byte slice.
    ///
    /// The slice must contain at least [`HEADER_SIZE_V1`] bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, SecureCoreError> {
        if data.len() < HEADER_SIZE_V1 as usize {
            return Err(SecureCoreError::InvalidFormat(format!(
                "data too short: expected at least {HEADER_SIZE_V1} bytes, got {}",
                data.len()
            )));
        }

        // Magic
        if data[0..4] != MAGIC {
            return Err(SecureCoreError::InvalidFormat(
                "invalid magic bytes: expected SENC".into(),
            ));
        }

        // Version
        let version = u16::from_le_bytes([data[4], data[5]]);
        if version > FORMAT_VERSION_V1 {
            return Err(SecureCoreError::UnsupportedVersion {
                found: version,
                max_supported: FORMAT_VERSION_V1,
            });
        }

        // Algorithm
        let algorithm = AlgorithmId::from_byte(data[6])?;

        // Nonce
        let mut nonce = [0u8; NONCE_SIZE];
        nonce.copy_from_slice(&data[7..19]);

        // Flags
        let flags = u16::from_le_bytes([data[19], data[20]]);

        // Header length
        let header_length = u32::from_le_bytes([data[21], data[22], data[23], data[24]]);
        if header_length != HEADER_SIZE_V1 {
            return Err(SecureCoreError::InvalidFormat(format!(
                "header_length mismatch: expected {HEADER_SIZE_V1}, got {header_length}"
            )));
        }

        Ok(Self {
            version,
            algorithm,
            nonce,
            flags,
            header_length,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Serialization / Deserialization ──────────────────────────────

    #[test]
    fn test_header_roundtrip() {
        let nonce = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let header = EncHeader::new_v1(nonce);
        let bytes = header.to_bytes();

        assert_eq!(bytes.len(), HEADER_SIZE_V1 as usize);

        let parsed = EncHeader::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.version, header.version);
        assert_eq!(parsed.algorithm, header.algorithm);
        assert_eq!(parsed.nonce, header.nonce);
        assert_eq!(parsed.flags, header.flags);
        assert_eq!(parsed.header_length, header.header_length);
    }

    #[test]
    fn test_header_wrong_magic() {
        let mut bytes = EncHeader::new_v1([0u8; NONCE_SIZE]).to_bytes();
        bytes[0] = 0xFF;

        let err = EncHeader::from_bytes(&bytes).unwrap_err();
        assert!(matches!(err, SecureCoreError::InvalidFormat(_)));
    }

    #[test]
    fn test_header_unsupported_version() {
        let mut bytes = EncHeader::new_v1([0u8; NONCE_SIZE]).to_bytes();
        // Set version to 99
        bytes[4] = 99;
        bytes[5] = 0;

        let err = EncHeader::from_bytes(&bytes).unwrap_err();
        assert!(matches!(
            err,
            SecureCoreError::UnsupportedVersion {
                found: 99,
                max_supported: 1
            }
        ));
    }

    #[test]
    fn test_header_truncated() {
        let err = EncHeader::from_bytes(&[0x53, 0x45, 0x4E, 0x43, 0x01]).unwrap_err();
        assert!(matches!(err, SecureCoreError::InvalidFormat(_)));
    }

    #[test]
    fn test_header_length_mismatch() {
        let mut bytes = EncHeader::new_v1([0u8; NONCE_SIZE]).to_bytes();
        // Set header_length to 99 instead of 25 — inconsistent with V1
        bytes[21] = 99;
        bytes[22] = 0;
        bytes[23] = 0;
        bytes[24] = 0;

        let err = EncHeader::from_bytes(&bytes).unwrap_err();
        assert!(matches!(err, SecureCoreError::InvalidFormat(_)));
    }

    // ── Robustness ──────────────────────────────────────────────────

    #[test]
    fn test_empty_input() {
        let err = EncHeader::from_bytes(&[]).unwrap_err();
        assert!(matches!(err, SecureCoreError::InvalidFormat(_)));
    }

    #[test]
    fn test_minimum_valid_header() {
        // Exactly 25 bytes — the smallest valid V1 header
        let header = EncHeader::new_v1([0xAA; NONCE_SIZE]);
        let bytes = header.to_bytes();
        assert_eq!(bytes.len(), 25);

        let parsed = EncHeader::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.algorithm, AlgorithmId::Aes256Gcm);
        assert_eq!(parsed.nonce, [0xAA; NONCE_SIZE]);
        assert_eq!(parsed.flags, 0);
    }
}
