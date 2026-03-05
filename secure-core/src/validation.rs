use crate::error::SecureCoreError;

/// Expected DEK length in bytes (AES-256).
pub const DEK_LENGTH: usize = 32;

/// Expected nonce length in bytes (GCM).
pub const NONCE_LENGTH: usize = 12;

/// Validates that a DEK slice is exactly 32 bytes.
pub fn validate_dek(dek: &[u8]) -> Result<(), SecureCoreError> {
    if dek.len() != DEK_LENGTH {
        return Err(SecureCoreError::InvalidParameter(format!(
            "DEK must be exactly {DEK_LENGTH} bytes, got {}",
            dek.len()
        )));
    }
    Ok(())
}

/// Validates that a nonce slice is exactly 12 bytes.
pub fn validate_nonce(nonce: &[u8]) -> Result<(), SecureCoreError> {
    if nonce.len() != NONCE_LENGTH {
        return Err(SecureCoreError::InvalidParameter(format!(
            "nonce must be exactly {NONCE_LENGTH} bytes, got {}",
            nonce.len()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_dek_ok() {
        assert!(validate_dek(&[0u8; 32]).is_ok());
    }

    #[test]
    fn test_validate_dek_too_short() {
        let err = validate_dek(&[0u8; 16]).unwrap_err();
        assert!(matches!(err, SecureCoreError::InvalidParameter(_)));
    }

    #[test]
    fn test_validate_dek_too_long() {
        let err = validate_dek(&[0u8; 64]).unwrap_err();
        assert!(matches!(err, SecureCoreError::InvalidParameter(_)));
    }

    #[test]
    fn test_validate_dek_empty() {
        let err = validate_dek(&[]).unwrap_err();
        assert!(matches!(err, SecureCoreError::InvalidParameter(_)));
    }

    #[test]
    fn test_validate_nonce_ok() {
        assert!(validate_nonce(&[0u8; 12]).is_ok());
    }

    #[test]
    fn test_validate_nonce_wrong_length() {
        let err = validate_nonce(&[0u8; 16]).unwrap_err();
        assert!(matches!(err, SecureCoreError::InvalidParameter(_)));
    }
}
