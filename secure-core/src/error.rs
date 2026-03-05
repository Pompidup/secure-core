use std::fmt;

/// Errors produced by secure-core operations.
#[derive(Debug)]
pub enum SecureCoreError {
    /// The binary data does not conform to the expected `.enc` format.
    InvalidFormat(String),

    /// The format version is not supported by this build.
    UnsupportedVersion { found: u16, max_supported: u16 },

    /// A cryptographic operation failed.
    CryptoError(String),

    /// An I/O error occurred.
    IoError(std::io::Error),

    /// A parameter passed to the API is invalid.
    InvalidParameter(String),
}

impl fmt::Display for SecureCoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidFormat(msg) => write!(f, "invalid format: {msg}"),
            Self::UnsupportedVersion {
                found,
                max_supported,
            } => write!(
                f,
                "unsupported version: found {found}, max supported {max_supported}"
            ),
            Self::CryptoError(msg) => write!(f, "crypto error: {msg}"),
            Self::IoError(err) => write!(f, "I/O error: {err}"),
            Self::InvalidParameter(msg) => write!(f, "invalid parameter: {msg}"),
        }
    }
}

impl std::error::Error for SecureCoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::IoError(err) => Some(err),
            _ => None,
        }
    }
}

impl From<std::io::Error> for SecureCoreError {
    fn from(err: std::io::Error) -> Self {
        Self::IoError(err)
    }
}
