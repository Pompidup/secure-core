use std::ffi::CString;
use std::os::raw::c_char;

use crate::error::SecureCoreError;

// ── Status codes ────────────────────────────────────────────────────────

pub const FFI_OK: i32 = 0;
pub const FFI_ERROR_INVALID_FORMAT: i32 = 1;
pub const FFI_ERROR_UNSUPPORTED_VERSION: i32 = 2;
pub const FFI_ERROR_CRYPTO: i32 = 3;
pub const FFI_ERROR_IO: i32 = 4;
pub const FFI_ERROR_INVALID_PARAM: i32 = 5;

// ── FFI types ───────────────────────────────────────────────────────────

/// A buffer allocated by Rust and returned to the caller.
///
/// The caller **must** free this via `secure_core_free_buffer`.
/// A null `ptr` with `len == 0` represents an empty buffer.
#[repr(C)]
pub struct FfiBuffer {
    pub ptr: *mut u8,
    pub len: usize,
}

impl FfiBuffer {
    pub fn empty() -> Self {
        Self {
            ptr: std::ptr::null_mut(),
            len: 0,
        }
    }

    pub fn from_vec(mut v: Vec<u8>) -> Self {
        let buf = Self {
            ptr: v.as_mut_ptr(),
            len: v.len(),
        };
        std::mem::forget(v);
        buf
    }
}

/// Result type returned by all FFI functions.
///
/// - `status == FFI_OK`: `data` contains the result, `error_msg` is null.
/// - `status != FFI_OK`: `error_msg` is a C string describing the error, `data` is empty.
///
/// The caller **must** free this via `secure_core_free_result`.
#[repr(C)]
pub struct FfiResult {
    pub status: i32,
    pub data: FfiBuffer,
    pub error_msg: *mut c_char,
}

impl FfiResult {
    pub fn ok(data: Vec<u8>) -> Self {
        Self {
            status: FFI_OK,
            data: FfiBuffer::from_vec(data),
            error_msg: std::ptr::null_mut(),
        }
    }

    pub fn ok_empty() -> Self {
        Self {
            status: FFI_OK,
            data: FfiBuffer::empty(),
            error_msg: std::ptr::null_mut(),
        }
    }

    pub fn from_error(err: SecureCoreError) -> Self {
        let (status, msg) = match &err {
            SecureCoreError::InvalidFormat(_) => (FFI_ERROR_INVALID_FORMAT, err.to_string()),
            SecureCoreError::UnsupportedVersion { .. } => {
                (FFI_ERROR_UNSUPPORTED_VERSION, err.to_string())
            }
            SecureCoreError::CryptoError(_) => (FFI_ERROR_CRYPTO, err.to_string()),
            SecureCoreError::IoError(_) => (FFI_ERROR_IO, err.to_string()),
            SecureCoreError::InvalidParameter(_) => (FFI_ERROR_INVALID_PARAM, err.to_string()),
        };

        let c_msg = CString::new(msg).unwrap_or_default().into_raw();

        Self {
            status,
            data: FfiBuffer::empty(),
            error_msg: c_msg,
        }
    }

    pub fn invalid_param(msg: &str) -> Self {
        Self::from_error(SecureCoreError::InvalidParameter(msg.into()))
    }
}
