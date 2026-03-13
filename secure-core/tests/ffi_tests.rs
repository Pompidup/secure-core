use std::ffi::{CStr, CString};

use secure_core::ffi::functions::*;
use secure_core::ffi::types::*;

fn make_test_dek() -> [u8; 32] {
    [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D,
        0x1E, 0x1F,
    ]
}

#[test]
fn test_ffi_encrypt_decrypt_roundtrip() {
    let plaintext = b"FFI roundtrip test data";
    let dek = make_test_dek();

    // SAFETY: plaintext and dek are valid stack-allocated slices with correct lengths.
    let enc_result = unsafe {
        secure_core_encrypt_bytes(plaintext.as_ptr(), plaintext.len(), dek.as_ptr(), dek.len())
    };
    assert_eq!(enc_result.status, FFI_OK);
    assert!(!enc_result.data.ptr.is_null());
    assert!(enc_result.data.len > 0);
    assert!(enc_result.error_msg.is_null());

    // SAFETY: enc_result.data was returned by secure_core_encrypt_bytes and is valid.
    let dec_result = unsafe {
        secure_core_decrypt_bytes(
            enc_result.data.ptr,
            enc_result.data.len,
            dek.as_ptr(),
            dek.len(),
        )
    };
    assert_eq!(dec_result.status, FFI_OK);
    assert!(!dec_result.data.ptr.is_null());
    assert_eq!(dec_result.data.len, plaintext.len());

    // SAFETY: dec_result.data.ptr is valid for dec_result.data.len bytes.
    let decrypted = unsafe { std::slice::from_raw_parts(dec_result.data.ptr, dec_result.data.len) };
    assert_eq!(decrypted, plaintext);

    // SAFETY: Both results were returned by secure_core_* functions and haven't been freed yet.
    unsafe {
        secure_core_free_result(enc_result);
        secure_core_free_result(dec_result);
    }
}

#[test]
fn test_ffi_error_invalid_dek_size() {
    let plaintext = b"test";
    let short_dek = [0u8; 16]; // 16 bytes instead of 32

    // SAFETY: plaintext and short_dek are valid stack-allocated slices.
    let result = unsafe {
        secure_core_encrypt_bytes(
            plaintext.as_ptr(),
            plaintext.len(),
            short_dek.as_ptr(),
            short_dek.len(),
        )
    };

    assert_eq!(result.status, FFI_ERROR_INVALID_PARAM);
    assert!(!result.error_msg.is_null());

    // SAFETY: error_msg was allocated by CString::into_raw in FfiResult::from_error.
    let msg = unsafe { CStr::from_ptr(result.error_msg) }
        .to_str()
        .unwrap();
    assert!(msg.contains("32 bytes"), "error message: {msg}");

    // SAFETY: result was returned by secure_core_encrypt_bytes.
    unsafe { secure_core_free_result(result) };
}

#[test]
fn test_ffi_error_null_dek() {
    let plaintext = b"test";

    // SAFETY: null dek_ptr with len 32 — the function must handle this gracefully.
    let result = unsafe {
        secure_core_encrypt_bytes(plaintext.as_ptr(), plaintext.len(), std::ptr::null(), 32)
    };

    assert_eq!(result.status, FFI_ERROR_INVALID_PARAM);
    assert!(!result.error_msg.is_null());

    // SAFETY: result was returned by secure_core_encrypt_bytes.
    unsafe { secure_core_free_result(result) };
}

#[test]
fn test_ffi_error_tampered_blob() {
    let plaintext = b"tamper test via FFI";
    let dek = make_test_dek();

    // SAFETY: plaintext and dek are valid.
    let enc_result = unsafe {
        secure_core_encrypt_bytes(plaintext.as_ptr(), plaintext.len(), dek.as_ptr(), dek.len())
    };
    assert_eq!(enc_result.status, FFI_OK);

    // Corrupt one byte in the encrypted blob
    // SAFETY: enc_result.data.ptr is valid for enc_result.data.len bytes.
    unsafe {
        let blob = std::slice::from_raw_parts_mut(enc_result.data.ptr, enc_result.data.len);
        blob[30] ^= 0xFF; // flip a byte in the ciphertext area
    }

    // SAFETY: enc_result.data is still a valid allocation (content is corrupted, not the pointer).
    let dec_result = unsafe {
        secure_core_decrypt_bytes(
            enc_result.data.ptr,
            enc_result.data.len,
            dek.as_ptr(),
            dek.len(),
        )
    };

    assert_eq!(dec_result.status, FFI_ERROR_CRYPTO);
    assert!(!dec_result.error_msg.is_null());

    // SAFETY: Both results were returned by secure_core_* functions.
    unsafe {
        secure_core_free_result(enc_result);
        secure_core_free_result(dec_result);
    }
}

#[test]
fn test_ffi_free_result_null_safe() {
    let empty_result = FfiResult {
        status: FFI_OK,
        data: FfiBuffer {
            ptr: std::ptr::null_mut(),
            len: 0,
        },
        error_msg: std::ptr::null_mut(),
    };

    // SAFETY: Freeing a result with null pointers and zero length must not crash.
    unsafe { secure_core_free_result(empty_result) };
}

#[test]
fn test_ffi_version_returns_string() {
    let version_ptr = secure_core_version();
    assert!(!version_ptr.is_null());

    // SAFETY: secure_core_version returns a static null-terminated string.
    let version = unsafe { CStr::from_ptr(version_ptr) }.to_str().unwrap();
    assert!(version.starts_with("0.1"), "unexpected version: {version}");
}

#[test]
fn test_ffi_encrypt_empty_plaintext() {
    let dek = make_test_dek();

    let enc_result =
        // SAFETY: null plaintext_ptr with len 0 is valid (empty input).
        unsafe { secure_core_encrypt_bytes(std::ptr::null(), 0, dek.as_ptr(), dek.len()) };
    assert_eq!(enc_result.status, FFI_OK);
    assert!(enc_result.data.len > 0); // header + tag

    // SAFETY: enc_result.data was returned by secure_core_encrypt_bytes.
    let dec_result = unsafe {
        secure_core_decrypt_bytes(
            enc_result.data.ptr,
            enc_result.data.len,
            dek.as_ptr(),
            dek.len(),
        )
    };
    assert_eq!(dec_result.status, FFI_OK);
    assert_eq!(dec_result.data.len, 0); // empty plaintext

    // SAFETY: Both results were returned by secure_core_* functions.
    unsafe {
        secure_core_free_result(enc_result);
        secure_core_free_result(dec_result);
    }
}

#[test]
fn test_ffi_wrap_unwrap_dek_roundtrip() {
    let dek = make_test_dek();
    let passphrase = CString::new("test-passphrase-12345").unwrap();

    // SAFETY: dek and passphrase are valid stack-allocated data.
    let wrap_result = unsafe {
        secure_core_wrap_dek_with_passphrase(dek.as_ptr(), dek.len(), passphrase.as_ptr())
    };
    assert_eq!(wrap_result.status, FFI_OK);
    assert!(!wrap_result.data.ptr.is_null());
    assert!(wrap_result.data.len > 0);

    // Verify the output is valid JSON
    let json = unsafe { std::slice::from_raw_parts(wrap_result.data.ptr, wrap_result.data.len) };
    let json_str = std::str::from_utf8(json).expect("wrap output should be valid UTF-8");
    assert!(json_str.contains("AES-256-GCM-ARGON2ID"));

    // Unwrap the DEK
    // SAFETY: wrap_result.data contains valid JSON bytes, passphrase is valid.
    let unwrap_result = unsafe {
        secure_core_unwrap_dek_with_passphrase(
            wrap_result.data.ptr,
            wrap_result.data.len,
            passphrase.as_ptr(),
        )
    };
    assert_eq!(unwrap_result.status, FFI_OK);
    assert_eq!(unwrap_result.data.len, 32);

    let unwrapped =
        unsafe { std::slice::from_raw_parts(unwrap_result.data.ptr, unwrap_result.data.len) };
    assert_eq!(unwrapped, &dek);

    unsafe {
        secure_core_free_result(wrap_result);
        secure_core_free_result(unwrap_result);
    }
}

#[test]
fn test_ffi_unwrap_dek_wrong_passphrase() {
    let dek = make_test_dek();
    let passphrase = CString::new("correct-passphrase").unwrap();
    let wrong_passphrase = CString::new("wrong-passphrase").unwrap();

    let wrap_result = unsafe {
        secure_core_wrap_dek_with_passphrase(dek.as_ptr(), dek.len(), passphrase.as_ptr())
    };
    assert_eq!(wrap_result.status, FFI_OK);

    let unwrap_result = unsafe {
        secure_core_unwrap_dek_with_passphrase(
            wrap_result.data.ptr,
            wrap_result.data.len,
            wrong_passphrase.as_ptr(),
        )
    };
    assert_eq!(unwrap_result.status, FFI_ERROR_CRYPTO);
    assert!(!unwrap_result.error_msg.is_null());

    unsafe {
        secure_core_free_result(wrap_result);
        secure_core_free_result(unwrap_result);
    }
}

#[test]
fn test_ffi_wrap_dek_invalid_params() {
    let passphrase = CString::new("test").unwrap();

    // Null DEK
    let result =
        unsafe { secure_core_wrap_dek_with_passphrase(std::ptr::null(), 32, passphrase.as_ptr()) };
    assert_eq!(result.status, FFI_ERROR_INVALID_PARAM);
    unsafe { secure_core_free_result(result) };

    // Wrong DEK size
    let short_dek = [0u8; 16];
    let result = unsafe {
        secure_core_wrap_dek_with_passphrase(
            short_dek.as_ptr(),
            short_dek.len(),
            passphrase.as_ptr(),
        )
    };
    assert_eq!(result.status, FFI_ERROR_INVALID_PARAM);
    unsafe { secure_core_free_result(result) };

    // Null passphrase
    let dek = make_test_dek();
    let result =
        unsafe { secure_core_wrap_dek_with_passphrase(dek.as_ptr(), dek.len(), std::ptr::null()) };
    assert_eq!(result.status, FFI_ERROR_INVALID_PARAM);
    unsafe { secure_core_free_result(result) };
}
