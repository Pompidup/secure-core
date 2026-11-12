use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::path::Path;

use crate::crypto::{decrypt_bytes, encrypt_bytes, Dek};
use crate::ffi::types::{FfiBuffer, FfiResult};
use crate::recovery;

/// Returns the crate version as a null-terminated C string.
///
/// The returned pointer is static and **must not** be freed by the caller.
#[no_mangle]
pub extern "C" fn secure_core_version() -> *const c_char {
    // SAFETY: This is a static byte string with a null terminator.
    // It lives for the entire program lifetime.
    static VERSION: &[u8] = concat!(env!("CARGO_PKG_VERSION"), "\0").as_bytes();
    VERSION.as_ptr() as *const c_char
}

/// Encrypts plaintext bytes and returns the `.enc` V1 blob.
///
/// # Safety
///
/// - `plaintext_ptr` must point to `plaintext_len` readable bytes (or be null if `plaintext_len == 0`).
/// - `dek_ptr` must point to exactly `dek_len` readable bytes.
/// - `dek_len` must be 32.
/// - The caller must free the returned `FfiResult` via `secure_core_free_result`.
#[no_mangle]
pub unsafe extern "C" fn secure_core_encrypt_bytes(
    plaintext_ptr: *const u8,
    plaintext_len: usize,
    dek_ptr: *const u8,
    dek_len: usize,
) -> FfiResult {
    let Some(dek) = validate_dek(dek_ptr, dek_len) else {
        return FfiResult::invalid_param("dek must be non-null and exactly 32 bytes");
    };

    // SAFETY: Caller guarantees plaintext_ptr is valid for plaintext_len bytes.
    let plaintext = if plaintext_len == 0 {
        &[]
    } else if plaintext_ptr.is_null() {
        return FfiResult::invalid_param("plaintext_ptr must not be null when plaintext_len > 0");
    } else {
        std::slice::from_raw_parts(plaintext_ptr, plaintext_len)
    };

    match encrypt_bytes(plaintext, dek.as_bytes()) {
        Ok(blob) => FfiResult::ok(blob),
        Err(e) => FfiResult::from_error(e),
    }
}

/// Decrypts a `.enc` V1 blob and returns the plaintext.
///
/// # Safety
///
/// - `blob_ptr` must point to `blob_len` readable bytes.
/// - `dek_ptr` must point to exactly `dek_len` readable bytes.
/// - `dek_len` must be 32.
/// - The caller must free the returned `FfiResult` via `secure_core_free_result`.
#[no_mangle]
pub unsafe extern "C" fn secure_core_decrypt_bytes(
    blob_ptr: *const u8,
    blob_len: usize,
    dek_ptr: *const u8,
    dek_len: usize,
) -> FfiResult {
    let Some(dek) = validate_dek(dek_ptr, dek_len) else {
        return FfiResult::invalid_param("dek must be non-null and exactly 32 bytes");
    };

    if blob_ptr.is_null() || blob_len == 0 {
        return FfiResult::invalid_param("blob must be non-null and non-empty");
    }

    // SAFETY: Caller guarantees blob_ptr is valid for blob_len bytes.
    let blob = std::slice::from_raw_parts(blob_ptr, blob_len);

    match decrypt_bytes(blob, dek.as_bytes()) {
        Ok(plaintext) => FfiResult::ok(plaintext),
        Err(e) => FfiResult::from_error(e),
    }
}

/// Encrypts a file using chunked streaming.
///
/// # Safety
///
/// - `input_path_ptr` and `output_path_ptr` must be valid null-terminated UTF-8 C strings.
/// - `dek_ptr` must point to exactly `dek_len` readable bytes.
/// - `dek_len` must be 32.
/// - The caller must free the returned `FfiResult` via `secure_core_free_result`.
#[no_mangle]
pub unsafe extern "C" fn secure_core_encrypt_file(
    input_path_ptr: *const c_char,
    output_path_ptr: *const c_char,
    dek_ptr: *const u8,
    dek_len: usize,
) -> FfiResult {
    let Some(dek) = validate_dek(dek_ptr, dek_len) else {
        return FfiResult::invalid_param("dek must be non-null and exactly 32 bytes");
    };

    let (Some(input_path), Some(output_path)) = (
        path_from_c_str(input_path_ptr),
        path_from_c_str(output_path_ptr),
    ) else {
        return FfiResult::invalid_param(
            "input_path and output_path must be valid UTF-8 C strings",
        );
    };

    match crate::api::encrypt_file(Path::new(input_path), Path::new(output_path), &dek) {
        Ok(result) => {
            // Return stream metadata as JSON
            let json = format!(
                "{{\"chunks\":{},\"total_plaintext_bytes\":{},\"total_ciphertext_bytes\":{}}}",
                result.stream_metadata.chunks,
                result.stream_metadata.total_plaintext_bytes,
                result.stream_metadata.total_ciphertext_bytes
            );
            FfiResult::ok(json.into_bytes())
        }
        Err(e) => FfiResult::from_error(e),
    }
}

/// Decrypts a V1.1 file using chunked streaming.
///
/// Legacy V1.0 streams (no final-chunk flag) are rejected with
/// `FFI_ERROR_INVALID_FORMAT`; see `secure_core_decrypt_file_allow_legacy`.
///
/// # Safety
///
/// - `input_path_ptr` and `output_path_ptr` must be valid null-terminated UTF-8 C strings.
/// - `dek_ptr` must point to exactly `dek_len` readable bytes.
/// - `dek_len` must be 32.
/// - The caller must free the returned `FfiResult` via `secure_core_free_result`.
#[no_mangle]
pub unsafe extern "C" fn secure_core_decrypt_file(
    input_path_ptr: *const c_char,
    output_path_ptr: *const c_char,
    dek_ptr: *const u8,
    dek_len: usize,
) -> FfiResult {
    decrypt_file_with(
        input_path_ptr,
        output_path_ptr,
        dek_ptr,
        dek_len,
        crate::api::decrypt_file,
    )
}

/// Decrypts a V1.1 **or legacy V1.0** file. Migration only.
///
/// Truncation of legacy input is NOT detected. Use it once to decrypt files
/// written before secure-core 0.3.0, then re-encrypt them with
/// `secure_core_encrypt_file`.
///
/// # Safety
///
/// Same requirements as [`secure_core_decrypt_file`].
#[no_mangle]
pub unsafe extern "C" fn secure_core_decrypt_file_allow_legacy(
    input_path_ptr: *const c_char,
    output_path_ptr: *const c_char,
    dek_ptr: *const u8,
    dek_len: usize,
) -> FfiResult {
    decrypt_file_with(
        input_path_ptr,
        output_path_ptr,
        dek_ptr,
        dek_len,
        crate::api::decrypt_file_allow_legacy,
    )
}

type DecryptFileFn = fn(
    &Path,
    &Path,
    &Dek,
) -> Result<crate::streaming::StreamMetadata, crate::error::SecureCoreError>;

/// Shared marshalling for the two file-decrypt entry points: validate the
/// inputs, delegate to `decrypt`, encode the metadata as JSON.
unsafe fn decrypt_file_with(
    input_path_ptr: *const c_char,
    output_path_ptr: *const c_char,
    dek_ptr: *const u8,
    dek_len: usize,
    decrypt: DecryptFileFn,
) -> FfiResult {
    let Some(dek) = validate_dek(dek_ptr, dek_len) else {
        return FfiResult::invalid_param("dek must be non-null and exactly 32 bytes");
    };

    let (Some(input_path), Some(output_path)) = (
        path_from_c_str(input_path_ptr),
        path_from_c_str(output_path_ptr),
    ) else {
        return FfiResult::invalid_param(
            "input_path and output_path must be valid UTF-8 C strings",
        );
    };

    match decrypt(Path::new(input_path), Path::new(output_path), &dek) {
        Ok(meta) => {
            let json = format!(
                "{{\"chunks\":{},\"total_plaintext_bytes\":{},\"total_ciphertext_bytes\":{}}}",
                meta.chunks, meta.total_plaintext_bytes, meta.total_ciphertext_bytes
            );
            FfiResult::ok(json.into_bytes())
        }
        Err(e) => FfiResult::from_error(e),
    }
}

/// Frees a buffer previously allocated by Rust.
///
/// The bytes are wiped before the memory is released, since a buffer may
/// hold decrypted plaintext or an unwrapped DEK.
///
/// After this call the buffer's `ptr` is invalid and must not be used.
///
/// # Safety
///
/// - `buf` must have been returned by a `secure_core_*` function.
/// - Must not be called twice on the same buffer.
#[no_mangle]
pub unsafe extern "C" fn secure_core_free_buffer(buf: FfiBuffer) {
    if !buf.ptr.is_null() && buf.len > 0 {
        // SAFETY: a non-empty buffer comes from FfiBuffer::from_vec, i.e. from
        // Box::<[u8]>::into_raw of exactly `buf.len` bytes. Rebuilding that
        // same boxed slice frees it with the layout it was allocated with.
        let mut boxed = Box::from_raw(std::ptr::slice_from_raw_parts_mut(buf.ptr, buf.len));
        zeroize::Zeroize::zeroize(&mut *boxed);
        drop(boxed);
    }
}

/// Frees an `FfiResult` and all memory it owns (data buffer + error message).
///
/// # Safety
///
/// - `result` must have been returned by a `secure_core_*` function.
/// - Must not be called twice on the same result.
#[no_mangle]
pub unsafe extern "C" fn secure_core_free_result(result: FfiResult) {
    // SAFETY: FfiBuffer was allocated by FfiBuffer::from_vec.
    secure_core_free_buffer(result.data);

    if !result.error_msg.is_null() {
        // SAFETY: error_msg was allocated by CString::into_raw in FfiResult::from_error.
        drop(CString::from_raw(result.error_msg));
    }
}

/// Wraps a DEK with a passphrase using Argon2id + AES-256-GCM.
///
/// Returns a JSON-encoded `RecoveryWrap` as bytes on success.
///
/// # Safety
///
/// - `dek_ptr` must point to exactly `dek_len` readable bytes.
/// - `dek_len` must be 32.
/// - `passphrase_ptr` must be a valid null-terminated UTF-8 C string.
/// - The caller must free the returned `FfiResult` via `secure_core_free_result`.
#[no_mangle]
pub unsafe extern "C" fn secure_core_wrap_dek_with_passphrase(
    dek_ptr: *const u8,
    dek_len: usize,
    passphrase_ptr: *const c_char,
) -> FfiResult {
    let Some(dek) = validate_dek(dek_ptr, dek_len) else {
        return FfiResult::invalid_param("dek must be non-null and exactly 32 bytes");
    };

    let Some(passphrase) = path_from_c_str(passphrase_ptr) else {
        return FfiResult::invalid_param("passphrase must be a valid UTF-8 C string");
    };

    match recovery::wrap_dek_with_passphrase(dek.as_bytes(), passphrase) {
        Ok(wrap) => match serde_json::to_vec(&wrap) {
            Ok(json) => FfiResult::ok(json),
            Err(e) => FfiResult::from_error(crate::error::SecureCoreError::CryptoError(format!(
                "failed to serialize RecoveryWrap: {e}"
            ))),
        },
        Err(e) => FfiResult::from_error(e),
    }
}

/// Unwraps a DEK from a JSON-encoded RecoveryWrap using the passphrase.
///
/// Returns the 32-byte DEK on success.
///
/// # Safety
///
/// - `recovery_json_ptr` must point to `recovery_json_len` readable bytes of valid UTF-8 JSON.
/// - `passphrase_ptr` must be a valid null-terminated UTF-8 C string.
/// - The caller must free the returned `FfiResult` via `secure_core_free_result`.
#[no_mangle]
pub unsafe extern "C" fn secure_core_unwrap_dek_with_passphrase(
    recovery_json_ptr: *const u8,
    recovery_json_len: usize,
    passphrase_ptr: *const c_char,
) -> FfiResult {
    if recovery_json_ptr.is_null() || recovery_json_len == 0 {
        return FfiResult::invalid_param("recovery_json must be non-null and non-empty");
    }

    let Some(passphrase) = path_from_c_str(passphrase_ptr) else {
        return FfiResult::invalid_param("passphrase must be a valid UTF-8 C string");
    };

    let json_bytes = std::slice::from_raw_parts(recovery_json_ptr, recovery_json_len);
    let json_str = match std::str::from_utf8(json_bytes) {
        Ok(s) => s,
        Err(_) => return FfiResult::invalid_param("recovery_json must be valid UTF-8"),
    };

    let wrap: recovery::RecoveryWrap = match serde_json::from_str(json_str) {
        Ok(w) => w,
        Err(e) => {
            return FfiResult::from_error(crate::error::SecureCoreError::InvalidFormat(format!(
                "invalid RecoveryWrap JSON: {e}"
            )))
        }
    };

    match recovery::unwrap_dek_with_passphrase(&wrap, passphrase) {
        Ok(dek) => FfiResult::ok(dek.as_bytes().to_vec()),
        Err(e) => FfiResult::from_error(e),
    }
}

// ── Internal helpers ────────────────────────────────────────────────────

/// Validates that the DEK pointer is non-null and exactly 32 bytes.
/// Returns a `Dek` if valid.
unsafe fn validate_dek(dek_ptr: *const u8, dek_len: usize) -> Option<Dek> {
    if dek_ptr.is_null() || dek_len != 32 {
        return None;
    }
    // SAFETY: Caller guarantees dek_ptr points to 32 readable bytes.
    let dek_slice = std::slice::from_raw_parts(dek_ptr, 32);
    let mut key = [0u8; 32];
    key.copy_from_slice(dek_slice);
    // `Dek::take` wipes our stack buffer after copying, so the temporary
    // key material does not linger on this frame.
    Some(Dek::take(&mut key))
}

/// Converts a C string pointer to a `&str`, returning `None` if null or invalid UTF-8.
unsafe fn path_from_c_str<'a>(ptr: *const c_char) -> Option<&'a str> {
    if ptr.is_null() {
        return None;
    }
    // SAFETY: Caller guarantees ptr is a valid null-terminated C string.
    CStr::from_ptr(ptr).to_str().ok()
}
