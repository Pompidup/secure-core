//! JNI bridge for Android integration.
//!
//! Maps Kotlin `SecureCoreLib` native methods to the Rust crypto API.
//! Enabled via the `jni` feature flag.

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::Path;

use jni::objects::{JByteArray, JClass, JObject, JString, JValue};
use jni::JNIEnv;

use zeroize::Zeroizing;

use crate::api;
use crate::crypto::{decrypt_bytes, encrypt_bytes, Dek};
use crate::error::SecureCoreError;
use crate::ffi::types::{
    FFI_ERROR_CRYPTO, FFI_ERROR_INTERNAL, FFI_ERROR_INVALID_FORMAT, FFI_ERROR_INVALID_PARAM,
    FFI_ERROR_IO, FFI_ERROR_UNSUPPORTED_RECOVERY_SCHEMA, FFI_ERROR_UNSUPPORTED_VERSION, FFI_OK,
};
use crate::recovery;

/// Runs a JNI entry-point body and turns a panic into a `NativeResult` with
/// status `FFI_ERROR_INTERNAL`, instead of letting it unwind into the JVM
/// (which aborts the Android process). Relies on `panic = "unwind"`.
fn jni_guard<'a>(env: JNIEnv<'a>, body: impl FnOnce(JNIEnv<'a>) -> JObject<'a>) -> JObject<'a> {
    // Both handles wrap the same per-thread JNIEnv pointer and are used on this
    // thread only; `fallback` is touched only after `body` (which owns `env`)
    // has returned or unwound, so they are never used concurrently.
    // SAFETY: same thread, never used concurrently (see above).
    let mut fallback = unsafe { env.unsafe_clone() };
    match catch_unwind(AssertUnwindSafe(move || body(env))) {
        Ok(result) => result,
        Err(_) => make_native_result(
            &mut fallback,
            FFI_ERROR_INTERNAL,
            None,
            Some("internal error: panic caught at the JNI boundary"),
        ),
    }
}

fn error_to_status(err: &SecureCoreError) -> i32 {
    match err {
        SecureCoreError::InvalidFormat(_) => FFI_ERROR_INVALID_FORMAT,
        SecureCoreError::UnsupportedVersion { .. } => FFI_ERROR_UNSUPPORTED_VERSION,
        SecureCoreError::UnsupportedRecoverySchema { .. } => FFI_ERROR_UNSUPPORTED_RECOVERY_SCHEMA,
        SecureCoreError::CryptoError(_) => FFI_ERROR_CRYPTO,
        SecureCoreError::IoError(_) => FFI_ERROR_IO,
        SecureCoreError::InvalidParameter(_) => FFI_ERROR_INVALID_PARAM,
    }
}

/// Creates a `NativeResult` JVM object.
///
/// `NativeResult(status: Int, data: ByteArray?, errorMessage: String?)`
///
/// Any JNI call in this function may fail — typically `OutOfMemoryError` on
/// allocation or `NoClassDefFoundError` if the library was packaged without
/// the companion Kotlin class. When that happens, the JVM has an exception
/// already pending; we MUST return without issuing further JNI calls so the
/// exception surfaces cleanly to Kotlin on method return. Previous code
/// used `.expect()` which unwound Rust across the FFI boundary and aborted
/// the JVM process — unacceptable on mobile.
fn make_native_result<'a>(
    env: &mut JNIEnv<'a>,
    status: i32,
    data: Option<&[u8]>,
    error_message: Option<&str>,
) -> JObject<'a> {
    // JNI forbids most calls while an exception is pending (CheckJNI aborts):
    // e.g. after a failed `convert_byte_array`. Let it surface to Kotlin.
    if env.exception_check().unwrap_or(true) {
        return JObject::null();
    }
    let class = match env.find_class("com/securecore/SecureCoreLib$NativeResult") {
        Ok(c) => c,
        Err(_) => return JObject::null(),
    };

    let data_obj: JObject = match data {
        Some(bytes) => {
            let arr = match env.new_byte_array(bytes.len() as i32) {
                Ok(a) => a,
                Err(_) => return JObject::null(),
            };
            if env
                .set_byte_array_region(&arr, 0, bytemuck_slice(bytes))
                .is_err()
            {
                return JObject::null();
            }
            arr.into()
        }
        None => JObject::null(),
    };

    let msg_obj: JObject = match error_message {
        Some(msg) => match env.new_string(msg) {
            Ok(s) => s.into(),
            Err(_) => return JObject::null(),
        },
        None => JObject::null(),
    };

    env.new_object(
        class,
        "(I[BLjava/lang/String;)V",
        &[
            JValue::Int(status),
            JValue::Object(&data_obj),
            JValue::Object(&msg_obj),
        ],
    )
    .unwrap_or_else(|_| JObject::null())
}

/// Reinterpret &[u8] as &[i8] for JNI byte array copy.
fn bytemuck_slice(bytes: &[u8]) -> &[i8] {
    // SAFETY: u8 and i8 have identical layout; JNI uses signed bytes.
    unsafe { std::slice::from_raw_parts(bytes.as_ptr() as *const i8, bytes.len()) }
}

#[no_mangle]
pub extern "system" fn Java_com_securecore_SecureCoreLib_version<'a>(
    env: JNIEnv<'a>,
    _class: JClass<'a>,
) -> JString<'a> {
    let version = env!("CARGO_PKG_VERSION");
    // On allocation failure an OutOfMemoryError is pending in the JVM and
    // will surface to Kotlin when control returns.
    env.new_string(version)
        .unwrap_or_else(|_| JString::from(JObject::null()))
}

#[no_mangle]
pub extern "system" fn Java_com_securecore_SecureCoreLib_nativeEncryptBytes<'a>(
    env: JNIEnv<'a>,
    _class: JClass<'a>,
    plaintext: JByteArray<'a>,
    dek: JByteArray<'a>,
) -> JObject<'a> {
    jni_guard(env, move |mut env| {
        // Heap copy of the DEK: wiped on drop (Dek::take only wipes `key`).
        let dek_bytes = match env.convert_byte_array(&dek) {
            Ok(b) => Zeroizing::new(b),
            Err(_) => {
                return make_native_result(
                    &mut env,
                    FFI_ERROR_INVALID_PARAM,
                    None,
                    Some("failed to read dek"),
                )
            }
        };

        if dek_bytes.len() != 32 {
            return make_native_result(
                &mut env,
                FFI_ERROR_INVALID_PARAM,
                None,
                Some(&format!(
                    "dek must be exactly 32 bytes, got {}",
                    dek_bytes.len()
                )),
            );
        }

        let plaintext_bytes = match env.convert_byte_array(&plaintext) {
            Ok(b) => Zeroizing::new(b),
            Err(_) => {
                return make_native_result(
                    &mut env,
                    FFI_ERROR_INVALID_PARAM,
                    None,
                    Some("failed to read plaintext"),
                )
            }
        };

        let mut key = [0u8; 32];
        key.copy_from_slice(&dek_bytes);
        let dek = Dek::take(&mut key);

        match encrypt_bytes(&plaintext_bytes, dek.as_bytes()) {
            Ok(blob) => make_native_result(&mut env, FFI_OK, Some(&blob), None),
            Err(e) => {
                let status = error_to_status(&e);
                make_native_result(&mut env, status, None, Some(&e.to_string()))
            }
        }
    })
}

#[no_mangle]
pub extern "system" fn Java_com_securecore_SecureCoreLib_nativeDecryptBytes<'a>(
    env: JNIEnv<'a>,
    _class: JClass<'a>,
    blob: JByteArray<'a>,
    dek: JByteArray<'a>,
) -> JObject<'a> {
    jni_guard(env, move |mut env| {
        // Heap copy of the DEK: wiped on drop (Dek::take only wipes `key`).
        let dek_bytes = match env.convert_byte_array(&dek) {
            Ok(b) => Zeroizing::new(b),
            Err(_) => {
                return make_native_result(
                    &mut env,
                    FFI_ERROR_INVALID_PARAM,
                    None,
                    Some("failed to read dek"),
                )
            }
        };

        if dek_bytes.len() != 32 {
            return make_native_result(
                &mut env,
                FFI_ERROR_INVALID_PARAM,
                None,
                Some(&format!(
                    "dek must be exactly 32 bytes, got {}",
                    dek_bytes.len()
                )),
            );
        }

        let blob_bytes = match env.convert_byte_array(&blob) {
            Ok(b) => b,
            Err(_) => {
                return make_native_result(
                    &mut env,
                    FFI_ERROR_INVALID_PARAM,
                    None,
                    Some("failed to read blob"),
                )
            }
        };

        let mut key = [0u8; 32];
        key.copy_from_slice(&dek_bytes);
        let dek = Dek::take(&mut key);

        match decrypt_bytes(&blob_bytes, dek.as_bytes()) {
            Ok(plaintext) => {
                let plaintext = Zeroizing::new(plaintext);
                make_native_result(&mut env, FFI_OK, Some(&plaintext), None)
            }
            Err(e) => {
                let status = error_to_status(&e);
                make_native_result(&mut env, status, None, Some(&e.to_string()))
            }
        }
    })
}

#[no_mangle]
pub extern "system" fn Java_com_securecore_SecureCoreLib_nativeWrapDekWithPassphrase<'a>(
    env: JNIEnv<'a>,
    _class: JClass<'a>,
    dek: JByteArray<'a>,
    passphrase: JString<'a>,
) -> JObject<'a> {
    jni_guard(env, move |mut env| {
        // Heap copy of the DEK: wiped on drop (Dek::take only wipes `key`).
        let dek_bytes = match env.convert_byte_array(&dek) {
            Ok(b) => Zeroizing::new(b),
            Err(_) => {
                return make_native_result(
                    &mut env,
                    FFI_ERROR_INVALID_PARAM,
                    None,
                    Some("failed to read dek"),
                )
            }
        };

        if dek_bytes.len() != 32 {
            return make_native_result(
                &mut env,
                FFI_ERROR_INVALID_PARAM,
                None,
                Some(&format!(
                    "dek must be exactly 32 bytes, got {}",
                    dek_bytes.len()
                )),
            );
        }

        // Zeroizing wipes the heap buffer on drop so the passphrase does not
        // linger in freed memory after this native call returns.
        let passphrase_str: Zeroizing<String> = match env.get_string(&passphrase) {
            Ok(s) => Zeroizing::new(s.into()),
            Err(_) => {
                return make_native_result(
                    &mut env,
                    FFI_ERROR_INVALID_PARAM,
                    None,
                    Some("failed to read passphrase"),
                )
            }
        };

        let mut key = [0u8; 32];
        key.copy_from_slice(&dek_bytes);
        let dek = Dek::take(&mut key);

        match recovery::wrap_dek_with_passphrase(dek.as_bytes(), &passphrase_str) {
            Ok(wrap) => match serde_json::to_vec(&wrap) {
                Ok(json) => make_native_result(&mut env, FFI_OK, Some(&json), None),
                Err(e) => make_native_result(
                    &mut env,
                    FFI_ERROR_CRYPTO,
                    None,
                    Some(&format!("failed to serialize RecoveryWrap: {e}")),
                ),
            },
            Err(e) => {
                let status = error_to_status(&e);
                make_native_result(&mut env, status, None, Some(&e.to_string()))
            }
        }
    })
}

#[no_mangle]
pub extern "system" fn Java_com_securecore_SecureCoreLib_nativeUnwrapDekWithPassphrase<'a>(
    env: JNIEnv<'a>,
    _class: JClass<'a>,
    recovery_wrap_json: JString<'a>,
    passphrase: JString<'a>,
) -> JObject<'a> {
    jni_guard(env, move |mut env| {
        let json_str: String = match env.get_string(&recovery_wrap_json) {
            Ok(s) => s.into(),
            Err(_) => {
                return make_native_result(
                    &mut env,
                    FFI_ERROR_INVALID_PARAM,
                    None,
                    Some("failed to read recoveryWrapJson"),
                )
            }
        };

        // Zeroizing wipes the heap buffer on drop so the passphrase does not
        // linger in freed memory after this native call returns.
        let passphrase_str: Zeroizing<String> = match env.get_string(&passphrase) {
            Ok(s) => Zeroizing::new(s.into()),
            Err(_) => {
                return make_native_result(
                    &mut env,
                    FFI_ERROR_INVALID_PARAM,
                    None,
                    Some("failed to read passphrase"),
                )
            }
        };

        let wrap: recovery::RecoveryWrap = match serde_json::from_str(&json_str) {
            Ok(w) => w,
            Err(e) => {
                return make_native_result(
                    &mut env,
                    FFI_ERROR_INVALID_PARAM,
                    None,
                    Some(&format!("invalid RecoveryWrap JSON: {e}")),
                )
            }
        };

        match recovery::unwrap_dek_with_passphrase(&wrap, &passphrase_str) {
            Ok(dek) => make_native_result(&mut env, FFI_OK, Some(dek.as_bytes()), None),
            Err(e) => {
                let status = error_to_status(&e);
                make_native_result(&mut env, status, None, Some(&e.to_string()))
            }
        }
    })
}

#[no_mangle]
pub extern "system" fn Java_com_securecore_SecureCoreLib_nativeEncryptFile<'a>(
    env: JNIEnv<'a>,
    _class: JClass<'a>,
    input_path: JString<'a>,
    output_path: JString<'a>,
    dek: JByteArray<'a>,
) -> JObject<'a> {
    jni_guard(env, move |mut env| {
        // Heap copy of the DEK: wiped on drop (Dek::take only wipes `key`).
        let dek_bytes = match env.convert_byte_array(&dek) {
            Ok(b) => Zeroizing::new(b),
            Err(_) => {
                return make_native_result(
                    &mut env,
                    FFI_ERROR_INVALID_PARAM,
                    None,
                    Some("failed to read dek"),
                )
            }
        };

        if dek_bytes.len() != 32 {
            return make_native_result(
                &mut env,
                FFI_ERROR_INVALID_PARAM,
                None,
                Some(&format!(
                    "dek must be exactly 32 bytes, got {}",
                    dek_bytes.len()
                )),
            );
        }

        let input_str: String = match env.get_string(&input_path) {
            Ok(s) => s.into(),
            Err(_) => {
                return make_native_result(
                    &mut env,
                    FFI_ERROR_INVALID_PARAM,
                    None,
                    Some("failed to read inputPath"),
                )
            }
        };

        let output_str: String = match env.get_string(&output_path) {
            Ok(s) => s.into(),
            Err(_) => {
                return make_native_result(
                    &mut env,
                    FFI_ERROR_INVALID_PARAM,
                    None,
                    Some("failed to read outputPath"),
                )
            }
        };

        let mut key = [0u8; 32];
        key.copy_from_slice(&dek_bytes);
        let dek = Dek::take(&mut key);

        match api::encrypt_file(Path::new(&input_str), Path::new(&output_str), &dek) {
            Ok(result) => match serde_json::to_vec(&result.stream_metadata) {
                Ok(json) => make_native_result(&mut env, FFI_OK, Some(&json), None),
                Err(e) => make_native_result(
                    &mut env,
                    FFI_ERROR_CRYPTO,
                    None,
                    Some(&format!("failed to serialize StreamMetadata: {e}")),
                ),
            },
            Err(e) => {
                let status = error_to_status(&e);
                make_native_result(&mut env, status, None, Some(&e.to_string()))
            }
        }
    })
}

/// Decrypts a V1.1 file. Legacy V1.0 streams are rejected (`INVALID_FORMAT`).
#[no_mangle]
pub extern "system" fn Java_com_securecore_SecureCoreLib_nativeDecryptFile<'a>(
    env: JNIEnv<'a>,
    _class: JClass<'a>,
    input_path: JString<'a>,
    output_path: JString<'a>,
    dek: JByteArray<'a>,
) -> JObject<'a> {
    jni_guard(env, move |env| {
        decrypt_file_jni(env, input_path, output_path, dek, api::decrypt_file)
    })
}

/// MIGRATION ONLY: decrypts a V1.1 or legacy V1.0 file. Truncation of legacy
/// input is not detected; re-encrypt the result with `nativeEncryptFile`.
#[no_mangle]
pub extern "system" fn Java_com_securecore_SecureCoreLib_nativeDecryptFileAllowLegacy<'a>(
    env: JNIEnv<'a>,
    _class: JClass<'a>,
    input_path: JString<'a>,
    output_path: JString<'a>,
    dek: JByteArray<'a>,
) -> JObject<'a> {
    jni_guard(env, move |env| {
        decrypt_file_jni(
            env,
            input_path,
            output_path,
            dek,
            api::decrypt_file_allow_legacy,
        )
    })
}

type DecryptFileFn =
    fn(&Path, &Path, &Dek) -> Result<crate::streaming::StreamMetadata, SecureCoreError>;

/// Shared marshalling for the two file-decrypt JNI entry points.
fn decrypt_file_jni<'a>(
    mut env: JNIEnv<'a>,
    input_path: JString<'a>,
    output_path: JString<'a>,
    dek: JByteArray<'a>,
    decrypt: DecryptFileFn,
) -> JObject<'a> {
    // Heap copy of the DEK: wiped on drop (Dek::take only wipes `key`).
    let dek_bytes = match env.convert_byte_array(&dek) {
        Ok(b) => Zeroizing::new(b),
        Err(_) => {
            return make_native_result(
                &mut env,
                FFI_ERROR_INVALID_PARAM,
                None,
                Some("failed to read dek"),
            )
        }
    };

    if dek_bytes.len() != 32 {
        return make_native_result(
            &mut env,
            FFI_ERROR_INVALID_PARAM,
            None,
            Some(&format!(
                "dek must be exactly 32 bytes, got {}",
                dek_bytes.len()
            )),
        );
    }

    let input_str: String = match env.get_string(&input_path) {
        Ok(s) => s.into(),
        Err(_) => {
            return make_native_result(
                &mut env,
                FFI_ERROR_INVALID_PARAM,
                None,
                Some("failed to read inputPath"),
            )
        }
    };

    let output_str: String = match env.get_string(&output_path) {
        Ok(s) => s.into(),
        Err(_) => {
            return make_native_result(
                &mut env,
                FFI_ERROR_INVALID_PARAM,
                None,
                Some("failed to read outputPath"),
            )
        }
    };

    let mut key = [0u8; 32];
    key.copy_from_slice(&dek_bytes);
    let dek = Dek::take(&mut key);

    match decrypt(Path::new(&input_str), Path::new(&output_str), &dek) {
        Ok(meta) => match serde_json::to_vec(&meta) {
            Ok(json) => make_native_result(&mut env, FFI_OK, Some(&json), None),
            Err(e) => make_native_result(
                &mut env,
                FFI_ERROR_CRYPTO,
                None,
                Some(&format!("failed to serialize StreamMetadata: {e}")),
            ),
        },
        Err(e) => {
            let status = error_to_status(&e);
            make_native_result(&mut env, status, None, Some(&e.to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The JNI status mapping must match the C FFI exactly, so Android/iOS read
    /// the same numeric code. In particular, a recovery-schema mismatch maps to
    /// the dedicated code, not the generic invalid-parameter one. `error_to_status`
    /// needs no JVM, so this runs under `--features jni` without a live `JNIEnv`.
    #[test]
    fn test_error_to_status_matches_ffi_codes() {
        assert_eq!(
            error_to_status(&SecureCoreError::UnsupportedRecoverySchema {
                found: "2.0".into()
            }),
            FFI_ERROR_UNSUPPORTED_RECOVERY_SCHEMA
        );
        assert_eq!(
            error_to_status(&SecureCoreError::InvalidParameter("x".into())),
            FFI_ERROR_INVALID_PARAM
        );
        assert_eq!(
            error_to_status(&SecureCoreError::CryptoError("x".into())),
            FFI_ERROR_CRYPTO
        );
        assert_ne!(
            FFI_ERROR_UNSUPPORTED_RECOVERY_SCHEMA,
            FFI_ERROR_INVALID_PARAM
        );
    }

    /// A malformed recovery JSON must surface as INVALID_FORMAT (1) through
    /// JNI, exactly like the C FFI, not INVALID_PARAM (5).
    #[test]
    fn test_malformed_recovery_json_maps_to_invalid_format_like_the_c_ffi() {
        let err = recovery::RecoveryWrap::from_json("{").unwrap_err();
        assert_eq!(error_to_status(&err), FFI_ERROR_INVALID_FORMAT);
    }

    /// Both boundaries must parse through `RecoveryWrap::from_json`, so they
    /// cannot drift apart again. Built with concat! so this test's own source
    /// does not match.
    #[test]
    fn test_boundaries_parse_recovery_json_through_the_shared_parser() {
        let direct = concat!("serde_json::", "from_str");
        for (name, src) in [
            ("jni_bridge.rs", include_str!("jni_bridge.rs")),
            ("ffi/functions.rs", include_str!("ffi/functions.rs")),
        ] {
            assert!(!src.contains(direct), "{name} parses JSON directly");
            assert!(src.contains("RecoveryWrap::from_json"), "{name}");
        }
    }
}
