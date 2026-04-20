//! JNI bridge for Android integration.
//!
//! Maps Kotlin `SecureCoreLib` native methods to the Rust crypto API.
//! Enabled via the `jni` feature flag.

use std::path::Path;

use jni::objects::{JByteArray, JClass, JObject, JString, JValue};
use jni::JNIEnv;

use zeroize::Zeroizing;

use crate::api;
use crate::crypto::{decrypt_bytes, encrypt_bytes, Dek};
use crate::error::SecureCoreError;
use crate::ffi::types::{
    FFI_ERROR_CRYPTO, FFI_ERROR_INVALID_FORMAT, FFI_ERROR_INVALID_PARAM, FFI_ERROR_IO,
    FFI_ERROR_UNSUPPORTED_VERSION, FFI_OK,
};
use crate::recovery;

fn error_to_status(err: &SecureCoreError) -> i32 {
    match err {
        SecureCoreError::InvalidFormat(_) => FFI_ERROR_INVALID_FORMAT,
        SecureCoreError::UnsupportedVersion { .. } => FFI_ERROR_UNSUPPORTED_VERSION,
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
    mut env: JNIEnv<'a>,
    _class: JClass<'a>,
    plaintext: JByteArray<'a>,
    dek: JByteArray<'a>,
) -> JObject<'a> {
    let dek_bytes = match env.convert_byte_array(&dek) {
        Ok(b) => b,
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
        Ok(b) => b,
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
}

#[no_mangle]
pub extern "system" fn Java_com_securecore_SecureCoreLib_nativeDecryptBytes<'a>(
    mut env: JNIEnv<'a>,
    _class: JClass<'a>,
    blob: JByteArray<'a>,
    dek: JByteArray<'a>,
) -> JObject<'a> {
    let dek_bytes = match env.convert_byte_array(&dek) {
        Ok(b) => b,
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
        Ok(plaintext) => make_native_result(&mut env, FFI_OK, Some(&plaintext), None),
        Err(e) => {
            let status = error_to_status(&e);
            make_native_result(&mut env, status, None, Some(&e.to_string()))
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_com_securecore_SecureCoreLib_nativeWrapDekWithPassphrase<'a>(
    mut env: JNIEnv<'a>,
    _class: JClass<'a>,
    dek: JByteArray<'a>,
    passphrase: JString<'a>,
) -> JObject<'a> {
    let dek_bytes = match env.convert_byte_array(&dek) {
        Ok(b) => b,
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
}

#[no_mangle]
pub extern "system" fn Java_com_securecore_SecureCoreLib_nativeUnwrapDekWithPassphrase<'a>(
    mut env: JNIEnv<'a>,
    _class: JClass<'a>,
    recovery_wrap_json: JString<'a>,
    passphrase: JString<'a>,
) -> JObject<'a> {
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
        Ok(dek) => make_native_result(&mut env, FFI_OK, Some(&dek), None),
        Err(e) => {
            let status = error_to_status(&e);
            make_native_result(&mut env, status, None, Some(&e.to_string()))
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_com_securecore_SecureCoreLib_nativeEncryptFile<'a>(
    mut env: JNIEnv<'a>,
    _class: JClass<'a>,
    input_path: JString<'a>,
    output_path: JString<'a>,
    dek: JByteArray<'a>,
) -> JObject<'a> {
    let dek_bytes = match env.convert_byte_array(&dek) {
        Ok(b) => b,
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
}

#[no_mangle]
pub extern "system" fn Java_com_securecore_SecureCoreLib_nativeDecryptFile<'a>(
    mut env: JNIEnv<'a>,
    _class: JClass<'a>,
    input_path: JString<'a>,
    output_path: JString<'a>,
    dek: JByteArray<'a>,
) -> JObject<'a> {
    let dek_bytes = match env.convert_byte_array(&dek) {
        Ok(b) => b,
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

    match api::decrypt_file(Path::new(&input_str), Path::new(&output_str), &dek) {
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
