use std::ffi::CStr;
use std::process;
use std::slice;

use rand::RngCore;

use secure_core::ffi::functions::*;
use secure_core::ffi::types::*;

// ── Helpers ─────────────────────────────────────────────────────────────

fn random_bytes(len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    rand::thread_rng().fill_bytes(&mut buf);
    buf
}

fn make_dek() -> [u8; 32] {
    let mut dek = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut dek);
    dek
}

fn check(condition: bool, msg: &str) {
    if !condition {
        eprintln!("FAIL: {msg}");
        process::exit(1);
    }
}

/// Extracts the error message string from an FfiResult (if present).
fn error_msg(result: &FfiResult) -> Option<String> {
    if result.error_msg.is_null() {
        return None;
    }
    // SAFETY: error_msg was set by secure_core FFI and is a valid C string.
    let cstr = unsafe { CStr::from_ptr(result.error_msg) };
    Some(cstr.to_string_lossy().into_owned())
}

// ── Roundtrip tests ─────────────────────────────────────────────────────

fn test_roundtrip(label: &str, size: usize) {
    let plaintext = random_bytes(size);
    let dek = make_dek();

    // SAFETY: plaintext and dek are valid slices with correct lengths.
    let enc_result = unsafe {
        secure_core_encrypt_bytes(plaintext.as_ptr(), plaintext.len(), dek.as_ptr(), dek.len())
    };
    check(
        enc_result.status == FFI_OK,
        &format!("{label}: encrypt failed (status={})", enc_result.status),
    );
    check(
        enc_result.data.len > 0,
        &format!("{label}: encrypted data is empty"),
    );

    // SAFETY: enc_result.data was returned by secure_core_encrypt_bytes.
    let blob = unsafe { slice::from_raw_parts(enc_result.data.ptr, enc_result.data.len) };

    let dec_result =
        // SAFETY: blob and dek are valid slices with correct lengths.
        unsafe { secure_core_decrypt_bytes(blob.as_ptr(), blob.len(), dek.as_ptr(), dek.len()) };
    check(
        dec_result.status == FFI_OK,
        &format!("{label}: decrypt failed (status={})", dec_result.status),
    );

    // SAFETY: dec_result.data was returned by secure_core_decrypt_bytes.
    let decrypted = unsafe { slice::from_raw_parts(dec_result.data.ptr, dec_result.data.len) };
    check(
        decrypted == plaintext.as_slice(),
        &format!("{label}: roundtrip mismatch"),
    );

    // SAFETY: results were returned by secure_core FFI functions.
    unsafe {
        secure_core_free_result(dec_result);
        secure_core_free_result(enc_result);
    }

    println!("  PASS: {label} ({size} bytes)");
}

fn run_roundtrip_tests() {
    println!("[ROUNDTRIP TESTS]");
    test_roundtrip("1KB", 1024);
    test_roundtrip("64KB", 64 * 1024);
    test_roundtrip("5MB", 5 * 1024 * 1024);
    println!();
}

// ── Error case tests ────────────────────────────────────────────────────

fn test_null_buffer() {
    let dek = make_dek();

    // plaintext_ptr is null with len > 0 → should fail
    let result =
        // SAFETY: intentionally passing null to test error handling.
        unsafe { secure_core_encrypt_bytes(std::ptr::null(), 10, dek.as_ptr(), dek.len()) };
    check(
        result.status == FFI_ERROR_INVALID_PARAM,
        "null buffer: wrong status",
    );
    check(
        error_msg(&result).is_some(),
        "null buffer: no error message",
    );

    // SAFETY: result was returned by secure_core FFI.
    unsafe { secure_core_free_result(result) };
    println!("  PASS: null buffer → FFI_ERROR_INVALID_PARAM");
}

fn test_invalid_dek_length() {
    let short_dek = [0u8; 16];
    let plaintext = b"test";

    // SAFETY: plaintext is valid; short_dek is intentionally wrong length.
    let result = unsafe {
        secure_core_encrypt_bytes(
            plaintext.as_ptr(),
            plaintext.len(),
            short_dek.as_ptr(),
            short_dek.len(),
        )
    };
    check(
        result.status == FFI_ERROR_INVALID_PARAM,
        "invalid dek: wrong status",
    );
    check(
        error_msg(&result).is_some(),
        "invalid dek: no error message",
    );

    // SAFETY: result was returned by secure_core FFI.
    unsafe { secure_core_free_result(result) };
    println!("  PASS: invalid DEK length → FFI_ERROR_INVALID_PARAM");
}

fn test_truncated_ciphertext() {
    let dek = make_dek();
    let plaintext = b"truncate me";

    // SAFETY: plaintext and dek are valid.
    let enc_result = unsafe {
        secure_core_encrypt_bytes(plaintext.as_ptr(), plaintext.len(), dek.as_ptr(), dek.len())
    };
    check(enc_result.status == FFI_OK, "truncated: encrypt failed");

    // SAFETY: enc_result.data was returned by secure_core_encrypt_bytes.
    let blob = unsafe { slice::from_raw_parts(enc_result.data.ptr, enc_result.data.len) };

    // Truncate to just the header (25 bytes) — missing tag
    let truncated = &blob[..25.min(blob.len())];

    // SAFETY: truncated is a valid slice derived from blob.
    let dec_result = unsafe {
        secure_core_decrypt_bytes(truncated.as_ptr(), truncated.len(), dek.as_ptr(), dek.len())
    };
    check(
        dec_result.status == FFI_ERROR_INVALID_FORMAT,
        &format!(
            "truncated: expected INVALID_FORMAT, got {}",
            dec_result.status
        ),
    );
    check(
        error_msg(&dec_result).is_some(),
        "truncated: no error message",
    );

    // SAFETY: results were returned by secure_core FFI.
    unsafe {
        secure_core_free_result(dec_result);
        secure_core_free_result(enc_result);
    }
    println!("  PASS: truncated ciphertext → FFI_ERROR_INVALID_FORMAT");
}

fn test_tampered_ciphertext() {
    let dek = make_dek();
    let plaintext = b"tamper me";

    // SAFETY: plaintext and dek are valid.
    let enc_result = unsafe {
        secure_core_encrypt_bytes(plaintext.as_ptr(), plaintext.len(), dek.as_ptr(), dek.len())
    };
    check(enc_result.status == FFI_OK, "tampered: encrypt failed");

    // Copy and flip a bit in the ciphertext area (after header)
    let mut tampered =
        // SAFETY: enc_result.data was returned by secure_core_encrypt_bytes.
        unsafe { slice::from_raw_parts(enc_result.data.ptr, enc_result.data.len).to_vec() };
    if tampered.len() > 26 {
        tampered[26] ^= 0xFF;
    }

    // SAFETY: tampered is a valid Vec.
    let dec_result = unsafe {
        secure_core_decrypt_bytes(tampered.as_ptr(), tampered.len(), dek.as_ptr(), dek.len())
    };
    check(
        dec_result.status == FFI_ERROR_CRYPTO,
        &format!("tampered: expected CRYPTO error, got {}", dec_result.status),
    );
    check(
        error_msg(&dec_result).is_some(),
        "tampered: no error message",
    );

    // SAFETY: results were returned by secure_core FFI.
    unsafe {
        secure_core_free_result(dec_result);
        secure_core_free_result(enc_result);
    }
    println!("  PASS: tampered ciphertext → FFI_ERROR_CRYPTO");
}

fn test_unsupported_version() {
    let dek = make_dek();
    let plaintext = b"version test";

    // SAFETY: plaintext and dek are valid.
    let enc_result = unsafe {
        secure_core_encrypt_bytes(plaintext.as_ptr(), plaintext.len(), dek.as_ptr(), dek.len())
    };
    check(enc_result.status == FFI_OK, "version: encrypt failed");

    // Copy and set version to 99 (bytes 4-5, little-endian)
    let mut bad_version =
        // SAFETY: enc_result.data was returned by secure_core_encrypt_bytes.
        unsafe { slice::from_raw_parts(enc_result.data.ptr, enc_result.data.len).to_vec() };
    bad_version[4] = 99;
    bad_version[5] = 0;

    // SAFETY: bad_version is a valid Vec.
    let dec_result = unsafe {
        secure_core_decrypt_bytes(
            bad_version.as_ptr(),
            bad_version.len(),
            dek.as_ptr(),
            dek.len(),
        )
    };
    check(
        dec_result.status == FFI_ERROR_UNSUPPORTED_VERSION,
        &format!(
            "version: expected UNSUPPORTED_VERSION, got {}",
            dec_result.status
        ),
    );
    let msg = error_msg(&dec_result);
    check(msg.is_some(), "version: no error message");

    // SAFETY: results were returned by secure_core FFI.
    unsafe {
        secure_core_free_result(dec_result);
        secure_core_free_result(enc_result);
    }
    println!("  PASS: unsupported version → FFI_ERROR_UNSUPPORTED_VERSION");
}

fn run_error_tests() {
    println!("[ERROR CASE TESTS]");
    test_null_buffer();
    test_invalid_dek_length();
    test_truncated_ciphertext();
    test_tampered_ciphertext();
    test_unsupported_version();
    println!();
}

// ── Stress test ─────────────────────────────────────────────────────────

fn run_stress_test() {
    println!("[STRESS TEST: 1000 iterations]");
    let dek = make_dek();
    let plaintext = random_bytes(4096);

    for i in 0..1000 {
        // SAFETY: plaintext and dek are valid slices with correct lengths.
        let enc_result = unsafe {
            secure_core_encrypt_bytes(plaintext.as_ptr(), plaintext.len(), dek.as_ptr(), dek.len())
        };
        check(
            enc_result.status == FFI_OK,
            &format!("stress iter {i}: encrypt failed"),
        );

        // SAFETY: enc_result.data was returned by secure_core_encrypt_bytes.
        let blob = unsafe { slice::from_raw_parts(enc_result.data.ptr, enc_result.data.len) };

        // SAFETY: blob and dek are valid slices with correct lengths.
        let dec_result = unsafe {
            secure_core_decrypt_bytes(blob.as_ptr(), blob.len(), dek.as_ptr(), dek.len())
        };
        check(
            dec_result.status == FFI_OK,
            &format!("stress iter {i}: decrypt failed"),
        );

        // SAFETY: dec_result.data was returned by secure_core_decrypt_bytes.
        let decrypted = unsafe { slice::from_raw_parts(dec_result.data.ptr, dec_result.data.len) };
        check(
            decrypted == plaintext.as_slice(),
            &format!("stress iter {i}: mismatch"),
        );

        // SAFETY: results were returned by secure_core FFI functions.
        unsafe {
            secure_core_free_result(dec_result);
            secure_core_free_result(enc_result);
        }

        if (i + 1) % 100 == 0 {
            println!("  iteration {}: OK", i + 1);
        }
    }

    println!("  NO LEAK DETECTED (manual check with valgrind recommended)");
    println!();
}

// ── Version check ───────────────────────────────────────────────────────

fn run_version_check() {
    println!("[VERSION CHECK]");
    let version_ptr = secure_core_version();
    check(!version_ptr.is_null(), "version: null pointer");
    // SAFETY: version_ptr is a valid null-terminated C string.
    let version = unsafe { CStr::from_ptr(version_ptr) }.to_str().unwrap();
    check(!version.is_empty(), "version: empty string");
    println!("  secure-core version: {version}");
    println!("  PASS");
    println!();
}

// ── Main ────────────────────────────────────────────────────────────────

fn main() {
    println!("=== secure-core FFI Harness ===\n");

    run_version_check();
    run_roundtrip_tests();
    run_error_tests();
    run_stress_test();

    println!("=== ALL TESTS PASSED ===");
}
