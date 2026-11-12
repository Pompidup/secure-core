//! Buffers handed out by the FFI may hold plaintext or a DEK (unwrap), so
//! `secure_core_free_buffer` must wipe them before releasing the memory.
//!
//! A watching global allocator checks, at deallocation time, that the block
//! at a given address is all zeros. Own binary so the allocator only affects
//! this test; single test to keep the watch slot free of interference.

use std::alloc::{GlobalAlloc, Layout, System};
use std::ffi::CString;
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

use secure_core::ffi::functions::*;
use secure_core::ffi::types::*;

struct WatchingAlloc;

static WATCHED: AtomicUsize = AtomicUsize::new(0);
/// 0 = not freed yet, 1 = freed wiped, 2 = freed with data left in it.
static VERDICT: AtomicU8 = AtomicU8::new(0);

// SAFETY: forwards every call to `System` unchanged; it only reads the block
// being freed, which is still owned and valid at that point.
unsafe impl GlobalAlloc for WatchingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        System.alloc(layout)
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if ptr as usize == WATCHED.load(Ordering::SeqCst) {
            let block = std::slice::from_raw_parts(ptr, layout.size());
            let wiped = block.iter().all(|&b| b == 0);
            VERDICT.store(if wiped { 1 } else { 2 }, Ordering::SeqCst);
            WATCHED.store(0, Ordering::SeqCst);
        }
        System.dealloc(ptr, layout)
    }
}

#[global_allocator]
static GLOBAL: WatchingAlloc = WatchingAlloc;

const DEK: [u8; 32] = [0x42; 32];

/// Frees `result` while watching its data block; returns whether it was wiped.
fn freed_wiped(result: FfiResult) -> bool {
    assert_eq!(result.status, FFI_OK);
    assert!(result.data.len > 0);
    VERDICT.store(0, Ordering::SeqCst);
    WATCHED.store(result.data.ptr as usize, Ordering::SeqCst);
    // SAFETY: result was returned by a secure_core_* function and is freed once.
    unsafe { secure_core_free_result(result) };
    VERDICT.load(Ordering::SeqCst) == 1
}

#[test]
fn test_ffi_buffers_holding_plaintext_or_keys_are_wiped_before_free() {
    let plaintext = b"confidential vault document";
    let (pt_ptr, pt_len) = (plaintext.as_ptr(), plaintext.len());
    // SAFETY: plaintext and DEK are valid slices of the given lengths.
    let enc = unsafe { secure_core_encrypt_bytes(pt_ptr, pt_len, DEK.as_ptr(), 32) };
    assert_eq!(enc.status, FFI_OK);
    // SAFETY: enc.data was returned by secure_core_encrypt_bytes.
    let blob = unsafe { std::slice::from_raw_parts(enc.data.ptr, enc.data.len) }.to_vec();
    // SAFETY: returned by secure_core_encrypt_bytes, freed once.
    unsafe { secure_core_free_result(enc) };

    // SAFETY: blob and DEK are valid slices of the given lengths.
    let dec = unsafe { secure_core_decrypt_bytes(blob.as_ptr(), blob.len(), DEK.as_ptr(), 32) };
    assert!(
        freed_wiped(dec),
        "decrypted plaintext must be wiped before free"
    );

    let pass = CString::new("correct horse battery staple").unwrap();
    // SAFETY: valid DEK and NUL-terminated passphrase.
    let wrap = unsafe { secure_core_wrap_dek_with_passphrase(DEK.as_ptr(), 32, pass.as_ptr()) };
    assert_eq!(wrap.status, FFI_OK);
    // SAFETY: wrap.data was returned by secure_core_wrap_dek_with_passphrase.
    let json = unsafe { std::slice::from_raw_parts(wrap.data.ptr, wrap.data.len) }.to_vec();
    // SAFETY: returned by secure_core_wrap_dek_with_passphrase, freed once.
    unsafe { secure_core_free_result(wrap) };

    let (json_ptr, json_len, pass_ptr) = (json.as_ptr(), json.len(), pass.as_ptr());
    // SAFETY: json is valid for its length and the passphrase is NUL-terminated.
    let unwrapped = unsafe { secure_core_unwrap_dek_with_passphrase(json_ptr, json_len, pass_ptr) };
    assert!(
        freed_wiped(unwrapped),
        "unwrapped DEK must be wiped before free"
    );
}
