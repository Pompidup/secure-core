//! FFI buffers must be released with the exact layout they were allocated
//! with, and must not leak.
//!
//! This test binary installs a checking global allocator. Every allocation
//! records its size in a 16-byte prefix; every deallocation compares the size
//! the caller claims with the recorded one. A mismatch is undefined behaviour
//! (`GlobalAlloc::dealloc` contract), masked by `malloc`/`free` on mobile but
//! heap corruption under a size-aware allocator. The allocator also tracks
//! live bytes to catch leaked buffers.
//!
//! It lives in its own integration-test file so the global allocator only
//! affects this binary, and runs as a single test to keep the counters free
//! of interference from parallel tests.

use std::alloc::{GlobalAlloc, Layout, System};
use std::ffi::CString;
use std::sync::atomic::{AtomicIsize, AtomicUsize, Ordering};

use secure_core::ffi::functions::*;
use secure_core::ffi::types::*;

struct CheckingAlloc;

static LAYOUT_MISMATCHES: AtomicUsize = AtomicUsize::new(0);
static LIVE_BYTES: AtomicIsize = AtomicIsize::new(0);
const PREFIX: usize = 16;

// SAFETY: every block handed out comes from `System` with a layout we can
// rebuild exactly in `dealloc` (stored size + fixed prefix and alignment);
// over-aligned requests are forwarded to `System` untouched.
unsafe impl GlobalAlloc for CheckingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if layout.align() > PREFIX {
            return System.alloc(layout);
        }
        let real = Layout::from_size_align_unchecked(layout.size() + PREFIX, PREFIX);
        let base = System.alloc(real);
        if base.is_null() {
            return base;
        }
        (base as *mut usize).write(layout.size());
        LIVE_BYTES.fetch_add(layout.size() as isize, Ordering::SeqCst);
        base.add(PREFIX)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if layout.align() > PREFIX {
            return System.dealloc(ptr, layout);
        }
        let base = ptr.sub(PREFIX);
        let allocated = (base as *const usize).read();
        if allocated != layout.size() {
            LAYOUT_MISMATCHES.fetch_add(1, Ordering::SeqCst);
        }
        LIVE_BYTES.fetch_sub(allocated as isize, Ordering::SeqCst);
        System.dealloc(
            base,
            Layout::from_size_align_unchecked(allocated + PREFIX, PREFIX),
        );
    }
}

#[global_allocator]
static GLOBAL: CheckingAlloc = CheckingAlloc;

const DEK: [u8; 32] = [0x42; 32];

/// Runs `case` twice (the first run warms up lazy statics such as the
/// thread RNG) and reports layout mismatches and leaked bytes of the second run.
fn measure(case: &dyn Fn()) -> (usize, isize) {
    case();
    let mismatches = LAYOUT_MISMATCHES.load(Ordering::SeqCst);
    let live = LIVE_BYTES.load(Ordering::SeqCst);
    case();
    (
        LAYOUT_MISMATCHES.load(Ordering::SeqCst) - mismatches,
        LIVE_BYTES.load(Ordering::SeqCst) - live,
    )
}

/// A named FFI scenario run under the checking allocator.
type Case<'a> = (&'static str, Box<dyn Fn() + 'a>);

fn encrypt(plaintext: &[u8]) -> Vec<u8> {
    let (ptr, len) = (plaintext.as_ptr(), plaintext.len());
    // SAFETY: plaintext and DEK are valid slices of the given lengths.
    let r = unsafe { secure_core_encrypt_bytes(ptr, len, DEK.as_ptr(), 32) };
    assert_eq!(r.status, FFI_OK);
    // SAFETY: r.data was returned by secure_core_encrypt_bytes and is valid for r.data.len bytes.
    let blob = unsafe { std::slice::from_raw_parts(r.data.ptr, r.data.len) }.to_vec();
    // SAFETY: r was returned by secure_core_encrypt_bytes and is freed exactly once.
    unsafe { secure_core_free_result(r) };
    blob
}

#[test]
fn test_every_ffi_buffer_is_freed_with_its_allocated_layout_and_never_leaks() {
    let blob = encrypt(b"hello from the vault");
    let empty_blob = encrypt(b"");
    let dir = tempfile::tempdir().unwrap();
    let plain = dir.path().join("plain.bin");
    let enc = dir.path().join("doc.enc");
    let out = dir.path().join("out.bin");
    std::fs::write(&plain, vec![7u8; 70_000]).unwrap();
    let (plain_c, enc_c, out_c) = (
        CString::new(plain.to_str().unwrap()).unwrap(),
        CString::new(enc.to_str().unwrap()).unwrap(),
        CString::new(out.to_str().unwrap()).unwrap(),
    );
    let passphrase = CString::new("correct horse battery staple").unwrap();
    let pass = passphrase.as_ptr();
    // SAFETY: valid DEK and NUL-terminated passphrase.
    let wrap = unsafe { secure_core_wrap_dek_with_passphrase(DEK.as_ptr(), 32, pass) };
    assert_eq!(wrap.status, FFI_OK);
    // SAFETY: wrap.data was returned by secure_core_wrap_dek_with_passphrase.
    let wrap_json = unsafe { std::slice::from_raw_parts(wrap.data.ptr, wrap.data.len) }.to_vec();
    // SAFETY: returned by secure_core_wrap_dek_with_passphrase, freed once.
    unsafe { secure_core_free_result(wrap) };

    let cases: Vec<Case> = vec![
        (
            "encrypt_bytes",
            Box::new(|| {
                encrypt(b"some plaintext");
            }),
        ),
        (
            "decrypt_bytes",
            Box::new(|| {
                // SAFETY: blob and DEK are valid slices of the given lengths.
                let r = unsafe {
                    secure_core_decrypt_bytes(blob.as_ptr(), blob.len(), DEK.as_ptr(), 32)
                };
                assert_eq!(r.status, FFI_OK);
                // SAFETY: returned by secure_core_decrypt_bytes, freed once.
                unsafe { secure_core_free_result(r) };
            }),
        ),
        (
            "decrypt_bytes (empty plaintext)",
            Box::new(|| {
                // SAFETY: empty_blob and DEK are valid slices of the given lengths.
                let r = unsafe {
                    secure_core_decrypt_bytes(
                        empty_blob.as_ptr(),
                        empty_blob.len(),
                        DEK.as_ptr(),
                        32,
                    )
                };
                assert_eq!(r.status, FFI_OK);
                assert_eq!(r.data.len, 0);
                // SAFETY: returned by secure_core_decrypt_bytes, freed once.
                unsafe { secure_core_free_result(r) };
            }),
        ),
        (
            "decrypt_bytes (error result)",
            Box::new(|| {
                let mut tampered = blob.clone();
                tampered[30] ^= 1;
                // SAFETY: tampered and DEK are valid slices of the given lengths.
                let r = unsafe {
                    secure_core_decrypt_bytes(tampered.as_ptr(), tampered.len(), DEK.as_ptr(), 32)
                };
                assert_eq!(r.status, FFI_ERROR_CRYPTO);
                // SAFETY: returned by secure_core_decrypt_bytes, freed once.
                unsafe { secure_core_free_result(r) };
            }),
        ),
        (
            "encrypt_file",
            Box::new(|| {
                // SAFETY: NUL-terminated paths and a valid DEK.
                let r = unsafe {
                    secure_core_encrypt_file(plain_c.as_ptr(), enc_c.as_ptr(), DEK.as_ptr(), 32)
                };
                assert_eq!(r.status, FFI_OK);
                // SAFETY: returned by secure_core_encrypt_file, freed once.
                unsafe { secure_core_free_result(r) };
            }),
        ),
        (
            "decrypt_file",
            Box::new(|| {
                // SAFETY: NUL-terminated paths and a valid DEK.
                let r = unsafe {
                    secure_core_decrypt_file(enc_c.as_ptr(), out_c.as_ptr(), DEK.as_ptr(), 32)
                };
                assert_eq!(r.status, FFI_OK);
                // SAFETY: returned by secure_core_decrypt_file, freed once.
                unsafe { secure_core_free_result(r) };
            }),
        ),
        (
            "wrap_dek_with_passphrase",
            Box::new(|| {
                // SAFETY: valid DEK and NUL-terminated passphrase.
                let r = unsafe {
                    secure_core_wrap_dek_with_passphrase(DEK.as_ptr(), 32, passphrase.as_ptr())
                };
                assert_eq!(r.status, FFI_OK);
                // SAFETY: returned by secure_core_wrap_dek_with_passphrase, freed once.
                unsafe { secure_core_free_result(r) };
            }),
        ),
        (
            "unwrap_dek_with_passphrase",
            Box::new(|| {
                // SAFETY: wrap_json is valid for its length; passphrase is NUL-terminated.
                let r = unsafe {
                    secure_core_unwrap_dek_with_passphrase(
                        wrap_json.as_ptr(),
                        wrap_json.len(),
                        passphrase.as_ptr(),
                    )
                };
                assert_eq!(r.status, FFI_OK);
                // SAFETY: returned by secure_core_unwrap_dek_with_passphrase, freed once.
                unsafe { secure_core_free_result(r) };
            }),
        ),
    ];

    let mut failures = Vec::new();
    for (name, case) in &cases {
        let (mismatches, leaked) = measure(case.as_ref());
        if mismatches != 0 || leaked != 0 {
            failures.push(format!(
                "{name}: {mismatches} bad dealloc(s), {leaked} byte(s) leaked"
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "FFI buffer lifecycle bugs:\n{}",
        failures.join("\n")
    );
}
