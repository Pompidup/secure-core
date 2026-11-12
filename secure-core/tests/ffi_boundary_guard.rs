//! A panic must never unwind out of an exported function: since Rust 1.81
//! that aborts the host process (the mobile app). Every C and JNI entry
//! point therefore runs its body inside a panic guard (`ffi_guard` /
//! `jni_guard`) that turns a panic into status `FFI_ERROR_INTERNAL` (7).
//!
//! This test enforces the rule structurally, so a new entry point cannot be
//! added without the guard. Only the `version` functions are exempt: they
//! return a static value and contain no fallible code.

use secure_core::ffi::types::FFI_ERROR_INTERNAL;

fn source(rel: &str) -> String {
    std::fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(rel)).unwrap()
}

/// Yields (name, body) for every top-level function whose signature contains
/// `marker`. A body ends at the first line that is exactly `}`.
fn exported_fns<'a>(src: &'a str, marker: &'a str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for (start, _) in src.match_indices(marker) {
        let rest = &src[start + marker.len()..];
        let name: String = rest
            .trim_start()
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        let end = rest.find("\n}\n").expect("function body end");
        out.push((name, rest[..end].to_string()));
    }
    out
}

#[test]
fn test_internal_error_status_code_is_7() {
    assert_eq!(FFI_ERROR_INTERNAL, 7);
}

#[test]
fn test_every_c_entry_point_runs_inside_the_panic_guard() {
    let src = source("src/ffi/functions.rs");
    let fns = exported_fns(&src, "extern \"C\" fn ");
    assert!(
        fns.len() >= 10,
        "expected the 10 exported C functions, found {}",
        fns.len()
    );
    let unguarded: Vec<_> = fns
        .iter()
        .filter(|(name, _)| name != "secure_core_version")
        .filter(|(_, body)| !body.contains("ffi_guard"))
        .map(|(name, _)| name.clone())
        .collect();
    assert!(
        unguarded.is_empty(),
        "C entry points without ffi_guard: {unguarded:?}"
    );
}

#[test]
fn test_every_jni_entry_point_runs_inside_the_panic_guard() {
    let src = source("src/jni_bridge.rs");
    let fns = exported_fns(&src, "extern \"system\" fn ");
    assert!(
        fns.len() >= 8,
        "expected the 8 exported JNI functions, found {}",
        fns.len()
    );
    let unguarded: Vec<_> = fns
        .iter()
        .filter(|(name, _)| !name.ends_with("_version"))
        .filter(|(_, body)| !body.contains("jni_guard"))
        .map(|(name, _)| name.clone())
        .collect();
    assert!(
        unguarded.is_empty(),
        "JNI entry points without jni_guard: {unguarded:?}"
    );
}
