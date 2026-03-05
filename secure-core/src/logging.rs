/// Logs a cryptographic operation.
///
/// This function **never** logs sensitive data (keys, plaintext, nonces).
/// Only the operation name and document identifier are emitted.
///
/// Requires the `log` feature to be enabled. Without it, this is a no-op.
pub fn log_operation(op: &str, doc_id: &str) {
    #[cfg(feature = "log")]
    log::info!("secure-core: op={op} doc_id={doc_id}");

    // Suppress unused variable warnings when `log` feature is disabled.
    #[cfg(not(feature = "log"))]
    {
        let _ = op;
        let _ = doc_id;
    }
}

// NOTE: assert_no_secret_in_log
// All log statements in this crate MUST go through `log_operation`.
// The function signature intentionally accepts only `op` and `doc_id` —
// there is no parameter for key bytes, plaintext, nonces, or any secret material.
// This is enforced by design: if you need to log something new, add a
// non-sensitive parameter to this function, never a raw byte slice.
