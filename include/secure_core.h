/*
 * secure_core.h — C header for secure-core FFI
 *
 * ABI version: v1.0.0 (FROZEN)
 * Stability: Stable for all v1.x releases.
 *            A signature change requires a new major version.
 *
 * This header is the single source of truth for the C ABI.
 * It MUST match the Rust FFI exports exactly.
 */

#ifndef SECURE_CORE_H
#define SECURE_CORE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Status codes ──────────────────────────────────────────────────── */

#define SECURE_CORE_OK                      0
#define SECURE_CORE_ERROR_INVALID_FORMAT    1
#define SECURE_CORE_ERROR_UNSUPPORTED_VERSION 2
#define SECURE_CORE_ERROR_CRYPTO            3
#define SECURE_CORE_ERROR_IO                4
#define SECURE_CORE_ERROR_INVALID_PARAM     5

/* ── Types ─────────────────────────────────────────────────────────── */

/*
 * A byte buffer allocated by Rust.
 *
 * Ownership: Rust owns the memory. The caller MUST NOT write to ptr
 * or free it directly. Use secure_core_free_buffer() or
 * secure_core_free_result() to release it.
 *
 * A null ptr with len == 0 represents an empty buffer.
 */
typedef struct {
    uint8_t *ptr;
    size_t   len;
} SecureCoreBuffer;

/*
 * Result returned by all FFI operations.
 *
 * On success (status == SECURE_CORE_OK):
 *   - data contains the output bytes
 *   - error_msg is NULL
 *
 * On failure (status != SECURE_CORE_OK):
 *   - data is empty (ptr=NULL, len=0)
 *   - error_msg is a null-terminated UTF-8 string
 *
 * Ownership: The caller MUST free this with secure_core_free_result().
 *            Must not be freed twice.
 */
typedef struct {
    int32_t          status;
    SecureCoreBuffer data;
    char            *error_msg;
} SecureCoreResult;

/* ── Functions ─────────────────────────────────────────────────────── */

/*
 * Returns the library version as a null-terminated C string.
 *
 * Ownership: The returned pointer is STATIC. Do NOT free it.
 * Thread-safety: Safe to call from any thread.
 */
const char *secure_core_version(void);

/*
 * Encrypts plaintext bytes into an .enc V1 blob.
 *
 * Parameters:
 *   plaintext_ptr  — pointer to plaintext data (may be NULL if plaintext_len == 0)
 *   plaintext_len  — number of bytes to encrypt
 *   dek_ptr        — pointer to the 32-byte Data Encryption Key (must not be NULL)
 *   dek_len        — must be exactly 32
 *
 * Returns: SecureCoreResult with the encrypted blob in data.
 *
 * Ownership:
 *   - plaintext_ptr: borrowed (read-only, caller retains ownership)
 *   - dek_ptr: borrowed (read-only, caller retains ownership)
 *   - return value: caller owns, MUST free via secure_core_free_result()
 *
 * Thread-safety: Safe to call from any thread. No shared mutable state.
 */
SecureCoreResult secure_core_encrypt_bytes(
    const uint8_t *plaintext_ptr,
    size_t         plaintext_len,
    const uint8_t *dek_ptr,
    size_t         dek_len
);

/*
 * Decrypts an .enc V1 blob back to plaintext.
 *
 * Parameters:
 *   blob_ptr  — pointer to the encrypted blob (must not be NULL)
 *   blob_len  — length of the blob (must be > 0)
 *   dek_ptr   — pointer to the 32-byte Data Encryption Key (must not be NULL)
 *   dek_len   — must be exactly 32
 *
 * Returns: SecureCoreResult with the decrypted plaintext in data.
 *
 * Ownership:
 *   - blob_ptr: borrowed (read-only, caller retains ownership)
 *   - dek_ptr: borrowed (read-only, caller retains ownership)
 *   - return value: caller owns, MUST free via secure_core_free_result()
 *
 * Thread-safety: Safe to call from any thread. No shared mutable state.
 */
SecureCoreResult secure_core_decrypt_bytes(
    const uint8_t *blob_ptr,
    size_t         blob_len,
    const uint8_t *dek_ptr,
    size_t         dek_len
);

/*
 * Encrypts a file using chunked streaming (64 KB chunks).
 *
 * Parameters:
 *   input_path_ptr  — null-terminated UTF-8 path to the input file
 *   output_path_ptr — null-terminated UTF-8 path to the output .enc file
 *   dek_ptr         — pointer to the 32-byte Data Encryption Key
 *   dek_len         — must be exactly 32
 *
 * Returns: SecureCoreResult with JSON metadata in data on success:
 *          {"chunks":N,"total_plaintext_bytes":N,"total_ciphertext_bytes":N}
 *
 * Ownership:
 *   - path pointers: borrowed (read-only, caller retains ownership)
 *   - dek_ptr: borrowed (read-only, caller retains ownership)
 *   - return value: caller owns, MUST free via secure_core_free_result()
 *
 * Thread-safety: Safe to call from any thread. File I/O may block.
 */
SecureCoreResult secure_core_encrypt_file(
    const char    *input_path_ptr,
    const char    *output_path_ptr,
    const uint8_t *dek_ptr,
    size_t         dek_len
);

/*
 * Decrypts a .enc file using chunked streaming.
 *
 * Parameters:
 *   input_path_ptr  — null-terminated UTF-8 path to the encrypted .enc file
 *   output_path_ptr — null-terminated UTF-8 path to the output plaintext file
 *   dek_ptr         — pointer to the 32-byte Data Encryption Key
 *   dek_len         — must be exactly 32
 *
 * Returns: SecureCoreResult with JSON metadata in data on success:
 *          {"chunks":N,"total_plaintext_bytes":N,"total_ciphertext_bytes":N}
 *
 * Ownership:
 *   - path pointers: borrowed (read-only, caller retains ownership)
 *   - dek_ptr: borrowed (read-only, caller retains ownership)
 *   - return value: caller owns, MUST free via secure_core_free_result()
 *
 * Thread-safety: Safe to call from any thread. File I/O may block.
 */
SecureCoreResult secure_core_decrypt_file(
    const char    *input_path_ptr,
    const char    *output_path_ptr,
    const uint8_t *dek_ptr,
    size_t         dek_len
);

/*
 * Frees a SecureCoreBuffer previously returned by Rust.
 *
 * After this call, buf.ptr is invalid and must not be dereferenced.
 *
 * Ownership: Transfers ownership back to Rust for deallocation.
 *            Must not be called twice on the same buffer.
 *
 * Thread-safety: Safe if the buffer is not accessed concurrently.
 */
void secure_core_free_buffer(SecureCoreBuffer buf);

/*
 * Frees a SecureCoreResult and all memory it owns (data + error_msg).
 *
 * After this call, all pointers in the result are invalid.
 *
 * Ownership: Transfers ownership back to Rust for deallocation.
 *            Must not be called twice on the same result.
 *
 * Thread-safety: Safe if the result is not accessed concurrently.
 */
void secure_core_free_result(SecureCoreResult result);

#ifdef __cplusplus
}
#endif

#endif /* SECURE_CORE_H */
