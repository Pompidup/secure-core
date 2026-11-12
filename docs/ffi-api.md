# FFI API Reference

## Overview

`secure-core` exposes a C-compatible FFI for integration with Kotlin (via JNI) and Swift. All functions use the `extern "C"` ABI and are `#[no_mangle]`.

The library is compiled as:
- `cdylib` — shared library (`.so` / `.dylib`) for dynamic linking
- `staticlib` — static library (`.a`) for static linking
- `rlib` — Rust library for Rust consumers

## Types

### `FfiBuffer`

```c
typedef struct {
    uint8_t *ptr;   // Pointer to data (null if empty)
    size_t   len;   // Length in bytes
} FfiBuffer;
```

### `FfiResult`

```c
typedef struct {
    int32_t   status;     // 0 = success, >0 = error code
    FfiBuffer data;       // Result data (empty on error)
    char     *error_msg;  // Error description (null on success)
} FfiResult;
```

### Status Codes

| Code | Constant                        | Description                   |
| ---- | ------------------------------- | ----------------------------- |
| 0    | `FFI_OK`                        | Success                       |
| 1    | `FFI_ERROR_INVALID_FORMAT`      | Malformed `.enc` data         |
| 2    | `FFI_ERROR_UNSUPPORTED_VERSION` | Unknown format version        |
| 3    | `FFI_ERROR_CRYPTO`              | Decryption/encryption failure |
| 4    | `FFI_ERROR_IO`                  | File I/O error                |
| 5    | `FFI_ERROR_INVALID_PARAM`       | Invalid parameter             |
| 6    | `FFI_ERROR_UNSUPPORTED_RECOVERY_SCHEMA` | Recovery bundle `schema_version` not supported by this build (0.4.0+) |
| 7    | `FFI_ERROR_INTERNAL`            | Panic caught at the boundary (secure-core bug); nothing produced (0.6.0+) |

Branch on the code; `error_msg` is diagnostic only. Treat any unknown code as a generic error.

## Functions

### `secure_core_version`

```c
const char* secure_core_version(void);
```

Returns the crate version as a static null-terminated string. **Do not free** the returned pointer.

### `secure_core_encrypt_bytes`

```c
FfiResult secure_core_encrypt_bytes(
    const uint8_t *plaintext_ptr,
    size_t         plaintext_len,
    const uint8_t *dek_ptr,
    size_t         dek_len
);
```

Encrypts `plaintext_len` bytes into a `.enc` V1 blob (in-memory). Returns the blob in `data`.

### `secure_core_decrypt_bytes`

```c
FfiResult secure_core_decrypt_bytes(
    const uint8_t *blob_ptr,
    size_t         blob_len,
    const uint8_t *dek_ptr,
    size_t         dek_len
);
```

Decrypts a `.enc` V1 blob and returns the plaintext in `data`.

### `secure_core_encrypt_file`

```c
FfiResult secure_core_encrypt_file(
    const char    *input_path,
    const char    *output_path,
    const uint8_t *dek_ptr,
    size_t         dek_len
);
```

Encrypts a file using chunked streaming. Returns stream metadata as JSON in `data`.

### `secure_core_decrypt_file`

```c
FfiResult secure_core_decrypt_file(
    const char    *input_path,
    const char    *output_path,
    const uint8_t *dek_ptr,
    size_t         dek_len
);
```

Decrypts a V1.1 file using chunked streaming. Returns stream metadata as JSON in `data`. Since 0.5.0, streams without `FLAG_STREAM_FINAL_CHUNK` are rejected with `FFI_ERROR_INVALID_FORMAT` before any plaintext is written.

### `secure_core_decrypt_file_allow_legacy` (0.5.0+, migration only)

```c
FfiResult secure_core_decrypt_file_allow_legacy(
    const char    *input_path,
    const char    *output_path,
    const uint8_t *dek_ptr,
    size_t         dek_len
);
```

Same contract as `secure_core_decrypt_file`, but also accepts legacy V1.0 streams (pre-0.3.0, `flags == 0`). **Truncation of legacy input is not detected.** Call it once per legacy file, then re-encrypt with `secure_core_encrypt_file`; never use it for regular document opening.

### `secure_core_wrap_dek_with_passphrase`

```c
FfiResult secure_core_wrap_dek_with_passphrase(
    const uint8_t *dek_ptr,
    size_t         dek_len,
    const char    *passphrase_ptr
);
```

Wraps a 32-byte DEK with a passphrase (Argon2id m=64 MiB, t=3, p=4, then AES-256-GCM) and returns the `RecoveryWrap` as UTF-8 JSON in `data` (see [Recovery format V1](recovery-format-v1.md)). The passphrase must be non-empty, NUL-terminated UTF-8; it is borrowed, never copied. **Blocking** (a few hundred ms): call it off the UI thread. Codes: `OK`, `INVALID_PARAM`, `CRYPTO`.

### `secure_core_unwrap_dek_with_passphrase`

```c
FfiResult secure_core_unwrap_dek_with_passphrase(
    const uint8_t *recovery_json_ptr,
    size_t         recovery_json_len,
    const char    *passphrase_ptr
);
```

Parses the `RecoveryWrap` JSON and returns the 32-byte DEK in `data`. Free the result as soon as the DEK has been handed to the keystore. **Blocking** (Argon2id). Codes:

- `OK`;
- `INVALID_PARAM`: arguments, base64 fields, sizes or algorithm invalid;
- `INVALID_FORMAT`: invalid JSON (same code through JNI since 0.6.0; before, JNI reported `INVALID_PARAM`);
- `UNSUPPORTED_RECOVERY_SCHEMA`: bundle created by a newer version, so the app should prompt for an update;
- `CRYPTO`: wrong passphrase or tampered bundle.

### `secure_core_free_buffer`

```c
void secure_core_free_buffer(FfiBuffer buf);
```

Frees a buffer allocated by Rust. **Must** be called on every `FfiBuffer` returned by the library.

### `secure_core_free_result`

```c
void secure_core_free_result(FfiResult result);
```

Frees an `FfiResult` and all memory it owns (data buffer + error message). **Must** be called on every `FfiResult` returned by the library.

## Ownership Rules

1. **Every `FfiResult` returned by a `secure_core_*` function must be freed** by calling `secure_core_free_result`. Failure to do so leaks memory.

2. **Every `FfiBuffer` returned by a `secure_core_*` function must be freed** by calling `secure_core_free_buffer` (or indirectly via `secure_core_free_result`). Do not free the same buffer twice.

3. **Do not free the pointer returned by `secure_core_version`** — it is a static string.

4. **Input pointers are borrowed.** The library does not take ownership of `plaintext_ptr`, `blob_ptr`, `dek_ptr`, `recovery_json_ptr`, `passphrase_ptr`, or path strings. The caller retains ownership and may free them after the call returns.

## Security Invariants

| Invariant | Enforcement |
| --------- | ----------- |
| `dek_ptr` must not be null | Returns `FFI_ERROR_INVALID_PARAM` |
| `dek_len` must be exactly 32 | Returns `FFI_ERROR_INVALID_PARAM` |
| `plaintext_ptr` must not be null when `plaintext_len > 0` | Returns `FFI_ERROR_INVALID_PARAM` |
| Path strings must be valid UTF-8 | Returns `FFI_ERROR_INVALID_PARAM` |
| The DEK is zeroized after use | `Dek` struct implements `ZeroizeOnDrop` |

## Platform Integration

### Kotlin / JNI

```kotlin
external fun secureCorEncryptBytes(plaintext: ByteArray, dek: ByteArray): ByteArray
```

The JNI wrapper should:
1. Pin the byte arrays (`GetByteArrayElements`).
2. Call the FFI function.
3. Copy the result data into a new `ByteArray`.
4. Call `secure_core_free_result`.
5. Release the pinned arrays.

### Swift

```swift
let result = secure_core_encrypt_bytes(ptr, len, dekPtr, 32)
defer { secure_core_free_result(result) }
```

Use `Data(bytes:count:)` to copy the result buffer into Swift-managed memory before freeing.
