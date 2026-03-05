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

Decrypts a file using chunked streaming. Returns stream metadata as JSON in `data`.

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

4. **Input pointers are borrowed.** The library does not take ownership of `plaintext_ptr`, `blob_ptr`, `dek_ptr`, or path strings. The caller retains ownership and may free them after the call returns.

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
