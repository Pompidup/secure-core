# API Overview — secure-core

## 1. Rust API

### Module `crypto`

```rust
/// A Data Encryption Key, zeroized on drop. Debug prints "Dek([REDACTED])".
pub struct Dek(pub [u8; 32]);

impl Dek {
    pub fn new(key: [u8; 32]) -> Self;
    pub fn as_bytes(&self) -> &[u8; 32];
}

/// Generates a cryptographically random 12-byte nonce.
pub fn generate_nonce() -> [u8; 12];

/// Encrypts plaintext → .enc V1 blob (header + ciphertext + tag).
pub fn encrypt_bytes(plaintext: &[u8], dek: &[u8; 32]) -> Result<Vec<u8>, SecureCoreError>;

/// Decrypts a .enc V1 blob → plaintext.
pub fn decrypt_bytes(blob: &[u8], dek: &[u8; 32]) -> Result<Vec<u8>, SecureCoreError>;
```

**Example:**

```rust
use secure_core::crypto::{encrypt_bytes, decrypt_bytes};

let key = [0u8; 32]; // Use a real key in production
let blob = encrypt_bytes(b"Hello", &key).unwrap();
let plaintext = decrypt_bytes(&blob, &key).unwrap();
assert_eq!(plaintext, b"Hello");
```

### Module `streaming`

```rust
pub const CHUNK_SIZE: usize = 65536; // 64 KB

pub struct StreamMetadata {
    pub chunks: u32,
    pub total_plaintext_bytes: u64,
    pub total_ciphertext_bytes: u64,
}

/// Encrypts a stream in 64 KB chunks with per-chunk nonces.
pub fn encrypt_stream<R: Read, W: Write>(
    input: R, output: W, dek: &Dek,
) -> Result<StreamMetadata, SecureCoreError>;

/// Decrypts a chunked stream.
pub fn decrypt_stream<R: Read, W: Write>(
    input: R, output: W, dek: &Dek,
) -> Result<StreamMetadata, SecureCoreError>;
```

**Example:**

```rust
use std::fs::File;
use secure_core::crypto::Dek;
use secure_core::streaming::encrypt_stream;

let dek = Dek::new([0u8; 32]);
let input = File::open("photo.jpg").unwrap();
let output = File::create("photo.jpg.enc").unwrap();
let meta = encrypt_stream(input, output, &dek).unwrap();
println!("Encrypted {} chunks", meta.chunks);
```

### Module `api`

```rust
pub struct EncryptResult {
    pub stream_metadata: StreamMetadata,
    pub document_metadata: DocumentMetadata,
}

/// Encrypts a file. Returns streaming metadata + partial document metadata.
pub fn encrypt_file(
    input_path: &Path, output_path: &Path, dek: &Dek,
) -> Result<EncryptResult, SecureCoreError>;

/// Decrypts a file.
pub fn decrypt_file(
    input_path: &Path, output_path: &Path, dek: &Dek,
) -> Result<StreamMetadata, SecureCoreError>;
```

### Module `metadata`

```rust
pub struct DocumentMetadata {
    pub doc_id: String,
    pub filename: String,
    pub mime_type: Option<String>,
    pub created_at: u64,
    pub plaintext_size: Option<u64>,
    pub ciphertext_size: u64,
    pub content_hash: Option<[u8; 32]>,
    pub wrapped_dek: WrappedDek,
}

pub struct WrappedDek {
    pub device_wrap: Vec<u8>,
    pub recovery_wrap: Option<Vec<u8>>,  // Reserved for V2
    pub wrap_algorithm: String,
}

impl DocumentMetadata {
    /// Validates required fields are present.
    pub fn validate(&self) -> Result<(), SecureCoreError>;
}
```

### Module `format`

```rust
pub const MAGIC: [u8; 4];           // "SENC"
pub const FORMAT_VERSION_V1: u16;   // 1

pub enum AlgorithmId { Aes256Gcm = 0x01 }

pub struct EncHeader {
    pub version: u16,
    pub algorithm: AlgorithmId,
    pub nonce: [u8; 12],
    pub flags: u16,
    pub header_length: u32,
}

impl EncHeader {
    pub fn new_v1(nonce: [u8; 12]) -> Self;
    pub fn to_bytes(&self) -> Vec<u8>;
    pub fn from_bytes(data: &[u8]) -> Result<Self, SecureCoreError>;
}
```

### Module `validation`

```rust
pub fn validate_dek(dek: &[u8]) -> Result<(), SecureCoreError>;
pub fn validate_nonce(nonce: &[u8]) -> Result<(), SecureCoreError>;
```

### Module `error`

```rust
pub enum SecureCoreError {
    InvalidFormat(String),
    UnsupportedVersion { found: u16, max_supported: u16 },
    CryptoError(String),
    IoError(std::io::Error),
    InvalidParameter(String),
}
```

### Module `logging`

```rust
/// Logs operation name + doc_id only. Never logs secrets.
/// No-op unless the `log` feature is enabled.
pub fn log_operation(op: &str, doc_id: &str);
```

---

## 2. FFI API (C-compatible)

All functions use `extern "C"` ABI. The caller **must** free results via `secure_core_free_result`.

### Functions

| Function | Description |
|---|---|
| `secure_core_version() -> *const c_char` | Returns crate version (static, do not free) |
| `secure_core_encrypt_bytes(plaintext, len, dek, dek_len) -> FfiResult` | In-memory encrypt |
| `secure_core_decrypt_bytes(blob, len, dek, dek_len) -> FfiResult` | In-memory decrypt |
| `secure_core_encrypt_file(input_path, output_path, dek, dek_len) -> FfiResult` | Streaming encrypt |
| `secure_core_decrypt_file(input_path, output_path, dek, dek_len) -> FfiResult` | Streaming decrypt |
| `secure_core_free_buffer(FfiBuffer)` | Free a Rust-allocated buffer |
| `secure_core_free_result(FfiResult)` | Free an FfiResult and its data |

### Status codes

| Code | Constant | Meaning |
|---|---|---|
| 0 | `FFI_OK` | Success |
| 1 | `FFI_ERROR_INVALID_FORMAT` | Bad `.enc` format |
| 2 | `FFI_ERROR_UNSUPPORTED_VERSION` | Unknown format version |
| 3 | `FFI_ERROR_CRYPTO` | Decryption / auth failure |
| 4 | `FFI_ERROR_IO` | I/O error |
| 5 | `FFI_ERROR_INVALID_PARAM` | Invalid parameter |

### Kotlin (JNI) pseudo-code

```kotlin
// Load the native library
System.loadLibrary("secure_core")

external fun secure_core_encrypt_bytes(
    plaintext: ByteArray, plaintextLen: Int,
    dek: ByteArray, dekLen: Int
): Long  // pointer to FfiResult

// Usage:
val dek = keystore.unwrapDek(wrappedDek)
val resultPtr = secure_core_encrypt_bytes(plaintext, plaintext.size, dek, 32)
val status = getStatus(resultPtr)
if (status == 0) {
    val encryptedData = getData(resultPtr)
    // ... store encryptedData
}
secure_core_free_result(resultPtr)
dek.fill(0)  // zeroize on platform side
```

### Swift pseudo-code

```swift
import SecureCore  // .xcframework wrapping libsecure_core.a

let dek: [UInt8] = try keychain.unwrapDek(wrappedDek)
defer { dek.withUnsafeMutableBytes { $0.resetBytes(in: $0.startIndex..<$0.endIndex) } }

let result = plaintext.withUnsafeBytes { ptr in
    secure_core_encrypt_bytes(ptr.baseAddress, ptr.count, dek, 32)
}
defer { secure_core_free_result(result) }

guard result.status == 0 else {
    let msg = String(cString: result.error_msg)
    throw SecureCoreError.ffi(msg)
}

let blob = Data(bytes: result.data.ptr, count: result.data.len)
```

---

## 3. Format `.enc` V1

The encrypted output uses a custom binary format:

```
[SENC magic 4B][version 2B][algo 1B][nonce 12B][flags 2B][header_length 4B] = 25 bytes header
[ciphertext + GCM auth tag 16B]  (in-memory mode)
-- or --
[chunk_len 4B][chunk ciphertext + tag]*  (streaming mode)
```

- Header is authenticated as AAD (tampering detected)
- AES-256-GCM with 128-bit auth tags
- Streaming: 64 KB chunks, per-chunk nonces derived via XOR

Full specification: [docs/enc-format-v1.md](enc-format-v1.md)
