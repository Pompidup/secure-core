# secure-core

Core cryptographic library for the Pompidup secure document platform.

Pure Rust, bytes-in/bytes-out encryption core designed for mobile platforms (Android & iOS).

## Features

- **AES-256-GCM** authenticated encryption (NIST approved, 128-bit auth tags)
- **In-memory** encrypt/decrypt for small payloads
- **Chunked streaming** for large files (64 KB chunks, constant memory usage)
- **Custom `.enc` V1 format** with authenticated header (AAD)
- **C-compatible FFI** for Kotlin/JNI and Swift integration
- **Zeroize on drop** for key material (`Dek` struct)
- **No plaintext on disk** — guaranteed by design
- **No secret logging** — only operation names and document IDs

## Quick start

```rust
use secure_core::crypto::{encrypt_bytes, decrypt_bytes, Dek};
use secure_core::streaming::{encrypt_stream, decrypt_stream};

// In-memory
let key = [0u8; 32]; // Use a real 256-bit key
let blob = encrypt_bytes(b"Hello, Pompidup!", &key).unwrap();
let plaintext = decrypt_bytes(&blob, &key).unwrap();

// Streaming (files, large data)
let dek = Dek::new(key);
let input = std::fs::File::open("photo.jpg").unwrap();
let output = std::fs::File::create("photo.jpg.enc").unwrap();
let meta = encrypt_stream(input, output, &dek).unwrap();
println!("{} chunks, {} bytes", meta.chunks, meta.total_ciphertext_bytes);
```

## Architecture

```
Platform (Kotlin / Swift)
    |
    v
[FFI layer]  extern "C" functions
    |
    v
[secure-core]  Rust library
    |-- crypto       AES-256-GCM encrypt/decrypt, Dek
    |-- streaming    Chunked streaming (64 KB)
    |-- format       .enc V1 header parsing
    |-- api          File-level encrypt/decrypt
    |-- metadata     DocumentMetadata, WrappedDek
    |-- validation   Input validation (DEK, nonce)
    |-- logging      Safe logging (no secrets)
    '-- ffi          C-compatible types & functions
```

## Build

```bash
# Standard build
cargo build --release

# Run tests
cargo test --all
cargo test --features _test-vectors  # integration tests with deterministic nonces

# Clippy + format check
cargo clippy -- -D warnings
cargo fmt --all -- --check

# Benchmarks
cargo bench

# Android cross-compilation
./scripts/build-android.sh
```

## FFI usage

The library exposes 7 `extern "C"` functions:

| Function | Description |
|---|---|
| `secure_core_encrypt_bytes` | In-memory encrypt |
| `secure_core_decrypt_bytes` | In-memory decrypt |
| `secure_core_encrypt_file` | Streaming file encrypt |
| `secure_core_decrypt_file` | Streaming file decrypt |
| `secure_core_version` | Returns crate version string |
| `secure_core_free_buffer` | Free a Rust-allocated buffer |
| `secure_core_free_result` | Free an FfiResult |

All functions return an `FfiResult` with status code, data buffer, and error message. The caller **must** free results via `secure_core_free_result`.

See [FFI API reference](docs/ffi-api.md) for full signatures and examples.

## `.enc` V1 format

```
[SENC 4B][version 2B][algo 1B][nonce 12B][flags 2B][header_len 4B] = 25B header
[ciphertext + 16B GCM tag]                                         (in-memory)
[chunk_len 4B | chunk ciphertext + tag]*                            (streaming)
```

The header is authenticated as AAD — any tampering is detected on decryption.

## Performance

| Operation | Size | Throughput |
|---|---|---|
| `encrypt_bytes` | 1 KB | ~157 MiB/s |
| `encrypt_bytes` | 1 MB | ~193 MiB/s |
| `decrypt_bytes` | 1 MB | ~194 MiB/s |
| `encrypt_stream` | 50 MB | ~185 MiB/s |
| `decrypt_stream` | 50 MB | ~187 MiB/s |

Measured on Apple Silicon, single-threaded (criterion 0.5).

## Security

- AES-256-GCM with random 96-bit nonces (OS CSPRNG)
- Full 128-bit authentication tags
- Header authenticated as AAD
- Per-chunk nonce derivation (XOR base nonce with chunk index)
- `Dek` derives `ZeroizeOnDrop` with redacted `Debug`
- No secrets in logs, no plaintext on disk
- Weekly `cargo audit` in CI

See [Security considerations](docs/security-considerations.md) and [Threat model](docs/threat-model.md).

## Documentation

| Document | Description |
|---|---|
| [API overview](docs/api-overview.md) | Rust API, FFI API, format summary |
| [FFI API reference](docs/ffi-api.md) | C function signatures, ownership rules |
| [`.enc` V1 format spec](docs/enc-format-v1.md) | Binary format specification |
| [Platform contract](docs/platform-contract.md) | Core vs platform responsibilities |
| [Threat model](docs/threat-model.md) | Covered/uncovered threats |
| [Security considerations](docs/security-considerations.md) | Nonce uniqueness, key handling, limits |
| [Security audit V1](docs/security-audit-v1.md) | Pre-release audit results |
| [Compatibility](docs/compatibility.md) | V1 forward-compat promise, V2 strategy |
| [FAQ](docs/faq.md) | Common questions |
| [Build Android](docs/build-android.md) | Cross-compilation setup |
| [ADR-001: Algorithm choice](docs/decisions/ADR-001-algo-choice.md) | Why AES-256-GCM |
| [ADR-002: Streaming strategy](docs/decisions/ADR-002-streaming-strategy.md) | Why 64 KB chunks |

## Project structure

```
secure-core/
  src/
    lib.rs           Module declarations + crate docs
    crypto.rs        AES-256-GCM, Dek, encrypt/decrypt
    streaming.rs     Chunked streaming
    format.rs        .enc V1 header
    api.rs           File-level API
    metadata.rs      DocumentMetadata, WrappedDek
    validation.rs    Input validation
    logging.rs       Safe logging
    ffi/
      mod.rs
      types.rs       FfiBuffer, FfiResult, status codes
      functions.rs   extern "C" functions
  benches/
    crypto_bench.rs  Criterion benchmarks
  tests/
    crypto_tests.rs, streaming_tests.rs, metadata_tests.rs,
    ffi_tests.rs, validation_tests.rs
docs/                Design docs, specs, ADRs
scripts/             Android build scripts
testdata/            Frozen reference blobs
```

## License

[Apache-2.0](LICENSE)
