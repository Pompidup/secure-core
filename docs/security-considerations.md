# Security Considerations — secure-core

This document describes the security properties, assumptions, and limits of the `secure-core` library. It complements the [threat model](threat-model.md) and [platform contract](platform-contract.md).

---

## 1. IV / Nonce Uniqueness

### In-memory encryption (`encrypt_bytes`)

Each call generates a fresh 96-bit random nonce via the OS CSPRNG (`rand::thread_rng()`). The nonce is embedded in the `.enc` V1 header.

**Collision bound**: With 96-bit random nonces under a single key, the birthday bound gives ~2^48 encryptions before a 50% collision probability. For mobile usage patterns (even millions of documents), the risk is negligible.

**Requirement**: The platform MUST NOT reuse the same DEK across independent key-wrapping domains without understanding this bound.

### Streaming encryption (`encrypt_stream`)

A single random base nonce is generated per stream. Per-chunk nonces are derived by XOR-ing the base nonce with the chunk index (big-endian u32 in the last 4 bytes). This guarantees uniqueness across all chunks within a single stream.

**Limit**: A single stream must not exceed `MAX_STREAM_CHUNKS` = `0x7FFF_FFFF` chunks (the top bit is reserved as the V1.1 final-chunk marker), i.e. `MAX_STREAM_PLAINTEXT_SIZE` ≈ 128 TiB at 64 KiB/chunk. Enforced at runtime via `checked_next_index`.

### Size limits — summary

| Path | Const | Limit |
|---|---|---|
| in-memory (`encrypt_bytes`) | `crypto::MAX_PLAINTEXT_SIZE` | 4 GiB on 64-bit, 2 GiB on 32-bit |
| streaming (`encrypt_stream`) | `streaming::MAX_STREAM_PLAINTEXT_SIZE` | ~128 TiB |

The in-memory cap is deliberately conservative: it ensures the plaintext (and a ciphertext buffer of similar size) both fit in process memory on a mobile device. Callers that would exceed it must switch to streaming. A Rust-level test asserts `MAX_PLAINTEXT_SIZE < MAX_STREAM_PLAINTEXT_SIZE` to prevent the two limits from drifting into inconsistency.

## 2. Key Handling

### DEK lifecycle

1. **Generation**: The platform generates the 32-byte DEK. Core never generates DEKs.
2. **Usage**: The platform passes the DEK to core for encrypt/decrypt operations.
3. **Zeroization**: The `Dek` struct derives `ZeroizeOnDrop` — key bytes are overwritten with zeros when the struct is dropped. For raw `[u8; 32]` keys passed to `encrypt_bytes` / `decrypt_bytes`, the caller is responsible for zeroization.
4. **No persistence**: Core never writes the DEK to disk, logs, or any persistent storage.

### Building a `Dek` at the FFI/JNI boundary

When key material arrives from caller memory (a C pointer, a JVM `byte[]`), the idiomatic pattern is:

```rust
let mut key = [0u8; 32];
key.copy_from_slice(&incoming);
let dek = Dek::take(&mut key); // `key` is wiped; only the Dek holds the secret now
```

`Dek::take(&mut src)` copies the bytes into the returned `Dek` and zeroes `src`, so the temporary stack buffer cannot leak the key after the function returns. Both `ffi/functions.rs` and `jni_bridge.rs` follow this pattern; mobile adapters should too when they build a `Dek` from a transient array.

Use `Dek::new(key)` only when the source is not sensitive (test vectors, constants). It takes the key by value and does not touch any upstream copy.

### JNI bridge robustness

`jni_bridge.rs` must not panic across the FFI boundary — doing so unwinds Rust into the JVM and aborts the Android process. Every fallible JNI call (`find_class`, `new_byte_array`, `new_string`, `new_object`, …) returns early with a null `JObject` (or equivalent) on failure. The pending JVM exception (`OutOfMemoryError`, `NoClassDefFoundError`, …) then surfaces to Kotlin on native-method return, giving the app a chance to degrade gracefully instead of dying.

### Key validation

- `validate_dek()` rejects keys that are not exactly 32 bytes.
- Core does not check for weak keys (all-zero, etc.) — AES-256 has no weak-key classes.

### Debug safety

The `Dek` type implements `Debug` as `Dek([REDACTED])`, preventing accidental key leakage in logs, error messages, or panic outputs.

## 3. Data Lifecycle

### Plaintext

- **In-memory**: Plaintext is held in `Vec<u8>` during encryption/decryption. The returned `Vec<u8>` is owned by the caller. Core does not retain internal copies.
- **Streaming**: Plaintext is processed in 64 KB chunks. Only one chunk is in memory at a time. Each chunk buffer is overwritten by the next read.
- **No disk writes**: Core never writes plaintext to disk. File I/O uses caller-provided `Read`/`Write` traits; the platform controls the destination.

### Ciphertext

- Ciphertext includes a 25-byte header, per-chunk length prefixes (streaming), and 16-byte GCM auth tags.
- The header is authenticated as AAD — any modification is detected on decryption.
- Chunk ordering is enforced via chunk-index AAD — reordering or truncation is detected.

### Metadata

- `DocumentMetadata` is serialized as JSON with hex-encoded byte fields.
- The `wrapped_dek` field contains the platform-encrypted DEK, never the raw DEK.
- Metadata validation (`validate()`) checks required fields are non-empty.

## 4. Limits and Boundaries

| Parameter | Limit | Rationale |
|---|---|---|
| Max plaintext (in-memory) | 4 GB | Prevents OOM on mobile devices |
| Max stream chunks | 2^32 | Nonce derivation uses 32-bit chunk index |
| Max stream size | ~256 TB | 2^32 chunks x 64 KB |
| Nonce size | 96 bits (12 bytes) | AES-GCM standard |
| Key size | 256 bits (32 bytes) | AES-256 |
| Auth tag size | 128 bits (16 bytes) | Full GCM tag |
| Chunk size | 64 KB | Balance between memory usage and throughput |
| Header size (V1) | 25 bytes | Fixed for V1 format |

## 5. What Core Does NOT Provide

These are explicitly the platform's responsibility (see [platform contract](platform-contract.md)):

- **Key generation and wrapping** — DEK creation, KEK management, key wrapping/unwrapping
- **Key storage** — secure enclave, keychain, or HSM integration
- **Access control** — authentication, authorization, permissions
- **Transport security** — TLS, certificate pinning
- **Secure deletion** — filesystem-level secure erase
- **Memory locking** — `mlock` / `VirtualLock` to prevent paging secrets to disk
- **Anti-tampering** — app integrity, root/jailbreak detection

## 6. Known Limitations

1. **No memory locking**: DEK bytes may be paged to swap. Platforms should use `mlock` if available.
2. **No side-channel hardening**: AES-GCM uses AES-NI where available (hardware constant-time), but software fallback on older hardware may be vulnerable to cache-timing attacks.
3. **No forward secrecy**: Compromise of a DEK exposes all data encrypted with that key. The platform should rotate DEKs per-document.
4. **GCM nonce reuse is catastrophic**: If the same (key, nonce) pair is ever reused, GCM authentication is broken and key material may leak. The random nonce generation makes this statistically negligible but the platform must never inject duplicate nonces via the test-vectors API.
