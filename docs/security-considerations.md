# Security Considerations — secure-core

This document describes the security properties, assumptions, and limits of the `secure-core` library. It complements the [threat model](threat-model.md) and [platform contract](platform-contract.md).

---

## 1. IV / Nonce Uniqueness

### In-memory encryption (`encrypt_bytes`)

Each call generates a fresh 96-bit random nonce with `rand::rng()`, i.e. rand's `ThreadRng`: a ChaCha-based CSPRNG seeded, and periodically reseeded, from the OS entropy source (`getrandom`). It is not a direct OS call per nonce, but it is cryptographically secure under the same assumption (threat model, hypothesis 3). The nonce is embedded in the `.enc` V1 header.

**Collision bound**: With 96-bit random nonces under a single key, the birthday bound gives ~2^48 encryptions before a 50% collision probability. The relevant budget is the NIST SP 800-38D one: at most **2^32** random-nonce invocations per key, to keep the collision probability below 2^-32. With one DEK per document (the platform's practice), a key sees one in-memory encryption, or one stream base nonce, per document version, so this bound is never approached.

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
3. **Zeroization**: The `Dek` struct derives `ZeroizeOnDrop`, so key bytes are overwritten with zeros when the struct is dropped. For raw `[u8; 32]` keys passed to `encrypt_bytes` / `decrypt_bytes`, the caller is responsible for zeroization. Since 0.6.0 the core also wipes:
   - the cipher state: the AES-256 key schedule (which starts with the raw DEK) and the GHASH key inside every `Aes256Gcm`, through the `zeroize` features of `aes-gcm`, `aes`, `ghash` and `polyval`;
   - recovery: `derive_recovery_key` returns `Zeroizing<[u8; 32]>`, `unwrap_dek_with_passphrase` returns a `Dek`, and the intermediate plaintext is wiped;
   - FFI: every buffer handed out (plaintext, unwrapped DEK, JSON) is wiped by `secure_core_free_buffer` before being freed;
   - JNI: the heap copies of the DEK and of the plaintext are `Zeroizing`.

   **Not covered:** copies made by the platform (the JVM `byte[]` returned to Kotlin, Swift `Data`), Argon2's internal working memory, and register or stack spills the compiler may create. The `polyval` ARMv8 PMULL backend (opt-in via `--cfg polyval_armv8`) has no wiping `Drop`; default builds use the software backend, which does.
4. **No persistence**: Core never writes the DEK to disk, logs, or any persistent storage.

### Building a `Dek` at the FFI/JNI boundary

When key material arrives from caller memory (a C pointer, a JVM `byte[]`), the idiomatic pattern is:

```rust
let mut key = [0u8; 32];
key.copy_from_slice(&incoming);
let dek = Dek::take(&mut key); // `key` is wiped; only the Dek holds the secret now
```

`Dek::take(&mut src)` copies the bytes into the returned `Dek` and zeroes `src`, so the temporary stack buffer cannot leak the key after the function returns. Both `ffi/functions.rs` and `jni_bridge.rs` follow this pattern. In JNI, the `Vec<u8>` returned by `convert_byte_array` is a second, heap copy, and is held in `Zeroizing` (since 0.6.0). Mobile adapters should do the same when they build a `Dek` from a transient array.

Use `Dek::new(key)` only when the source is not sensitive (test vectors, constants). It takes the key by value and does not touch any upstream copy.

### JNI bridge robustness

`jni_bridge.rs` must not panic across the FFI boundary — doing so unwinds Rust into the JVM and aborts the Android process. Every fallible JNI call (`find_class`, `new_byte_array`, `new_string`, `new_object`, …) returns early with a null `JObject` (or equivalent) on failure. The pending JVM exception (`OutOfMemoryError`, `NoClassDefFoundError`, …) then surfaces to Kotlin on native-method return, giving the app a chance to degrade gracefully instead of dying.

### Passphrase handling

See also `docs/platform-contract.md` section 4 for the corresponding platform-side obligations (zeroize the UI-held buffer, avoid intermediate immutable Kotlin/Swift `String`, etc.).

`recovery::wrap_dek_with_passphrase` and `recovery::unwrap_dek_with_passphrase` take `&str` — they borrow, never own. The caller keeps control of the passphrase buffer and is responsible for its lifecycle.

- **C FFI path** (`ffi/functions.rs`): the passphrase `&str` is borrowed via `CStr::from_ptr` directly from the caller's `const char*`. Nothing is copied on the Rust side; zeroizing the original C string is the caller's responsibility (platform contract).
- **JNI path** (`jni_bridge.rs`): `env.get_string(&passphrase)` materializes the JVM `String` into a fresh **Rust-owned** `String` on the heap. That allocation is wrapped in `zeroize::Zeroizing<String>`, so its backing buffer is overwritten with zeros on drop — the passphrase does not linger in freed Rust memory after the native call returns. The JVM's own `String` remains under Kotlin's control; the platform layer should call `CharArray.fill('\u0000')` or equivalent on its source buffer to close the remaining window.

What we cannot control: once a passphrase is fed to Argon2id (`argon2::Argon2::hash_password_into`), the third-party crate owns its working memory. Its zeroization of internal state is outside this crate's contract.

### Key validation

- `validate_dek()` rejects keys that are not exactly 32 bytes.
- Core does not check for weak keys (all-zero, etc.) — AES-256 has no weak-key classes.

### Debug safety

The `Dek` type implements `Debug` as `Dek([REDACTED])`, preventing accidental key leakage in logs, error messages, or panic outputs.

## 3. Data Lifecycle

### Plaintext

- **In-memory**: Plaintext is held in `Vec<u8>` during encryption/decryption. The returned `Vec<u8>` is owned by the caller. Core does not retain internal copies.
- **Streaming**: Plaintext is processed in 64 KB chunks, and at most two chunks are held at a time (the one being processed plus one look-ahead, needed to authenticate the final chunk). Chunk plaintext buffers are `Zeroizing` and wiped when dropped (since 0.6.0).
- **Disk writes**: the bytes and stream APIs never touch the filesystem; streaming uses caller-provided `Read`/`Write` traits and the platform controls the destination. The only path that writes plaintext to disk is `decrypt_file` (and its FFI/JNI equivalents), and only to the `output_path` chosen by the platform, which also owns its lifecycle (permissions, `SecureDelete` after use).

### Ciphertext

- Ciphertext includes a 25-byte header, per-chunk length prefixes (streaming), and 16-byte GCM auth tags.
- In-memory: the header is authenticated as AAD, so any modification is detected on decryption.
- Streaming: the header is **not** part of the chunk AAD. The nonce is protected indirectly (it derives every chunk nonce), but `version` and `flags` are not. Readers therefore require `FLAG_STREAM_FINAL_CHUNK` and reject streams without it (since 0.5.0).
- Chunk ordering is enforced via the chunk index (nonce and AAD), so reordering is detected. Truncation is detected via the final-chunk marker, including when the flag has been cleared.
- The migration-only `decrypt_stream_allow_legacy` / `*_allow_legacy` entry points do **not** detect truncation of legacy streams. Use them once to re-encrypt pre-0.3.0 files, never for regular reads.

### Metadata

- `DocumentMetadata` is serialized as JSON with hex-encoded byte fields.
- The `wrapped_dek` field contains the platform-encrypted DEK, never the raw DEK.
- Metadata validation (`validate()`) checks required fields are non-empty.

## 4. Limits and Boundaries

| Parameter | Limit | Rationale |
|---|---|---|
| Max plaintext (in-memory) | 4 GiB on 64-bit, 2 GiB on 32-bit (`armeabi-v7a`) | Prevents OOM on mobile devices (`crypto::MAX_PLAINTEXT_SIZE`) |
| Max stream chunks | 2^31 − 1 (`0x7FFF_FFFF`) | 32-bit chunk index whose top bit is reserved as the V1.1 final-chunk marker (`streaming::MAX_STREAM_CHUNKS`) |
| Max stream size | ~128 TiB | (2^31 − 1) chunks × 64 KiB (`streaming::MAX_STREAM_PLAINTEXT_SIZE`) |
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
2. **Side channels**: on x86/x86_64, AES and GHASH use AES-NI/CLMUL when available. On ARM (Android, iOS) the default build uses RustCrypto's **software** backends: bitsliced ("fixsliced") AES and a software POLYVAL, both designed to be constant-time, so there is no table-lookup cache-timing leak, but they are slower than hardware AES. Hardware ARMv8 AES/PMULL is only used when building with `--cfg aes_armv8` / `--cfg polyval_armv8`. No protection is claimed against power or EM analysis (threat model).
3. **No forward secrecy**: Compromise of a DEK exposes all data encrypted with that key. The platform should rotate DEKs per-document.
4. **GCM nonce reuse is catastrophic**: if the same (key, nonce) pair is ever reused, the XOR of the two plaintexts leaks, and the GHASH authentication key `H` can be recovered, which lets an attacker forge valid ciphertexts under that key. The AES key itself is not revealed. Random nonce generation makes reuse statistically negligible, but the platform must never inject duplicate nonces through the test-vectors API (`_test-vectors` must never be enabled in production builds).
