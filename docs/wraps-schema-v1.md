# WrapsEnvelope Schema V1 — Frozen Specification

## Overview

The `WrapsEnvelope` is the canonical JSON structure used to store a wrapped (encrypted)
Data Encryption Key (DEK). It is stored in the metadata database alongside each encrypted
document and must be identical in structure across all platforms (Android, iOS, desktop).

## JSON Schema

```json
{
  "schema_version": "1.1",
  "device": {
    "algo": "AES-256-GCM-KEYSTORE",
    "key_alias": "secure_core_master_key_v1",
    "iv": "<base64 12 bytes>",
    "tag": "<base64 16 bytes>",
    "ciphertext": "<base64 N bytes>"
  },
  "recovery": null
}
```

## Field Definitions

### Top-Level

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `schema_version` | string | YES | Schema version. Must be `"1.1"` for this spec. |
| `device` | object | YES | Device-local wrap using OS keystore. MUST NOT be null. |
| `recovery` | object\|null | NO | Recovery wrap for cross-device restore. null in V1. |

### `device` Object

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `algo` | string | YES | Wrapping algorithm identifier (human-readable, not an integer). |
| `key_alias` | string | YES | Alias of the master key in the OS keystore/keychain. |
| `iv` | string | YES | Base64-encoded initialization vector (12 bytes for GCM). |
| `tag` | string | YES | Base64-encoded authentication tag (16 bytes for GCM). |
| `ciphertext` | string | YES | Base64-encoded wrapped DEK ciphertext (without tag). |

### `recovery` Object (null in V1, populated in recovery bundles)

When non-null, contains a passphrase-derived wrap of the DEK for cross-device
transfer. Used exclusively in recovery bundles (see `docs/recovery-format-v1.md`).

```json
"recovery": {
  "algo": "AES-256-GCM-ARGON2ID",
  "kdf": "argon2id-v19",
  "kdf_params": { "m": 65536, "t": 3, "p": 4 },
  "salt": "<base64 32 bytes>",
  "iv": "<base64 12 bytes>",
  "tag": "<base64 16 bytes>",
  "ciphertext": "<base64 32 bytes>"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `algo` | string | YES | `"AES-256-GCM-ARGON2ID"` |
| `kdf` | string | YES | `"argon2id-v19"` (Argon2id version 0x13) |
| `kdf_params` | object | YES | `{ "m": 65536, "t": 3, "p": 4 }` — memory (KiB), iterations, parallelism |
| `salt` | string | YES | Base64-encoded 32-byte random salt for Argon2id |
| `iv` | string | YES | Base64-encoded 12-byte nonce for AES-256-GCM |
| `tag` | string | YES | Base64-encoded 16-byte GCM authentication tag |
| `ciphertext` | string | YES | Base64-encoded 32-byte wrapped DEK |

The passphrase is **never stored** in the envelope or bundle.

## Rules

1. **`device` is MANDATORY** — a null `device` field is a fatal validation error.
2. **`recovery` is OPTIONAL** — null in V1, non-null in V2+. Readers must tolerate null.
3. **`algo` is a stable string** — not an integer, for cross-platform readability.
   Known values:
   - `"AES-256-GCM-KEYSTORE"` — Android Keystore AES-256-GCM
   - `"AES-256-GCM-KEYCHAIN"` — iOS Keychain AES-256-GCM (future)
4. **Binary values use standard base64** — RFC 4648, NOT URL-safe, with `=` padding.
5. **`key_alias` identifies the master key** — which key in the Keystore/Keychain
   was used for wrapping. This enables key rotation and multi-key scenarios.
6. **`schema_version` is checked on read** — readers must reject versions they
   don't support with `WRAP_VERSION_TOO_NEW`.

## Wire Format (Android)

On Android, `KeystoreKeyManager` produces the `device` fields as follows:
- `iv` = `Cipher.getIV()` (12 bytes, base64)
- `ciphertext` + `tag` = `Cipher.doFinal(dek)` — GCM appends the 16-byte tag to ciphertext.
  Split: `ciphertext = output[0..output.len-16]`, `tag = output[output.len-16..]`
- `algo` = `"AES-256-GCM-KEYSTORE"`
- `key_alias` = the alias passed to `KeyGenParameterSpec.Builder`

## Wire Format (iOS, future)

On iOS, `SecureEnclaveKeyManager` will produce:
- `algo` = `"AES-256-GCM-KEYCHAIN"`
- `key_alias` = Keychain item label
- Same `iv`, `tag`, `ciphertext` split

## Versioning

| Schema Version | Status | Changes |
|---------------|--------|---------|
| `1.1` | **Current, frozen** | Initial stable release |

Future schema versions (e.g., `1.2`) may add optional fields to `device` or introduce
`recovery`. The `schema_version` field enables readers to detect and handle new formats.

## Storage

The `WrapsEnvelope` is serialized as a JSON string and stored:
- **Android**: `documents.wrapped_dek` column (TEXT) in Room database
- **iOS** (future): Core Data or SQLite equivalent
- **Rust core**: `DocumentMetadata.wrapped_dek` field (`WrapsEnvelope` struct)

## Cross-Platform Contract

All platforms MUST:
1. Produce valid `WrapsEnvelope` JSON on wrap
2. Parse and validate `WrapsEnvelope` JSON on unwrap
3. Check `schema_version` and reject unknown versions
4. Reject null `device`
5. Tolerate null `recovery` (V1)
6. Use standard base64 encoding for binary fields
