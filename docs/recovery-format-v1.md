# Recovery Bundle Format V1

## Overview

The recovery bundle enables cloudless document transfer between devices.
A user exports their documents into a single `.zip` archive, protected by a
passphrase-derived key. The bundle can be shared via AirDrop, iCloud Drive,
Google Drive, USB, etc. — it remains **unreadable without the passphrase**.

## Archive Structure

```
recovery_bundle_v1.zip
  manifest.json
  documents/
    {docId}.enc
  metadata/
    {docId}.meta.json
  wraps/
    {docId}.wraps.json
```

### `manifest.json`

```json
{
  "format": "recovery_bundle_v1",
  "version": 1,
  "created_at": "2026-03-06T12:00:00Z",
  "document_count": 3,
  "checksum": "<SHA-256 hex of sorted docId list>"
}
```

| Field | Type | Description |
|-------|------|-------------|
| `format` | string | Must be `"recovery_bundle_v1"`. |
| `version` | integer | Must be `1`. |
| `created_at` | string | ISO 8601 timestamp of export. |
| `document_count` | integer | Number of documents in the bundle. |
| `checksum` | string | SHA-256 hex of the sorted, newline-joined docId list. Integrity check. |

### `documents/{docId}.enc`

The encrypted document file, exactly as stored on the source device.
Uses the original DEK, encrypted with AES-256-GCM (`.enc` V1 format).

### `metadata/{docId}.meta.json`

The `DocumentEntity` / `DocumentRecord` serialized as JSON:

```json
{
  "docId": "abc-123",
  "filename": "passport.pdf",
  "mimeType": "application/pdf",
  "createdAt": 1709726400000,
  "plaintextSize": 204800,
  "ciphertextSize": 204841,
  "contentHash": null
}
```

Note: `wrappedDek` / `wrapsJson` is **not** included here — it is in `wraps/`.

### `wraps/{docId}.wraps.json`

A `WrapsEnvelope` with the `recovery` field populated:

```json
{
  "schema_version": "1.1",
  "device": null,
  "recovery": {
    "schema_version": "1.0",
    "algo": "AES-256-GCM-ARGON2ID",
    "kdf": "argon2id-v19",
    "kdf_params": { "m": 65536, "t": 3, "p": 4 },
    "salt": "<base64 32 bytes>",
    "iv": "<base64 12 bytes>",
    "tag": "<base64 16 bytes>",
    "ciphertext": "<base64 32 bytes>"
  }
}
```

**Note on the two `schema_version` fields.** The outer one belongs to
`WrapsEnvelope` (device / recovery container). The inner one belongs to
`RecoveryWrap` itself and governs the passphrase-derived KDF + cipher
parameters. They evolve independently.

The `device` field is `null` in the bundle — it is re-created on import
using the target device's keystore/keychain.

## Security Properties

1. **No DEK in cleartext** — DEKs are re-wrapped with the passphrase-derived
   recovery key before inclusion. The original device wrap is stripped.
2. **Argon2id KDF** — passphrase is stretched with Argon2id (m=65536 KiB,
   t=3 iterations, p=4 lanes) to resist brute-force attacks.
3. **AES-256-GCM** — each DEK wrap uses a unique random nonce (12 bytes)
   and produces a 16-byte authentication tag.
4. **No cloud dependency** — the bundle is self-contained. Transfer via any
   channel (AirDrop, USB, email attachment). Security relies solely on the
   passphrase, not the transport.

## Export Flow

1. User selects documents to export.
2. App generates or displays a recovery passphrase.
3. For each document:
   a. Unwrap the DEK using the device keystore.
   b. Call `wrap_dek_with_passphrase(dek, passphrase)` via Rust FFI.
   c. Write `.enc`, `.meta.json`, and `.wraps.json` to the zip.
   d. Zeroize the DEK immediately.
4. Write `manifest.json` with document count and checksum.
5. Produce the final `.zip` file.

## Import Flow

1. User provides the bundle file and the recovery passphrase.
2. Parse `manifest.json`, verify format and checksum.
3. For each document:
   a. Read `wraps/{docId}.wraps.json`.
   b. Call `unwrap_dek_with_passphrase(wrap, passphrase)` via Rust FFI.
   c. Wrap the DEK with the local device keystore.
   d. Store the `.enc` file in the document store.
   e. Save metadata with the new device-wrapped DEK.
   f. Zeroize the DEK immediately.
4. Report import results (count, any failures).

## Versioning

### Bundle format (`manifest.json`)

| Version | Status | Notes |
|---------|--------|-------|
| 1 | **Current** | Initial release with Argon2id + AES-256-GCM |

Future versions may add support for additional KDFs or multi-recipient wraps.
The `format` and `version` fields in `manifest.json` enable forward compatibility.

### `RecoveryWrap` schema (`wraps/{docId}.wraps.json → recovery`)

The `RecoveryWrap` carries its own `schema_version` field governing the
passphrase-derived key material.

| `schema_version` | Algo | KDF | Params | Status |
|------------------|------|-----|--------|--------|
| `"1.0"` | `AES-256-GCM-ARGON2ID` | `argon2id-v19` | `m=65536, t=3, p=4` | **Current** |

**Compatibility posture.**

- A `RecoveryWrap` written before versioning was introduced does not carry
  `schema_version` in its JSON. Such blobs deserialize as `"1.0"` — this is
  the deliberate migration path, no user action required.
- A `secure-core` build accepts exactly one version at unwrap time. Blobs
  stamped with an unknown `schema_version` (e.g. a future `"1.1"` or `"2.0"`
  seen by an older client) are rejected with an `InvalidParameter` error;
  callers should surface this as "bundle produced by a newer app version —
  please update".
- A version bump happens when any of the wire-level parameters changes:
  Argon2 m/t/p, KDF identifier, cipher, or tag/nonce length. The `algo`,
  `kdf`, and `kdf_params` fields stay in the JSON for self-description, but
  `schema_version` is the single coarse gate that clients must understand
  before touching the bundle.
