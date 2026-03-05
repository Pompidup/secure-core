# React Native API Contract - SecureCore v1

This contract is stable for the entire v1 release line.

## Module Name

`SecureCore` (accessed via `NativeModules.SecureCore` or TurboModule)

## Methods

### `importDocument(uri: string): Promise<{ docId: string }>`

Imports a document from a content URI, encrypts it, and stores it.

**Parameters:**
- `uri` - Android content URI (e.g. `content://...` from a file picker)

**Resolves with:**
- `{ docId: string }` - Unique identifier for the stored document

**Error codes:** `IO_ERROR`, `CRYPTO_ERROR`, `KEY_ERROR`

---

### `decryptToMemory(docId: string): Promise<{ bytes: string, mimeType: string }>`

Decrypts a document and returns its content as base64-encoded bytes.

**Parameters:**
- `docId` - Document identifier returned by `importDocument`

**Resolves with:**
- `bytes` - Base64-encoded plaintext content (no wrap)
- `mimeType` - MIME type of the original document

**Error codes:** `NOT_FOUND`, `CRYPTO_ERROR`, `KEY_ERROR`, `IO_ERROR`

> **Note:** Binary data is returned as base64 because React Native's bridge does not support raw byte arrays. Decode on the JS side with `atob()` or a Buffer library.

---

### `decryptToTempFile(docId: string): Promise<{ uri: string }>`

Decrypts a document to a temporary file and returns a `file://` URI.

**Parameters:**
- `docId` - Document identifier

**Resolves with:**
- `uri` - `file://` URI pointing to the decrypted temp file

**Error codes:** `NOT_FOUND`, `CRYPTO_ERROR`, `KEY_ERROR`, `IO_ERROR`

> **Warning:** The temp file is not automatically purged. Use `PreviewManager` lifecycle hooks or delete it manually after use.

---

### `listDocuments(): Promise<Array<DocumentInfo>>`

Lists all stored documents.

**Resolves with:**
```typescript
Array<{
  docId: string;
  filename: string;
  mimeType: string | null;
  createdAt: number;      // Unix timestamp in milliseconds
  ciphertextSize: number;  // Size in bytes
}>
```

**Error codes:** `IO_ERROR`

---

### `deleteDocument(docId: string): Promise<{ deleted: boolean }>`

Permanently deletes a document (ciphertext blob + metadata).

**Parameters:**
- `docId` - Document identifier

**Resolves with:**
- `{ deleted: true }` on success

**Error codes:** `NOT_FOUND`, `IO_ERROR`

---

## Error Codes

| Code | Meaning |
|------|---------|
| `CRYPTO_ERROR` | Encryption/decryption failure (wrong key, tampered data, bad format) |
| `NOT_FOUND` | Document ID does not exist |
| `INVALID_PARAM` | A parameter is invalid |
| `IO_ERROR` | File system or stream error |
| `KEY_ERROR` | Keystore access denied or key unavailable |

Error messages are intentionally generic and never expose cryptographic internals.

## Usage Example

```javascript
import { NativeModules } from 'react-native';
const { SecureCore } = NativeModules;

// Import
const { docId } = await SecureCore.importDocument(pickerUri);

// List
const docs = await SecureCore.listDocuments();

// Decrypt to memory (base64)
const { bytes, mimeType } = await SecureCore.decryptToMemory(docId);

// Decrypt to temp file
const { uri } = await SecureCore.decryptToTempFile(docId);

// Delete
await SecureCore.deleteDocument(docId);
```
