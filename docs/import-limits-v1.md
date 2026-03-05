# Import Limits - V1

## Supported MIME Types

| MIME Type | Extension | Category |
|-----------|-----------|----------|
| `image/jpeg` | .jpg, .jpeg | Image |
| `image/png` | .png | Image |
| `image/webp` | .webp | Image |
| `application/pdf` | .pdf | Document |
| `text/plain` | .txt | Text |

Any other MIME type is rejected with `UNSUPPORTED_TYPE`.

## Size Limit

- **Maximum:** 50 MB per document
- Checked before reading the full content (via `ContentResolver` cursor size)
- Text imports (`importFromText`) are also size-checked
- Rejected with `FILE_TOO_LARGE` error code

## Import Flow

```
User picks file (content:// URI)
  -> ImportService.importFromUri()
    -> validateUri()         — can we open the stream?
    -> resolveMimeType()     — is it in the allowed set?
    -> resolveSize()         — is it under 50 MB?
    -> DocumentService.importDocument(stream, filename, mimeType)
      -> encrypt in memory
      -> write .enc blob
      -> save metadata
      -> return docId
```

## No Intermediate Plaintext Files

**Guarantee:** At no point during import is a plaintext copy of the document written to disk.

The import flow reads from the `ContentResolver` stream directly into memory, encrypts it there, and writes only the ciphertext blob to the app's private storage. The plaintext exists only in RAM for the duration of the encryption operation.

## Cancellation / Failure Behavior

If import fails at any stage:

| Failure Point | Cleanup |
|---------------|---------|
| URI not accessible | Nothing to clean up |
| MIME type rejected | Nothing to clean up |
| Size exceeded | Nothing to clean up |
| Encryption fails | DEK zeroed, no blob written |
| Blob written but metadata save fails | `DocumentService` deletes the orphaned blob |
| Exception during any step | `DocumentService` catch block deletes blob + zeros DEK |

Result: **no orphaned `.enc` files** after a failed import.

## Error Codes (JS)

| Code | When |
|------|------|
| `UNSUPPORTED_TYPE` | MIME type not in the V1 allowed set |
| `FILE_TOO_LARGE` | File exceeds 50 MB |
| `URI_ERROR` | Content URI cannot be opened |
| `CRYPTO_ERROR` | Encryption failed |
| `IO_ERROR` | File system error during blob write |
| `KEY_ERROR` | Keystore unavailable for DEK wrapping |
