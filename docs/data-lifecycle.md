# Data Lifecycle

End-to-end lifecycle of a document in SecureCore V1.

## 1. Import

```
User selects file -> ContentResolver stream -> encrypt in RAM -> write .enc blob -> save metadata
```

- The plaintext is **never written to disk**. It exists only in RAM during encryption.
- A fresh DEK (256-bit AES key) is generated per document.
- The DEK is wrapped by the Keystore KEK and stored in metadata.
- The plaintext DEK is zeroed immediately after use.
- If any step fails, the partially written blob is deleted (atomic rollback).

## 2. Storage at Rest

- **Ciphertext blob:** `noBackupFilesDir/documents/{docId}.enc`
- **Metadata:** Room database (`secure_core.db`) with wrapped DEK, filename, MIME type, timestamps
- **Keystore KEK:** Hardware-backed Android Keystore, non-exportable, device-bound

The blob is AES-256-GCM encrypted. Tampering with any byte causes decryption to fail with an authentication error.

## 3. Preview / Decrypt

| MIME Type | Strategy | Location |
|-----------|----------|----------|
| `image/*` | In-memory | RAM only, no file on disk |
| `text/*` | In-memory | RAM only, no file on disk |
| `application/pdf` | Temp file | `cacheDir/previews/{docId}.preview` |
| Other | Temp file | `cacheDir/previews/{docId}.preview` |

Temp files are purged:
- Immediately when the preview is released
- When the app goes to background (`ON_STOP`)
- On next app launch (expired files > 5 min)

In-memory bytes are zeroed on release.

## 4. Deletion

```
DocumentService.deleteDocument(docId)
  -> delete .enc blob from disk
  -> delete metadata row from database
```

Both the ciphertext and metadata are permanently removed. The wrapped DEK is deleted with the metadata row.

## 5. App Uninstall

Android deletes:
- The entire `noBackupFilesDir` (all `.enc` blobs)
- The app's database directory (`secure_core.db`)
- The Keystore keys associated with the app's UID

**Result: all data is irrecoverable after uninstall.** There is no cloud backup, no export, and the Keystore KEK cannot be extracted.

## 6. Reinstallation

After uninstall + reinstall:
- A new KEK is generated in the Keystore
- No previous documents exist (storage was deleted)
- No previous keys exist (Keystore entries were deleted)

**Previous data cannot be recovered.** This is by design for V1.

## 7. Backup

**Disabled intentionally.** See [android-storage-policy.md](android-storage-policy.md).

- `allowBackup="false"` in the manifest
- Documents stored in `noBackupFilesDir` (excluded from Auto Backup by OS)
- XML rules exclude documents and database from both cloud backup and device transfer
- Even if ciphertext were somehow backed up, it's useless without the device-bound Keystore KEK

## Summary

| Phase | Plaintext on disk? | Ciphertext on disk? | Key on disk? |
|-------|:------------------:|:-------------------:|:------------:|
| Import | No | Yes (.enc) | Wrapped in DB |
| At rest | No | Yes (.enc) | Wrapped in DB |
| Preview (image/text) | No | Yes (.enc) | Wrapped in DB |
| Preview (PDF/other) | Temp file (purged) | Yes (.enc) | Wrapped in DB |
| After deletion | No | No | No |
| After uninstall | No | No | No |
| In backup | No | No | No |
