# iOS Preview Policy

## MIME Type Strategy

| MIME pattern | Handle type | Rationale |
|---|---|---|
| `image/*` | `.inMemory` | Images are small enough to hold in RAM; no file touches disk |
| `text/*` | `.inMemory` | Same as images; avoids plaintext leaking to the filesystem |
| `application/pdf` | `.tempFile` | QuickLook requires a file URL; written to `sc_previews/` |
| All others | `.tempFile` | Default to file-based preview for unknown types |

## Temporary File Lifecycle

1. **Creation** -- `openPreview(docId:mimeType:)` decrypts the document and, for temp-file types, writes it to `FileManager.temporaryDirectory/sc_previews/{UUID}.{ext}`. The UUID filename prevents docId leakage.
2. **Display** -- The caller (e.g. `QuickLookPreviewController`) presents the file to the user.
3. **Release** -- `releasePreview(_:)` deletes the temp file immediately.
4. **Background purge** -- `PreviewLifecycleObserver` listens for `willResignActiveNotification` and calls `purgeAllPreviews()` to remove all temp files when the app leaves the foreground.
5. **Foreground cleanup** -- On `willEnterForegroundNotification`, `purgeExpiredPreviews(maxAge: 300)` removes any files older than 5 minutes (covers edge cases where the observer was not active).

## Known Limitations

- **Crash / force-kill**: If the app is killed (e.g. by the OS or a crash) before `willResignActive` fires, temporary preview files may remain on disk. They are cleaned up on the next launch via `purgeAllPreviews()` or `purgeExpiredPreviews()`.
- **In-memory size**: Very large images or text files are loaded fully into memory. A future enhancement could add a size threshold to fall back to temp files.
