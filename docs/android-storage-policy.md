# Android Storage Policy

## Why `noBackupFilesDir`

All encrypted document blobs are stored under `context.noBackupFilesDir`
rather than `filesDir` or external storage. This directory is explicitly
**excluded from Android Auto Backup** (Google Drive backup), which prevents
encrypted blobs from leaking to cloud storage where they could be targeted
for offline attack.

From the Android docs:

> Files in this directory are not included in automatic backup and restore
> operations from Android 6.0 (API level 23) onward.

This is critical because the Device Master Key (DMK) lives in the Android
Keystore and is **not** included in backups. If blobs were backed up but
the DMK was not, restored blobs would be undecryptable — a confusing UX.
Worse, if an attacker obtained a backup, they could attempt brute-force
attacks on the blobs offline.

## File naming convention

```
{noBackupFilesDir}/documents/
    {docId}.enc          # final encrypted blob
    {docId}.enc.tmp      # in-flight write (atomic rename pending)
```

- `docId` is an opaque string (typically a UUID) validated to contain no
  path separators (`/`, `\`) and no `..` sequences.
- The `.enc` extension signals that the file is an encrypted blob in the
  secure-core V1 format.
- `.enc.tmp` files are intermediate artifacts of atomic writes.

## Atomic write protocol

1. Write encrypted bytes to `{docId}.enc.tmp`.
2. Rename `.enc.tmp` to `.enc` (atomic on the same filesystem).
3. On failure, delete the `.enc.tmp` to avoid leaving partial data.

This guarantees that a `.enc` file is either complete or absent — never
partially written.

## Cleanup policy at startup

On application startup, `cleanOrphanedTempFiles()` should be called to
remove any `.enc.tmp` files older than **5 minutes**. These are leftovers
from interrupted writes (process kill, crash, OOM).

The 5-minute threshold avoids deleting temp files from writes that are
still in progress (e.g., a large document being encrypted).

Recommended call site:

```kotlin
class SecureCoreInitializer : Initializer<Unit> {
    override fun create(context: Context) {
        val store = PrivateDirDocumentStore(
            context.noBackupFilesDir.resolve("documents")
        )
        val cleaned = store.cleanOrphanedTempFiles()
        if (cleaned > 0) {
            Log.i("SecureCore", "Cleaned $cleaned orphaned temp files")
        }
    }
}
```
