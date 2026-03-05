# Android Storage Policy

## Storage Location

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

## Backup Policy

### V1 Promise

**No document ever leaves the device via Android backup mechanisms.**

### Configuration

#### `AndroidManifest.xml`

```xml
<application
    android:allowBackup="false"
    android:fullBackupContent="@xml/backup_rules"
    android:dataExtractionRules="@xml/data_extraction_rules" />
```

- `allowBackup="false"` — Disables Auto Backup entirely as the primary control
- `fullBackupContent` — Defense-in-depth exclusion rules for Android < 12
- `dataExtractionRules` — Defense-in-depth exclusion rules for Android 12+

#### `backup_rules.xml` (Android < 12)

Excludes:
- `documents/` directory (encrypted blobs)
- `secure_core.db` (metadata database)
- All SharedPreferences

#### `data_extraction_rules.xml` (Android 12+)

Excludes from both **cloud backup** and **device-to-device transfer**:
- `documents/` directory
- All databases

### Defense in Depth

Even if `allowBackup` were somehow overridden by the consuming app:
1. Documents are in `noBackupFilesDir` (never backed up regardless of XML rules)
2. XML rules explicitly exclude the documents directory and database
3. Even if backed up, the ciphertext is useless without the Keystore KEK (which is non-exportable and device-bound)

### Known Limitations

- A rooted device with manual backup tools (e.g., `adb backup` with root) can copy any file. This is out of scope for V1.
- `allowBackup="false"` is set on the library manifest. If the consuming app overrides it to `true`, the XML exclusion rules and `noBackupFilesDir` still protect the data.

### Verified By

- `BackupPolicyTest.testDocumentsDir_isInNoBackupFilesDir`
- `BackupPolicyTest.testAllowBackup_isFalse`
- `BackupPolicyTest.testEncFilesNotInBackupableDir`
