# iOS Storage Policy

## Storage Location

All encrypted document blobs are stored under:

```
Application Support/documents/
    {docId}.enc          # final encrypted blob
    {docId}.enc.tmp      # in-flight write (atomic rename pending)
```

`Application Support` is used instead of `Documents/` or `tmp/` because:

- It is not user-visible in the Files app.
- It survives app updates.
- It can be excluded from iCloud backup on a per-file basis.

## iCloud Backup Exclusion

Both the `documents/` directory **and** each individual `.enc` file are
marked with `isExcludedFromBackupKey = true`. This prevents encrypted blobs
from being included in iCloud or local backups.

This is critical because the Device Master Key (DMK) lives in the Keychain
with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` and is **not** included
in iCloud Keychain sync or unencrypted backups. If blobs were backed up but
the DMK was not, restored blobs would be undecryptable.

### Defense in Depth

- **Directory-level**: `isExcludedFromBackup = true` on the `documents/` dir.
- **File-level**: Each `.enc` and `.enc.tmp` file is individually excluded
  after creation.
- Even if a file were somehow backed up, the ciphertext is useless without
  the Keychain DMK (which is device-bound and non-exportable).

## File Naming Convention

- `docId` is an opaque string (typically a UUID) validated to contain no
  path separators (`/`, `\`) and no `..` sequences.
- The `.enc` extension signals an encrypted blob in the secure-core V1 format.
- `.enc.tmp` files are intermediate artifacts of atomic writes.

## Atomic Write Protocol

1. Write encrypted bytes to `{docId}.enc.tmp`.
2. Apply `isExcludedFromBackup = true` on the temp file.
3. Rename `.enc.tmp` to `.enc` via `FileManager.replaceItemAt(_:withItemAt:)`.
4. Apply `isExcludedFromBackup = true` on the final `.enc` file.
5. On failure: delete the `.enc.tmp` to avoid leaving partial data.

This guarantees that a `.enc` file is either complete or absent — never
partially written.

## Cleanup Policy at Startup

On application startup, `cleanOrphanedTempFiles()` should be called to
remove any `.enc.tmp` files older than **5 minutes**. These are leftovers
from interrupted writes (process kill, crash, OOM).

The 5-minute threshold avoids deleting temp files from writes that are
still in progress (e.g., a large document being encrypted).

Recommended call site:

```swift
func application(_ application: UIApplication,
                 didFinishLaunchingWithOptions launchOptions: ...) -> Bool {
    let store = AppGroupDocumentStore()
    let cleaned = try? store.cleanOrphanedTempFiles()
    if let cleaned = cleaned, cleaned > 0 {
        print("SecureCore: cleaned \(cleaned) orphaned temp files")
    }
    return true
}
```

## Reinstallation Behavior

When the app is deleted:
- Files in Application Support are **deleted by the OS**.
- Keychain items **may persist** (iOS does not guarantee deletion).

On reinstall:
- Document blobs are gone (expected — they must be re-provisioned from server).
- If the Keychain DMK survived, it is orphaned but harmless.

## Known Limitations

- A jailbroken device with file system access can copy any file. This is
  out of scope for V1.
- `isExcludedFromBackup` is advisory; Apple could change backup behavior
  in future iOS versions. The Keychain DMK being device-bound provides the
  ultimate protection.
