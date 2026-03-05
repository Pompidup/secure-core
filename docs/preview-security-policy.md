# Preview Security Policy

## Principle

No preview file is durable. All decrypted content rendered for preview must be ephemeral and purged as aggressively as possible.

## Preview Strategies by MIME Type

| MIME Type       | Strategy   | Rationale                                        |
|-----------------|------------|--------------------------------------------------|
| `image/*`       | In-memory  | Decrypted bytes stay in RAM only, no file on disk |
| `text/*`        | In-memory  | Same as images                                    |
| `application/pdf` | Temp file | PDF renderers require a file descriptor           |
| Other           | Temp file  | Fallback for unknown types                        |

## Purge Guarantees

| Event                        | Action                     |
|------------------------------|----------------------------|
| `releasePreview(TempFile)`   | File deleted immediately   |
| `releasePreview(InMemory)`   | Byte array zeroed          |
| App goes to background (ON_STOP) | All preview files purged |
| App returns to foreground (ON_START) | Expired previews purged (> 5 min) |
| App startup                  | Expired previews purged    |
| New preview opened           | Expired previews purged    |

## Known Limitation

A brutal crash (process kill, OOM) may leave a temporary preview file on disk. This file will be purged on the next app launch when `purgeExpiredPreviews()` runs during startup.

## Integration

The `LifecyclePreviewPurger` must be registered on `ProcessLifecycleOwner` in the Application class:

```kotlin
ProcessLifecycleOwner.get().lifecycle.addObserver(
    LifecyclePreviewPurger(previewManager)
)
```
