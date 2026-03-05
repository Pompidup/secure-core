# iOS Database — GRDB (SQLite)

## Why GRDB over CoreData

| Criteria | GRDB | CoreData |
|---|---|---|
| Parity with Android/Room | Direct SQL, same schema | Object graph, different paradigm |
| Testability | In-memory `DatabaseQueue()` | Requires NSPersistentContainer setup |
| Pure Swift | Yes | ObjC runtime dependency |
| Migration control | Explicit versioned migrations | Lightweight + mapping models |
| Bundle size | ~1 MB (SQLite is OS-provided) | Built-in but heavier API surface |

GRDB was chosen because it provides the closest equivalent to Android Room:
explicit SQL table definitions, versioned migrations, and Codable record
mapping. This makes cross-platform schema parity straightforward.

## Database File Location

```
Application Support/database/secure_core.db
```

The database file is excluded from iCloud backup via
`isExcludedFromBackup = true`, matching the document store policy.

## Schema — V1

```sql
CREATE TABLE documents (
    doc_id          TEXT    PRIMARY KEY NOT NULL,
    filename        TEXT    NOT NULL,
    mime_type       TEXT,
    created_at      INTEGER NOT NULL,
    plaintext_size  INTEGER,
    ciphertext_size INTEGER NOT NULL,
    content_hash    TEXT,
    wraps_json      TEXT    NOT NULL
);
```

| Column | Type | Notes |
|---|---|---|
| `doc_id` | TEXT PK | Opaque ID (typically UUID) |
| `filename` | TEXT | Original filename for display |
| `mime_type` | TEXT | MIME type (nullable) |
| `created_at` | INTEGER | Unix timestamp in milliseconds |
| `plaintext_size` | INTEGER | Original file size (nullable) |
| `ciphertext_size` | INTEGER | Encrypted blob size |
| `content_hash` | TEXT | SHA-256 of plaintext (nullable) |
| `wraps_json` | TEXT | Serialized WrapsEnvelope JSON |

## Migration Strategy

Migrations are registered in `AppDatabase.migrate()` using GRDB's
`DatabaseMigrator`. Each migration is named and runs exactly once:

```swift
migrator.registerMigration("v1") { db in
    try db.create(table: "documents") { ... }
}

// Future:
migrator.registerMigration("v2") { db in
    try db.alter(table: "documents") { t in
        t.add(column: "updated_at", .integer)
    }
}
```

Migrations are applied in order. GRDB tracks which migrations have run
in the `grdb_migrations` internal table.

## Reconciliation

At app startup, `ReconciliationService.reconcile()` compares the filesystem
(document store) with the database (metadata repository):

- **Metadata without file**: Row deleted from database.
- **File without metadata**: File moved to quarantine directory.

This handles crashes during write operations where only one of the two
stores was updated.

## Testing

All tests use in-memory databases (`AppDatabase()` with no path), so no
disk I/O or cleanup is needed. Reconciliation tests use temporary
directories that are cleaned up in `tearDown()`.
