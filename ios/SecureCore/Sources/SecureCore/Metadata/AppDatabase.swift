import Foundation
import GRDB

/// Manages the SQLite database for document metadata.
///
/// Uses GRDB with versioned migrations. The database file is excluded from
/// iCloud backup (see `docs/ios-database.md`).
public final class AppDatabase {
    public let dbQueue: DatabaseQueue

    /// Creates a database with a file on disk.
    public init(path: String) throws {
        dbQueue = try DatabaseQueue(path: path)
        try migrate(dbQueue)
        try excludeFromBackup(URL(fileURLWithPath: path))
    }

    /// Creates an in-memory database (for tests).
    public init() throws {
        dbQueue = try DatabaseQueue()
        try migrate(dbQueue)
    }

    /// Creates a shared database at the default Application Support location.
    public static func makeShared() throws -> AppDatabase {
        let appSupport = FileManager.default.urls(
            for: .applicationSupportDirectory, in: .userDomainMask
        ).first!
        let dbDir = appSupport.appendingPathComponent("database")
        try FileManager.default.createDirectory(
            at: dbDir, withIntermediateDirectories: true)
        let dbPath = dbDir.appendingPathComponent("secure_core.db").path
        return try AppDatabase(path: dbPath)
    }

    // MARK: - Migrations

    private func migrate(_ db: DatabaseQueue) throws {
        var migrator = DatabaseMigrator()

        migrator.registerMigration("v1") { db in
            try db.create(table: "documents") { t in
                t.primaryKey("doc_id", .text).notNull()
                t.column("filename", .text).notNull()
                t.column("mime_type", .text)
                t.column("created_at", .integer).notNull()
                t.column("plaintext_size", .integer)
                t.column("ciphertext_size", .integer).notNull()
                t.column("content_hash", .text)
                t.column("wraps_json", .text).notNull()
            }
        }

        try migrator.migrate(db)
    }

    // MARK: - Backup Exclusion

    private func excludeFromBackup(_ url: URL) throws {
        var mutableURL = url
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        try mutableURL.setResourceValues(values)
    }
}
