import Foundation
import GRDB

/// Repository for document metadata CRUD operations.
///
/// Wraps GRDB read/write access to the `documents` table.
public final class MetadataRepository: MetadataRepositoryProtocol {
    private let dbQueue: DatabaseQueue

    public init(database: AppDatabase) {
        self.dbQueue = database.dbQueue
    }

    /// Inserts or replaces a document record.
    public func save(_ record: DocumentRecord) throws {
        try dbQueue.write { db in
            try record.save(db)
        }
    }

    /// Finds a document by its ID, or returns `nil`.
    public func find(docId: String) throws -> DocumentRecord? {
        try dbQueue.read { db in
            try DocumentRecord.fetchOne(db, key: docId)
        }
    }

    /// Returns all document records, ordered by creation date (newest first).
    public func list() throws -> [DocumentRecord] {
        try dbQueue.read { db in
            try DocumentRecord
                .order(DocumentRecord.Columns.createdAt.desc)
                .fetchAll(db)
        }
    }

    /// Deletes a document record. Returns `true` if a row was deleted.
    public func delete(docId: String) throws -> Bool {
        try dbQueue.write { db in
            try DocumentRecord.deleteOne(db, key: docId)
        }
    }
}
