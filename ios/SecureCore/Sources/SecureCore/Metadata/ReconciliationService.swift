import Foundation

/// Report produced by reconciliation.
public struct ReconciliationReport: Equatable {
    /// Metadata rows without a matching .enc file (deleted from DB).
    public let orphanedMetadata: Int
    /// .enc files without matching metadata (moved to quarantine).
    public let orphanedFiles: Int
}

/// Reconciles the document store (filesystem) with the metadata repository (database).
///
/// Call `reconcile()` at app startup to detect and resolve inconsistencies.
public final class ReconciliationService {
    private let store: DocumentStoreProtocol
    private let repository: MetadataRepository
    private let documentsDir: URL
    private let quarantineDir: URL
    private let fileManager: FileManager

    public init(
        store: DocumentStoreProtocol,
        repository: MetadataRepository,
        documentsDir: URL,
        quarantineDir: URL,
        fileManager: FileManager = .default
    ) {
        self.store = store
        self.repository = repository
        self.documentsDir = documentsDir
        self.quarantineDir = quarantineDir
        self.fileManager = fileManager
    }

    /// Compares filesystem and database, cleaning up orphans.
    ///
    /// - Metadata without a matching .enc file: metadata row is deleted.
    /// - .enc file without matching metadata: file is moved to quarantine.
    public func reconcile() throws -> ReconciliationReport {
        try fileManager.createDirectory(at: quarantineDir, withIntermediateDirectories: true)

        let fileIds = Set(try store.listDocumentIds())
        let metadataList = try repository.list()
        let metadataIds = Set(metadataList.map(\.docId))

        // Case 1: metadata without file
        let orphanedMeta = metadataIds.subtracting(fileIds)
        for docId in orphanedMeta {
            _ = try repository.delete(docId: docId)
        }

        // Case 2: file without metadata
        let orphanedFiles = fileIds.subtracting(metadataIds)
        for docId in orphanedFiles {
            let source = documentsDir.appendingPathComponent("\(docId).enc")
            let dest = quarantineDir.appendingPathComponent("\(docId).enc")
            if fileManager.fileExists(atPath: source.path) {
                do {
                    try fileManager.moveItem(at: source, to: dest)
                } catch {
                    _ = try? store.deleteDocument(docId: docId)
                }
            }
        }

        return ReconciliationReport(
            orphanedMetadata: orphanedMeta.count,
            orphanedFiles: orphanedFiles.count
        )
    }
}
