import Foundation

/// `DocumentStoreProtocol` implementation backed by the app's Application Support directory.
///
/// Documents are stored as `{docId}.enc` inside a `documents/` subdirectory.
/// Writes are atomic: data goes to `{docId}.enc.tmp` first, then is renamed.
/// Both the directory and individual files are excluded from iCloud backup.
///
/// See `docs/ios-storage-policy.md` for rationale.
public final class AppGroupDocumentStore: DocumentStoreProtocol {
    private static let encSuffix = ".enc"
    private static let tmpSuffix = ".enc.tmp"
    private static let orphanAgeSeconds: TimeInterval = 5 * 60 // 5 minutes

    private let baseDir: URL
    private let fileManager: FileManager

    /// Creates a store with a custom base directory (useful for testing).
    public init(baseDir: URL, fileManager: FileManager = .default) {
        self.baseDir = baseDir
        self.fileManager = fileManager
        ensureDirectoryExists()
    }

    /// Creates a store using the default Application Support/documents/ path.
    public convenience init() {
        let appSupport = FileManager.default.urls(
            for: .applicationSupportDirectory, in: .userDomainMask
        ).first!
        let docsDir = appSupport.appendingPathComponent("documents")
        self.init(baseDir: docsDir)
    }

    // MARK: - DocumentStoreProtocol

    public func writeDocument(docId: String, data: Data) throws {
        try validateDocId(docId)
        let target = fileURL(for: docId)
        let tmp = tmpFileURL(for: docId)

        do {
            try data.write(to: tmp, options: .atomic)
            try excludeFromBackup(tmp)

            // Atomic rename: remove existing then move tmp into place
            if fileManager.fileExists(atPath: target.path) {
                _ = try fileManager.replaceItemAt(target, withItemAt: tmp)
            } else {
                try fileManager.moveItem(at: tmp, to: target)
            }

            try excludeFromBackup(target)
        } catch {
            try? fileManager.removeItem(at: tmp)
            throw DocumentStoreError.writeFailure(error.localizedDescription)
        }
    }

    public func readDocument(docId: String) throws -> Data {
        try validateDocId(docId)
        let file = fileURL(for: docId)
        guard fileManager.fileExists(atPath: file.path) else {
            throw DocumentStoreError.documentNotFound(docId: docId)
        }
        do {
            return try Data(contentsOf: file)
        } catch {
            throw DocumentStoreError.readFailure(error.localizedDescription)
        }
    }

    public func readDocumentStream(docId: String) throws -> InputStream {
        try validateDocId(docId)
        let file = fileURL(for: docId)
        guard fileManager.fileExists(atPath: file.path) else {
            throw DocumentStoreError.documentNotFound(docId: docId)
        }
        guard let stream = InputStream(url: file) else {
            throw DocumentStoreError.readFailure("Cannot open stream for \(docId)")
        }
        return stream
    }

    public func deleteDocument(docId: String) throws -> Bool {
        try validateDocId(docId)
        let file = fileURL(for: docId)
        guard fileManager.fileExists(atPath: file.path) else {
            return false
        }
        try fileManager.removeItem(at: file)
        return true
    }

    public func listDocumentIds() throws -> [String] {
        guard fileManager.fileExists(atPath: baseDir.path) else {
            return []
        }
        let contents = try fileManager.contentsOfDirectory(
            at: baseDir, includingPropertiesForKeys: nil)
        return contents
            .filter {
                $0.pathExtension == "enc"
                    && !$0.lastPathComponent.hasSuffix(Self.tmpSuffix)
            }
            .map { $0.deletingPathExtension().lastPathComponent }
            .sorted()
    }

    public func documentExists(docId: String) -> Bool {
        guard (try? validateDocId(docId)) != nil else { return false }
        return fileManager.fileExists(atPath: fileURL(for: docId).path)
    }

    public func cleanOrphanedTempFiles() throws -> Int {
        guard fileManager.fileExists(atPath: baseDir.path) else { return 0 }
        let contents = try fileManager.contentsOfDirectory(
            at: baseDir, includingPropertiesForKeys: [.contentModificationDateKey])

        let cutoff = Date().addingTimeInterval(-Self.orphanAgeSeconds)
        var deleted = 0

        for url in contents {
            guard url.lastPathComponent.hasSuffix(Self.tmpSuffix) else { continue }

            let resourceValues = try url.resourceValues(forKeys: [.contentModificationDateKey])
            guard let modDate = resourceValues.contentModificationDate else { continue }

            if modDate < cutoff {
                try fileManager.removeItem(at: url)
                deleted += 1
            }
        }
        return deleted
    }

    // MARK: - Backup Exclusion

    /// Checks whether the directory is currently excluded from iCloud backup.
    public func isDirectoryExcludedFromBackup() -> Bool {
        let values = try? baseDir.resourceValues(forKeys: [.isExcludedFromBackupKey])
        return values?.isExcludedFromBackup ?? false
    }

    /// Checks whether a specific document file is excluded from iCloud backup.
    public func isDocumentExcludedFromBackup(docId: String) -> Bool {
        let url = fileURL(for: docId)
        let values = try? url.resourceValues(forKeys: [.isExcludedFromBackupKey])
        return values?.isExcludedFromBackup ?? false
    }

    // MARK: - Private

    private func fileURL(for docId: String) -> URL {
        baseDir.appendingPathComponent("\(docId)\(Self.encSuffix)")
    }

    private func tmpFileURL(for docId: String) -> URL {
        baseDir.appendingPathComponent("\(docId)\(Self.tmpSuffix)")
    }

    private func validateDocId(_ docId: String) throws {
        guard !docId.isEmpty else {
            throw DocumentStoreError.invalidDocId("docId must not be empty")
        }
        guard !docId.contains("/"), !docId.contains("\\"), !docId.contains("..") else {
            throw DocumentStoreError.invalidDocId(
                "docId must not contain path separators or '..'")
        }
    }

    private func ensureDirectoryExists() {
        if !fileManager.fileExists(atPath: baseDir.path) {
            try? fileManager.createDirectory(at: baseDir, withIntermediateDirectories: true)
        }
        try? excludeFromBackup(baseDir)
    }

    private func excludeFromBackup(_ url: URL) throws {
        var mutableURL = url
        var resourceValues = URLResourceValues()
        resourceValues.isExcludedFromBackup = true
        try mutableURL.setResourceValues(resourceValues)
    }
}
