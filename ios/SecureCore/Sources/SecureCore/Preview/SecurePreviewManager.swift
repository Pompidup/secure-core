import Foundation

/// Errors specific to preview operations.
public enum PreviewError: Error, Equatable {
    case documentNotFound(docId: String)
    case decryptionFailed(String)
    case fileCreationFailed(String)
}

/// Secure preview manager that decrypts documents for display.
///
/// Strategy by MIME type:
/// - `image/*` → `.inMemory` (no file written to disk)
/// - `text/*` → `.inMemory`
/// - `application/pdf` → `.tempFile` (written to temporary directory)
/// - All others → `.tempFile`
///
/// Temporary files use random UUID filenames to avoid leaking document IDs.
public final class SecurePreviewManager: PreviewManagerProtocol {
    private let previewsDir: URL
    private let documentStore: DocumentStoreProtocol
    private let fileManager: FileManager

    /// Creates a preview manager.
    /// - Parameters:
    ///   - documentStore: The store used to read encrypted documents.
    ///   - previewsDir: Override for the temporary previews directory (useful for testing).
    ///   - fileManager: File manager instance.
    public init(
        documentStore: DocumentStoreProtocol,
        previewsDir: URL? = nil,
        fileManager: FileManager = .default
    ) {
        self.documentStore = documentStore
        self.previewsDir = previewsDir
            ?? FileManager.default.temporaryDirectory.appendingPathComponent("sc_previews")
        self.fileManager = fileManager
        ensureDirectoryExists()
    }

    // MARK: - PreviewManagerProtocol

    public func openPreview(docId: String, mimeType: String) async throws -> PreviewHandle {
        let data: Data
        do {
            data = try documentStore.readDocument(docId: docId)
        } catch {
            throw PreviewError.documentNotFound(docId: docId)
        }

        if shouldUseInMemory(mimeType: mimeType) {
            return .inMemory(data: data, mimeType: mimeType)
        }

        let ext = fileExtension(for: mimeType)
        let filename = UUID().uuidString + ext
        let fileURL = previewsDir.appendingPathComponent(filename)

        do {
            try data.write(to: fileURL, options: .atomic)
        } catch {
            throw PreviewError.fileCreationFailed(error.localizedDescription)
        }

        return .tempFile(url: fileURL, mimeType: mimeType)
    }

    public func releasePreview(_ handle: PreviewHandle) throws {
        guard case .tempFile(let url, _) = handle else { return }
        if fileManager.fileExists(atPath: url.path) {
            try fileManager.removeItem(at: url)
        }
    }

    public func purgeAllPreviews() throws -> Int {
        guard fileManager.fileExists(atPath: previewsDir.path) else { return 0 }
        let contents = try fileManager.contentsOfDirectory(
            at: previewsDir, includingPropertiesForKeys: nil)
        var deleted = 0
        for url in contents {
            try fileManager.removeItem(at: url)
            deleted += 1
        }
        return deleted
    }

    public func purgeExpiredPreviews(maxAge: TimeInterval = 300) throws -> Int {
        guard fileManager.fileExists(atPath: previewsDir.path) else { return 0 }
        let contents = try fileManager.contentsOfDirectory(
            at: previewsDir, includingPropertiesForKeys: [.contentModificationDateKey])
        let cutoff = Date().addingTimeInterval(-maxAge)
        var deleted = 0

        for url in contents {
            let resourceValues = try url.resourceValues(forKeys: [.contentModificationDateKey])
            guard let modDate = resourceValues.contentModificationDate else { continue }
            if modDate < cutoff {
                try fileManager.removeItem(at: url)
                deleted += 1
            }
        }
        return deleted
    }

    // MARK: - Private

    private func shouldUseInMemory(mimeType: String) -> Bool {
        let lower = mimeType.lowercased()
        return lower.hasPrefix("image/") || lower.hasPrefix("text/")
    }

    private func fileExtension(for mimeType: String) -> String {
        switch mimeType.lowercased() {
        case "application/pdf": return ".pdf"
        case "application/zip": return ".zip"
        case "application/msword": return ".doc"
        case "application/vnd.openxmlformats-officedocument.wordprocessingml.document":
            return ".docx"
        default: return ".bin"
        }
    }

    private func ensureDirectoryExists() {
        if !fileManager.fileExists(atPath: previewsDir.path) {
            try? fileManager.createDirectory(
                at: previewsDir, withIntermediateDirectories: true)
        }
    }
}
