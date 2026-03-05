import Foundation

/// Handle representing a decrypted document ready for preview.
public enum PreviewHandle {
    /// Document held entirely in memory (no file on disk).
    case inMemory(data: Data, mimeType: String)
    /// Document written to a temporary file for QuickLook or similar viewers.
    case tempFile(url: URL, mimeType: String)
}

/// Contract for secure document preview lifecycle management.
///
/// Implementations must ensure that temporary files use non-revealing
/// filenames (no docId) and are purged aggressively on app backgrounding.
public protocol PreviewManagerProtocol {
    /// Decrypts a document and returns a preview handle.
    /// Images and text are returned in-memory; PDFs and other types as temp files.
    func openPreview(docId: String, mimeType: String) async throws -> PreviewHandle

    /// Releases resources associated with a preview handle.
    /// For `.tempFile` handles, the temporary file is deleted.
    func releasePreview(_ handle: PreviewHandle) throws

    /// Deletes all temporary preview files. Returns the count deleted.
    func purgeAllPreviews() throws -> Int

    /// Deletes temporary preview files older than `maxAge`. Returns the count deleted.
    func purgeExpiredPreviews(maxAge: TimeInterval) throws -> Int
}
