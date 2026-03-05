import Foundation

/// Contract for encrypted document storage, mirroring the Android `DocumentStore` interface.
///
/// All documents are stored as `.enc` blobs. Implementations must guarantee
/// atomic writes (no partial files visible) and never log document contents.
public protocol DocumentStoreProtocol {
    /// Writes encrypted data atomically for the given document ID.
    func writeDocument(docId: String, data: Data) throws

    /// Reads the full encrypted blob for the given document ID.
    func readDocument(docId: String) throws -> Data

    /// Returns an `InputStream` for streaming reads of the given document.
    func readDocumentStream(docId: String) throws -> InputStream

    /// Deletes the document. Returns `true` if it existed, `false` otherwise.
    func deleteDocument(docId: String) throws -> Bool

    /// Returns a sorted list of all stored document IDs.
    func listDocumentIds() throws -> [String]

    /// Returns `true` if a document with this ID exists on disk.
    func documentExists(docId: String) -> Bool

    /// Removes `.enc.tmp` files older than 5 minutes. Returns the count deleted.
    func cleanOrphanedTempFiles() throws -> Int
}
