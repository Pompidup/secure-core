import Foundation
import Security

/// Errors specific to document service operations.
public enum DocumentServiceError: Error, Equatable {
    case encryptionFailed(String)
    case decryptionFailed(String)
    case randomGenerationFailed
    case metadataNotFound(docId: String)
}

/// Orchestration service that assembles all SecureCore components to provide
/// high-level document import, decrypt, list, and delete operations.
///
/// Guarantees:
/// - DEKs are zeroized immediately after use.
/// - On import failure, partial state (file / metadata) is cleaned up.
/// - Atomic writes via the underlying `DocumentStoreProtocol`.
public final class DocumentService {
    private static let dekLength = 32

    private let secureCoreLib: SecureCoreLibProtocol
    private let keyManager: KeyManagerProtocol
    private let documentStore: DocumentStoreProtocol
    private let metadataRepository: MetadataRepositoryProtocol

    public init(
        secureCoreLib: SecureCoreLibProtocol,
        keyManager: KeyManagerProtocol,
        documentStore: DocumentStoreProtocol,
        metadataRepository: MetadataRepositoryProtocol
    ) {
        self.secureCoreLib = secureCoreLib
        self.keyManager = keyManager
        self.documentStore = documentStore
        self.metadataRepository = metadataRepository
    }

    // MARK: - Public API

    /// Imports a document: generates a DEK, encrypts, stores the blob and metadata.
    /// Returns the generated document ID.
    public func importDocument(data: Data, filename: String, mimeType: String) async throws
        -> String
    {
        let docId = UUID().uuidString

        // Generate DEK
        var dek = try generateRandomBytes(count: Self.dekLength)
        defer { dek.resetBytes(in: dek.startIndex..<dek.endIndex) }

        // Encrypt
        let blob: Data
        do {
            blob = try secureCoreLib.encryptBytes(data, dek: dek)
        } catch {
            throw DocumentServiceError.encryptionFailed(error.localizedDescription)
        }

        // Wrap DEK
        let wrapsJson: Data
        do {
            wrapsJson = try keyManager.wrapDek(dek)
        } catch {
            throw error
        }

        // Store encrypted blob
        do {
            try documentStore.writeDocument(docId: docId, data: blob)
        } catch {
            throw error
        }

        // Save metadata
        let record = DocumentRecord(
            docId: docId,
            filename: filename,
            mimeType: mimeType,
            createdAt: Int64(Date().timeIntervalSince1970 * 1000),
            plaintextSize: Int64(data.count),
            ciphertextSize: Int64(blob.count),
            wrapsJson: String(data: wrapsJson, encoding: .utf8) ?? ""
        )

        do {
            try metadataRepository.save(record)
        } catch {
            // Cleanup: remove the stored blob since metadata save failed
            _ = try? documentStore.deleteDocument(docId: docId)
            throw error
        }

        return docId
    }

    /// Decrypts a document and returns the plaintext bytes.
    public func decryptDocument(docId: String) async throws -> Data {
        let record = try findRecordOrThrow(docId: docId)
        let blob = try documentStore.readDocument(docId: docId)

        guard let wrapsData = record.wrapsJson.data(using: .utf8) else {
            throw DocumentServiceError.decryptionFailed("Invalid wrapsJson encoding")
        }

        var dek = try keyManager.unwrapDek(wrapsData)
        defer { dek.resetBytes(in: dek.startIndex..<dek.endIndex) }

        do {
            return try secureCoreLib.decryptBytes(blob, dek: dek)
        } catch {
            throw DocumentServiceError.decryptionFailed(error.localizedDescription)
        }
    }

    /// Decrypts a document and writes the plaintext to a temporary file.
    /// The caller is responsible for deleting the file when done.
    public func decryptDocumentToTempFile(docId: String, tempDir: URL) async throws -> URL {
        let plaintext = try await decryptDocument(docId: docId)
        let record = try findRecordOrThrow(docId: docId)

        let ext = fileExtension(for: record.mimeType)
        let filename = UUID().uuidString + ext
        let fileURL = tempDir.appendingPathComponent(filename)

        try plaintext.write(to: fileURL, options: .atomic)
        return fileURL
    }

    /// Lists all document metadata records.
    public func listDocuments() async throws -> [DocumentRecord] {
        try metadataRepository.list()
    }

    /// Deletes a document's encrypted file and metadata.
    public func deleteDocument(docId: String) async throws {
        _ = try documentStore.deleteDocument(docId: docId)
        try metadataRepository.delete(docId: docId)
    }

    // MARK: - Private

    private func findRecordOrThrow(docId: String) throws -> DocumentRecord {
        guard let record = try metadataRepository.find(docId: docId) else {
            throw DocumentServiceError.metadataNotFound(docId: docId)
        }
        return record
    }

    private func generateRandomBytes(count: Int) throws -> Data {
        var bytes = [UInt8](repeating: 0, count: count)
        let status = SecRandomCopyBytes(kSecRandomDefault, count, &bytes)
        guard status == errSecSuccess else {
            throw DocumentServiceError.randomGenerationFailed
        }
        return Data(bytes)
    }

    private func fileExtension(for mimeType: String?) -> String {
        switch mimeType?.lowercased() {
        case "application/pdf": return ".pdf"
        case "image/jpeg": return ".jpg"
        case "image/png": return ".png"
        case "text/plain": return ".txt"
        default: return ".bin"
        }
    }
}
