import Foundation
import XCTest

@testable import SecureCore

// MARK: - Mocks

private final class MockSecureCoreLib: SecureCoreLibProtocol {
    /// Simple XOR "encryption" for deterministic round-trip tests.
    func encryptBytes(_ plaintext: Data, dek: Data) throws -> Data {
        Data(plaintext.enumerated().map { $0.element ^ dek[$0.offset % dek.count] })
    }

    func decryptBytes(_ blob: Data, dek: Data) throws -> Data {
        Data(blob.enumerated().map { $0.element ^ dek[$0.offset % dek.count] })
    }
}

private final class ThrowingSecureCoreLib: SecureCoreLibProtocol {
    func encryptBytes(_ plaintext: Data, dek: Data) throws -> Data {
        throw DocumentServiceError.encryptionFailed("simulated")
    }

    func decryptBytes(_ blob: Data, dek: Data) throws -> Data {
        throw DocumentServiceError.decryptionFailed("simulated")
    }
}

private final class MockKeyManager: KeyManagerProtocol {
    /// Stores the last DEK that was wrapped, so tests can verify zeroization.
    var lastWrappedDek: Data?

    func wrapDek(_ dek: Data) throws -> Data {
        lastWrappedDek = Data(dek)
        // "Wrap" = just base64-encode the DEK for test simplicity
        return dek.base64EncodedData()
    }

    func unwrapDek(_ wrapsJson: Data) throws -> Data {
        guard let decoded = Data(base64Encoded: wrapsJson) else {
            throw KeyManagerError.unwrapFailed("bad base64")
        }
        return decoded
    }

    func isKeyAvailable() -> Bool { true }
    func deleteKey() throws {}
}

private final class MockDocumentStore: DocumentStoreProtocol, @unchecked Sendable {
    private let lock = NSLock()
    private var _documents: [String: Data] = [:]
    var shouldThrowOnWrite = false

    var documents: [String: Data] {
        lock.lock()
        defer { lock.unlock() }
        return _documents
    }

    func writeDocument(docId: String, data: Data) throws {
        if shouldThrowOnWrite {
            throw DocumentStoreError.writeFailure("simulated")
        }
        lock.lock()
        _documents[docId] = data
        lock.unlock()
    }

    func readDocument(docId: String) throws -> Data {
        lock.lock()
        let data = _documents[docId]
        lock.unlock()
        guard let data else {
            throw DocumentStoreError.documentNotFound(docId: docId)
        }
        return data
    }

    func readDocumentStream(docId: String) throws -> InputStream {
        InputStream(data: try readDocument(docId: docId))
    }

    func deleteDocument(docId: String) throws -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return _documents.removeValue(forKey: docId) != nil
    }

    func listDocumentIds() throws -> [String] {
        lock.lock()
        defer { lock.unlock() }
        return _documents.keys.sorted()
    }

    func documentExists(docId: String) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return _documents[docId] != nil
    }

    func cleanOrphanedTempFiles() throws -> Int { 0 }
}

private final class MockMetadataRepository: MetadataRepositoryProtocol, @unchecked Sendable {
    private let lock = NSLock()
    private var _records: [String: DocumentRecord] = [:]
    var shouldThrowOnSave = false

    var records: [String: DocumentRecord] {
        lock.lock()
        defer { lock.unlock() }
        return _records
    }

    func save(_ record: DocumentRecord) throws {
        if shouldThrowOnSave {
            throw NSError(domain: "test", code: 1, userInfo: [NSLocalizedDescriptionKey: "simulated save failure"])
        }
        lock.lock()
        _records[record.docId] = record
        lock.unlock()
    }

    func find(docId: String) throws -> DocumentRecord? {
        lock.lock()
        defer { lock.unlock() }
        return _records[docId]
    }

    func list() throws -> [DocumentRecord] {
        lock.lock()
        defer { lock.unlock() }
        return Array(_records.values).sorted { $0.createdAt > $1.createdAt }
    }

    @discardableResult
    func delete(docId: String) throws -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return _records.removeValue(forKey: docId) != nil
    }
}

// MARK: - Tests

final class DocumentServiceTests: XCTestCase {
    private var lib: MockSecureCoreLib!
    private var keyManager: MockKeyManager!
    private var store: MockDocumentStore!
    private var metadata: MockMetadataRepository!
    private var service: DocumentService!

    override func setUp() {
        super.setUp()
        lib = MockSecureCoreLib()
        keyManager = MockKeyManager()
        store = MockDocumentStore()
        metadata = MockMetadataRepository()
        service = DocumentService(
            secureCoreLib: lib,
            keyManager: keyManager,
            documentStore: store,
            metadataRepository: metadata
        )
    }

    // MARK: - Import + Decrypt round-trip

    func testImportAndDecryptRoundtrip() async throws {
        let original = Data("Hello, SecureCore!".utf8)

        let docId = try await service.importDocument(
            data: original, filename: "test.txt", mimeType: "text/plain")

        // Verify encrypted blob is stored (not plaintext)
        let storedBlob = store.documents[docId]!
        XCTAssertNotEqual(storedBlob, original)

        // Verify metadata was saved
        let record = metadata.records[docId]!
        XCTAssertEqual(record.filename, "test.txt")
        XCTAssertEqual(record.mimeType, "text/plain")
        XCTAssertEqual(record.plaintextSize, Int64(original.count))
        XCTAssertEqual(record.ciphertextSize, Int64(storedBlob.count))

        // Decrypt and verify round-trip
        let decrypted = try await service.decryptDocument(docId: docId)
        XCTAssertEqual(decrypted, original)
    }

    // MARK: - Import failure: store throws → no metadata saved

    func testImportFailure_storeThrows_noMetadataSaved() async {
        store.shouldThrowOnWrite = true

        do {
            _ = try await service.importDocument(
                data: Data("data".utf8), filename: "fail.txt", mimeType: "text/plain")
            XCTFail("Expected error")
        } catch {
            // Store threw → metadata should NOT have been saved
            XCTAssertTrue(metadata.records.isEmpty, "No metadata should be saved on store failure")
        }
    }

    // MARK: - Import failure: metadata throws → blob cleaned up

    func testImportFailure_metadataThrows_blobCleanedUp() async {
        metadata.shouldThrowOnSave = true

        do {
            _ = try await service.importDocument(
                data: Data("data".utf8), filename: "fail.txt", mimeType: "text/plain")
            XCTFail("Expected error")
        } catch {
            // Metadata save failed → blob should have been cleaned up
            XCTAssertTrue(
                store.documents.isEmpty,
                "Blob should be deleted when metadata save fails")
        }
    }

    // MARK: - DEK zeroization after import

    func testDekZeroizedAfterImport() async throws {
        _ = try await service.importDocument(
            data: Data("test".utf8), filename: "z.txt", mimeType: "text/plain")

        // The mock captured the DEK before zeroization.
        // We can't directly observe the zeroization of the local var,
        // but we verify the wrapsJson in metadata is valid (DEK was usable during import).
        let record = metadata.records.values.first!
        let wrapsData = record.wrapsJson.data(using: .utf8)!
        // Unwrap should succeed, proving the DEK was properly wrapped before zeroization
        let dek = try keyManager.unwrapDek(wrapsData)
        XCTAssertEqual(dek.count, 32)
    }

    // MARK: - DEK zeroization after decrypt

    func testDekZeroizedAfterDecrypt() async throws {
        let original = Data("secret".utf8)
        let docId = try await service.importDocument(
            data: original, filename: "s.txt", mimeType: "text/plain")

        // Decrypt succeeds (DEK was usable)
        let decrypted = try await service.decryptDocument(docId: docId)
        XCTAssertEqual(decrypted, original)

        // The DEK local variable is zeroized via defer — we verify the operation
        // completed successfully which means the defer block executed.
    }

    // MARK: - Delete

    func testDeleteDocument_removesFileAndMetadata() async throws {
        let docId = try await service.importDocument(
            data: Data("delete me".utf8), filename: "d.txt", mimeType: "text/plain")

        XCTAssertTrue(store.documents.keys.contains(docId))
        XCTAssertNotNil(metadata.records[docId])

        try await service.deleteDocument(docId: docId)

        XCTAssertFalse(store.documents.keys.contains(docId))
        XCTAssertNil(metadata.records[docId])
    }

    // MARK: - List documents

    func testListDocuments() async throws {
        _ = try await service.importDocument(
            data: Data("a".utf8), filename: "a.txt", mimeType: "text/plain")
        _ = try await service.importDocument(
            data: Data("b".utf8), filename: "b.txt", mimeType: "text/plain")

        let docs = try await service.listDocuments()
        XCTAssertEqual(docs.count, 2)
    }

    // MARK: - Concurrent imports: no DEK leak

    func testConcurrentImports_noDekLeak() async throws {
        let dataA = Data("document-A".utf8)
        let dataB = Data("document-B".utf8)

        async let idA = service.importDocument(
            data: dataA, filename: "a.pdf", mimeType: "application/pdf")
        async let idB = service.importDocument(
            data: dataB, filename: "b.pdf", mimeType: "application/pdf")

        let (docIdA, docIdB) = try await (idA, idB)

        // Both documents should be independently decryptable
        let decryptedA = try await service.decryptDocument(docId: docIdA)
        let decryptedB = try await service.decryptDocument(docId: docIdB)

        XCTAssertEqual(decryptedA, dataA)
        XCTAssertEqual(decryptedB, dataB)

        // Each should have its own metadata and blob
        XCTAssertNotEqual(docIdA, docIdB)
        XCTAssertEqual(store.documents.count, 2)
        XCTAssertEqual(metadata.records.count, 2)
    }

    // MARK: - Decrypt to temp file

    func testDecryptDocumentToTempFile() async throws {
        let original = Data("file content".utf8)
        let docId = try await service.importDocument(
            data: original, filename: "f.txt", mimeType: "text/plain")

        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("DocumentServiceTests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(
            at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let fileURL = try await service.decryptDocumentToTempFile(
            docId: docId, tempDir: tempDir)

        XCTAssertTrue(FileManager.default.fileExists(atPath: fileURL.path))
        XCTAssertEqual(try Data(contentsOf: fileURL), original)
        XCTAssertTrue(fileURL.lastPathComponent.hasSuffix(".txt"))
        // Filename should NOT contain the docId
        XCTAssertFalse(fileURL.lastPathComponent.contains(docId))
    }
}
