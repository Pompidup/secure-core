import Foundation
import XCTest

@testable import SecureCore

/// Tests verifying that plaintext never leaks to disk in unprotected locations.
final class AntiLeakTests: XCTestCase {
    private var storeDir: URL!
    private var previewsDir: URL!
    private var store: AppGroupDocumentStore!
    private var previewManager: SecurePreviewManager!
    private var lib: XORCryptoLib!
    private var keyManager: InMemoryKeyManager!
    private var metadata: InMemoryMetadataRepository!
    private var service: DocumentService!

    /// Known plaintext that must never appear on disk unencrypted.
    private let sentinel = "SUPER_SECRET_PLAINTEXT_CANARY_12345"

    override func setUp() {
        super.setUp()
        let base = FileManager.default.temporaryDirectory
            .appendingPathComponent("AntiLeakTests-\(UUID().uuidString)")
        storeDir = base.appendingPathComponent("documents")
        previewsDir = base.appendingPathComponent("sc_previews")

        store = AppGroupDocumentStore(baseDir: storeDir)
        previewManager = SecurePreviewManager(
            documentStore: store, previewsDir: previewsDir)
        lib = XORCryptoLib()
        keyManager = InMemoryKeyManager()
        metadata = InMemoryMetadataRepository()
        service = DocumentService(
            secureCoreLib: lib,
            keyManager: keyManager,
            documentStore: store,
            metadataRepository: metadata
        )
    }

    override func tearDown() {
        let base = storeDir.deletingLastPathComponent()
        try? FileManager.default.removeItem(at: base)
        super.tearDown()
    }

    // MARK: - testImport_noClearTextInDocumentsDir

    func testImport_noClearTextInDocumentsDir() async throws {
        let plaintext = Data(sentinel.utf8)

        _ = try await service.importDocument(
            data: plaintext, filename: "secret.txt", mimeType: "text/plain")

        // Scan the store directory: no file should contain the plaintext sentinel
        let storeFiles = try FileManager.default.contentsOfDirectory(
            at: storeDir, includingPropertiesForKeys: nil)

        for file in storeFiles {
            let contents = try Data(contentsOf: file)
            XCTAssertFalse(
                contents.range(of: Data(sentinel.utf8)) != nil,
                "Plaintext found in \(file.lastPathComponent)")
        }

        // Previews directory should be empty (no preview was opened)
        let previewFiles = try FileManager.default.contentsOfDirectory(
            at: previewsDir, includingPropertiesForKeys: nil)
        XCTAssertTrue(previewFiles.isEmpty, "No preview files should exist after import")
    }

    // MARK: - testPreviewClosed_noTempFileRemaining

    func testPreviewClosed_noTempFileRemaining() async throws {
        let pdfData = Data("%PDF-1.4 fake content".utf8)
        try store.writeDocument(docId: "pdf-doc", data: pdfData)

        let handle = try await previewManager.openPreview(
            docId: "pdf-doc", mimeType: "application/pdf")

        guard case .tempFile = handle else {
            XCTFail("Expected tempFile handle for PDF")
            return
        }

        // Verify file exists before release
        let beforeRelease = try FileManager.default.contentsOfDirectory(
            at: previewsDir, includingPropertiesForKeys: nil)
        XCTAssertEqual(beforeRelease.count, 1)

        // Close preview
        try previewManager.releasePreview(handle)

        // sc_previews/ should be empty
        let afterRelease = try FileManager.default.contentsOfDirectory(
            at: previewsDir, includingPropertiesForKeys: nil)
        XCTAssertTrue(afterRelease.isEmpty, "sc_previews/ should be empty after release")
    }

    // MARK: - testAppBackground_previewsPurged

    func testAppBackground_previewsPurged() async throws {
        let pdfData = Data("%PDF-1.4 fake".utf8)
        try store.writeDocument(docId: "bg-doc", data: pdfData)

        _ = try await previewManager.openPreview(
            docId: "bg-doc", mimeType: "application/pdf")

        // Verify file exists
        let before = try FileManager.default.contentsOfDirectory(
            at: previewsDir, includingPropertiesForKeys: nil)
        XCTAssertEqual(before.count, 1, "Preview file should exist before background")

        // Simulate willResignActive (same as PreviewLifecycleObserver does)
        _ = try previewManager.purgeAllPreviews()

        // sc_previews/ should be empty
        let after = try FileManager.default.contentsOfDirectory(
            at: previewsDir, includingPropertiesForKeys: nil)
        XCTAssertTrue(after.isEmpty, "All previews should be purged on background")
    }
}

// MARK: - Shared test helpers

/// Simple XOR "encryption" for deterministic round-trip in hardening tests.
final class XORCryptoLib: SecureCoreLibProtocol {
    func encryptBytes(_ plaintext: Data, dek: Data) throws -> Data {
        Data(plaintext.enumerated().map { $0.element ^ dek[$0.offset % dek.count] })
    }

    func decryptBytes(_ blob: Data, dek: Data) throws -> Data {
        Data(blob.enumerated().map { $0.element ^ dek[$0.offset % dek.count] })
    }
}

/// In-memory key manager that base64-encodes the DEK as "wrapping".
final class InMemoryKeyManager: KeyManagerProtocol {
    func wrapDek(_ dek: Data) throws -> Data { dek.base64EncodedData() }
    func unwrapDek(_ wrapsJson: Data) throws -> Data {
        guard let decoded = Data(base64Encoded: wrapsJson) else {
            throw KeyManagerError.unwrapFailed("bad base64")
        }
        return decoded
    }
    func isKeyAvailable() -> Bool { true }
    func deleteKey() throws {}
}

/// Thread-safe in-memory metadata repository for hardening tests.
final class InMemoryMetadataRepository: MetadataRepositoryProtocol, @unchecked Sendable {
    private let lock = NSLock()
    private var records: [String: DocumentRecord] = [:]

    func save(_ record: DocumentRecord) throws {
        lock.lock(); defer { lock.unlock() }
        records[record.docId] = record
    }
    func find(docId: String) throws -> DocumentRecord? {
        lock.lock(); defer { lock.unlock() }
        return records[docId]
    }
    func list() throws -> [DocumentRecord] {
        lock.lock(); defer { lock.unlock() }
        return Array(records.values).sorted { $0.createdAt > $1.createdAt }
    }
    @discardableResult
    func delete(docId: String) throws -> Bool {
        lock.lock(); defer { lock.unlock() }
        return records.removeValue(forKey: docId) != nil
    }
}
