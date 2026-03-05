import Foundation
import XCTest

@testable import SecureCore

// MARK: - Stub document store

private final class StubDocumentStore: DocumentStoreProtocol {
    var documents: [String: Data] = [:]

    func writeDocument(docId: String, data: Data) throws {
        documents[docId] = data
    }

    func readDocument(docId: String) throws -> Data {
        guard let data = documents[docId] else {
            throw DocumentStoreError.documentNotFound(docId: docId)
        }
        return data
    }

    func readDocumentStream(docId: String) throws -> InputStream {
        let data = try readDocument(docId: docId)
        return InputStream(data: data)
    }

    func deleteDocument(docId: String) throws -> Bool {
        documents.removeValue(forKey: docId) != nil
    }

    func listDocumentIds() throws -> [String] {
        documents.keys.sorted()
    }

    func documentExists(docId: String) -> Bool {
        documents[docId] != nil
    }

    func cleanOrphanedTempFiles() throws -> Int { 0 }
}

// MARK: - Tests

final class PreviewManagerTests: XCTestCase {
    private var store: StubDocumentStore!
    private var previewsDir: URL!
    private var manager: SecurePreviewManager!

    override func setUp() {
        super.setUp()
        store = StubDocumentStore()
        previewsDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("PreviewTests-\(UUID().uuidString)")
        manager = SecurePreviewManager(
            documentStore: store,
            previewsDir: previewsDir
        )
    }

    override func tearDown() {
        try? FileManager.default.removeItem(at: previewsDir)
        super.tearDown()
    }

    // MARK: - In-memory previews (images, text)

    func testImagePreview_inMemory_noFile() async throws {
        store.documents["img-001"] = Data([0xFF, 0xD8, 0xFF, 0xE0])

        let handle = try await manager.openPreview(docId: "img-001", mimeType: "image/jpeg")

        guard case .inMemory(let data, let mime) = handle else {
            XCTFail("Expected inMemory handle for image")
            return
        }
        XCTAssertEqual(data, Data([0xFF, 0xD8, 0xFF, 0xE0]))
        XCTAssertEqual(mime, "image/jpeg")

        // No file should have been created in the previews directory
        let contents = try FileManager.default.contentsOfDirectory(
            at: previewsDir, includingPropertiesForKeys: nil)
        XCTAssertTrue(contents.isEmpty, "Previews directory should be empty for in-memory preview")
    }

    func testTextPreview_inMemory() async throws {
        store.documents["note-001"] = Data("Hello".utf8)

        let handle = try await manager.openPreview(docId: "note-001", mimeType: "text/plain")

        guard case .inMemory(let data, _) = handle else {
            XCTFail("Expected inMemory handle for text")
            return
        }
        XCTAssertEqual(String(data: data, encoding: .utf8), "Hello")
    }

    // MARK: - Temp file previews (PDF, other)

    func testPdfPreview_tempFile_created() async throws {
        let pdfData = Data("%PDF-1.4 fake".utf8)
        store.documents["doc-pdf"] = pdfData

        let handle = try await manager.openPreview(docId: "doc-pdf", mimeType: "application/pdf")

        guard case .tempFile(let url, let mime) = handle else {
            XCTFail("Expected tempFile handle for PDF")
            return
        }
        XCTAssertEqual(mime, "application/pdf")
        XCTAssertTrue(FileManager.default.fileExists(atPath: url.path))
        XCTAssertEqual(try Data(contentsOf: url), pdfData)
        XCTAssertTrue(url.lastPathComponent.hasSuffix(".pdf"))

        // Filename should NOT contain the docId
        XCTAssertFalse(url.lastPathComponent.contains("doc-pdf"))
    }

    // MARK: - Release

    func testReleasePreview_fileDeleted() async throws {
        store.documents["doc-rel"] = Data("content".utf8)
        let handle = try await manager.openPreview(
            docId: "doc-rel", mimeType: "application/pdf")

        guard case .tempFile(let url, _) = handle else {
            XCTFail("Expected tempFile")
            return
        }
        XCTAssertTrue(FileManager.default.fileExists(atPath: url.path))

        try manager.releasePreview(handle)
        XCTAssertFalse(
            FileManager.default.fileExists(atPath: url.path),
            "File should be deleted after release")
    }

    func testReleaseInMemory_noError() async throws {
        store.documents["img-002"] = Data([1, 2, 3])
        let handle = try await manager.openPreview(docId: "img-002", mimeType: "image/png")
        // Releasing an in-memory handle should be a no-op
        XCTAssertNoThrow(try manager.releasePreview(handle))
    }

    // MARK: - Purge all

    func testPurgeAll_removesAllFiles() async throws {
        store.documents["a"] = Data("a".utf8)
        store.documents["b"] = Data("b".utf8)
        store.documents["c"] = Data("c".utf8)

        _ = try await manager.openPreview(docId: "a", mimeType: "application/pdf")
        _ = try await manager.openPreview(docId: "b", mimeType: "application/pdf")
        _ = try await manager.openPreview(docId: "c", mimeType: "application/pdf")

        let deleted = try manager.purgeAllPreviews()
        XCTAssertEqual(deleted, 3)

        let remaining = try FileManager.default.contentsOfDirectory(
            at: previewsDir, includingPropertiesForKeys: nil)
        XCTAssertTrue(remaining.isEmpty)
    }

    // MARK: - Purge expired

    func testPurgeExpired_keepsRecent() async throws {
        store.documents["old"] = Data("old".utf8)
        store.documents["recent"] = Data("recent".utf8)

        // Create an "old" preview file manually with a past modification date
        let oldFile = previewsDir.appendingPathComponent("old-preview.pdf")
        try Data("old".utf8).write(to: oldFile)
        let oldDate = Date().addingTimeInterval(-10 * 60) // 10 min ago
        try FileManager.default.setAttributes(
            [.modificationDate: oldDate], ofItemAtPath: oldFile.path)

        // Create a recent preview via the manager
        _ = try await manager.openPreview(docId: "recent", mimeType: "application/pdf")

        let deleted = try manager.purgeExpiredPreviews(maxAge: 300)
        XCTAssertEqual(deleted, 1, "Only the old file should be purged")

        let remaining = try FileManager.default.contentsOfDirectory(
            at: previewsDir, includingPropertiesForKeys: nil)
        XCTAssertEqual(remaining.count, 1, "Recent file should remain")
    }

    // MARK: - Orphaned previews purged at startup

    func testOrphanedPreviews_purgedAtStartup() throws {
        // Simulate orphaned files from a previous session
        let orphan1 = previewsDir.appendingPathComponent("orphan1.pdf")
        let orphan2 = previewsDir.appendingPathComponent("orphan2.bin")
        try Data("orphan".utf8).write(to: orphan1)
        try Data("orphan".utf8).write(to: orphan2)

        // A new manager instance should be able to purge all
        let freshManager = SecurePreviewManager(
            documentStore: store,
            previewsDir: previewsDir
        )
        let deleted = try freshManager.purgeAllPreviews()
        XCTAssertEqual(deleted, 2, "Both orphaned files should be purged")
    }

    // MARK: - Error: document not found

    func testOpenPreview_documentNotFound() async {
        do {
            _ = try await manager.openPreview(docId: "missing", mimeType: "image/png")
            XCTFail("Expected error")
        } catch let error as PreviewError {
            guard case .documentNotFound(let docId) = error else {
                XCTFail("Expected documentNotFound, got \(error)")
                return
            }
            XCTAssertEqual(docId, "missing")
        } catch {
            XCTFail("Unexpected error type: \(error)")
        }
    }
}
