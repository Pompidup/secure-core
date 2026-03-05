import Foundation
import XCTest

@testable import SecureCore

final class DocumentStoreTests: XCTestCase {
    private var store: AppGroupDocumentStore!
    private var tempDir: URL!

    override func setUp() {
        super.setUp()
        tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("SecureCoreTests-\(UUID().uuidString)")
        store = AppGroupDocumentStore(baseDir: tempDir)
    }

    override func tearDown() {
        try? FileManager.default.removeItem(at: tempDir)
        super.tearDown()
    }

    // MARK: - Write / Read

    func testWriteReadRoundtrip() throws {
        let data = Data([1, 2, 3, 4, 5])
        try store.writeDocument(docId: "doc-001", data: data)
        let read = try store.readDocument(docId: "doc-001")
        XCTAssertEqual(data, read)
    }

    func testOverwriteExistingDocument() throws {
        try store.writeDocument(docId: "overwrite", data: Data([1, 2, 3]))
        try store.writeDocument(docId: "overwrite", data: Data([4, 5, 6]))
        XCTAssertEqual(try store.readDocument(docId: "overwrite"), Data([4, 5, 6]))
    }

    func testReadDocumentStream() throws {
        let data = Data([10, 20, 30, 40, 50])
        try store.writeDocument(docId: "stream-doc", data: data)
        let stream = try store.readDocumentStream(docId: "stream-doc")
        stream.open()
        defer { stream.close() }
        var buffer = [UInt8](repeating: 0, count: 1024)
        let bytesRead = stream.read(&buffer, maxLength: buffer.count)
        XCTAssertEqual(Data(buffer[0..<bytesRead]), data)
    }

    // MARK: - Atomic write safety

    func testAtomicWrite_noClearTextOnFailure() throws {
        // Simulate a crash mid-write: manually create a .tmp file
        let tmpURL = tempDir.appendingPathComponent("doc-crash.enc.tmp")
        try Data([0xFF]).write(to: tmpURL)

        // The .enc file should NOT exist
        XCTAssertFalse(store.documentExists(docId: "doc-crash"))

        // A subsequent real write should succeed cleanly
        try store.writeDocument(docId: "doc-crash", data: Data([10, 20, 30]))
        XCTAssertTrue(store.documentExists(docId: "doc-crash"))
        XCTAssertEqual(try store.readDocument(docId: "doc-crash"), Data([10, 20, 30]))
    }

    // MARK: - iCloud backup exclusion

    func testExcludedFromBackup() throws {
        try store.writeDocument(docId: "backup-test", data: Data([1]))
        XCTAssertTrue(
            store.isDocumentExcludedFromBackup(docId: "backup-test"),
            "Document file should be excluded from iCloud backup"
        )
    }

    func testDirectoryExcludedFromBackup() {
        XCTAssertTrue(
            store.isDirectoryExcludedFromBackup(),
            "Documents directory should be excluded from iCloud backup"
        )
    }

    // MARK: - Delete

    func testDeleteNonExistent_returnsFalse() throws {
        let result = try store.deleteDocument(docId: "xyz")
        XCTAssertFalse(result)
    }

    func testDeleteExisting() throws {
        try store.writeDocument(docId: "to-delete", data: Data([1]))
        XCTAssertTrue(store.documentExists(docId: "to-delete"))
        XCTAssertTrue(try store.deleteDocument(docId: "to-delete"))
        XCTAssertFalse(store.documentExists(docId: "to-delete"))
    }

    // MARK: - List

    func testListDocumentIds() throws {
        try store.writeDocument(docId: "alpha", data: Data([1]))
        try store.writeDocument(docId: "beta", data: Data([2]))
        try store.writeDocument(docId: "gamma", data: Data([3]))

        // Create a .tmp that should NOT appear in the list
        let tmpURL = tempDir.appendingPathComponent("hidden.enc.tmp")
        try Data([0]).write(to: tmpURL)

        let ids = try store.listDocumentIds()
        XCTAssertEqual(ids, ["alpha", "beta", "gamma"])
    }

    // MARK: - Temp file cleanup

    func testCleanOrphanedTempFiles() throws {
        // Create 3 .tmp files with old timestamps
        let oldDate = Date().addingTimeInterval(-10 * 60) // 10 min ago
        for i in 1...3 {
            let tmp = tempDir.appendingPathComponent("orphan-\(i).enc.tmp")
            try Data([UInt8(i)]).write(to: tmp)
            try FileManager.default.setAttributes(
                [.modificationDate: oldDate], ofItemAtPath: tmp.path)
        }
        // Create 1 recent .tmp (should NOT be cleaned)
        let recent = tempDir.appendingPathComponent("recent.enc.tmp")
        try Data([99]).write(to: recent)

        let cleaned = try store.cleanOrphanedTempFiles()
        XCTAssertEqual(cleaned, 3, "Should clean 3 old orphans")
        XCTAssertTrue(
            FileManager.default.fileExists(atPath: recent.path),
            "Recent tmp should remain")
    }

    // MARK: - Error: not found

    func testReadNonExistentThrows() {
        XCTAssertThrowsError(try store.readDocument(docId: "no-such-doc")) { error in
            guard case DocumentStoreError.documentNotFound(let docId) = error else {
                XCTFail("Expected documentNotFound, got \(error)")
                return
            }
            XCTAssertEqual(docId, "no-such-doc")
        }
    }

    func testReadStreamNonExistentThrows() {
        XCTAssertThrowsError(try store.readDocumentStream(docId: "no-such-doc")) { error in
            guard case DocumentStoreError.documentNotFound = error else {
                XCTFail("Expected documentNotFound, got \(error)")
                return
            }
        }
    }

    // MARK: - Validation

    func testRejectsPathTraversal() {
        XCTAssertThrowsError(try store.writeDocument(docId: "../escape", data: Data([1]))) {
            error in
            guard case DocumentStoreError.invalidDocId = error else {
                XCTFail("Expected invalidDocId, got \(error)")
                return
            }
        }
    }

    func testRejectsSlashInDocId() {
        XCTAssertThrowsError(try store.writeDocument(docId: "sub/dir", data: Data([1]))) {
            error in
            guard case DocumentStoreError.invalidDocId = error else {
                XCTFail("Expected invalidDocId, got \(error)")
                return
            }
        }
    }
}
