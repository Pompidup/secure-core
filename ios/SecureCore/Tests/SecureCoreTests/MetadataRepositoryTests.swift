import Foundation
import GRDB
import XCTest

@testable import SecureCore

final class MetadataRepositoryTests: XCTestCase {
    private var db: AppDatabase!
    private var repository: MetadataRepository!

    override func setUp() {
        super.setUp()
        db = try! AppDatabase()
        repository = MetadataRepository(database: db)
    }

    private func sampleWrapsJson() -> String {
        """
        {"schema_version":"1.1","device":{"algo":"AES-256-GCM-KEYCHAIN","key_alias":"test","iv":"oKCgoKCgoKCgoKCg","tag":"sLCwsLCwsLCwsLCwsLCw","ciphertext":"AQIDBA=="},"recovery":null}
        """
    }

    private func makeRecord(docId: String) -> DocumentRecord {
        DocumentRecord(
            docId: docId,
            filename: "\(docId).pdf",
            mimeType: "application/pdf",
            createdAt: Int64(Date().timeIntervalSince1970 * 1000),
            plaintextSize: 1024,
            ciphertextSize: 1080,
            contentHash: "abcdef1234567890",
            wrapsJson: sampleWrapsJson()
        )
    }

    // MARK: - CRUD

    func testInsertAndFind() throws {
        let record = makeRecord(docId: "doc-001")
        try repository.save(record)

        let found = try repository.find(docId: "doc-001")
        XCTAssertNotNil(found)
        XCTAssertEqual(found?.docId, "doc-001")
        XCTAssertEqual(found?.filename, "doc-001.pdf")
        XCTAssertEqual(found?.mimeType, "application/pdf")
    }

    func testListEmpty() throws {
        let list = try repository.list()
        XCTAssertTrue(list.isEmpty)
    }

    func testListMultiple() throws {
        try repository.save(makeRecord(docId: "a"))
        try repository.save(makeRecord(docId: "b"))
        try repository.save(makeRecord(docId: "c"))

        let list = try repository.list()
        XCTAssertEqual(list.count, 3)
    }

    func testDeleteNonExistent_returnsFalse() throws {
        let deleted = try repository.delete(docId: "non-existent")
        XCTAssertFalse(deleted)
    }

    func testDeleteExisting() throws {
        try repository.save(makeRecord(docId: "to-delete"))
        let deleted = try repository.delete(docId: "to-delete")
        XCTAssertTrue(deleted)
        XCTAssertNil(try repository.find(docId: "to-delete"))
    }

    func testUpsertOverwrites() throws {
        var record = makeRecord(docId: "upsert")
        try repository.save(record)

        record.filename = "updated.pdf"
        try repository.save(record)

        let found = try repository.find(docId: "upsert")
        XCTAssertEqual(found?.filename, "updated.pdf")
    }

    // MARK: - Migration

    func testMigration_v1_tablesExist() throws {
        let tables = try db.dbQueue.read { db in
            try String.fetchAll(
                db,
                sql: "SELECT name FROM sqlite_master WHERE type='table' AND name='documents'"
            )
        }
        XCTAssertEqual(tables, ["documents"])
    }

    func testMigration_v1_columns() throws {
        let columns = try db.dbQueue.read { db in
            try Row.fetchAll(db, sql: "PRAGMA table_info('documents')")
        }
        let names = columns.map { $0["name"] as! String }
        XCTAssertTrue(names.contains("doc_id"))
        XCTAssertTrue(names.contains("filename"))
        XCTAssertTrue(names.contains("mime_type"))
        XCTAssertTrue(names.contains("created_at"))
        XCTAssertTrue(names.contains("plaintext_size"))
        XCTAssertTrue(names.contains("ciphertext_size"))
        XCTAssertTrue(names.contains("content_hash"))
        XCTAssertTrue(names.contains("wraps_json"))
    }
}

// MARK: - Reconciliation Tests

final class ReconciliationTests: XCTestCase {
    private var db: AppDatabase!
    private var repository: MetadataRepository!
    private var docsDir: URL!
    private var quarantineDir: URL!

    override func setUp() {
        super.setUp()
        db = try! AppDatabase()
        repository = MetadataRepository(database: db)
        let tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent("ReconcTests-\(UUID().uuidString)")
        docsDir = tmp.appendingPathComponent("documents")
        quarantineDir = tmp.appendingPathComponent("quarantine")
        try! FileManager.default.createDirectory(
            at: docsDir, withIntermediateDirectories: true)
    }

    override func tearDown() {
        try? FileManager.default.removeItem(at: docsDir.deletingLastPathComponent())
        super.tearDown()
    }

    private func sampleWrapsJson() -> String {
        """
        {"schema_version":"1.1","device":{"algo":"AES-256-GCM-KEYCHAIN","key_alias":"test","iv":"oKCgoKCgoKCgoKCg","tag":"sLCwsLCwsLCwsLCwsLCw","ciphertext":"AQIDBA=="},"recovery":null}
        """
    }

    private func makeRecord(docId: String) -> DocumentRecord {
        DocumentRecord(
            docId: docId,
            filename: "\(docId).pdf",
            createdAt: Int64(Date().timeIntervalSince1970 * 1000),
            ciphertextSize: 1080,
            wrapsJson: sampleWrapsJson()
        )
    }

    func testReconciliation_metadataWithoutFile() throws {
        let store = AppGroupDocumentStore(baseDir: docsDir)

        // Insert metadata but no .enc file
        try repository.save(makeRecord(docId: "orphan-meta"))

        let service = ReconciliationService(
            store: store, repository: repository,
            documentsDir: docsDir, quarantineDir: quarantineDir)
        let report = try service.reconcile()

        XCTAssertEqual(report.orphanedMetadata, 1)
        XCTAssertEqual(report.orphanedFiles, 0)
        XCTAssertNil(try repository.find(docId: "orphan-meta"))
    }

    func testReconciliation_fileWithoutMetadata() throws {
        let store = AppGroupDocumentStore(baseDir: docsDir)

        // Write a .enc file but no metadata row
        try store.writeDocument(docId: "orphan-file", data: Data([1, 2, 3]))

        let service = ReconciliationService(
            store: store, repository: repository,
            documentsDir: docsDir, quarantineDir: quarantineDir)
        let report = try service.reconcile()

        XCTAssertEqual(report.orphanedMetadata, 0)
        XCTAssertEqual(report.orphanedFiles, 1)
        XCTAssertFalse(store.documentExists(docId: "orphan-file"))

        let quarantined = quarantineDir.appendingPathComponent("orphan-file.enc")
        XCTAssertTrue(
            FileManager.default.fileExists(atPath: quarantined.path),
            "File should be in quarantine")
    }

    func testReconciliation_allConsistent() throws {
        let store = AppGroupDocumentStore(baseDir: docsDir)

        try store.writeDocument(docId: "consistent", data: Data([10, 20]))
        try repository.save(makeRecord(docId: "consistent"))

        let service = ReconciliationService(
            store: store, repository: repository,
            documentsDir: docsDir, quarantineDir: quarantineDir)
        let report = try service.reconcile()

        XCTAssertEqual(report.orphanedMetadata, 0)
        XCTAssertEqual(report.orphanedFiles, 0)
        XCTAssertTrue(store.documentExists(docId: "consistent"))
    }
}
