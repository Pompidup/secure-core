import Foundation
import GRDB
import XCTest

@testable import SecureCore

/// Tests verifying data integrity under crash/kill scenarios.
final class AntiLossTests: XCTestCase {
    private var storeDir: URL!
    private var quarantineDir: URL!
    private var store: AppGroupDocumentStore!
    private var db: AppDatabase!
    private var repository: MetadataRepository!
    private var lib: XORCryptoLib!
    private var keyManager: InMemoryKeyManager!
    private var metadata: InMemoryMetadataRepository!
    private var service: DocumentService!

    override func setUp() {
        super.setUp()
        let base = FileManager.default.temporaryDirectory
            .appendingPathComponent("AntiLossTests-\(UUID().uuidString)")
        storeDir = base.appendingPathComponent("documents")
        quarantineDir = base.appendingPathComponent("quarantine")

        store = AppGroupDocumentStore(baseDir: storeDir)
        db = try! AppDatabase()
        repository = MetadataRepository(database: db)

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

    // MARK: - testKillDuringImport_noCorruptedFile

    func testKillDuringImport_noCorruptedFile() async throws {
        // Start an import in a Task and cancel it quickly to simulate kill
        let bigData = Data(repeating: 0xAA, count: 1024 * 1024) // 1MB
        let task = Task {
            try await service.importDocument(
                data: bigData, filename: "big.bin", mimeType: "application/octet-stream")
        }

        // Give a tiny bit of time then cancel
        try await Task.sleep(nanoseconds: 100_000_000) // 100ms
        task.cancel()

        // Wait for task to complete (cancelled or successful)
        let result = await task.result

        // Check filesystem state
        let allFiles = try FileManager.default.contentsOfDirectory(
            at: storeDir, includingPropertiesForKeys: nil)
        let encFiles = allFiles.filter { $0.pathExtension == "enc" }
        let tmpFiles = allFiles.filter { $0.lastPathComponent.hasSuffix(".enc.tmp") }

        switch result {
        case .success(let docId):
            // Import completed before cancellation — that's fine
            // Verify the .enc file is consistent with metadata
            XCTAssertTrue(store.documentExists(docId: docId))
            let metaRecord = try metadata.find(docId: docId)
            XCTAssertNotNil(metaRecord, "Metadata must exist if .enc file exists")

        case .failure:
            // Import was cancelled or failed
            // Verify: no .enc without matching metadata
            for encFile in encFiles {
                let docId = encFile.deletingPathExtension().lastPathComponent
                let metaRecord = try metadata.find(docId: docId)
                XCTAssertNotNil(
                    metaRecord,
                    "Orphaned .enc file without metadata: \(docId)")
            }
        }

        // No .enc.tmp files should remain (atomic write cleans up)
        XCTAssertTrue(
            tmpFiles.isEmpty,
            "No .enc.tmp files should remain after import completes or is cancelled")
    }

    // MARK: - testReconciliation_afterSimulatedCrash

    func testReconciliation_afterSimulatedCrash() throws {
        // Create an orphaned .enc.tmp file (simulates crash mid-write)
        let tmpFile = storeDir.appendingPathComponent("crash-doc.enc.tmp")
        try Data("partial".utf8).write(to: tmpFile)

        // Set modification date to >5 min ago so cleanOrphanedTempFiles picks it up
        let oldDate = Date().addingTimeInterval(-10 * 60)
        try FileManager.default.setAttributes(
            [.modificationDate: oldDate], ofItemAtPath: tmpFile.path)

        // Run cleanup (equivalent to what happens at startup)
        let cleaned = try store.cleanOrphanedTempFiles()
        XCTAssertEqual(cleaned, 1, "Orphaned .enc.tmp should be cleaned")
        XCTAssertFalse(
            FileManager.default.fileExists(atPath: tmpFile.path),
            ".enc.tmp file should be deleted")
    }

    // MARK: - testReconciliation_orphanedEncMovedToQuarantine

    func testReconciliation_orphanedEncMovedToQuarantine() throws {
        // Create a .enc file without metadata (simulates metadata save crash)
        try store.writeDocument(docId: "orphan-enc", data: Data("encrypted".utf8))

        // Repository has no record for "orphan-enc"

        let reconciliation = ReconciliationService(
            store: store,
            repository: repository,
            documentsDir: storeDir,
            quarantineDir: quarantineDir
        )

        let report = try reconciliation.reconcile()
        XCTAssertEqual(report.orphanedFiles, 1)

        // File should have been moved to quarantine
        let quarantineFile = quarantineDir.appendingPathComponent("orphan-enc.enc")
        XCTAssertTrue(
            FileManager.default.fileExists(atPath: quarantineFile.path),
            "Orphaned .enc should be moved to quarantine")
    }

    // MARK: - testAtomicWrite_noPartialFiles

    func testAtomicWrite_noPartialFiles() throws {
        // Verify that writes are atomic: after a successful write,
        // the file contains exactly the expected data
        let data = Data(repeating: 0xBB, count: 512 * 1024) // 512KB
        try store.writeDocument(docId: "atomic-test", data: data)

        let readBack = try store.readDocument(docId: "atomic-test")
        XCTAssertEqual(readBack.count, data.count, "File size must match exactly")
        XCTAssertEqual(readBack, data, "File contents must match exactly")

        // No .enc.tmp remnants
        let allFiles = try FileManager.default.contentsOfDirectory(
            at: storeDir, includingPropertiesForKeys: nil)
        let tmpFiles = allFiles.filter { $0.lastPathComponent.hasSuffix(".enc.tmp") }
        XCTAssertTrue(tmpFiles.isEmpty, "No .enc.tmp files should remain after successful write")
    }
}
