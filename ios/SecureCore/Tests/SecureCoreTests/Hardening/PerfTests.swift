import Foundation
import XCTest

@testable import SecureCore

/// Performance tests for large document encryption/decryption.
///
/// These tests use 50MB payloads and are intended for CI or device runs.
/// On simulators, time thresholds are relaxed (x3 tolerance).
final class PerfTests: XCTestCase {
    private var storeDir: URL!
    private var store: AppGroupDocumentStore!
    private var lib: XORCryptoLib!
    private var keyManager: InMemoryKeyManager!
    private var metadata: InMemoryMetadataRepository!
    private var service: DocumentService!

    private static let fiftyMB = 50 * 1024 * 1024

    override func setUp() {
        super.setUp()
        let base = FileManager.default.temporaryDirectory
            .appendingPathComponent("PerfTests-\(UUID().uuidString)")
        storeDir = base.appendingPathComponent("documents")

        store = AppGroupDocumentStore(baseDir: storeDir)
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

    // MARK: - testEncryptDecrypt_50MB_memoryBudget

    func testEncryptDecrypt_50MB_memoryBudget() async throws {
        let largeData = Data(repeating: 0x42, count: Self.fiftyMB)

        let memBefore = currentResidentMemoryMB()

        let docId = try await service.importDocument(
            data: largeData, filename: "large.bin", mimeType: "application/octet-stream")

        let memAfterImport = currentResidentMemoryMB()

        let _ = try await service.decryptDocument(docId: docId)

        let memAfterDecrypt = currentResidentMemoryMB()

        let peakDelta = max(memAfterImport - memBefore, memAfterDecrypt - memBefore)

        // Budget: 300MB peak memory increase for a 50MB file
        // Accounts for plaintext + ciphertext + file I/O buffers + XOR mock overhead.
        // Real AES crypto will be more efficient; this validates order of magnitude.
        XCTAssertLessThan(
            peakDelta, 300.0,
            "Memory peak delta \(peakDelta)MB exceeds 300MB budget for 50MB file")
    }

    // MARK: - testEncryptDecrypt_50MB_timeLimit

    func testEncryptDecrypt_50MB_timeLimit() async throws {
        let largeData = Data(repeating: 0x42, count: Self.fiftyMB)

        let start = CFAbsoluteTimeGetCurrent()

        let docId = try await service.importDocument(
            data: largeData, filename: "large.bin", mimeType: "application/octet-stream")

        let _ = try await service.decryptDocument(docId: docId)

        let elapsed = CFAbsoluteTimeGetCurrent() - start

        // 20s on device, 60s on simulator (x3 tolerance)
        let isSimulator = ProcessInfo.processInfo.environment["SIMULATOR_DEVICE_NAME"] != nil
        let limit: Double = isSimulator ? 60.0 : 20.0

        XCTAssertLessThan(
            elapsed, limit,
            "Encrypt+Decrypt took \(String(format: "%.1f", elapsed))s, limit is \(limit)s")
    }

    // MARK: - Memory measurement

    private func currentResidentMemoryMB() -> Double {
        var info = mach_task_basic_info()
        var count = mach_msg_type_number_t(
            MemoryLayout<mach_task_basic_info>.size / MemoryLayout<natural_t>.size)
        let result = withUnsafeMutablePointer(to: &info) { infoPtr in
            infoPtr.withMemoryRebound(to: integer_t.self, capacity: Int(count)) { ptr in
                task_info(mach_task_self_, task_flavor_t(MACH_TASK_BASIC_INFO), ptr, &count)
            }
        }
        guard result == KERN_SUCCESS else { return 0 }
        return Double(info.resident_size) / (1024 * 1024)
    }
}
