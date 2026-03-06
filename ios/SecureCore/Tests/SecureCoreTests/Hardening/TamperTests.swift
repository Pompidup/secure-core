import Foundation
import XCTest

@testable import SecureCore

/// Tests verifying that tampered ciphertext is detected and rejected.
final class TamperTests: XCTestCase {
    private var storeDir: URL!
    private var store: AppGroupDocumentStore!
    private var lib: TamperDetectingCryptoLib!
    private var keyManager: InMemoryKeyManager!
    private var metadata: InMemoryMetadataRepository!
    private var service: DocumentService!

    override func setUp() {
        super.setUp()
        let base = FileManager.default.temporaryDirectory
            .appendingPathComponent("TamperTests-\(UUID().uuidString)")
        storeDir = base.appendingPathComponent("documents")

        store = AppGroupDocumentStore(baseDir: storeDir)
        lib = TamperDetectingCryptoLib()
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

    // MARK: - testTamperedEncFile_decryptFails

    func testTamperedEncFile_decryptFails() async throws {
        let original = Data("confidential document content".utf8)

        let docId = try await service.importDocument(
            data: original, filename: "tamper.txt", mimeType: "text/plain")

        // Verify decrypt works before tampering
        let decrypted = try await service.decryptDocument(docId: docId)
        XCTAssertEqual(decrypted, original)

        // Tamper: read the .enc file, flip 1 byte, write it back
        let encFile = storeDir.appendingPathComponent("\(docId).enc")
        var blob = try Data(contentsOf: encFile)
        XCTAssertFalse(blob.isEmpty, "Encrypted file should not be empty")

        // Flip the last byte
        blob[blob.count - 1] ^= 0xFF
        try blob.write(to: encFile)

        // Decrypt should now fail
        do {
            _ = try await service.decryptDocument(docId: docId)
            XCTFail("Decrypt of tampered file should throw")
        } catch let error as DocumentServiceError {
            guard case .decryptionFailed = error else {
                XCTFail("Expected decryptionFailed, got \(error)")
                return
            }
            // This maps to "CRYPTO_ERROR" in the RN bridge
        } catch {
            // Also acceptable — the crypto lib threw directly
            // This is still correct behavior (tampered data rejected)
        }
    }

    // MARK: - testTamperedEncFile_originalStillDecryptable

    func testTamperedEncFile_originalNotAffected() async throws {
        let original = Data("doc A".utf8)
        let docIdA = try await service.importDocument(
            data: original, filename: "a.txt", mimeType: "text/plain")

        let otherData = Data("doc B".utf8)
        let docIdB = try await service.importDocument(
            data: otherData, filename: "b.txt", mimeType: "text/plain")

        // Tamper only doc A
        let encFileA = storeDir.appendingPathComponent("\(docIdA).enc")
        var blobA = try Data(contentsOf: encFileA)
        blobA[0] ^= 0xFF
        try blobA.write(to: encFileA)

        // Doc B should still decrypt fine
        let decryptedB = try await service.decryptDocument(docId: docIdB)
        XCTAssertEqual(decryptedB, otherData, "Untampered doc should still decrypt")
    }
}

/// Crypto lib that includes a checksum to detect tampering.
/// Appends a simple 4-byte checksum (XOR-based) to the ciphertext.
private final class TamperDetectingCryptoLib: SecureCoreLibProtocol {
    func encryptBytes(_ plaintext: Data, dek: Data) throws -> Data {
        // XOR encrypt
        var cipher = Data(plaintext.enumerated().map { $0.element ^ dek[$0.offset % dek.count] })
        // Append 4-byte checksum
        let checksum = computeChecksum(cipher)
        cipher.append(contentsOf: checksum)
        return cipher
    }

    func decryptBytes(_ blob: Data, dek: Data) throws -> Data {
        guard blob.count >= 4 else {
            throw DocumentServiceError.decryptionFailed("Blob too short")
        }

        let cipherPart = blob.prefix(blob.count - 4)
        let storedChecksum = Array(blob.suffix(4))
        let expectedChecksum = computeChecksum(cipherPart)

        guard storedChecksum == expectedChecksum else {
            throw DocumentServiceError.decryptionFailed("Integrity check failed — data tampered")
        }

        return Data(cipherPart.enumerated().map { $0.element ^ dek[$0.offset % dek.count] })
    }

    private func computeChecksum(_ data: Data) -> [UInt8] {
        var hash: UInt32 = 0x811c9dc5  // FNV-1a seed
        for byte in data {
            hash ^= UInt32(byte)
            hash &*= 0x01000193
        }
        return withUnsafeBytes(of: hash.bigEndian) { Array($0) }
    }
}
