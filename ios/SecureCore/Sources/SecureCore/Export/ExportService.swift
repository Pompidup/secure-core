import Foundation
import ZIPFoundation

/// Errors specific to export/import operations.
public enum ExportServiceError: Error, Equatable {
    case documentNotFound(docId: String)
    case unwrapFailed(String)
    case wrapFailed(String)
    case invalidBundle(String)
    case ioError(String)
}

public struct ExportReport: Equatable {
    public let exportedCount: Int
    public let failedCount: Int
    public let failedDocIds: [String]
}

public struct ImportReport: Equatable {
    public let importedCount: Int
    public let skippedCount: Int
    public let failedCount: Int
    public let failedDocIds: [String]
}

/// Handles export and import of recovery bundles for cloudless document transfer.
///
/// See docs/recovery-format-v1.md for the bundle format specification.
public final class ExportService {
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

    // MARK: - Export

    /// Exports selected documents into a recovery bundle zip at the given URL.
    public func exportBundle(
        docIds: [String],
        passphrase: String,
        outputURL: URL
    ) async throws -> ExportReport {
        var exported = 0
        var failedDocIds: [String] = []

        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        // Create subdirectories
        let docsDir = tempDir.appendingPathComponent("documents")
        let metaDir = tempDir.appendingPathComponent("metadata")
        let wrapsDir = tempDir.appendingPathComponent("wraps")
        try FileManager.default.createDirectory(at: docsDir, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: metaDir, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: wrapsDir, withIntermediateDirectories: true)

        for docId in docIds {
            do {
                try exportDocument(
                    docId: docId,
                    passphrase: passphrase,
                    docsDir: docsDir,
                    metaDir: metaDir,
                    wrapsDir: wrapsDir
                )
                exported += 1
            } catch {
                failedDocIds.append(docId)
            }
        }

        // Write manifest
        let exportedIds = docIds.filter { !failedDocIds.contains($0) }
        let manifest = buildManifest(docIds: exportedIds)
        let manifestData = try JSONSerialization.data(
            withJSONObject: manifest,
            options: [.prettyPrinted, .sortedKeys]
        )
        try manifestData.write(to: tempDir.appendingPathComponent("manifest.json"))

        // Create zip
        try FileManager.default.zipItem(at: tempDir, to: outputURL)

        return ExportReport(
            exportedCount: exported,
            failedCount: failedDocIds.count,
            failedDocIds: failedDocIds
        )
    }

    // MARK: - Import

    /// Imports documents from a recovery bundle zip.
    public func importBundle(
        bundleURL: URL,
        passphrase: String
    ) async throws -> ImportReport {
        var imported = 0
        var skipped = 0
        var failedDocIds: [String] = []

        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        // Unzip
        try FileManager.default.unzipItem(at: bundleURL, to: tempDir)

        // Find the content root (may be nested in a subdirectory)
        let contentRoot = try findContentRoot(in: tempDir)

        // Enumerate documents
        let docsDir = contentRoot.appendingPathComponent("documents")
        let metaDir = contentRoot.appendingPathComponent("metadata")
        let wrapsDir = contentRoot.appendingPathComponent("wraps")

        let encFiles = try FileManager.default.contentsOfDirectory(
            at: docsDir,
            includingPropertiesForKeys: nil
        ).filter { $0.pathExtension == "enc" }

        for encFile in encFiles {
            let docId = encFile.deletingPathExtension().lastPathComponent

            do {
                // Check for duplicate
                if let _ = try? metadataRepository.find(docId: docId) {
                    skipped += 1
                    continue
                }

                // Read files
                let encData = try Data(contentsOf: encFile)
                let metaData = try Data(contentsOf: metaDir.appendingPathComponent("\(docId).meta.json"))
                let wrapsData = try Data(contentsOf: wrapsDir.appendingPathComponent("\(docId).wraps.json"))

                // Parse recovery wrap
                guard let wrapsObj = try JSONSerialization.jsonObject(with: wrapsData) as? [String: Any],
                      let recoveryObj = wrapsObj["recovery"] as? [String: Any] else {
                    failedDocIds.append(docId)
                    continue
                }

                let recoveryData = try JSONSerialization.data(withJSONObject: recoveryObj)

                // Unwrap DEK with passphrase via Rust FFI
                var dek = try SecureCoreLibBridge.unwrapDekWithPassphrase(recoveryData, passphrase: passphrase)
                defer { dek.resetBytes(in: dek.startIndex..<dek.endIndex) }

                // Re-wrap with device keychain
                let deviceWrapsJson = try keyManager.wrapDek(dek)

                // Store encrypted file
                try documentStore.writeDocument(docId: docId, data: encData)

                // Parse and save metadata
                guard let metaObj = try JSONSerialization.jsonObject(with: metaData) as? [String: Any] else {
                    _ = try? documentStore.deleteDocument(docId: docId)
                    failedDocIds.append(docId)
                    continue
                }

                let record = DocumentRecord(
                    docId: metaObj["docId"] as? String ?? docId,
                    filename: metaObj["filename"] as? String ?? "unknown",
                    mimeType: metaObj["mimeType"] as? String,
                    createdAt: metaObj["createdAt"] as? Int64 ?? Int64(Date().timeIntervalSince1970 * 1000),
                    plaintextSize: metaObj["plaintextSize"] as? Int64,
                    ciphertextSize: metaObj["ciphertextSize"] as? Int64 ?? Int64(encData.count),
                    wrapsJson: String(data: deviceWrapsJson, encoding: .utf8) ?? ""
                )

                try metadataRepository.save(record)
                imported += 1
            } catch {
                failedDocIds.append(docId)
            }
        }

        return ImportReport(
            importedCount: imported,
            skippedCount: skipped,
            failedCount: failedDocIds.count,
            failedDocIds: failedDocIds
        )
    }

    // MARK: - Private

    private func exportDocument(
        docId: String,
        passphrase: String,
        docsDir: URL,
        metaDir: URL,
        wrapsDir: URL
    ) throws {
        guard let record = try metadataRepository.find(docId: docId) else {
            throw ExportServiceError.documentNotFound(docId: docId)
        }

        guard let wrapsData = record.wrapsJson.data(using: .utf8) else {
            throw ExportServiceError.unwrapFailed("Invalid wrapsJson encoding")
        }

        // Unwrap DEK from device keychain
        var dek = try keyManager.unwrapDek(wrapsData)
        defer { dek.resetBytes(in: dek.startIndex..<dek.endIndex) }

        // Re-wrap DEK with passphrase via Rust FFI
        let recoveryWrapData = try SecureCoreLibBridge.wrapDekWithPassphrase(dek, passphrase: passphrase)

        // Build wraps envelope
        guard let recoveryObj = try JSONSerialization.jsonObject(with: recoveryWrapData) as? [String: Any] else {
            throw ExportServiceError.wrapFailed("Invalid recovery wrap JSON")
        }

        let wrapsEnvelope: [String: Any] = [
            "schema_version": "1.1",
            "device": NSNull(),
            "recovery": recoveryObj
        ]
        let wrapsEnvelopeData = try JSONSerialization.data(withJSONObject: wrapsEnvelope)

        // Write encrypted document
        let encData = try documentStore.readDocument(docId: docId)
        try encData.write(to: docsDir.appendingPathComponent("\(docId).enc"))

        // Write metadata (without wrappedDek)
        let metaDict: [String: Any?] = [
            "docId": record.docId,
            "filename": record.filename,
            "mimeType": record.mimeType,
            "createdAt": record.createdAt,
            "plaintextSize": record.plaintextSize,
            "ciphertextSize": record.ciphertextSize,
            "contentHash": record.contentHash
        ]
        let metaData = try JSONSerialization.data(
            withJSONObject: metaDict.compactMapValues { $0 }
        )
        try metaData.write(to: metaDir.appendingPathComponent("\(docId).meta.json"))

        // Write recovery wrap
        try wrapsEnvelopeData.write(to: wrapsDir.appendingPathComponent("\(docId).wraps.json"))
    }

    private func buildManifest(docIds: [String]) -> [String: Any] {
        let sorted = docIds.sorted()
        let checksumInput = sorted.joined(separator: "\n")
        let checksumData = checksumInput.data(using: .utf8) ?? Data()
        let checksum = sha256Hex(checksumData)

        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime]

        return [
            "format": "recovery_bundle_v1",
            "version": 1,
            "created_at": formatter.string(from: Date()),
            "document_count": sorted.count,
            "checksum": checksum
        ]
    }

    private func sha256Hex(_ data: Data) -> String {
        var hash = [UInt8](repeating: 0, count: 32)
        data.withUnsafeBytes { bytes in
            _ = CC_SHA256(bytes.baseAddress, CC_LONG(data.count), &hash)
        }
        return hash.map { String(format: "%02x", $0) }.joined()
    }

    private func findContentRoot(in dir: URL) throws -> URL {
        // Check if manifest.json is directly in dir
        if FileManager.default.fileExists(atPath: dir.appendingPathComponent("manifest.json").path) {
            return dir
        }
        // Check one level deep (zip may contain a root folder)
        let contents = try FileManager.default.contentsOfDirectory(
            at: dir, includingPropertiesForKeys: [.isDirectoryKey]
        )
        for item in contents {
            var isDir: ObjCBool = false
            if FileManager.default.fileExists(atPath: item.path, isDirectory: &isDir), isDir.boolValue {
                if FileManager.default.fileExists(atPath: item.appendingPathComponent("manifest.json").path) {
                    return item
                }
            }
        }
        throw ExportServiceError.invalidBundle("manifest.json not found in bundle")
    }
}

// MARK: - SecureCoreLibBridge extension for recovery operations

/// Bridge to Rust FFI for passphrase-based DEK wrapping/unwrapping.
/// The actual implementation calls the C functions from secure_core.h.
public enum SecureCoreLibBridge {
    /// Wraps a DEK with a passphrase. Returns JSON-encoded RecoveryWrap.
    public static func wrapDekWithPassphrase(_ dek: Data, passphrase: String) throws -> Data {
        // TODO: Call secure_core_wrap_dek_with_passphrase via C bridge
        fatalError("Not yet implemented — requires FFI binding")
    }

    /// Unwraps a DEK from a JSON-encoded RecoveryWrap using the passphrase.
    public static func unwrapDekWithPassphrase(_ recoveryWrapJson: Data, passphrase: String) throws -> Data {
        // TODO: Call secure_core_unwrap_dek_with_passphrase via C bridge
        fatalError("Not yet implemented — requires FFI binding")
    }
}
