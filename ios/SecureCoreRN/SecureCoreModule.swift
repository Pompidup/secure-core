import Foundation
import React
import SecureCore

/// React Native bridge module exposing the same API as the Android `SecureCoreModule`.
///
/// Method signatures and error codes are identical across platforms so that the
/// TypeScript layer (`SecureCoreAPI`) works without any `Platform.OS` branching.
@objc(SecureCore)
final class SecureCoreModule: NSObject, RCTBridgeModule {

    static func moduleName() -> String! { "SecureCore" }

    static func requiresMainQueueSetup() -> Bool { false }

    // MARK: - Dependencies

    /// Set during app startup (e.g. in AppDelegate).
    static var documentService: DocumentService?
    static var previewManager: PreviewManagerProtocol?

    private var documentService: DocumentService {
        guard let svc = Self.documentService else {
            fatalError("SecureCoreModule.documentService not initialized")
        }
        return svc
    }

    private var tempDir: URL {
        FileManager.default.temporaryDirectory.appendingPathComponent("previews")
    }

    // MARK: - importDocument

    @objc func importDocument(
        _ uriString: String,
        resolve: @escaping RCTPromiseResolveBlock,
        reject: @escaping RCTPromiseRejectBlock
    ) {
        Task {
            do {
                guard let url = URL(string: uriString) else {
                    reject("INVALID_PARAM", "Invalid URI: \(uriString)", nil)
                    return
                }

                let data = try readFileData(from: url)
                let filename = url.lastPathComponent
                let mimeType = Self.mimeType(for: url)

                let docId = try await documentService.importDocument(
                    data: data, filename: filename, mimeType: mimeType)

                resolve(["docId": docId])
            } catch {
                Self.rejectWithError(reject, error: error)
            }
        }
    }

    // MARK: - decryptToMemory

    @objc func decryptToMemory(
        _ docId: String,
        resolve: @escaping RCTPromiseResolveBlock,
        reject: @escaping RCTPromiseRejectBlock
    ) {
        Task {
            do {
                let data = try await documentService.decryptDocument(docId: docId)
                let mimeType = try await getMimeType(docId: docId)

                resolve([
                    "bytes": data.base64EncodedString(),
                    "mimeType": mimeType,
                ])
            } catch {
                Self.rejectWithError(reject, error: error)
            }
        }
    }

    // MARK: - decryptToTempFile

    @objc func decryptToTempFile(
        _ docId: String,
        resolve: @escaping RCTPromiseResolveBlock,
        reject: @escaping RCTPromiseRejectBlock
    ) {
        Task {
            do {
                let dir = tempDir
                if !FileManager.default.fileExists(atPath: dir.path) {
                    try FileManager.default.createDirectory(
                        at: dir, withIntermediateDirectories: true)
                }

                let fileURL = try await documentService.decryptDocumentToTempFile(
                    docId: docId, tempDir: dir)

                resolve(["uri": fileURL.absoluteString])
            } catch {
                Self.rejectWithError(reject, error: error)
            }
        }
    }

    // MARK: - listDocuments

    @objc func listDocuments(
        _ resolve: @escaping RCTPromiseResolveBlock,
        reject: @escaping RCTPromiseRejectBlock
    ) {
        Task {
            do {
                let docs = try await documentService.listDocuments()
                let array = docs.map { doc -> [String: Any] in
                    var map: [String: Any] = [
                        "docId": doc.docId,
                        "filename": doc.filename,
                        "createdAt": Double(doc.createdAt),
                        "ciphertextSize": Double(doc.ciphertextSize),
                    ]
                    if let mime = doc.mimeType {
                        map["mimeType"] = mime
                    }
                    return map
                }
                resolve(array)
            } catch {
                Self.rejectWithError(reject, error: error)
            }
        }
    }

    // MARK: - deleteDocument

    @objc func deleteDocument(
        _ docId: String,
        resolve: @escaping RCTPromiseResolveBlock,
        reject: @escaping RCTPromiseRejectBlock
    ) {
        Task {
            do {
                try await documentService.deleteDocument(docId: docId)
                resolve(["deleted": true])
            } catch {
                Self.rejectWithError(reject, error: error)
            }
        }
    }

    // MARK: - Error mapping

    /// Maps Swift errors to the same error codes used by the Android module.
    static func rejectWithError(_ reject: @escaping RCTPromiseRejectBlock, error: Error) {
        let (code, message): (String, String)

        switch error {
        case DocumentServiceError.encryptionFailed(let msg):
            (code, message) = ("CRYPTO_ERROR", "Encryption failed: \(msg)")
        case DocumentServiceError.decryptionFailed(let msg):
            (code, message) = ("CRYPTO_ERROR", "Decryption failed: \(msg)")
        case DocumentServiceError.metadataNotFound(let docId):
            (code, message) = ("NOT_FOUND", "Document not found: \(docId)")
        case DocumentServiceError.randomGenerationFailed:
            (code, message) = ("CRYPTO_ERROR", "Random generation failed")

        case DocumentStoreError.documentNotFound(let docId):
            (code, message) = ("NOT_FOUND", "Document not found: \(docId)")
        case DocumentStoreError.writeFailure(let msg):
            (code, message) = ("IO_ERROR", "Write failed: \(msg)")
        case DocumentStoreError.readFailure(let msg):
            (code, message) = ("IO_ERROR", "Read failed: \(msg)")
        case DocumentStoreError.storageFull:
            (code, message) = ("IO_ERROR", "Storage full")
        case DocumentStoreError.invalidDocId(let msg):
            (code, message) = ("INVALID_PARAM", "Invalid document ID: \(msg)")

        case KeyManagerError.keyNotFound:
            (code, message) = ("KEY_ERROR", "Key not found")
        case KeyManagerError.keyInvalidated:
            (code, message) = ("KEY_ERROR", "Key invalidated")
        case KeyManagerError.authCancelled:
            (code, message) = ("AUTH_REQUIRED", "Authentication cancelled")
        case KeyManagerError.authFailed:
            (code, message) = ("AUTH_REQUIRED", "Authentication failed")
        case KeyManagerError.biometricLockout:
            (code, message) = ("AUTH_REQUIRED", "Too many attempts, try again later")
        case KeyManagerError.passcodeNotSet:
            (code, message) = ("AUTH_REQUIRED", "Passcode not set")
        case KeyManagerError.wrapFailed(let msg):
            (code, message) = ("KEY_ERROR", "Wrap failed: \(msg)")
        case KeyManagerError.unwrapFailed(let msg):
            (code, message) = ("KEY_ERROR", "Unwrap failed: \(msg)")
        case KeyManagerError.invalidWrapsFormat(let msg):
            (code, message) = ("CRYPTO_ERROR", "Invalid format: \(msg)")
        case KeyManagerError.algoUnsupported(let msg):
            (code, message) = ("CRYPTO_ERROR", "Unsupported algorithm: \(msg)")
        case KeyManagerError.versionTooNew:
            (code, message) = ("CRYPTO_ERROR", "Unsupported format version")

        default:
            (code, message) = ("IO_ERROR", "Unexpected error: \(error.localizedDescription)")
        }

        reject(code, message, error)
    }

    // MARK: - Helpers

    private func readFileData(from url: URL) throws -> Data {
        let accessing = url.startAccessingSecurityScopedResource()
        defer {
            if accessing { url.stopAccessingSecurityScopedResource() }
        }
        return try Data(contentsOf: url)
    }

    private func getMimeType(docId: String) async throws -> String {
        let docs = try await documentService.listDocuments()
        return docs.first(where: { $0.docId == docId })?.mimeType ?? "application/octet-stream"
    }

    static func mimeType(for url: URL) -> String {
        switch url.pathExtension.lowercased() {
        case "jpg", "jpeg": return "image/jpeg"
        case "png": return "image/png"
        case "gif": return "image/gif"
        case "pdf": return "application/pdf"
        case "txt": return "text/plain"
        case "doc": return "application/msword"
        case "docx":
            return "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        default: return "application/octet-stream"
        }
    }
}
