import Foundation
import GRDB

/// Metadata record for an encrypted document, stored in SQLite via GRDB.
///
/// Maps to the `documents` table. Mirrors the Android `DocumentEntity` schema.
public struct DocumentRecord: Codable, Equatable, Identifiable {
    public static let databaseTableName = "documents"

    public var id: String { docId }

    public var docId: String
    public var filename: String
    public var mimeType: String?
    public var createdAt: Int64
    public var plaintextSize: Int64?
    public var ciphertextSize: Int64
    public var contentHash: String?
    /// WrapsEnvelope JSON string (see docs/wraps-schema-v1.md).
    public var wrapsJson: String

    public init(
        docId: String,
        filename: String,
        mimeType: String? = nil,
        createdAt: Int64,
        plaintextSize: Int64? = nil,
        ciphertextSize: Int64,
        contentHash: String? = nil,
        wrapsJson: String
    ) {
        self.docId = docId
        self.filename = filename
        self.mimeType = mimeType
        self.createdAt = createdAt
        self.plaintextSize = plaintextSize
        self.ciphertextSize = ciphertextSize
        self.contentHash = contentHash
        self.wrapsJson = wrapsJson
    }
}

// MARK: - GRDB Conformance

extension DocumentRecord: FetchableRecord, PersistableRecord {
    public static var databaseColumnDecodingStrategy: DatabaseColumnDecodingStrategy {
        .convertFromSnakeCase
    }

    public static var databaseColumnEncodingStrategy: DatabaseColumnEncodingStrategy {
        .convertToSnakeCase
    }

    enum Columns: String, ColumnExpression {
        case docId = "doc_id"
        case filename
        case mimeType = "mime_type"
        case createdAt = "created_at"
        case plaintextSize = "plaintext_size"
        case ciphertextSize = "ciphertext_size"
        case contentHash = "content_hash"
        case wrapsJson = "wraps_json"
    }
}
