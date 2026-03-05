import Foundation

/// Contract for document metadata CRUD operations.
///
/// Extracted from `MetadataRepository` to allow mocking in tests.
public protocol MetadataRepositoryProtocol {
    func save(_ record: DocumentRecord) throws
    func find(docId: String) throws -> DocumentRecord?
    func list() throws -> [DocumentRecord]
    @discardableResult
    func delete(docId: String) throws -> Bool
}
