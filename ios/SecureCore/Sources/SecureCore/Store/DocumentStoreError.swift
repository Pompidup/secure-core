import Foundation

public enum DocumentStoreError: Error, Equatable {
    case documentNotFound(docId: String)
    case writeFailure(String)
    case readFailure(String)
    case storageFull
    case invalidDocId(String)

    public static func == (lhs: DocumentStoreError, rhs: DocumentStoreError) -> Bool {
        switch (lhs, rhs) {
        case (.documentNotFound(let a), .documentNotFound(let b)): return a == b
        case (.writeFailure(let a), .writeFailure(let b)): return a == b
        case (.readFailure(let a), .readFailure(let b)): return a == b
        case (.storageFull, .storageFull): return true
        case (.invalidDocId(let a), .invalidDocId(let b)): return a == b
        default: return false
        }
    }
}
