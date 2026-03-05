import Foundation

public enum KeyManagerError: Error, Equatable {
    case keyNotFound
    case keyInvalidated
    case authCancelled
    case authFailed
    case biometricLockout
    case passcodeNotSet
    case wrapFailed(String)
    case unwrapFailed(String)
    case invalidWrapsFormat(String)
    case algoUnsupported(String)
    case versionTooNew(found: String, supported: String)
}
