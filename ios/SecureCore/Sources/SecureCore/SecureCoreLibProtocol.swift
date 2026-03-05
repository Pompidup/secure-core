import Foundation

/// Swift-side contract for the native encryption library (xcframework).
///
/// Implementations call the C functions exposed by `secure_core.h`.
public protocol SecureCoreLibProtocol {
    /// Encrypts plaintext bytes using the given 32-byte DEK.
    func encryptBytes(_ plaintext: Data, dek: Data) throws -> Data

    /// Decrypts a blob produced by `encryptBytes` using the same DEK.
    func decryptBytes(_ blob: Data, dek: Data) throws -> Data
}
