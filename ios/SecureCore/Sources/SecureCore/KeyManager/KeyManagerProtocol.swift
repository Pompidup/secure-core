import Foundation

/// Contract for DEK wrapping/unwrapping, mirroring the Android `KeyManager` interface.
///
/// All implementations must produce and consume `WrapsEnvelope` JSON
/// (see `docs/wraps-schema-v1.md`).
public protocol KeyManagerProtocol {
    /// Wraps a 32-byte DEK using the device master key.
    /// Returns the `WrapsEnvelope` JSON as `Data`.
    func wrapDek(_ dek: Data) throws -> Data

    /// Unwraps a DEK from a `WrapsEnvelope` JSON blob.
    /// May trigger biometric authentication.
    func unwrapDek(_ wrapsJson: Data) throws -> Data

    /// Returns `true` if the master key exists in the Keychain.
    func isKeyAvailable() -> Bool

    /// Permanently deletes the master key. All wrapped DEKs become unrecoverable.
    func deleteKey() throws
}
