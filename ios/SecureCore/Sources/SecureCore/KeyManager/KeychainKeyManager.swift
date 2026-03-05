import CryptoKit
import Foundation
import LocalAuthentication
import Security

/// `KeyManagerProtocol` implementation backed by the iOS Keychain.
///
/// Uses AES-256-GCM (CryptoKit) to wrap/unwrap DEKs. The master key is stored
/// in the Keychain with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` to prevent
/// cloud backup and cross-device migration.
///
/// Produces and consumes `WrapsEnvelope` JSON (see `docs/wraps-schema-v1.md`).
public final class KeychainKeyManager: KeyManagerProtocol {
    public static let defaultAlias = "secure_core_master_key_v1"

    private static let gcmNonceLength = 12
    private static let gcmTagLength = 16
    private static let dekLength = 32

    private let alias: String

    public init(alias: String = KeychainKeyManager.defaultAlias) {
        self.alias = alias
    }

    // MARK: - KeyManagerProtocol

    public func wrapDek(_ dek: Data) throws -> Data {
        guard dek.count == Self.dekLength else {
            throw KeyManagerError.wrapFailed("DEK must be exactly 32 bytes")
        }

        do {
            let masterKey = try getOrCreateKey()
            let nonce = AES.GCM.Nonce()
            let sealedBox = try AES.GCM.seal(dek, using: masterKey, nonce: nonce)

            let iv = Data(sealedBox.nonce)
            let tag = sealedBox.tag
            let ciphertext = sealedBox.ciphertext

            let envelope = WrapsEnvelope(
                schemaVersion: WrapsEnvelope.currentSchemaVersion,
                device: DeviceWrap(
                    algo: WrapsEnvelope.algoKeychainGCM,
                    keyAlias: alias,
                    iv: iv.base64EncodedString(),
                    tag: tag.base64EncodedString(),
                    ciphertext: ciphertext.base64EncodedString()
                )
            )

            return try envelope.toJson()
        } catch let error as KeyManagerError {
            throw error
        } catch {
            throw KeyManagerError.wrapFailed(error.localizedDescription)
        }
    }

    public func unwrapDek(_ wrapsJson: Data) throws -> Data {
        do {
            let envelope = try WrapsEnvelope.fromJson(wrapsJson)
            try envelope.validate()

            guard let device = envelope.device else {
                throw KeyManagerError.invalidWrapsFormat("device must not be null")
            }

            guard let masterKey = try loadKey() else {
                throw KeyManagerError.keyNotFound
            }

            let iv = try device.ivData()
            let tag = try device.tagData()
            let ciphertext = try device.ciphertextData()

            let nonce = try AES.GCM.Nonce(data: iv)
            let sealedBox = try AES.GCM.SealedBox(
                nonce: nonce,
                ciphertext: ciphertext,
                tag: tag
            )

            return try AES.GCM.open(sealedBox, using: masterKey)
        } catch let error as KeyManagerError {
            throw error
        } catch {
            throw KeyManagerError.unwrapFailed(error.localizedDescription)
        }
    }

    public func isKeyAvailable() -> Bool {
        return (try? loadKey()) != nil
    }

    public func deleteKey() throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: alias,
        ]
        let status = SecItemDelete(query as CFDictionary)
        if status != errSecSuccess && status != errSecItemNotFound {
            throw KeyManagerError.keyNotFound
        }
    }

    // MARK: - Keychain Operations

    private func loadKey() throws -> SymmetricKey? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: alias,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        switch status {
        case errSecSuccess:
            guard let keyData = result as? Data, keyData.count == Self.dekLength else {
                throw KeyManagerError.keyInvalidated
            }
            return SymmetricKey(data: keyData)
        case errSecItemNotFound:
            return nil
        case errSecAuthFailed:
            throw KeyManagerError.authFailed
        case errSecUserCanceled:
            throw KeyManagerError.authCancelled
        default:
            throw KeyManagerError.keyNotFound
        }
    }

    private func getOrCreateKey() throws -> SymmetricKey {
        if let existing = try loadKey() {
            return existing
        }

        let key = SymmetricKey(size: .bits256)
        let keyData = key.withUnsafeBytes { Data($0) }

        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: alias,
            kSecValueData as String: keyData,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        ]

        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw KeyManagerError.wrapFailed("Failed to store key in Keychain: \(status)")
        }

        return key
    }
}
