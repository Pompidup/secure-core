import Foundation

/// Canonical envelope for a wrapped DEK.
///
/// See `docs/wraps-schema-v1.md` for the frozen specification.
public struct WrapsEnvelope: Codable, Equatable {
    public static let currentSchemaVersion = "1.1"
    public static let algoKeychainGCM = "AES-256-GCM-KEYCHAIN"

    public let schemaVersion: String
    public let device: DeviceWrap?
    public let recovery: AnyCodable?

    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case device
        case recovery
    }

    public init(schemaVersion: String, device: DeviceWrap?, recovery: AnyCodable? = nil) {
        self.schemaVersion = schemaVersion
        self.device = device
        self.recovery = recovery
    }

    public static func fromJson(_ data: Data) throws -> WrapsEnvelope {
        let decoder = JSONDecoder()
        let envelope: WrapsEnvelope
        do {
            envelope = try decoder.decode(WrapsEnvelope.self, from: data)
        } catch {
            throw KeyManagerError.invalidWrapsFormat("invalid JSON: \(error.localizedDescription)")
        }

        if envelope.schemaVersion.isEmpty {
            throw KeyManagerError.invalidWrapsFormat("missing schema_version")
        }
        if envelope.schemaVersion != currentSchemaVersion {
            throw KeyManagerError.versionTooNew(
                found: envelope.schemaVersion, supported: currentSchemaVersion)
        }

        return envelope
    }

    public func toJson() throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        return try encoder.encode(self)
    }

    public func validate() throws {
        if schemaVersion != Self.currentSchemaVersion {
            throw KeyManagerError.versionTooNew(
                found: schemaVersion, supported: Self.currentSchemaVersion)
        }

        guard let device = device else {
            throw KeyManagerError.invalidWrapsFormat("device must not be null")
        }

        if device.algo.isEmpty {
            throw KeyManagerError.invalidWrapsFormat("device.algo must not be empty")
        }
        if device.keyAlias.isEmpty {
            throw KeyManagerError.invalidWrapsFormat("device.key_alias must not be empty")
        }

        let ivBytes = try device.ivData()
        if ivBytes.count != 12 {
            throw KeyManagerError.invalidWrapsFormat(
                "device.iv must be 12 bytes, got \(ivBytes.count)")
        }

        let tagBytes = try device.tagData()
        if tagBytes.count != 16 {
            throw KeyManagerError.invalidWrapsFormat(
                "device.tag must be 16 bytes, got \(tagBytes.count)")
        }

        let ciphertextBytes = try device.ciphertextData()
        if ciphertextBytes.isEmpty {
            throw KeyManagerError.invalidWrapsFormat("device.ciphertext must not be empty")
        }
    }
}

public struct DeviceWrap: Codable, Equatable {
    public let algo: String
    public let keyAlias: String
    public let iv: String
    public let tag: String
    public let ciphertext: String

    enum CodingKeys: String, CodingKey {
        case algo
        case keyAlias = "key_alias"
        case iv
        case tag
        case ciphertext
    }

    public init(algo: String, keyAlias: String, iv: String, tag: String, ciphertext: String) {
        self.algo = algo
        self.keyAlias = keyAlias
        self.iv = iv
        self.tag = tag
        self.ciphertext = ciphertext
    }

    public func ivData() throws -> Data {
        guard let data = Data(base64Encoded: iv) else {
            throw KeyManagerError.invalidWrapsFormat("device.iv: invalid base64")
        }
        return data
    }

    public func tagData() throws -> Data {
        guard let data = Data(base64Encoded: tag) else {
            throw KeyManagerError.invalidWrapsFormat("device.tag: invalid base64")
        }
        return data
    }

    public func ciphertextData() throws -> Data {
        guard let data = Data(base64Encoded: ciphertext) else {
            throw KeyManagerError.invalidWrapsFormat("device.ciphertext: invalid base64")
        }
        return data
    }
}

/// Minimal type-erased Codable wrapper for the `recovery` field.
public struct AnyCodable: Codable, Equatable {
    public let value: [String: String]

    public init(_ value: [String: String]) {
        self.value = value
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if container.decodeNil() {
            value = [:]
        } else {
            value = try container.decode([String: String].self)
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        if value.isEmpty {
            try container.encodeNil()
        } else {
            try container.encode(value)
        }
    }
}
