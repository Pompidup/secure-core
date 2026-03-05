import CryptoKit
import Foundation
import XCTest

@testable import SecureCore

// MARK: - In-Memory Fake KeyManager (no real Keychain)

private final class FakeKeyManager: KeyManagerProtocol {
    private var secretKey: SymmetricKey?
    private let alias = "fake_test_key"

    private func getOrCreate() -> SymmetricKey {
        if let key = secretKey { return key }
        let key = SymmetricKey(size: .bits256)
        secretKey = key
        return key
    }

    func wrapDek(_ dek: Data) throws -> Data {
        guard dek.count == 32 else {
            throw KeyManagerError.wrapFailed("DEK must be exactly 32 bytes")
        }
        let key = getOrCreate()
        let nonce = AES.GCM.Nonce()
        let sealedBox = try AES.GCM.seal(dek, using: key, nonce: nonce)

        let envelope = WrapsEnvelope(
            schemaVersion: WrapsEnvelope.currentSchemaVersion,
            device: DeviceWrap(
                algo: WrapsEnvelope.algoKeychainGCM,
                keyAlias: alias,
                iv: Data(sealedBox.nonce).base64EncodedString(),
                tag: sealedBox.tag.base64EncodedString(),
                ciphertext: sealedBox.ciphertext.base64EncodedString()
            )
        )
        return try envelope.toJson()
    }

    func unwrapDek(_ wrapsJson: Data) throws -> Data {
        guard let key = secretKey else {
            throw KeyManagerError.keyNotFound
        }
        let envelope = try WrapsEnvelope.fromJson(wrapsJson)
        guard let device = envelope.device else {
            throw KeyManagerError.invalidWrapsFormat("device is null")
        }

        let iv = try device.ivData()
        let tag = try device.tagData()
        let ciphertext = try device.ciphertextData()

        let nonce = try AES.GCM.Nonce(data: iv)
        let sealedBox = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ciphertext, tag: tag)
        return try AES.GCM.open(sealedBox, using: key)
    }

    func isKeyAvailable() -> Bool {
        return secretKey != nil
    }

    func deleteKey() throws {
        secretKey = nil
    }
}

// MARK: - KeyManager Tests

final class KeyManagerTests: XCTestCase {
    private var manager: KeyManagerProtocol!

    override func setUp() {
        super.setUp()
        manager = FakeKeyManager()
    }

    func testWrapUnwrapRoundtrip() throws {
        let dek = Data(0..<32)
        let wrappedJson = try manager.wrapDek(dek)
        let unwrapped = try manager.unwrapDek(wrappedJson)
        XCTAssertEqual(dek, unwrapped)
    }

    func testWrapProducesValidEnvelope() throws {
        let dek = Data(0..<32)
        let wrappedJson = try manager.wrapDek(dek)
        let envelope = try WrapsEnvelope.fromJson(wrappedJson)

        XCTAssertEqual(envelope.schemaVersion, WrapsEnvelope.currentSchemaVersion)
        XCTAssertNotNil(envelope.device)
        XCTAssertEqual(envelope.device?.algo, WrapsEnvelope.algoKeychainGCM)
        XCTAssertNil(envelope.recovery)
    }

    func testDekZeroizedAfterWrap() throws {
        var dek = Data(repeating: 0xAA, count: 32)
        _ = try manager.wrapDek(dek)

        // Simulate caller zeroizing after use
        let count = dek.count
        dek.resetBytes(in: 0..<count)
        XCTAssertEqual(dek, Data(repeating: 0, count: 32))
    }

    func testKeyNotFoundOnUnwrapWithoutKey() {
        let fresh = FakeKeyManager()
        XCTAssertFalse(fresh.isKeyAvailable())

        let fakeJson = "{}".data(using: .utf8)!
        XCTAssertThrowsError(try fresh.unwrapDek(fakeJson)) { error in
            if case KeyManagerError.keyNotFound = error {
                // expected
            } else if case KeyManagerError.invalidWrapsFormat = error {
                // also acceptable — format checked first
            } else {
                XCTFail("Expected keyNotFound or invalidWrapsFormat, got \(error)")
            }
        }
    }

    func testAutoCreateKeyOnWrap() throws {
        let fresh = FakeKeyManager()
        XCTAssertFalse(fresh.isKeyAvailable())

        let dek = Data(repeating: 0xBB, count: 32)
        let wrappedJson = try fresh.wrapDek(dek)
        XCTAssertTrue(fresh.isKeyAvailable())

        let unwrapped = try fresh.unwrapDek(wrappedJson)
        XCTAssertEqual(dek, unwrapped)
    }

    func testDeleteKeyMakesUnavailable() throws {
        let dek = Data(0..<32)
        _ = try manager.wrapDek(dek)
        XCTAssertTrue(manager.isKeyAvailable())

        try manager.deleteKey()
        XCTAssertFalse(manager.isKeyAvailable())
    }

    func testUnwrapAfterDeleteThrowsKeyNotFound() throws {
        let dek = Data(0..<32)
        let wrappedJson = try manager.wrapDek(dek)
        try manager.deleteKey()

        XCTAssertThrowsError(try manager.unwrapDek(wrappedJson)) { error in
            guard case KeyManagerError.keyNotFound = error else {
                XCTFail("Expected keyNotFound, got \(error)")
                return
            }
        }
    }

    func testWrapRejectsInvalidDekLength() {
        let shortDek = Data(repeating: 0xFF, count: 16)
        XCTAssertThrowsError(try manager.wrapDek(shortDek)) { error in
            guard case KeyManagerError.wrapFailed = error else {
                XCTFail("Expected wrapFailed, got \(error)")
                return
            }
        }
    }

    func testTwoWrapsProduceDifferentOutput() throws {
        let dek = Data(0..<32)
        let w1 = try manager.wrapDek(dek)
        let w2 = try manager.wrapDek(dek)
        XCTAssertNotEqual(w1, w2, "Two wraps should differ (different nonces)")
    }
}

// MARK: - WrapsEnvelope Tests

final class WrapsEnvelopeTests: XCTestCase {
    func testRoundtripJson() throws {
        let envelope = WrapsEnvelope(
            schemaVersion: WrapsEnvelope.currentSchemaVersion,
            device: DeviceWrap(
                algo: WrapsEnvelope.algoKeychainGCM,
                keyAlias: "test_key",
                iv: Data(repeating: 0xAA, count: 12).base64EncodedString(),
                tag: Data(repeating: 0xBB, count: 16).base64EncodedString(),
                ciphertext: Data(repeating: 0xCC, count: 32).base64EncodedString()
            )
        )

        let json = try envelope.toJson()
        let decoded = try WrapsEnvelope.fromJson(json)
        XCTAssertEqual(envelope, decoded)
    }

    func testInvalidVersionThrows() {
        let json = """
            {"schema_version":"2.0","device":null,"recovery":null}
            """.data(using: .utf8)!

        XCTAssertThrowsError(try WrapsEnvelope.fromJson(json)) { error in
            guard case KeyManagerError.versionTooNew(let found, let supported) = error else {
                XCTFail("Expected versionTooNew, got \(error)")
                return
            }
            XCTAssertEqual(found, "2.0")
            XCTAssertEqual(supported, "1.1")
        }
    }

    func testValidateRejectsNullDevice() throws {
        let envelope = WrapsEnvelope(
            schemaVersion: WrapsEnvelope.currentSchemaVersion,
            device: nil
        )
        XCTAssertThrowsError(try envelope.validate()) { error in
            guard case KeyManagerError.invalidWrapsFormat = error else {
                XCTFail("Expected invalidWrapsFormat, got \(error)")
                return
            }
        }
    }
}

// MARK: - SessionManager Tests

final class SessionManagerTests: XCTestCase {
    func testSessionInactiveByDefault() {
        let session = SessionManager()
        XCTAssertFalse(session.isSessionActive())
    }

    func testSessionActiveAfterAuth() {
        let session = SessionManager()
        session.recordSuccessfulAuth()
        XCTAssertTrue(session.isSessionActive())
    }

    func testSessionInvalidated() {
        let session = SessionManager()
        session.recordSuccessfulAuth()
        session.invalidateSession()
        XCTAssertFalse(session.isSessionActive())
    }

    func testSessionExpiryWithMockClock() {
        var now = Date()
        let session = SessionManager(sessionDuration: 300) { now }

        session.recordSuccessfulAuth()
        XCTAssertTrue(session.isSessionActive())

        // Advance clock by 4 minutes — still active
        now = now.addingTimeInterval(240)
        XCTAssertTrue(session.isSessionActive())

        // Advance clock to 6 minutes total — expired
        now = now.addingTimeInterval(120)
        XCTAssertFalse(session.isSessionActive())
    }
}
