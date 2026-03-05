package com.securecore

/**
 * Abstraction over encryption/decryption for testability.
 *
 * The default implementation delegates to [SecureCoreLib].
 */
interface CryptoEngine {
    fun encryptBytes(plaintext: ByteArray, dek: ByteArray): SecureCoreResult<ByteArray>
    fun decryptBytes(blob: ByteArray, dek: ByteArray): SecureCoreResult<ByteArray>
}

/**
 * Production [CryptoEngine] backed by the Rust native library.
 */
object NativeCryptoEngine : CryptoEngine {
    override fun encryptBytes(plaintext: ByteArray, dek: ByteArray): SecureCoreResult<ByteArray> =
        SecureCoreLib.encryptBytes(plaintext, dek)

    override fun decryptBytes(blob: ByteArray, dek: ByteArray): SecureCoreResult<ByteArray> =
        SecureCoreLib.decryptBytes(blob, dek)
}
