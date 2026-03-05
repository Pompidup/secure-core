package com.securecore.keymanager

/**
 * Port for DEK wrapping/unwrapping using a device-level master key.
 *
 * Implementations must never log or expose DEK bytes.
 * Returns/accepts [WrapsEnvelope] JSON strings for cross-platform compatibility.
 */
interface KeyManager {
    fun wrapDek(dek: ByteArray): String
    fun unwrapDek(wrappedDekJson: String): ByteArray
    fun isKeyAvailable(): Boolean
    fun deleteKey()
}
