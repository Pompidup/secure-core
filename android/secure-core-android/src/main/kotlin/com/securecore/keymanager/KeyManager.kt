package com.securecore.keymanager

/**
 * Port for DEK wrapping/unwrapping using a device-level master key.
 *
 * Implementations must never log or expose DEK bytes.
 */
interface KeyManager {
    fun wrapDek(dek: ByteArray): ByteArray
    fun unwrapDek(wrappedDek: ByteArray): ByteArray
    fun isKeyAvailable(): Boolean
    fun deleteKey()
}
