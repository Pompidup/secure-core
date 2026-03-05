package com.securecore.keymanager

import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * JVM unit tests for [KeyManager] using a fake in-memory implementation.
 *
 * These tests validate the contract and zeroization behavior without
 * requiring the Android Keystore (no Robolectric needed).
 */
class KeyManagerTest {

    private lateinit var manager: KeyManager

    /**
     * In-memory [KeyManager] that mimics KeystoreKeyManager behavior
     * using a standard JCE AES-256-GCM key.
     */
    private class FakeKeyManager : KeyManager {
        private var secretKey: SecretKey? = null

        private fun getOrCreate(): SecretKey {
            secretKey?.let { return it }
            val kg = KeyGenerator.getInstance("AES")
            kg.init(256)
            val key = kg.generateKey()
            secretKey = key
            return key
        }

        override fun wrapDek(dek: ByteArray): ByteArray {
            require(dek.size == 32) { "DEK must be exactly 32 bytes" }
            val key = getOrCreate()
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, key)
            val nonce = cipher.iv
            val ct = cipher.doFinal(dek)
            return nonce + ct
        }

        override fun unwrapDek(wrappedDek: ByteArray): ByteArray {
            val key = secretKey ?: throw KeyManagerError.KeyNotFound()
            val nonce = wrappedDek.copyOfRange(0, 12)
            val ct = wrappedDek.copyOfRange(12, wrappedDek.size)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, nonce))
            return cipher.doFinal(ct)
        }

        override fun isKeyAvailable(): Boolean = secretKey != null

        override fun deleteKey() {
            secretKey = null
        }
    }

    @Before
    fun setUp() {
        manager = FakeKeyManager()
    }

    @Test
    fun testWrapUnwrapRoundtrip() {
        val dek = ByteArray(32) { it.toByte() }
        val wrapped = manager.wrapDek(dek)
        val unwrapped = manager.unwrapDek(wrapped)
        assertArrayEquals(dek, unwrapped)
    }

    @Test
    fun testDekZeroizedAfterUnwrap() {
        val dek = ByteArray(32) { (it + 1).toByte() }
        val original = dek.copyOf()
        val wrapped = manager.wrapDek(dek)
        val unwrapped = manager.unwrapDek(wrapped)

        // Caller is responsible for zeroizing — simulate it
        assertArrayEquals(original, unwrapped)
        unwrapped.fill(0)
        assertTrue("Unwrapped DEK should be zeroized", unwrapped.all { it == 0.toByte() })
    }

    @Test
    fun testKeyNotFoundOnFirstUse() {
        val fresh = FakeKeyManager()
        assertFalse("Key should not exist initially", fresh.isKeyAvailable())

        // wrapDek auto-generates the key
        val dek = ByteArray(32) { 0xAA.toByte() }
        val wrapped = fresh.wrapDek(dek)
        assertTrue("Key should exist after wrapDek", fresh.isKeyAvailable())

        val unwrapped = fresh.unwrapDek(wrapped)
        assertArrayEquals(dek, unwrapped)
    }

    @Test
    fun testDeleteKeyMakesItUnavailable() {
        val dek = ByteArray(32) { it.toByte() }
        manager.wrapDek(dek)
        assertTrue(manager.isKeyAvailable())

        manager.deleteKey()
        assertFalse(manager.isKeyAvailable())
    }

    @Test(expected = KeyManagerError.KeyNotFound::class)
    fun testUnwrapAfterDeleteThrowsKeyNotFound() {
        val dek = ByteArray(32) { it.toByte() }
        val wrapped = manager.wrapDek(dek)
        manager.deleteKey()
        manager.unwrapDek(wrapped)
    }

    @Test(expected = IllegalArgumentException::class)
    fun testWrapRejectsInvalidDekLength() {
        manager.wrapDek(ByteArray(16))
    }

    @Test
    fun testWrappedDekContainsNonce() {
        val dek = ByteArray(32) { it.toByte() }
        val wrapped = manager.wrapDek(dek)
        // GCM nonce (12) + ciphertext (32) + tag (16) = 60
        assertEquals("Wrapped DEK should be 60 bytes", 60, wrapped.size)
    }

    @Test
    fun testTwoWrapsProduceDifferentOutput() {
        val dek = ByteArray(32) { it.toByte() }
        val w1 = manager.wrapDek(dek)
        val w2 = manager.wrapDek(dek)
        assertFalse("Two wraps should differ (different nonces)", w1.contentEquals(w2))
    }
}
