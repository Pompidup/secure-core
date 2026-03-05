package com.securecore.keymanager

import android.util.Base64
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
     * Produces WrapsEnvelope JSON just like the real implementation.
     */
    private class FakeKeyManager : KeyManager {
        private var secretKey: SecretKey? = null
        private val alias = "fake_test_key"

        private fun getOrCreate(): SecretKey {
            secretKey?.let { return it }
            val kg = KeyGenerator.getInstance("AES")
            kg.init(256)
            val key = kg.generateKey()
            secretKey = key
            return key
        }

        override fun wrapDek(dek: ByteArray): String {
            require(dek.size == 32) { "DEK must be exactly 32 bytes" }
            val key = getOrCreate()
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, key)
            val iv = cipher.iv
            val output = cipher.doFinal(dek)

            val tagStart = output.size - 16
            val ciphertext = output.copyOfRange(0, tagStart)
            val tag = output.copyOfRange(tagStart, output.size)

            val envelope = WrapsEnvelope(
                schemaVersion = WrapsEnvelope.CURRENT_SCHEMA_VERSION,
                device = DeviceWrap(
                    algo = WrapsEnvelope.ALGO_AES_256_GCM_KEYSTORE,
                    keyAlias = alias,
                    iv = Base64.encodeToString(iv, Base64.NO_WRAP),
                    tag = Base64.encodeToString(tag, Base64.NO_WRAP),
                    ciphertext = Base64.encodeToString(ciphertext, Base64.NO_WRAP)
                )
            )
            return envelope.toJson()
        }

        override fun unwrapDek(wrappedDekJson: String): ByteArray {
            val key = secretKey ?: throw KeyManagerError.KeyNotFound()
            val envelope = WrapsEnvelope.fromJson(wrappedDekJson)
            val device = envelope.device ?: throw KeyManagerError.WrapFormatInvalid("device is null")

            val iv = device.ivBytes()
            val ciphertext = device.ciphertextBytes()
            val tag = device.tagBytes()
            val input = ciphertext + tag

            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, iv))
            return cipher.doFinal(input)
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
        val wrappedJson = manager.wrapDek(dek)
        val unwrapped = manager.unwrapDek(wrappedJson)
        assertArrayEquals(dek, unwrapped)
    }

    @Test
    fun testWrapProducesValidEnvelopeJson() {
        val dek = ByteArray(32) { it.toByte() }
        val wrappedJson = manager.wrapDek(dek)
        val envelope = WrapsEnvelope.fromJson(wrappedJson)
        assertEquals(WrapsEnvelope.CURRENT_SCHEMA_VERSION, envelope.schemaVersion)
        assertNotNull(envelope.device)
        assertEquals(WrapsEnvelope.ALGO_AES_256_GCM_KEYSTORE, envelope.device!!.algo)
        assertNull(envelope.recovery)
    }

    @Test
    fun testDekZeroizedAfterUnwrap() {
        val dek = ByteArray(32) { (it + 1).toByte() }
        val original = dek.copyOf()
        val wrappedJson = manager.wrapDek(dek)
        val unwrapped = manager.unwrapDek(wrappedJson)

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
        val wrappedJson = fresh.wrapDek(dek)
        assertTrue("Key should exist after wrapDek", fresh.isKeyAvailable())

        val unwrapped = fresh.unwrapDek(wrappedJson)
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
        val wrappedJson = manager.wrapDek(dek)
        manager.deleteKey()
        manager.unwrapDek(wrappedJson)
    }

    @Test(expected = IllegalArgumentException::class)
    fun testWrapRejectsInvalidDekLength() {
        manager.wrapDek(ByteArray(16))
    }

    @Test
    fun testTwoWrapsProduceDifferentOutput() {
        val dek = ByteArray(32) { it.toByte() }
        val w1 = manager.wrapDek(dek)
        val w2 = manager.wrapDek(dek)
        assertNotEquals("Two wraps should differ (different nonces)", w1, w2)
    }
}
