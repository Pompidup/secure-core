package com.securecore

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import kotlin.random.Random

@RunWith(AndroidJUnit4::class)
class JniIntegrationTest {

    @Before
    fun setUp() {
        SecureCoreLib.load()
    }

    @Test
    fun testVersionString() {
        val version = SecureCoreLib.version()
        assertTrue("Version should contain '0.1', got: $version", version.contains("0.1"))
    }

    @Test
    fun testEncryptDecryptRoundtrip() {
        val plaintext = "Hello from Android JNI".toByteArray()
        val dek = ByteArray(32) { it.toByte() }

        val encResult = SecureCoreLib.encryptBytes(plaintext, dek)
        assertTrue("Encrypt should succeed", encResult is SecureCoreResult.Success)
        val blob = (encResult as SecureCoreResult.Success).value

        val decResult = SecureCoreLib.decryptBytes(blob, dek)
        assertTrue("Decrypt should succeed", decResult is SecureCoreResult.Success)
        val recovered = (decResult as SecureCoreResult.Success).value

        assertArrayEquals(plaintext, recovered)
    }

    @Test
    fun testEncryptDecryptLarge() {
        val plaintext = Random.nextBytes(5 * 1024 * 1024)
        val dek = ByteArray(32) { it.toByte() }

        val encResult = SecureCoreLib.encryptBytes(plaintext, dek)
        assertTrue("Encrypt large should succeed", encResult is SecureCoreResult.Success)
        val blob = (encResult as SecureCoreResult.Success).value

        val decResult = SecureCoreLib.decryptBytes(blob, dek)
        assertTrue("Decrypt large should succeed", decResult is SecureCoreResult.Success)
        val recovered = (decResult as SecureCoreResult.Success).value

        assertArrayEquals(plaintext, recovered)
    }

    @Test
    fun testTamperedCiphertext() {
        val plaintext = "tamper test".toByteArray()
        val dek = ByteArray(32) { it.toByte() }

        val encResult = SecureCoreLib.encryptBytes(plaintext, dek)
        assertTrue("Encrypt should succeed", encResult is SecureCoreResult.Success)
        val blob = (encResult as SecureCoreResult.Success).value

        // Flip a byte in the middle of the blob
        blob[blob.size / 2] = (blob[blob.size / 2].toInt() xor 0xFF).toByte()

        val decResult = SecureCoreLib.decryptBytes(blob, dek)
        assertTrue(
            "Decrypt tampered data should return CryptoError",
            decResult is SecureCoreResult.Error && decResult.error is SecureCoreError.CryptoError
        )
    }

    @Test
    fun testInvalidDekLength() {
        val plaintext = "bad key test".toByteArray()
        val dek = ByteArray(16) // Wrong length

        val result = SecureCoreLib.encryptBytes(plaintext, dek)
        assertTrue(
            "Invalid DEK length should return InvalidParameter",
            result is SecureCoreResult.Error && result.error is SecureCoreError.InvalidParameter
        )
    }

    @Test
    fun testStressLoop() {
        val dek = ByteArray(32) { it.toByte() }

        repeat(100) { i ->
            val plaintext = "stress iteration $i".toByteArray()

            val encResult = SecureCoreLib.encryptBytes(plaintext, dek)
            assertTrue("Encrypt iteration $i should succeed", encResult is SecureCoreResult.Success)
            val blob = (encResult as SecureCoreResult.Success).value

            val decResult = SecureCoreLib.decryptBytes(blob, dek)
            assertTrue("Decrypt iteration $i should succeed", decResult is SecureCoreResult.Success)
            val recovered = (decResult as SecureCoreResult.Success).value

            assertArrayEquals("Roundtrip iteration $i mismatch", plaintext, recovered)
        }
    }
}
