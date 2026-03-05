package com.securecore

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs

class SecureCoreErrorTest {

    @Test
    fun `fromFfiCode maps CODE_INVALID_FORMAT`() {
        val error = SecureCoreError.fromFfiCode(SecureCoreError.CODE_INVALID_FORMAT, "bad format")
        assertIs<SecureCoreError.InvalidFormat>(error)
        assertEquals(1, error.code)
        assertEquals("bad format", error.message)
    }

    @Test
    fun `fromFfiCode maps CODE_UNSUPPORTED_VERSION`() {
        val error = SecureCoreError.fromFfiCode(SecureCoreError.CODE_UNSUPPORTED_VERSION, "v99")
        assertIs<SecureCoreError.UnsupportedVersion>(error)
        assertEquals(2, error.code)
    }

    @Test
    fun `fromFfiCode maps CODE_CRYPTO`() {
        val error = SecureCoreError.fromFfiCode(SecureCoreError.CODE_CRYPTO, "tampered")
        assertIs<SecureCoreError.CryptoError>(error)
        assertEquals(3, error.code)
    }

    @Test
    fun `fromFfiCode maps CODE_IO`() {
        val error = SecureCoreError.fromFfiCode(SecureCoreError.CODE_IO, "disk full")
        assertIs<SecureCoreError.IoError>(error)
        assertEquals(4, error.code)
    }

    @Test
    fun `fromFfiCode maps CODE_INVALID_PARAM`() {
        val error = SecureCoreError.fromFfiCode(SecureCoreError.CODE_INVALID_PARAM, "bad dek")
        assertIs<SecureCoreError.InvalidParameter>(error)
        assertEquals(5, error.code)
    }

    @Test
    fun `fromFfiCode maps unknown codes`() {
        val error = SecureCoreError.fromFfiCode(99, "unknown")
        assertIs<SecureCoreError.Unknown>(error)
        assertEquals(99, error.code)
        assertEquals("unknown", error.message)
    }

    @Test
    fun `error codes match C header constants`() {
        assertEquals(0, SecureCoreError.CODE_OK)
        assertEquals(1, SecureCoreError.CODE_INVALID_FORMAT)
        assertEquals(2, SecureCoreError.CODE_UNSUPPORTED_VERSION)
        assertEquals(3, SecureCoreError.CODE_CRYPTO)
        assertEquals(4, SecureCoreError.CODE_IO)
        assertEquals(5, SecureCoreError.CODE_INVALID_PARAM)
    }
}
