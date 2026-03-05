package com.securecore

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNull

class SecureCoreResultTest {

    @Test
    fun `Success getOrThrow returns value`() {
        val result: SecureCoreResult<ByteArray> = SecureCoreResult.Success(byteArrayOf(1, 2, 3))
        assertEquals(3, result.getOrThrow().size)
    }

    @Test
    fun `Error getOrThrow throws`() {
        val error = SecureCoreError.CryptoError("bad key")
        val result: SecureCoreResult<ByteArray> = SecureCoreResult.Error(error)
        val thrown = assertFailsWith<SecureCoreError.CryptoError> { result.getOrThrow() }
        assertEquals("bad key", thrown.message)
    }

    @Test
    fun `Success getOrNull returns value`() {
        val result: SecureCoreResult<ByteArray> = SecureCoreResult.Success(byteArrayOf(42))
        assertEquals(42, result.getOrNull()?.get(0))
    }

    @Test
    fun `Error getOrNull returns null`() {
        val result: SecureCoreResult<ByteArray> = SecureCoreResult.Error(
            SecureCoreError.InvalidParameter("oops")
        )
        assertNull(result.getOrNull())
    }

    @Test
    fun `map transforms Success`() {
        val result: SecureCoreResult<ByteArray> = SecureCoreResult.Success(byteArrayOf(1, 2, 3))
        val mapped = result.map { it.size }
        assertIs<SecureCoreResult.Success<Int>>(mapped)
        assertEquals(3, mapped.value)
    }

    @Test
    fun `map preserves Error`() {
        val error = SecureCoreError.IoError("fail")
        val result: SecureCoreResult<ByteArray> = SecureCoreResult.Error(error)
        val mapped = result.map { it.size }
        assertIs<SecureCoreResult.Error>(mapped)
        assertEquals(error, mapped.error)
    }

    @Test
    fun `wrapNative returns Error when library not loaded`() {
        // SecureCoreLib.load() not called, so native calls should fail gracefully
        val result = SecureCoreLib.encryptBytes(byteArrayOf(1), ByteArray(32))
        assertIs<SecureCoreResult.Error>(result)
    }
}
