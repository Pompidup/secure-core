package com.securecore

/**
 * Kotlin interface to the secure-core Rust library via JNI.
 *
 * The native library is loaded once via [System.loadLibrary]. All methods
 * are thread-safe (no shared mutable state in the native layer).
 *
 * Memory: The native layer allocates and frees its own buffers. The JNI
 * bridge copies data into JVM byte arrays before returning, so there are
 * no dangling native pointers.
 */
object SecureCoreLib {

    private var loaded = false

    /**
     * Loads the native library. Call this once before any other method.
     * Safe to call multiple times (idempotent).
     */
    @Synchronized
    fun load() {
        if (!loaded) {
            System.loadLibrary("secure_core")
            loaded = true
        }
    }

    // ── JNI native declarations ─────────────────────────────────────

    /**
     * Encrypts plaintext bytes and returns the .enc V1 blob.
     *
     * @param plaintext the data to encrypt
     * @param dek 32-byte Data Encryption Key
     * @return encrypted blob on success
     * @throws SecureCoreError on failure
     */
    @JvmStatic
    private external fun nativeEncryptBytes(plaintext: ByteArray, dek: ByteArray): NativeResult

    /**
     * Decrypts a .enc V1 blob and returns the plaintext.
     *
     * @param blob the encrypted .enc blob
     * @param dek 32-byte Data Encryption Key
     * @return decrypted plaintext on success
     * @throws SecureCoreError on failure
     */
    @JvmStatic
    private external fun nativeDecryptBytes(blob: ByteArray, dek: ByteArray): NativeResult

    /**
     * Returns the native library version string.
     */
    @JvmStatic
    external fun version(): String

    // ── Public Kotlin API ───────────────────────────────────────────

    /**
     * Encrypts plaintext bytes.
     *
     * @param plaintext the data to encrypt (may be empty)
     * @param dek 32-byte Data Encryption Key
     * @return [SecureCoreResult.Success] with the .enc blob, or [SecureCoreResult.Error]
     */
    fun encryptBytes(plaintext: ByteArray, dek: ByteArray): SecureCoreResult<ByteArray> {
        return wrapNative { nativeEncryptBytes(plaintext, dek) }
    }

    /**
     * Decrypts a .enc V1 blob.
     *
     * @param blob the encrypted .enc blob
     * @param dek 32-byte Data Encryption Key
     * @return [SecureCoreResult.Success] with the plaintext, or [SecureCoreResult.Error]
     */
    fun decryptBytes(blob: ByteArray, dek: ByteArray): SecureCoreResult<ByteArray> {
        return wrapNative { nativeDecryptBytes(blob, dek) }
    }

    // ── Internal ────────────────────────────────────────────────────

    /**
     * JNI bridge result. The native JNI function returns this struct.
     * On success: status=0, data=bytes, errorMessage=null.
     * On error: status>0, data=null, errorMessage=description.
     */
    internal class NativeResult(
        @JvmField val status: Int,
        @JvmField val data: ByteArray?,
        @JvmField val errorMessage: String?
    )

    private fun wrapNative(block: () -> NativeResult): SecureCoreResult<ByteArray> {
        return try {
            val result = block()
            if (result.status == SecureCoreError.CODE_OK) {
                SecureCoreResult.Success(result.data ?: ByteArray(0))
            } else {
                val error = SecureCoreError.fromFfiCode(
                    result.status,
                    result.errorMessage ?: "unknown error"
                )
                SecureCoreResult.Error(error)
            }
        } catch (e: UnsatisfiedLinkError) {
            SecureCoreResult.Error(
                SecureCoreError.InvalidParameter("Native library not loaded. Call SecureCoreLib.load() first.")
            )
        }
    }
}
