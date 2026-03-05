package com.securecore

/**
 * Errors returned by the secure-core native library.
 *
 * Each variant maps to an FFI status code defined in `include/secure_core.h`.
 * Status code values are frozen for the v1.x ABI.
 */
sealed class SecureCoreError(val code: Int, override val message: String) : Exception(message) {

    /** The encrypted data does not conform to the .enc format. */
    class InvalidFormat(message: String) : SecureCoreError(CODE_INVALID_FORMAT, message)

    /** The format version is not supported by this build. */
    class UnsupportedVersion(message: String) : SecureCoreError(CODE_UNSUPPORTED_VERSION, message)

    /** A cryptographic operation failed (wrong key, tampered data). */
    class CryptoError(message: String) : SecureCoreError(CODE_CRYPTO, message)

    /** An I/O error occurred during file operations. */
    class IoError(message: String) : SecureCoreError(CODE_IO, message)

    /** A parameter passed to the API is invalid. */
    class InvalidParameter(message: String) : SecureCoreError(CODE_INVALID_PARAM, message)

    /** An unknown error code was returned by the native library. */
    class Unknown(code: Int, message: String) : SecureCoreError(code, message)

    companion object {
        // These values MUST match include/secure_core.h (ABI frozen v1.0.0)
        const val CODE_OK = 0
        const val CODE_INVALID_FORMAT = 1
        const val CODE_UNSUPPORTED_VERSION = 2
        const val CODE_CRYPTO = 3
        const val CODE_IO = 4
        const val CODE_INVALID_PARAM = 5

        /**
         * Creates the appropriate [SecureCoreError] from an FFI status code.
         */
        fun fromFfiCode(code: Int, message: String): SecureCoreError = when (code) {
            CODE_INVALID_FORMAT -> InvalidFormat(message)
            CODE_UNSUPPORTED_VERSION -> UnsupportedVersion(message)
            CODE_CRYPTO -> CryptoError(message)
            CODE_IO -> IoError(message)
            CODE_INVALID_PARAM -> InvalidParameter(message)
            else -> Unknown(code, message)
        }
    }
}
