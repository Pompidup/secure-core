package com.securecore.keymanager

sealed class KeyManagerError(override val message: String, override val cause: Throwable? = null) :
    Exception(message, cause) {

    class KeyNotFound(message: String = "Master key not found in keystore") :
        KeyManagerError(message)

    class KeyInvalidated(message: String = "Master key invalidated (e.g. new biometric enrolled)") :
        KeyManagerError(message)

    class AuthRequired(message: String = "User authentication required to access key") :
        KeyManagerError(message)

    class WrapFailed(cause: Exception) :
        KeyManagerError("Failed to wrap DEK", cause)

    class UnwrapFailed(cause: Exception) :
        KeyManagerError("Failed to unwrap DEK", cause)
}
