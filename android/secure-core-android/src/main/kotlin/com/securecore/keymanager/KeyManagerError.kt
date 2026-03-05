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

    class WrapFormatInvalid(detail: String) :
        KeyManagerError("WRAP_FORMAT_INVALID: $detail")

    class AlgoUnsupported(algo: String) :
        KeyManagerError("WRAP_ALGO_UNSUPPORTED: $algo")

    class VersionTooNew(found: String, supported: String) :
        KeyManagerError("WRAP_VERSION_TOO_NEW: found $found, supported $supported")

    class RecoveryNotConfigured :
        KeyManagerError("WRAP_RECOVERY_NOT_CONFIGURED: recovery wrap is null")
}
