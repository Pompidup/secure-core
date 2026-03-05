package com.securecore

/**
 * Result type for secure-core operations.
 *
 * Wraps either a successful value or a [SecureCoreError].
 */
sealed class SecureCoreResult<out T> {

    /** The operation succeeded with [value]. */
    data class Success<T>(val value: T) : SecureCoreResult<T>()

    /** The operation failed with [error]. */
    data class Error(val error: SecureCoreError) : SecureCoreResult<Nothing>()

    /** Returns the value if success, or throws the error. */
    fun getOrThrow(): T = when (this) {
        is Success -> value
        is Error -> throw error
    }

    /** Returns the value if success, or null. */
    fun getOrNull(): T? = when (this) {
        is Success -> value
        is Error -> null
    }

    /** Maps the success value. */
    fun <R> map(transform: (T) -> R): SecureCoreResult<R> = when (this) {
        is Success -> Success(transform(value))
        is Error -> this
    }
}
