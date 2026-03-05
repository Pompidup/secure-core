package com.securecore.auth

import androidx.fragment.app.FragmentActivity

sealed class AuthError(message: String) : Exception(message) {
    class UserCancelled : AuthError("Authentication cancelled by user")
    class LockedOut(val remainingMs: Long) : AuthError("Too many attempts, locked out")
    class NoBiometrics : AuthError("No biometrics enrolled")
    class NotAvailable : AuthError("Biometric hardware not available")
    class AuthRequired : AuthError("Authentication required")
}

interface AuthManager {
    suspend fun authenticate(activity: FragmentActivity): Result<Unit>
    fun isSessionActive(): Boolean
    fun invalidateSession()
    fun getSessionRemainingMs(): Long
}
