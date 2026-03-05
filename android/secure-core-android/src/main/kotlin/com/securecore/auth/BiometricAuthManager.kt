package com.securecore.auth

import androidx.biometric.BiometricManager.Authenticators
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import kotlin.coroutines.resume
import kotlinx.coroutines.suspendCancellableCoroutine

class BiometricAuthManager(
    private val sessionDurationMs: Long = DEFAULT_SESSION_DURATION_MS,
    private val clock: () -> Long = System::currentTimeMillis
) : AuthManager {

    @Volatile
    private var lastAuthAt: Long = 0L

    override suspend fun authenticate(activity: FragmentActivity): Result<Unit> =
        suspendCancellableCoroutine { continuation ->
            val executor = ContextCompat.getMainExecutor(activity)

            val callback = object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    lastAuthAt = clock()
                    if (continuation.isActive) {
                        continuation.resume(Result.success(Unit))
                    }
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    val error = mapError(errorCode)
                    if (continuation.isActive) {
                        continuation.resume(Result.failure(error))
                    }
                }

                override fun onAuthenticationFailed() {
                    // Called on single failed attempt; prompt stays open.
                    // Final failure arrives via onAuthenticationError.
                }
            }

            val prompt = BiometricPrompt(activity, executor, callback)

            val promptInfo = BiometricPrompt.PromptInfo.Builder()
                .setTitle("Déverrouiller SecureCore")
                .setDescription("Utilisez votre empreinte ou code appareil")
                .setAllowedAuthenticators(
                    Authenticators.BIOMETRIC_STRONG or Authenticators.DEVICE_CREDENTIAL
                )
                .build()

            prompt.authenticate(promptInfo)

            continuation.invokeOnCancellation { prompt.cancelAuthentication() }
        }

    override fun isSessionActive(): Boolean {
        if (lastAuthAt == 0L) return false
        return clock() < lastAuthAt + sessionDurationMs
    }

    override fun invalidateSession() {
        lastAuthAt = 0L
    }

    override fun getSessionRemainingMs(): Long {
        if (lastAuthAt == 0L) return 0L
        val remaining = (lastAuthAt + sessionDurationMs) - clock()
        return if (remaining > 0) remaining else 0L
    }

    private fun mapError(errorCode: Int): AuthError = when (errorCode) {
        BiometricPrompt.ERROR_USER_CANCELED,
        BiometricPrompt.ERROR_NEGATIVE_BUTTON -> AuthError.UserCancelled()

        BiometricPrompt.ERROR_LOCKOUT,
        BiometricPrompt.ERROR_LOCKOUT_PERMANENT -> AuthError.LockedOut(30_000L)

        BiometricPrompt.ERROR_NO_BIOMETRICS -> AuthError.NoBiometrics()

        BiometricPrompt.ERROR_HW_NOT_PRESENT,
        BiometricPrompt.ERROR_HW_UNAVAILABLE -> AuthError.NotAvailable()

        else -> AuthError.UserCancelled()
    }

    companion object {
        const val DEFAULT_SESSION_DURATION_MS = 5L * 60 * 1000 // 5 minutes
    }
}
