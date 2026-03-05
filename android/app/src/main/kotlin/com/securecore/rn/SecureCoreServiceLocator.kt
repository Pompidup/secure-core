package com.securecore.rn

import com.securecore.auth.AuthGate

/**
 * Simple service locator for providing [AuthGate] to the RN module.
 *
 * Must be initialized in Application.onCreate() before any React Native
 * bridge calls. Example:
 *
 * ```kotlin
 * SecureCoreServiceLocator.authGate = AuthGate(documentService, authManager) { currentActivity as? FragmentActivity }
 * ```
 */
object SecureCoreServiceLocator {
    var authGate: AuthGate? = null
}
