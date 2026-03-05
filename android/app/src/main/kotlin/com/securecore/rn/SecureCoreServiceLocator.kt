package com.securecore.rn

import com.securecore.auth.AuthGate
import com.securecore.`import`.ImportService

/**
 * Simple service locator for providing dependencies to the RN module.
 *
 * Must be initialized in Application.onCreate() before any React Native bridge calls.
 */
object SecureCoreServiceLocator {
    var authGate: AuthGate? = null
    var importService: ImportService? = null
}
