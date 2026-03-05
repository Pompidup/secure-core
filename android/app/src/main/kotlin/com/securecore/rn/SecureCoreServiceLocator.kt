package com.securecore.rn

import com.securecore.DocumentService

/**
 * Simple service locator for providing [DocumentService] to the RN module.
 *
 * Must be initialized in Application.onCreate() before any React Native
 * bridge calls. Example:
 *
 * ```kotlin
 * SecureCoreServiceLocator.documentService = documentService
 * ```
 */
object SecureCoreServiceLocator {
    var documentService: DocumentService? = null
}
