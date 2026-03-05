package com.securecore.auth

import androidx.fragment.app.FragmentActivity
import com.securecore.DocumentMetadata
import com.securecore.DocumentService
import java.io.File
import java.io.InputStream

/**
 * Wraps [DocumentService] with authentication checks.
 *
 * Operations that access plaintext (decrypt*) require an active session.
 * Non-sensitive operations (list, import, delete) pass through without auth.
 */
class AuthGate(
    private val documentService: DocumentService,
    private val authManager: AuthManager,
    private val activityProvider: () -> FragmentActivity?
) {

    suspend fun importDocument(
        inputStream: InputStream,
        filename: String,
        mimeType: String
    ): Result<String> = documentService.importDocument(inputStream, filename, mimeType)

    suspend fun decryptDocument(docId: String): Result<ByteArray> {
        ensureAuthenticated().onFailure { return Result.failure(it) }
        return documentService.decryptDocument(docId)
    }

    suspend fun decryptDocumentToTempFile(docId: String, tempDir: File): Result<File> {
        ensureAuthenticated().onFailure { return Result.failure(it) }
        return documentService.decryptDocumentToTempFile(docId, tempDir)
    }

    suspend fun listDocuments(): Result<List<DocumentMetadata>> =
        documentService.listDocuments()

    suspend fun deleteDocument(docId: String): Result<Unit> =
        documentService.deleteDocument(docId)

    private suspend fun ensureAuthenticated(): Result<Unit> {
        if (authManager.isSessionActive()) return Result.success(Unit)

        val activity = activityProvider()
            ?: return Result.failure(AuthError.AuthRequired())

        return authManager.authenticate(activity)
    }
}
