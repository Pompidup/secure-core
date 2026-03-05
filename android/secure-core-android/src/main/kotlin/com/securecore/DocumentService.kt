package com.securecore

import com.securecore.keymanager.KeyManager
import com.securecore.metadata.DocumentEntity
import com.securecore.metadata.MetadataRepository
import com.securecore.store.DocumentStore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.io.InputStream
import java.security.SecureRandom
import java.util.UUID

/**
 * Central orchestrator for document encryption workflows.
 *
 * Coordinates [CryptoEngine], [KeyManager], [DocumentStore], and
 * [MetadataRepository] to provide atomic import/decrypt/delete operations.
 *
 * DEKs are zeroized immediately after use.
 */
class DocumentService(
    private val cryptoEngine: CryptoEngine,
    private val keyManager: KeyManager,
    private val documentStore: DocumentStore,
    private val metadataRepository: MetadataRepository
) {

    suspend fun importDocument(
        inputStream: InputStream,
        filename: String,
        mimeType: String
    ): Result<String> = withContext(Dispatchers.IO) {
        val docId = UUID.randomUUID().toString()
        val dek = ByteArray(32)
        try {
            SecureRandom().nextBytes(dek)

            val plaintext = inputStream.readBytes()
            val plaintextSize = plaintext.size.toLong()

            val blob = when (val result = cryptoEngine.encryptBytes(plaintext, dek)) {
                is SecureCoreResult.Success -> result.value
                is SecureCoreResult.Error -> return@withContext Result.failure(result.error)
            }

            val wrappedDek = keyManager.wrapDek(dek)
            dek.fill(0)

            documentStore.writeDocument(docId, blob)

            val entity = DocumentEntity(
                docId = docId,
                filename = filename,
                mimeType = mimeType,
                createdAt = System.currentTimeMillis(),
                plaintextSize = plaintextSize,
                ciphertextSize = blob.size.toLong(),
                contentHash = null,
                wrappedDek = wrappedDek,
                recoveryWrap = null,
                wrapAlgorithm = "AES-GCM-KEYSTORE"
            )

            when (val saveResult = metadataRepository.save(entity)) {
                is SecureCoreResult.Success -> {}
                is SecureCoreResult.Error -> {
                    documentStore.deleteDocument(docId)
                    return@withContext Result.failure(saveResult.error)
                }
            }

            Result.success(docId)
        } catch (e: Exception) {
            dek.fill(0)
            documentStore.deleteDocument(docId)
            Result.failure(e)
        }
    }

    suspend fun decryptDocument(docId: String): Result<ByteArray> = withContext(Dispatchers.IO) {
        val dek = ByteArray(0) // placeholder
        try {
            val entity = when (val result = metadataRepository.get(docId)) {
                is SecureCoreResult.Success -> result.value
                    ?: return@withContext Result.failure(
                        SecureCoreError.InvalidParameter("Document not found: $docId")
                    )
                is SecureCoreResult.Error -> return@withContext Result.failure(result.error)
            }

            val unwrappedDek = keyManager.unwrapDek(entity.wrappedDek)
            try {
                val blob = documentStore.readDocument(docId)

                val plaintext = when (val result = cryptoEngine.decryptBytes(blob, unwrappedDek)) {
                    is SecureCoreResult.Success -> result.value
                    is SecureCoreResult.Error -> return@withContext Result.failure(result.error)
                }

                Result.success(plaintext)
            } finally {
                unwrappedDek.fill(0)
            }
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    suspend fun decryptDocumentToTempFile(
        docId: String,
        tempDir: File
    ): Result<File> = withContext(Dispatchers.IO) {
        when (val result = decryptDocument(docId)) {
            is Result -> {
                val plaintext = result.getOrElse { return@withContext Result.failure(it) }
                try {
                    tempDir.mkdirs()
                    val file = File(tempDir, "$docId.preview")
                    file.writeBytes(plaintext)
                    file.deleteOnExit()
                    Result.success(file)
                } catch (e: Exception) {
                    Result.failure(e)
                }
            }
        }
    }

    suspend fun listDocuments(): Result<List<DocumentMetadata>> = withContext(Dispatchers.IO) {
        when (val result = metadataRepository.list()) {
            is SecureCoreResult.Success -> Result.success(
                result.value.map { entity ->
                    DocumentMetadata(
                        docId = entity.docId,
                        filename = entity.filename,
                        mimeType = entity.mimeType,
                        createdAt = entity.createdAt,
                        plaintextSize = entity.plaintextSize,
                        ciphertextSize = entity.ciphertextSize
                    )
                }
            )
            is SecureCoreResult.Error -> Result.failure(result.error)
        }
    }

    suspend fun deleteDocument(docId: String): Result<Unit> = withContext(Dispatchers.IO) {
        try {
            documentStore.deleteDocument(docId)
            when (val result = metadataRepository.delete(docId)) {
                is SecureCoreResult.Success -> Result.success(Unit)
                is SecureCoreResult.Error -> Result.failure(result.error)
            }
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
}
