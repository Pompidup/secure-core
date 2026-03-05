package com.securecore.metadata

import com.securecore.store.DocumentStore
import java.io.File

/**
 * Reconciles [DocumentStore] (filesystem) with [MetadataRepository] (database).
 *
 * Call [reconcile] at app startup to detect and resolve inconsistencies.
 *
 * @param store the document store to query for file IDs
 * @param repository the metadata database
 * @param documentsDir the directory containing .enc files (same dir used by the store)
 * @param quarantineDir directory to move orphaned .enc files into
 * @param logger optional logging callback (defaults to android.util.Log when available)
 */
class ReconciliationService(
    private val store: DocumentStore,
    private val repository: MetadataRepository,
    private val documentsDir: File,
    private val quarantineDir: File,
    private val logger: Logger = DefaultLogger
) {

    fun interface Logger {
        fun log(level: String, tag: String, message: String)
    }

    private object DefaultLogger : Logger {
        override fun log(level: String, tag: String, message: String) {
            try {
                val logClass = Class.forName("android.util.Log")
                when (level) {
                    "E" -> logClass.getMethod("e", String::class.java, String::class.java)
                        .invoke(null, tag, message)
                    "W" -> logClass.getMethod("w", String::class.java, String::class.java)
                        .invoke(null, tag, message)
                    else -> logClass.getMethod("i", String::class.java, String::class.java)
                        .invoke(null, tag, message)
                }
            } catch (_: Exception) {
                // Not on Android — silently ignore
            }
        }
    }

    companion object {
        private const val TAG = "ReconciliationService"
    }

    data class ReconciliationReport(
        val orphanedMetadata: Int,
        val orphanedFiles: Int
    )

    /**
     * Compares filesystem and database, cleaning up orphans.
     *
     * - Metadata without a matching .enc file: metadata row is deleted.
     * - .enc file without matching metadata: file is moved to [quarantineDir].
     */
    fun reconcile(): ReconciliationReport {
        quarantineDir.mkdirs()

        val fileIds = store.listDocumentIds().toSet()
        val metadataList = when (val result = repository.list()) {
            is com.securecore.SecureCoreResult.Success -> result.value
            is com.securecore.SecureCoreResult.Error -> {
                logger.log("E", TAG, "Failed to list metadata: ${result.error.message}")
                return ReconciliationReport(0, 0)
            }
        }
        val metadataIds = metadataList.map { it.docId }.toSet()

        // Case 1: metadata without file
        val orphanedMeta = metadataIds - fileIds
        for (docId in orphanedMeta) {
            logger.log("W", TAG, "Orphaned metadata (no .enc file): $docId — deleting row")
            repository.delete(docId)
        }

        // Case 2: file without metadata
        val orphanedFiles = fileIds - metadataIds
        for (docId in orphanedFiles) {
            logger.log("W", TAG, "Orphaned file (no metadata): $docId — moving to quarantine")
            val source = File(documentsDir, "$docId.enc")
            val dest = File(quarantineDir, "$docId.enc")
            if (source.exists()) {
                if (!source.renameTo(dest)) {
                    logger.log("W", TAG, "Could not quarantine $docId, deleting instead")
                    store.deleteDocument(docId)
                }
            }
        }

        return ReconciliationReport(
            orphanedMetadata = orphanedMeta.size,
            orphanedFiles = orphanedFiles.size
        )
    }
}
