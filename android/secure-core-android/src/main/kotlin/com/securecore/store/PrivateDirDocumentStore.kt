package com.securecore.store

import java.io.File
import java.io.FileInputStream
import java.io.IOException
import java.io.InputStream

/**
 * [DocumentStore] backed by the app's private `noBackupFilesDir`.
 *
 * Documents are stored as `{docId}.enc` inside a `documents/` subdirectory.
 * Writes are atomic: data goes to `{docId}.enc.tmp` first, then is renamed.
 *
 * @param baseDir the root directory for document storage
 *   (typically `context.noBackupFilesDir.resolve("documents")`)
 */
class PrivateDirDocumentStore(private val baseDir: File) : DocumentStore {

    companion object {
        private const val ENC_SUFFIX = ".enc"
        private const val TMP_SUFFIX = ".enc.tmp"
        private const val ORPHAN_AGE_MS = 5 * 60 * 1000L // 5 minutes
    }

    init {
        baseDir.mkdirs()
    }

    override fun writeDocument(docId: String, encryptedBytes: ByteArray) {
        validateDocId(docId)
        val target = fileFor(docId)
        val tmp = tmpFileFor(docId)

        try {
            tmp.outputStream().use { it.write(encryptedBytes) }
            if (!tmp.renameTo(target)) {
                throw IOException("Atomic rename failed: ${tmp.name} -> ${target.name}")
            }
        } catch (e: IOException) {
            tmp.delete()
            throw DocumentStoreError.WriteFailure(e)
        }
    }

    override fun readDocument(docId: String): ByteArray {
        validateDocId(docId)
        val file = fileFor(docId)
        if (!file.exists()) {
            throw DocumentStoreError.DocumentNotFound(docId)
        }
        return file.readBytes()
    }

    override fun readDocumentStream(docId: String): InputStream {
        validateDocId(docId)
        val file = fileFor(docId)
        if (!file.exists()) {
            throw DocumentStoreError.DocumentNotFound(docId)
        }
        return FileInputStream(file)
    }

    override fun deleteDocument(docId: String): Boolean {
        validateDocId(docId)
        return fileFor(docId).delete()
    }

    override fun listDocumentIds(): List<String> {
        return baseDir.listFiles()
            ?.filter { it.isFile && it.name.endsWith(ENC_SUFFIX) && !it.name.endsWith(TMP_SUFFIX) }
            ?.map { it.name.removeSuffix(ENC_SUFFIX) }
            ?.sorted()
            ?: emptyList()
    }

    override fun documentExists(docId: String): Boolean {
        validateDocId(docId)
        return fileFor(docId).exists()
    }

    override fun cleanOrphanedTempFiles(): Int {
        val cutoff = System.currentTimeMillis() - ORPHAN_AGE_MS
        val orphans = baseDir.listFiles()
            ?.filter { it.isFile && it.name.endsWith(TMP_SUFFIX) && it.lastModified() < cutoff }
            ?: emptyList()

        var deleted = 0
        for (file in orphans) {
            if (file.delete()) deleted++
        }
        return deleted
    }

    private fun fileFor(docId: String): File = File(baseDir, "$docId$ENC_SUFFIX")

    private fun tmpFileFor(docId: String): File = File(baseDir, "$docId$TMP_SUFFIX")

    private fun validateDocId(docId: String) {
        require(docId.isNotBlank()) { "docId must not be blank" }
        require(!docId.contains('/') && !docId.contains('\\') && !docId.contains("..")) {
            "docId must not contain path separators or '..'"
        }
    }
}
