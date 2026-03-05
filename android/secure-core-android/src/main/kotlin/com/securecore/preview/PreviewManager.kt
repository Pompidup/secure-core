package com.securecore.preview

import com.securecore.DocumentService
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File

sealed class PreviewHandle {
    abstract val mimeType: String

    data class InMemory(val bytes: ByteArray, override val mimeType: String) : PreviewHandle() {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is InMemory) return false
            return bytes.contentEquals(other.bytes) && mimeType == other.mimeType
        }

        override fun hashCode(): Int = 31 * bytes.contentHashCode() + mimeType.hashCode()
    }

    data class TempFile(val file: File, override val mimeType: String) : PreviewHandle()
}

class PreviewManager(
    private val documentService: DocumentService,
    private val previewDir: File
) {

    suspend fun openPreview(docId: String, mimeType: String): Result<PreviewHandle> =
        withContext(Dispatchers.IO) {
            purgeExpiredPreviews()

            val plaintext = documentService.decryptDocument(docId).getOrElse {
                return@withContext Result.failure(it)
            }

            try {
                val handle = if (shouldUseInMemory(mimeType)) {
                    PreviewHandle.InMemory(plaintext, mimeType)
                } else {
                    previewDir.mkdirs()
                    val file = File(previewDir, "$docId.preview")
                    file.writeBytes(plaintext)
                    PreviewHandle.TempFile(file, mimeType)
                }
                Result.success(handle)
            } catch (e: Exception) {
                Result.failure(e)
            }
        }

    fun releasePreview(handle: PreviewHandle) {
        when (handle) {
            is PreviewHandle.InMemory -> handle.bytes.fill(0)
            is PreviewHandle.TempFile -> handle.file.delete()
        }
    }

    fun purgeAllPreviews(): Int {
        val files = previewDir.listFiles() ?: return 0
        var count = 0
        for (file in files) {
            if (file.delete()) count++
        }
        return count
    }

    fun purgeExpiredPreviews(maxAgeMs: Long = 5 * 60 * 1000): Int {
        val files = previewDir.listFiles() ?: return 0
        val cutoff = System.currentTimeMillis() - maxAgeMs
        var count = 0
        for (file in files) {
            if (file.lastModified() < cutoff) {
                if (file.delete()) count++
            }
        }
        return count
    }

    private fun shouldUseInMemory(mimeType: String): Boolean =
        mimeType.startsWith("image/") || mimeType.startsWith("text/")
}
