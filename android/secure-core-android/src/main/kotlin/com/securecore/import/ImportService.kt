package com.securecore.`import`

import android.content.ContentResolver
import android.net.Uri
import android.provider.OpenableColumns
import com.securecore.DocumentService
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

class ImportService(
    private val documentService: DocumentService,
    private val contentResolver: ContentResolver
) {

    suspend fun importFromUri(uri: Uri): Result<String> = withContext(Dispatchers.IO) {
        validateUri(uri).onFailure { return@withContext Result.failure(it) }

        val mimeType = resolveMimeType(uri)
        if (mimeType !in ALLOWED_MIME_TYPES) {
            return@withContext Result.failure(ImportError.UnsupportedMimeType(mimeType))
        }

        val size = resolveSize(uri)
        if (size != null && size > MAX_FILE_SIZE_BYTES) {
            return@withContext Result.failure(ImportError.FileTooLarge(size, MAX_FILE_SIZE_BYTES))
        }

        val filename = resolveFilename(uri)

        val inputStream = try {
            contentResolver.openInputStream(uri)
        } catch (e: Exception) {
            return@withContext Result.failure(ImportError.UriNotAccessible(uri.toString()))
        } ?: return@withContext Result.failure(ImportError.UriNotAccessible(uri.toString()))

        inputStream.use { stream ->
            documentService.importDocument(stream, filename, mimeType)
        }
    }

    suspend fun importFromText(text: String, filename: String): Result<String> =
        withContext(Dispatchers.IO) {
            val bytes = text.toByteArray(Charsets.UTF_8)
            if (bytes.size.toLong() > MAX_FILE_SIZE_BYTES) {
                return@withContext Result.failure(
                    ImportError.FileTooLarge(bytes.size.toLong(), MAX_FILE_SIZE_BYTES)
                )
            }

            bytes.inputStream().use { stream ->
                documentService.importDocument(stream, filename, "text/plain")
            }
        }

    private fun resolveMimeType(uri: Uri): String {
        return contentResolver.getType(uri) ?: "application/octet-stream"
    }

    private fun resolveFilename(uri: Uri): String {
        contentResolver.query(uri, null, null, null, null)?.use { cursor ->
            val nameIndex = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
            if (nameIndex >= 0 && cursor.moveToFirst()) {
                return cursor.getString(nameIndex)
            }
        }
        return uri.lastPathSegment ?: "unknown"
    }

    private fun resolveSize(uri: Uri): Long? {
        contentResolver.query(uri, null, null, null, null)?.use { cursor ->
            val sizeIndex = cursor.getColumnIndex(OpenableColumns.SIZE)
            if (sizeIndex >= 0 && cursor.moveToFirst() && !cursor.isNull(sizeIndex)) {
                return cursor.getLong(sizeIndex)
            }
        }
        return null
    }

    private fun validateUri(uri: Uri): Result<Unit> {
        return try {
            contentResolver.openInputStream(uri)?.close()
                ?: return Result.failure(ImportError.UriNotAccessible(uri.toString()))
            Result.success(Unit)
        } catch (e: Exception) {
            Result.failure(ImportError.UriNotAccessible(uri.toString()))
        }
    }

    companion object {
        const val MAX_FILE_SIZE_BYTES = 50L * 1024 * 1024 // 50 MB

        val ALLOWED_MIME_TYPES = setOf(
            "image/jpeg",
            "image/png",
            "image/webp",
            "application/pdf",
            "text/plain"
        )
    }
}
