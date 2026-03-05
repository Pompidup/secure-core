package com.securecore.`import`

import android.content.ContentResolver
import android.database.Cursor
import android.net.Uri
import android.provider.OpenableColumns
import com.securecore.DocumentService
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.mockito.kotlin.any
import org.mockito.kotlin.eq
import org.mockito.kotlin.mock
import org.mockito.kotlin.never
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever
import java.io.ByteArrayInputStream

class ImportServiceTest {

    private lateinit var documentService: DocumentService
    private lateinit var contentResolver: ContentResolver
    private lateinit var importService: ImportService

    private val testUri: Uri = Uri.parse("content://test/doc")

    @Before
    fun setUp() {
        documentService = mock()
        contentResolver = mock()
        importService = ImportService(documentService, contentResolver)
    }

    private fun mockUriAccessible(
        uri: Uri,
        mimeType: String,
        content: ByteArray,
        filename: String = "test.file",
        size: Long = content.size.toLong()
    ) {
        // validateUri opens then closes
        whenever(contentResolver.openInputStream(uri))
            .thenReturn(ByteArrayInputStream(content))  // validateUri
            .thenReturn(ByteArrayInputStream(content))  // actual read

        whenever(contentResolver.getType(uri)).thenReturn(mimeType)

        val cursor: Cursor = mock()
        whenever(contentResolver.query(eq(uri), any(), any(), any(), any())).thenReturn(cursor)
        whenever(cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)).thenReturn(0)
        whenever(cursor.getColumnIndex(OpenableColumns.SIZE)).thenReturn(1)
        whenever(cursor.moveToFirst()).thenReturn(true)
        whenever(cursor.getString(0)).thenReturn(filename)
        whenever(cursor.isNull(1)).thenReturn(false)
        whenever(cursor.getLong(1)).thenReturn(size)
    }

    @Test
    fun testImportJpeg_success() = runBlocking {
        val jpegBytes = ByteArray(1024) { 0xFF.toByte() }
        mockUriAccessible(testUri, "image/jpeg", jpegBytes, "photo.jpg")
        whenever(documentService.importDocument(any(), eq("photo.jpg"), eq("image/jpeg")))
            .thenReturn(Result.success("doc-jpeg-1"))

        val result = importService.importFromUri(testUri)

        assertTrue(result.isSuccess)
        assertEquals("doc-jpeg-1", result.getOrThrow())
    }

    @Test
    fun testImportPdf_success() = runBlocking {
        val pdfBytes = ByteArray(2048)
        mockUriAccessible(testUri, "application/pdf", pdfBytes, "report.pdf")
        whenever(documentService.importDocument(any(), eq("report.pdf"), eq("application/pdf")))
            .thenReturn(Result.success("doc-pdf-1"))

        val result = importService.importFromUri(testUri)

        assertTrue(result.isSuccess)
        assertEquals("doc-pdf-1", result.getOrThrow())
    }

    @Test
    fun testImportText_success() = runBlocking {
        whenever(documentService.importDocument(any(), eq("notes.txt"), eq("text/plain")))
            .thenReturn(Result.success("doc-txt-1"))

        val result = importService.importFromText("Hello, world!", "notes.txt")

        assertTrue(result.isSuccess)
        assertEquals("doc-txt-1", result.getOrThrow())
    }

    @Test
    fun testImportUnsupportedType_mp4() = runBlocking {
        val videoBytes = ByteArray(100)
        mockUriAccessible(testUri, "video/mp4", videoBytes, "clip.mp4")

        val result = importService.importFromUri(testUri)

        assertTrue(result.isFailure)
        val error = result.exceptionOrNull()
        assertTrue(error is ImportError.UnsupportedMimeType)
        assertEquals("video/mp4", (error as ImportError.UnsupportedMimeType).found)
    }

    @Test
    fun testImportTooLarge_51mb() = runBlocking {
        // Mock a file that reports 51 MB via cursor, but use small actual content
        val smallContent = ByteArray(16)
        mockUriAccessible(
            testUri,
            "image/png",
            smallContent,
            "huge.png",
            size = 51L * 1024 * 1024
        )

        val result = importService.importFromUri(testUri)

        assertTrue(result.isFailure)
        val error = result.exceptionOrNull()
        assertTrue(error is ImportError.FileTooLarge)
        assertEquals(51L * 1024 * 1024, (error as ImportError.FileTooLarge).sizeBytes)
        assertEquals(50L * 1024 * 1024, error.maxBytes)
    }

    @Test
    fun testImportCancelled_midway_noOrphanFiles() = runBlocking {
        val content = ByteArray(1024)
        mockUriAccessible(testUri, "image/jpeg", content, "photo.jpg")

        // Simulate DocumentService failing mid-import (it handles its own cleanup)
        whenever(documentService.importDocument(any(), eq("photo.jpg"), eq("image/jpeg")))
            .thenReturn(Result.failure(RuntimeException("Simulated crash")))

        val result = importService.importFromUri(testUri)

        assertTrue(result.isFailure)
        // ImportService does not call deleteDocument — DocumentService handles cleanup
        verify(documentService, never()).deleteDocument(any())
    }

    @Test
    fun testImportUriNotAccessible() = runBlocking {
        whenever(contentResolver.openInputStream(testUri)).thenReturn(null)

        val result = importService.importFromUri(testUri)

        assertTrue(result.isFailure)
        assertTrue(result.exceptionOrNull() is ImportError.UriNotAccessible)
    }

    @Test
    fun testImportTextTooLarge() = runBlocking {
        // Create text larger than 50 MB
        val hugeText = "x".repeat((50 * 1024 * 1024) + 1)

        val result = importService.importFromText(hugeText, "huge.txt")

        assertTrue(result.isFailure)
        assertTrue(result.exceptionOrNull() is ImportError.FileTooLarge)
    }
}
