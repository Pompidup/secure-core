package com.securecore.preview

import com.securecore.DocumentService
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever

class PreviewManagerTest {

    @get:Rule
    val tempFolder = TemporaryFolder()

    private lateinit var previewDir: java.io.File
    private lateinit var documentService: DocumentService
    private lateinit var previewManager: PreviewManager

    private val testBytes = "hello world".toByteArray()

    @Before
    fun setUp() {
        previewDir = tempFolder.newFolder("previews")
        documentService = mock()
        previewManager = PreviewManager(documentService, previewDir)
    }

    @After
    fun tearDown() {
        previewManager.purgeAllPreviews()
    }

    @Test
    fun testImagePreview_inMemory_noFile() = runBlocking {
        whenever(documentService.decryptDocument("doc1"))
            .thenReturn(Result.success(testBytes))

        val result = previewManager.openPreview("doc1", "image/png")

        assertTrue(result.isSuccess)
        val handle = result.getOrThrow()
        assertTrue(handle is PreviewHandle.InMemory)
        assertEquals(0, previewDir.listFiles()?.size ?: 0)

        previewManager.releasePreview(handle)
    }

    @Test
    fun testTextPreview_inMemory_noFile() = runBlocking {
        whenever(documentService.decryptDocument("doc2"))
            .thenReturn(Result.success(testBytes))

        val result = previewManager.openPreview("doc2", "text/plain")

        assertTrue(result.isSuccess)
        assertTrue(result.getOrThrow() is PreviewHandle.InMemory)
        assertEquals(0, previewDir.listFiles()?.size ?: 0)
    }

    @Test
    fun testPdfPreview_tempFile_exists() = runBlocking {
        whenever(documentService.decryptDocument("doc3"))
            .thenReturn(Result.success(testBytes))

        val result = previewManager.openPreview("doc3", "application/pdf")

        assertTrue(result.isSuccess)
        val handle = result.getOrThrow()
        assertTrue(handle is PreviewHandle.TempFile)
        val tempFile = (handle as PreviewHandle.TempFile).file
        assertTrue(tempFile.exists())
        assertArrayEquals(testBytes, tempFile.readBytes())
    }

    @Test
    fun testReleasePreview_fileDeleted() = runBlocking {
        whenever(documentService.decryptDocument("doc4"))
            .thenReturn(Result.success(testBytes))

        val handle = previewManager.openPreview("doc4", "application/pdf").getOrThrow()
        val file = (handle as PreviewHandle.TempFile).file
        assertTrue(file.exists())

        previewManager.releasePreview(handle)

        assertFalse(file.exists())
    }

    @Test
    fun testPurgeOnStop_allFilesRemoved() = runBlocking {
        whenever(documentService.decryptDocument("a"))
            .thenReturn(Result.success(testBytes))
        whenever(documentService.decryptDocument("b"))
            .thenReturn(Result.success(testBytes))
        whenever(documentService.decryptDocument("c"))
            .thenReturn(Result.success(testBytes))

        previewManager.openPreview("a", "application/pdf")
        previewManager.openPreview("b", "application/pdf")
        previewManager.openPreview("c", "application/pdf")

        assertEquals(3, previewDir.listFiles()!!.size)

        val purged = previewManager.purgeAllPreviews()

        assertEquals(3, purged)
        assertEquals(0, previewDir.listFiles()!!.size)
    }

    @Test
    fun testPurgeAtStartup_orphanedPreviews_removed() {
        // Simulate orphaned preview files from a previous crash
        java.io.File(previewDir, "orphan1.preview").writeBytes(testBytes)
        java.io.File(previewDir, "orphan2.preview").writeBytes(testBytes)

        // Set last-modified to the past so they appear expired
        val pastTime = System.currentTimeMillis() - 10 * 60 * 1000
        previewDir.listFiles()!!.forEach { it.setLastModified(pastTime) }

        assertEquals(2, previewDir.listFiles()!!.size)

        val purged = previewManager.purgeExpiredPreviews()

        assertEquals(2, purged)
        assertEquals(0, previewDir.listFiles()!!.size)
    }

    @Test
    fun testReleaseInMemory_zerosBytes() = runBlocking {
        whenever(documentService.decryptDocument("doc5"))
            .thenReturn(Result.success("secret".toByteArray()))

        val handle = previewManager.openPreview("doc5", "image/jpeg").getOrThrow()
        assertTrue(handle is PreviewHandle.InMemory)

        previewManager.releasePreview(handle)

        val bytes = (handle as PreviewHandle.InMemory).bytes
        assertTrue(bytes.all { it == 0.toByte() })
    }
}
