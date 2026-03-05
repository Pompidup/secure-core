package com.securecore.hardening

import android.os.Environment
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.securecore.CryptoEngine
import com.securecore.DocumentService
import com.securecore.NativeCryptoEngine
import com.securecore.SecureCoreResult
import com.securecore.keymanager.KeyManager
import com.securecore.keymanager.KeystoreKeyManager
import com.securecore.metadata.AppDatabase
import com.securecore.metadata.MetadataRepository
import com.securecore.preview.PreviewManager
import com.securecore.store.PrivateDirDocumentStore
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

@RunWith(AndroidJUnit4::class)
class AntiLeakTest {

    private lateinit var documentService: DocumentService
    private lateinit var previewManager: PreviewManager
    private lateinit var documentsDir: File
    private lateinit var previewDir: File

    private val testContent = "SENSITIVE_PLAINTEXT_MARKER_${System.nanoTime()}"

    @Before
    fun setUp() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        documentsDir = File(context.noBackupFilesDir, "documents")
        previewDir = File(context.cacheDir, "previews")

        val store = PrivateDirDocumentStore(documentsDir)
        val db = AppDatabase.createInMemory(context)
        val repository = MetadataRepository(db.documentDao())
        val keyManager = KeystoreKeyManager()
        val cryptoEngine: CryptoEngine = NativeCryptoEngine

        documentService = DocumentService(cryptoEngine, keyManager, store, repository)
        previewManager = PreviewManager(documentService, previewDir)
    }

    @After
    fun tearDown() {
        previewManager.purgeAllPreviews()
    }

    @Test
    fun testImport_noClearTextInPublicStorage() = runBlocking {
        val result = documentService.importDocument(
            testContent.byteInputStream(),
            "secret.txt",
            "text/plain"
        )
        assertTrue(result.isSuccess)

        val publicDirs = listOfNotNull(
            Environment.getExternalStorageDirectory(),
            InstrumentationRegistry.getInstrumentation().targetContext.externalCacheDir
        )

        for (dir in publicDirs) {
            if (!dir.exists()) continue
            val found = searchForContent(dir, testContent.toByteArray())
            assertFalse(
                "Found plaintext in public storage: ${dir.absolutePath}",
                found
            )
        }

        // Also verify the encrypted blob does NOT contain the plaintext marker
        val docId = result.getOrThrow()
        val encFile = File(documentsDir, "$docId.enc")
        assertTrue(encFile.exists())
        val encContent = encFile.readBytes()
        assertFalse(
            "Encrypted file contains plaintext",
            String(encContent).contains(testContent)
        )
    }

    @Test
    fun testPreviewClosed_noClearTextInCache() = runBlocking {
        val docId = documentService.importDocument(
            testContent.byteInputStream(),
            "report.pdf",
            "application/pdf"
        ).getOrThrow()

        val handle = previewManager.openPreview(docId, "application/pdf").getOrThrow()

        // Preview file should exist for PDF (TempFile strategy)
        val filesBeforeRelease = previewDir.listFiles()?.size ?: 0
        assertTrue("PDF preview should create temp file", filesBeforeRelease > 0)

        previewManager.releasePreview(handle)

        val filesAfterRelease = previewDir.listFiles()?.size ?: 0
        assertEquals("Preview dir should be empty after release", 0, filesAfterRelease)
    }

    @Test
    fun testAppBackground_previewsPurged() = runBlocking {
        val docId = documentService.importDocument(
            testContent.byteInputStream(),
            "report.pdf",
            "application/pdf"
        ).getOrThrow()

        previewManager.openPreview(docId, "application/pdf").getOrThrow()
        assertTrue((previewDir.listFiles()?.size ?: 0) > 0)

        // Simulate ON_STOP (app going to background)
        val purged = previewManager.purgeAllPreviews()

        assertTrue("Should have purged at least 1 file", purged > 0)
        assertEquals(0, previewDir.listFiles()?.size ?: 0)
    }

    private fun searchForContent(dir: File, content: ByteArray, maxDepth: Int = 3): Boolean {
        if (maxDepth <= 0) return false
        val files = dir.listFiles() ?: return false
        for (file in files) {
            if (file.isDirectory) {
                if (searchForContent(file, content, maxDepth - 1)) return true
            } else if (file.isFile && file.length() < 10 * 1024 * 1024) {
                try {
                    if (file.readBytes().let { bytes ->
                            String(bytes).contains(String(content))
                        }) return true
                } catch (_: Exception) {
                    // Permission denied or other — skip
                }
            }
        }
        return false
    }
}
