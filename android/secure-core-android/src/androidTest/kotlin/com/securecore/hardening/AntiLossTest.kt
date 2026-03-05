package com.securecore.hardening

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.securecore.CryptoEngine
import com.securecore.DocumentService
import com.securecore.NativeCryptoEngine
import com.securecore.keymanager.KeystoreKeyManager
import com.securecore.metadata.AppDatabase
import com.securecore.metadata.MetadataRepository
import com.securecore.metadata.ReconciliationService
import com.securecore.preview.PreviewManager
import com.securecore.store.PrivateDirDocumentStore
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

@RunWith(AndroidJUnit4::class)
class AntiLossTest {

    private lateinit var documentsDir: File
    private lateinit var quarantineDir: File
    private lateinit var previewDir: File
    private lateinit var store: PrivateDirDocumentStore
    private lateinit var repository: MetadataRepository
    private lateinit var documentService: DocumentService
    private lateinit var reconciliationService: ReconciliationService

    @Before
    fun setUp() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        documentsDir = File(context.noBackupFilesDir, "documents-test-${System.nanoTime()}")
        quarantineDir = File(context.noBackupFilesDir, "quarantine-test-${System.nanoTime()}")
        previewDir = File(context.cacheDir, "previews-test-${System.nanoTime()}")

        store = PrivateDirDocumentStore(documentsDir)
        val db = AppDatabase.buildInMemory(context)
        repository = MetadataRepository(db.documentDao())
        val keyManager = KeystoreKeyManager()
        val cryptoEngine: CryptoEngine = NativeCryptoEngine

        documentService = DocumentService(cryptoEngine, keyManager, store, repository)
        reconciliationService = ReconciliationService(
            store, repository, documentsDir, quarantineDir
        )
    }

    @Test
    fun testOrphanedEncFile_reconciledOnStartup() = runBlocking {
        // Simulate a crash that left an .enc file without metadata:
        // write a fake .enc file directly to the documents dir
        val orphanId = "orphan-${System.nanoTime()}"
        File(documentsDir, "$orphanId.enc").writeBytes(ByteArray(256))

        // Verify the orphan exists on disk but not in metadata
        assertTrue(store.documentExists(orphanId))

        val report = reconciliationService.reconcile()

        assertEquals("Should detect 1 orphaned file", 1, report.orphanedFiles)
        // File should be moved to quarantine, not in documents dir anymore
        assertFalse(store.documentExists(orphanId))
        assertTrue(File(quarantineDir, "$orphanId.enc").exists())
    }

    @Test
    fun testOrphanedTmpFile_cleanedOnStartup() {
        // Simulate crash during atomic write: .enc.tmp left behind
        val tmpFile = File(documentsDir, "crash-doc.enc.tmp")
        tmpFile.writeBytes(ByteArray(128))
        // Set old timestamp so it's considered orphaned
        tmpFile.setLastModified(System.currentTimeMillis() - 10 * 60 * 1000)

        val cleaned = store.cleanOrphanedTempFiles()

        assertTrue("Should clean at least 1 orphaned tmp", cleaned >= 1)
        assertFalse(tmpFile.exists())
    }

    @Test
    fun testOrphanedMetadata_reconciledOnStartup() = runBlocking {
        // Import a document normally
        val docId = documentService.importDocument(
            "test content".byteInputStream(),
            "test.txt",
            "text/plain"
        ).getOrThrow()

        // Simulate file deletion (corruption or disk error)
        File(documentsDir, "$docId.enc").delete()

        val report = reconciliationService.reconcile()

        assertEquals("Should detect 1 orphaned metadata", 1, report.orphanedMetadata)
    }

    @Test
    fun testKillDuringPreview_cleanupOnRestart() = runBlocking {
        val docId = documentService.importDocument(
            "preview content".byteInputStream(),
            "doc.pdf",
            "application/pdf"
        ).getOrThrow()

        val previewManager = PreviewManager(documentService, previewDir)
        previewManager.openPreview(docId, "application/pdf").getOrThrow()

        // Verify preview file exists
        assertTrue((previewDir.listFiles()?.size ?: 0) > 0)

        // Simulate restart: set files as old, then purge expired
        previewDir.listFiles()?.forEach {
            it.setLastModified(System.currentTimeMillis() - 10 * 60 * 1000)
        }

        val purged = previewManager.purgeExpiredPreviews()

        assertTrue("Should purge orphaned preview files", purged > 0)
        assertEquals(0, previewDir.listFiles()?.size ?: 0)
    }
}
