package com.securecore.hardening

import android.os.Debug
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.securecore.CryptoEngine
import com.securecore.DocumentService
import com.securecore.NativeCryptoEngine
import com.securecore.keymanager.KeystoreKeyManager
import com.securecore.metadata.AppDatabase
import com.securecore.metadata.MetadataRepository
import com.securecore.store.PrivateDirDocumentStore
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.ByteArrayInputStream
import java.io.File

@RunWith(AndroidJUnit4::class)
class PerfTest {

    private lateinit var documentService: DocumentService
    private lateinit var documentsDir: File

    companion object {
        private const val SIZE_50MB = 50L * 1024 * 1024
        private const val MAX_PEAK_RAM_MB = 200
        private const val MAX_DURATION_MS = 15_000L
    }

    @Before
    fun setUp() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        documentsDir = File(context.noBackupFilesDir, "documents-perf-${System.nanoTime()}")

        val store = PrivateDirDocumentStore(documentsDir)
        val db = AppDatabase.createInMemory(context)
        val repository = MetadataRepository(db.documentDao())
        val keyManager = KeystoreKeyManager()
        val cryptoEngine: CryptoEngine = NativeCryptoEngine

        documentService = DocumentService(cryptoEngine, keyManager, store, repository)
    }

    @Test
    fun testEncryptDecrypt_50mb_withinMemoryBudget() = runBlocking {
        val data = ByteArray(SIZE_50MB.toInt())

        // Force GC before measuring
        System.gc()
        Thread.sleep(100)

        val memBefore = getUsedMemoryMB()

        val docId = documentService.importDocument(
            ByteArrayInputStream(data),
            "large.bin",
            "application/octet-stream"
        ).getOrThrow()

        val memAfterImport = getUsedMemoryMB()

        documentService.decryptDocument(docId)
            .getOrThrow()

        val memAfterDecrypt = getUsedMemoryMB()
        val peakRam = maxOf(memAfterImport, memAfterDecrypt) - memBefore

        assertTrue(
            "Peak RAM usage $peakRam MB exceeds budget of $MAX_PEAK_RAM_MB MB",
            peakRam < MAX_PEAK_RAM_MB
        )
    }

    @Test
    fun testEncryptDecrypt_50mb_withinTimeLimit() = runBlocking {
        val data = ByteArray(SIZE_50MB.toInt())

        val startMs = System.currentTimeMillis()

        val docId = documentService.importDocument(
            ByteArrayInputStream(data),
            "large.bin",
            "application/octet-stream"
        ).getOrThrow()

        documentService.decryptDocument(docId)
            .getOrThrow()

        val durationMs = System.currentTimeMillis() - startMs

        assertTrue(
            "Encrypt+Decrypt took ${durationMs}ms, exceeds limit of ${MAX_DURATION_MS}ms",
            durationMs < MAX_DURATION_MS
        )
    }

    private fun getUsedMemoryMB(): Long {
        val runtime = Runtime.getRuntime()
        return (runtime.totalMemory() - runtime.freeMemory()) / (1024 * 1024)
    }
}
