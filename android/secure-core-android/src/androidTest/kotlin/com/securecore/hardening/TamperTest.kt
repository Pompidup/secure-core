package com.securecore.hardening

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.securecore.CryptoEngine
import com.securecore.DocumentService
import com.securecore.NativeCryptoEngine
import com.securecore.SecureCoreError
import com.securecore.keymanager.KeystoreKeyManager
import com.securecore.metadata.AppDatabase
import com.securecore.metadata.MetadataRepository
import com.securecore.store.PrivateDirDocumentStore
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

@RunWith(AndroidJUnit4::class)
class TamperTest {

    private lateinit var documentService: DocumentService
    private lateinit var documentsDir: File

    @Before
    fun setUp() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        documentsDir = File(context.noBackupFilesDir, "documents-tamper-${System.nanoTime()}")

        val store = PrivateDirDocumentStore(documentsDir)
        val db = AppDatabase.buildInMemory(context)
        val repository = MetadataRepository(db.documentDao())
        val keyManager = KeystoreKeyManager()
        val cryptoEngine: CryptoEngine = NativeCryptoEngine

        documentService = DocumentService(cryptoEngine, keyManager, store, repository)
    }

    @Test
    fun testTamperedEncFile_decryptFails() = runBlocking {
        val originalContent = "This is confidential data for tamper testing"

        val docId = documentService.importDocument(
            originalContent.byteInputStream(),
            "confidential.txt",
            "text/plain"
        ).getOrThrow()

        // Locate the .enc file and tamper with it
        val encFile = File(documentsDir, "$docId.enc")
        assertTrue("Encrypted file should exist", encFile.exists())

        val encBytes = encFile.readBytes()
        assertTrue("Encrypted file should have content", encBytes.isNotEmpty())

        // Flip one byte in the middle of the ciphertext
        val tampered = encBytes.copyOf()
        val tamperIndex = tampered.size / 2
        tampered[tamperIndex] = (tampered[tamperIndex].toInt() xor 0xFF).toByte()
        encFile.writeBytes(tampered)

        // Attempt to decrypt — should fail with a crypto error, not crash
        val result = documentService.decryptDocument(docId)

        assertTrue("Decrypt of tampered file should fail", result.isFailure)
        val error = result.exceptionOrNull()
        assertTrue(
            "Error should be a crypto error, got: ${error?.javaClass?.simpleName}",
            error is SecureCoreError.CryptoError ||
            error is SecureCoreError.InvalidFormat
        )
    }

    @Test
    fun testTruncatedEncFile_decryptFails() = runBlocking {
        val docId = documentService.importDocument(
            "truncation test data".byteInputStream(),
            "trunc.txt",
            "text/plain"
        ).getOrThrow()

        val encFile = File(documentsDir, "$docId.enc")
        val encBytes = encFile.readBytes()

        // Truncate to half the original size
        encFile.writeBytes(encBytes.copyOf(encBytes.size / 2))

        val result = documentService.decryptDocument(docId)

        assertTrue("Decrypt of truncated file should fail", result.isFailure)
    }

    @Test
    fun testEmptyEncFile_decryptFails() = runBlocking {
        val docId = documentService.importDocument(
            "empty test data".byteInputStream(),
            "empty.txt",
            "text/plain"
        ).getOrThrow()

        val encFile = File(documentsDir, "$docId.enc")
        encFile.writeBytes(ByteArray(0))

        val result = documentService.decryptDocument(docId)

        assertTrue("Decrypt of empty file should fail", result.isFailure)
    }
}
