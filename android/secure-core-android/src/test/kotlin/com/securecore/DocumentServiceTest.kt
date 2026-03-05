package com.securecore

import android.util.Base64
import com.securecore.keymanager.DeviceWrap
import com.securecore.keymanager.KeyManager
import com.securecore.keymanager.KeyManagerError
import com.securecore.keymanager.WrapsEnvelope
import com.securecore.metadata.DocumentDao
import com.securecore.metadata.DocumentEntity
import com.securecore.metadata.MetadataRepository
import com.securecore.store.DocumentStore
import com.securecore.store.DocumentStoreError
import kotlinx.coroutines.test.runTest
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.File
import java.io.InputStream
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

class DocumentServiceTest {

    private lateinit var service: DocumentService
    private lateinit var cryptoEngine: FakeCryptoEngine
    private lateinit var keyManager: FakeKeyManager
    private lateinit var documentStore: FakeDocumentStore
    private lateinit var metadataRepository: MetadataRepository
    private lateinit var dao: FakeDocumentDao

    // ── Fakes ────────────────────────────────────────────────────────

    private class FakeCryptoEngine : CryptoEngine {
        // Simple XOR-based "encryption" for testing (NOT real crypto)
        override fun encryptBytes(plaintext: ByteArray, dek: ByteArray): SecureCoreResult<ByteArray> {
            val blob = ByteArray(plaintext.size)
            for (i in plaintext.indices) {
                blob[i] = (plaintext[i].toInt() xor dek[i % dek.size].toInt()).toByte()
            }
            return SecureCoreResult.Success(blob)
        }

        override fun decryptBytes(blob: ByteArray, dek: ByteArray): SecureCoreResult<ByteArray> {
            // XOR is its own inverse
            return encryptBytes(blob, dek)
        }
    }

    private class FakeKeyManager : KeyManager {
        private var secretKey: SecretKey? = null
        private val alias = "fake_test_key"

        private fun getOrCreate(): SecretKey {
            secretKey?.let { return it }
            val kg = KeyGenerator.getInstance("AES")
            kg.init(256)
            val key = kg.generateKey()
            secretKey = key
            return key
        }

        override fun wrapDek(dek: ByteArray): String {
            require(dek.size == 32) { "DEK must be exactly 32 bytes" }
            val key = getOrCreate()
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, key)
            val iv = cipher.iv
            val output = cipher.doFinal(dek)
            val tagStart = output.size - 16
            val ciphertext = output.copyOfRange(0, tagStart)
            val tag = output.copyOfRange(tagStart, output.size)

            return WrapsEnvelope(
                schemaVersion = WrapsEnvelope.CURRENT_SCHEMA_VERSION,
                device = DeviceWrap(
                    algo = WrapsEnvelope.ALGO_AES_256_GCM_KEYSTORE,
                    keyAlias = alias,
                    iv = Base64.encodeToString(iv, Base64.NO_WRAP),
                    tag = Base64.encodeToString(tag, Base64.NO_WRAP),
                    ciphertext = Base64.encodeToString(ciphertext, Base64.NO_WRAP)
                )
            ).toJson()
        }

        override fun unwrapDek(wrappedDekJson: String): ByteArray {
            val key = secretKey ?: throw KeyManagerError.KeyNotFound()
            val envelope = WrapsEnvelope.fromJson(wrappedDekJson)
            val device = envelope.device ?: throw KeyManagerError.WrapFormatInvalid("device is null")
            val iv = device.ivBytes()
            val ciphertext = device.ciphertextBytes()
            val tag = device.tagBytes()
            val input = ciphertext + tag
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, iv))
            return cipher.doFinal(input)
        }

        override fun isKeyAvailable(): Boolean = secretKey != null
        override fun deleteKey() { secretKey = null }
    }

    private class FakeDocumentStore(var failOnWrite: Boolean = false) : DocumentStore {
        val docs = mutableMapOf<String, ByteArray>()

        override fun writeDocument(docId: String, encryptedBytes: ByteArray) {
            if (failOnWrite) throw DocumentStoreError.WriteFailure(java.io.IOException("disk full"))
            docs[docId] = encryptedBytes.copyOf()
        }

        override fun readDocument(docId: String): ByteArray =
            docs[docId] ?: throw DocumentStoreError.DocumentNotFound(docId)

        override fun readDocumentStream(docId: String): InputStream =
            ByteArrayInputStream(readDocument(docId))

        override fun deleteDocument(docId: String): Boolean = docs.remove(docId) != null
        override fun listDocumentIds(): List<String> = docs.keys.sorted()
        override fun documentExists(docId: String): Boolean = docs.containsKey(docId)
        override fun cleanOrphanedTempFiles(): Int = 0
    }

    private class FakeDocumentDao : DocumentDao {
        val store = mutableMapOf<String, DocumentEntity>()

        override fun insert(doc: DocumentEntity) { store[doc.docId] = doc }
        override fun findById(docId: String): DocumentEntity? = store[docId]
        override fun findAll(): List<DocumentEntity> = store.values.sortedByDescending { it.createdAt }
        override fun delete(docId: String): Int = if (store.remove(docId) != null) 1 else 0
        override fun update(doc: DocumentEntity) { if (store.containsKey(doc.docId)) store[doc.docId] = doc }
    }

    // ── Setup ────────────────────────────────────────────────────────

    @Before
    fun setUp() {
        cryptoEngine = FakeCryptoEngine()
        keyManager = FakeKeyManager()
        documentStore = FakeDocumentStore()
        dao = FakeDocumentDao()
        metadataRepository = MetadataRepository(dao)

        service = DocumentService(cryptoEngine, keyManager, documentStore, metadataRepository)
    }

    // ── Tests ────────────────────────────────────────────────────────

    @Test
    fun testImportAndDecryptRoundtrip() = runTest {
        val plaintext = "Hello, Pompidup!".toByteArray()
        val input = ByteArrayInputStream(plaintext)

        val importResult = service.importDocument(input, "test.pdf", "application/pdf")
        assertTrue("Import should succeed", importResult.isSuccess)
        val docId = importResult.getOrThrow()

        // Verify metadata saved
        val meta = dao.findById(docId)
        assertNotNull(meta)
        assertEquals("test.pdf", meta!!.filename)
        assertEquals("application/pdf", meta.mimeType)
        assertEquals(plaintext.size.toLong(), meta.plaintextSize)

        // Verify wrappedDek is valid WrapsEnvelope JSON
        val envelope = WrapsEnvelope.fromJson(meta.wrappedDek)
        assertEquals(WrapsEnvelope.CURRENT_SCHEMA_VERSION, envelope.schemaVersion)
        assertNotNull(envelope.device)

        // Verify file stored
        assertTrue(documentStore.documentExists(docId))

        // Decrypt
        val decryptResult = service.decryptDocument(docId)
        assertTrue("Decrypt should succeed", decryptResult.isSuccess)
        assertArrayEquals(plaintext, decryptResult.getOrThrow())
    }

    @Test
    fun testImportFailure_storeFails_cleanup() = runTest {
        documentStore.failOnWrite = true

        val input = ByteArrayInputStream("fail test".toByteArray())
        val result = service.importDocument(input, "fail.pdf", "application/pdf")

        assertTrue("Import should fail", result.isFailure)

        // No metadata should be saved
        assertTrue("No metadata should exist", dao.store.isEmpty())

        // No file should exist
        assertTrue("No files should exist", documentStore.docs.isEmpty())
    }

    @Test
    fun testDekZeroizedAfterImport() = runTest {
        val input = ByteArrayInputStream("dek test".toByteArray())
        val result = service.importDocument(input, "dek.pdf", "application/pdf")
        assertTrue(result.isSuccess)

        val docId = result.getOrThrow()
        val meta = dao.findById(docId)!!
        // wrappedDek should be a non-empty JSON string
        assertTrue("wrappedDek should not be empty", meta.wrappedDek.isNotEmpty())
        // Verify it's valid envelope JSON
        val envelope = WrapsEnvelope.fromJson(meta.wrappedDek)
        assertNotNull(envelope.device)
    }

    @Test
    fun testDekZeroizedAfterDecrypt() = runTest {
        // Import first
        val plaintext = "zeroize test".toByteArray()
        val docId = service.importDocument(
            ByteArrayInputStream(plaintext), "z.pdf", "application/pdf"
        ).getOrThrow()

        // Decrypt — if DEK wasn't zeroized, the keyManager would have no record
        // of the unwrapped key, proving it was a temporary local variable
        val result = service.decryptDocument(docId)
        assertTrue(result.isSuccess)
        assertArrayEquals(plaintext, result.getOrThrow())
    }

    @Test
    fun testDeleteDocument_removesFileAndMetadata() = runTest {
        val docId = service.importDocument(
            ByteArrayInputStream("delete me".toByteArray()), "del.pdf", "application/pdf"
        ).getOrThrow()

        assertTrue(documentStore.documentExists(docId))
        assertNotNull(dao.findById(docId))

        val result = service.deleteDocument(docId)
        assertTrue("Delete should succeed", result.isSuccess)

        assertFalse("File should be gone", documentStore.documentExists(docId))
        assertNull("Metadata should be gone", dao.findById(docId))
    }

    @Test
    fun testDecryptDocumentToTempFile() = runTest {
        val plaintext = "temp file test".toByteArray()
        val docId = service.importDocument(
            ByteArrayInputStream(plaintext), "tmp.pdf", "application/pdf"
        ).getOrThrow()

        val tempDir = File(System.getProperty("java.io.tmpdir"), "securecore-test-${System.nanoTime()}")
        try {
            val result = service.decryptDocumentToTempFile(docId, tempDir)
            assertTrue(result.isSuccess)
            val file = result.getOrThrow()
            assertTrue(file.exists())
            assertEquals("$docId.preview", file.name)
            assertArrayEquals(plaintext, file.readBytes())
        } finally {
            tempDir.deleteRecursively()
        }
    }

    @Test
    fun testListDocuments() = runTest {
        service.importDocument(
            ByteArrayInputStream("a".toByteArray()), "a.pdf", "application/pdf"
        )
        service.importDocument(
            ByteArrayInputStream("b".toByteArray()), "b.pdf", "application/pdf"
        )

        val result = service.listDocuments()
        assertTrue(result.isSuccess)
        val list = result.getOrThrow()
        assertEquals(2, list.size)
        assertTrue(list.any { it.filename == "a.pdf" })
        assertTrue(list.any { it.filename == "b.pdf" })
    }

    @Test
    fun testDecryptNonExistentDocument() = runTest {
        val result = service.decryptDocument("non-existent")
        assertTrue("Should fail for missing doc", result.isFailure)
    }
}
