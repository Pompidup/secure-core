package com.securecore.metadata

import com.securecore.SecureCoreResult
import com.securecore.keymanager.DeviceWrap
import com.securecore.keymanager.WrapsEnvelope
import com.securecore.store.PrivateDirDocumentStore
import org.junit.Assert.*
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class MetadataRepositoryTest {

    @get:Rule
    val tempFolder = TemporaryFolder()

    private lateinit var dao: FakeDocumentDao
    private lateinit var repository: MetadataRepository

    /**
     * In-memory fake DAO for pure JVM tests (no Robolectric/Room needed).
     */
    private class FakeDocumentDao : DocumentDao {
        private val store = mutableMapOf<String, DocumentEntity>()

        override fun insert(doc: DocumentEntity) {
            store[doc.docId] = doc
        }

        override fun findById(docId: String): DocumentEntity? = store[docId]

        override fun findAll(): List<DocumentEntity> =
            store.values.sortedByDescending { it.createdAt }

        override fun delete(docId: String): Int {
            return if (store.remove(docId) != null) 1 else 0
        }

        override fun update(doc: DocumentEntity) {
            if (store.containsKey(doc.docId)) {
                store[doc.docId] = doc
            }
        }
    }

    companion object {
        fun sampleEnvelopeJson(): String = WrapsEnvelope(
            schemaVersion = WrapsEnvelope.CURRENT_SCHEMA_VERSION,
            device = DeviceWrap(
                algo = WrapsEnvelope.ALGO_AES_256_GCM_KEYSTORE,
                keyAlias = "secure_core_master_key_v1",
                iv = "oKCgoKCgoKCgoKCg",       // 12 bytes base64
                tag = "sLCwsLCwsLCwsLCwsLCw",   // 16 bytes base64
                ciphertext = "AQIDBA=="          // 4 bytes base64
            )
        ).toJson()
    }

    private fun makeEntity(docId: String): DocumentEntity = DocumentEntity(
        docId = docId,
        filename = "$docId.pdf",
        mimeType = "application/pdf",
        createdAt = System.currentTimeMillis(),
        plaintextSize = 1024,
        ciphertextSize = 1080,
        contentHash = "abcdef1234567890",
        wrappedDek = sampleEnvelopeJson()
    )

    @Before
    fun setUp() {
        dao = FakeDocumentDao()
        repository = MetadataRepository(dao)
    }

    @Test
    fun testInsertAndFind() {
        val entity = makeEntity("doc-001")
        val saveResult = repository.save(entity)
        assertTrue("Save should succeed", saveResult is SecureCoreResult.Success)

        val getResult = repository.get("doc-001")
        assertTrue("Get should succeed", getResult is SecureCoreResult.Success)
        val found = (getResult as SecureCoreResult.Success).value
        assertNotNull(found)
        assertEquals("doc-001", found!!.docId)
        assertEquals("doc-001.pdf", found.filename)
    }

    @Test
    fun testWrappedDekIsValidEnvelopeJson() {
        val entity = makeEntity("doc-envelope")
        repository.save(entity)
        val found = (repository.get("doc-envelope") as SecureCoreResult.Success).value!!
        val envelope = WrapsEnvelope.fromJson(found.wrappedDek)
        assertEquals(WrapsEnvelope.CURRENT_SCHEMA_VERSION, envelope.schemaVersion)
        assertNotNull(envelope.device)
        assertEquals(WrapsEnvelope.ALGO_AES_256_GCM_KEYSTORE, envelope.device!!.algo)
    }

    @Test
    fun testDeleteNonExistent() {
        val result = repository.delete("non-existent")
        assertTrue("Delete should succeed", result is SecureCoreResult.Success)
        assertEquals(0, (result as SecureCoreResult.Success).value)
    }

    @Test
    fun testListEmpty() {
        val result = repository.list()
        assertTrue("List should succeed", result is SecureCoreResult.Success)
        assertEquals(emptyList<DocumentEntity>(), (result as SecureCoreResult.Success).value)
    }

    @Test
    fun testListMultiple() {
        repository.save(makeEntity("a"))
        repository.save(makeEntity("b"))
        repository.save(makeEntity("c"))

        val result = repository.list()
        assertTrue(result is SecureCoreResult.Success)
        assertEquals(3, (result as SecureCoreResult.Success).value.size)
    }

    @Test
    fun testReconciliation_metadataWithoutFile() {
        val docsDir = tempFolder.newFolder("documents")
        val quarantineDir = tempFolder.newFolder("quarantine")
        val store = PrivateDirDocumentStore(docsDir)

        // Insert metadata but no .enc file
        repository.save(makeEntity("orphan-meta"))

        val service = ReconciliationService(store, repository, docsDir, quarantineDir)
        val report = service.reconcile()

        assertEquals("Should detect 1 orphaned metadata", 1, report.orphanedMetadata)
        assertEquals(0, report.orphanedFiles)

        // Metadata should be deleted
        val getResult = repository.get("orphan-meta")
        assertTrue(getResult is SecureCoreResult.Success)
        assertNull((getResult as SecureCoreResult.Success).value)
    }

    @Test
    fun testReconciliation_fileWithoutMetadata() {
        val docsDir = tempFolder.newFolder("documents")
        val quarantineDir = tempFolder.newFolder("quarantine")
        val store = PrivateDirDocumentStore(docsDir)

        // Write a .enc file but no metadata row
        store.writeDocument("orphan-file", byteArrayOf(1, 2, 3))

        val service = ReconciliationService(store, repository, docsDir, quarantineDir)
        val report = service.reconcile()

        assertEquals(0, report.orphanedMetadata)
        assertEquals("Should detect 1 orphaned file", 1, report.orphanedFiles)

        // File should be moved to quarantine
        assertFalse("File should no longer be in documents", store.documentExists("orphan-file"))
        assertTrue(
            "File should be in quarantine",
            java.io.File(quarantineDir, "orphan-file.enc").exists()
        )
    }

    @Test
    fun testReconciliation_allConsistent() {
        val docsDir = tempFolder.newFolder("documents")
        val quarantineDir = tempFolder.newFolder("quarantine")
        val store = PrivateDirDocumentStore(docsDir)

        // Both file and metadata exist
        store.writeDocument("consistent", byteArrayOf(10, 20))
        repository.save(makeEntity("consistent"))

        val service = ReconciliationService(store, repository, docsDir, quarantineDir)
        val report = service.reconcile()

        assertEquals(0, report.orphanedMetadata)
        assertEquals(0, report.orphanedFiles)
        assertTrue(store.documentExists("consistent"))
    }
}
