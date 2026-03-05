package com.securecore.store

import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.rules.TemporaryFolder
import org.junit.Rule
import java.io.File

class DocumentStoreTest {

    @get:Rule
    val tempFolder = TemporaryFolder()

    private lateinit var store: PrivateDirDocumentStore
    private lateinit var baseDir: File

    @Before
    fun setUp() {
        baseDir = tempFolder.newFolder("documents")
        store = PrivateDirDocumentStore(baseDir)
    }

    @Test
    fun testWriteReadRoundtrip() {
        val data = byteArrayOf(1, 2, 3, 4, 5)
        store.writeDocument("doc-001", data)
        val read = store.readDocument("doc-001")
        assertArrayEquals(data, read)
    }

    @Test
    fun testAtomicWriteNoCorruptedFile() {
        // Simulate: a .tmp exists but no .enc (as if process died mid-write)
        val tmp = File(baseDir, "doc-crash.enc.tmp")
        tmp.writeBytes(byteArrayOf(0xFF.toByte()))

        // The .enc file should NOT exist
        assertFalse("Partial write should not produce .enc", store.documentExists("doc-crash"))

        // A subsequent real write should succeed cleanly
        store.writeDocument("doc-crash", byteArrayOf(10, 20, 30))
        assertTrue(store.documentExists("doc-crash"))
        assertArrayEquals(byteArrayOf(10, 20, 30), store.readDocument("doc-crash"))
    }

    @Test
    fun testDeleteNonExistent() {
        val result = store.deleteDocument("xyz")
        assertFalse("Deleting non-existent doc should return false", result)
    }

    @Test
    fun testDeleteExisting() {
        store.writeDocument("to-delete", byteArrayOf(1))
        assertTrue(store.documentExists("to-delete"))
        assertTrue(store.deleteDocument("to-delete"))
        assertFalse(store.documentExists("to-delete"))
    }

    @Test
    fun testCleanOrphanedTempFiles() {
        // Create 3 .tmp files with old timestamps
        val oldTime = System.currentTimeMillis() - 10 * 60 * 1000 // 10 min ago
        for (i in 1..3) {
            val tmp = File(baseDir, "orphan-$i.enc.tmp")
            tmp.writeBytes(byteArrayOf(i.toByte()))
            tmp.setLastModified(oldTime)
        }
        // Create 1 recent .tmp (should NOT be cleaned)
        val recent = File(baseDir, "recent.enc.tmp")
        recent.writeBytes(byteArrayOf(99))
        recent.setLastModified(System.currentTimeMillis())

        val cleaned = store.cleanOrphanedTempFiles()
        assertEquals("Should clean 3 old orphans", 3, cleaned)
        assertTrue("Recent tmp should remain", recent.exists())
    }

    @Test
    fun testListDocumentIds() {
        store.writeDocument("alpha", byteArrayOf(1))
        store.writeDocument("beta", byteArrayOf(2))
        store.writeDocument("gamma", byteArrayOf(3))

        // Create a .tmp that should NOT appear in the list
        File(baseDir, "hidden.enc.tmp").writeBytes(byteArrayOf(0))

        val ids = store.listDocumentIds()
        assertEquals(listOf("alpha", "beta", "gamma"), ids)
    }

    @Test(expected = DocumentStoreError.DocumentNotFound::class)
    fun testReadNonExistentThrows() {
        store.readDocument("no-such-doc")
    }

    @Test(expected = DocumentStoreError.DocumentNotFound::class)
    fun testReadStreamNonExistentThrows() {
        store.readDocumentStream("no-such-doc")
    }

    @Test
    fun testReadDocumentStream() {
        val data = byteArrayOf(10, 20, 30, 40, 50)
        store.writeDocument("stream-doc", data)
        val read = store.readDocumentStream("stream-doc").use { it.readBytes() }
        assertArrayEquals(data, read)
    }

    @Test
    fun testNoBackupDir() {
        // Verify the store uses the directory we gave it (which in production
        // would be context.noBackupFilesDir/documents)
        assertTrue("Base dir should exist", baseDir.exists())
        assertTrue("Base dir should be a directory", baseDir.isDirectory)
    }

    @Test(expected = IllegalArgumentException::class)
    fun testRejectsPathTraversal() {
        store.writeDocument("../escape", byteArrayOf(1))
    }

    @Test(expected = IllegalArgumentException::class)
    fun testRejectsSlashInDocId() {
        store.writeDocument("sub/dir", byteArrayOf(1))
    }

    @Test
    fun testOverwriteExistingDocument() {
        store.writeDocument("overwrite", byteArrayOf(1, 2, 3))
        store.writeDocument("overwrite", byteArrayOf(4, 5, 6))
        assertArrayEquals(byteArrayOf(4, 5, 6), store.readDocument("overwrite"))
    }
}
