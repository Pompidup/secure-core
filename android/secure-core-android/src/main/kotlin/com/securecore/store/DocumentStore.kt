package com.securecore.store

import java.io.InputStream

/**
 * Port for encrypted document storage in the app's private sandbox.
 *
 * All documents are stored as `.enc` blobs. Implementations must guarantee
 * atomic writes (no partial files visible) and never log document contents.
 */
interface DocumentStore {
    fun writeDocument(docId: String, encryptedBytes: ByteArray)
    fun readDocument(docId: String): ByteArray
    fun readDocumentStream(docId: String): InputStream
    fun deleteDocument(docId: String): Boolean
    fun listDocumentIds(): List<String>
    fun documentExists(docId: String): Boolean
    fun cleanOrphanedTempFiles(): Int
}
