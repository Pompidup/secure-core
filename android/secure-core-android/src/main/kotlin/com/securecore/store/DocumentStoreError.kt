package com.securecore.store

import java.io.IOException

sealed class DocumentStoreError(override val message: String, override val cause: Throwable? = null) :
    Exception(message, cause) {

    class DocumentNotFound(docId: String) :
        DocumentStoreError("Document not found: $docId")

    class WriteFailure(cause: IOException) :
        DocumentStoreError("Failed to write document", cause)

    class CorruptedDocument(docId: String) :
        DocumentStoreError("Document is corrupted: $docId")

    class StorageFull :
        DocumentStoreError("Insufficient storage space")
}
