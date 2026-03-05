package com.securecore

/**
 * Public-facing document metadata (no wrapped DEK or internal fields).
 */
data class DocumentMetadata(
    val docId: String,
    val filename: String,
    val mimeType: String?,
    val createdAt: Long,
    val plaintextSize: Long?,
    val ciphertextSize: Long
)
