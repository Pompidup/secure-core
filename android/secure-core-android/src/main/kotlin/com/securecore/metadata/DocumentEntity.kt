package com.securecore.metadata

import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity(tableName = "documents")
data class DocumentEntity(
    @PrimaryKey val docId: String,
    val filename: String,
    val mimeType: String?,
    val createdAt: Long,
    val plaintextSize: Long?,
    val ciphertextSize: Long,
    val contentHash: String?,
    /** WrapsEnvelope JSON string (see docs/wraps-schema-v1.md). */
    val wrappedDek: String
)
