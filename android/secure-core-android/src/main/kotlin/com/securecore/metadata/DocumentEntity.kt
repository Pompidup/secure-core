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
    val wrappedDek: ByteArray,
    val recoveryWrap: ByteArray?,
    val wrapAlgorithm: String
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is DocumentEntity) return false
        return docId == other.docId &&
            filename == other.filename &&
            mimeType == other.mimeType &&
            createdAt == other.createdAt &&
            plaintextSize == other.plaintextSize &&
            ciphertextSize == other.ciphertextSize &&
            contentHash == other.contentHash &&
            wrappedDek.contentEquals(other.wrappedDek) &&
            recoveryWrap.contentEquals(other.recoveryWrap) &&
            wrapAlgorithm == other.wrapAlgorithm
    }

    override fun hashCode(): Int {
        var result = docId.hashCode()
        result = 31 * result + wrappedDek.contentHashCode()
        return result
    }
}

private fun ByteArray?.contentEquals(other: ByteArray?): Boolean {
    if (this == null && other == null) return true
    if (this == null || other == null) return false
    return this.contentEquals(other)
}
