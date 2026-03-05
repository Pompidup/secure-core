package com.securecore.metadata

import com.securecore.SecureCoreResult

/**
 * Repository wrapping [DocumentDao] with [SecureCoreResult] return types.
 */
class MetadataRepository(private val dao: DocumentDao) {

    fun save(entity: DocumentEntity): SecureCoreResult<Unit> {
        return try {
            dao.insert(entity)
            SecureCoreResult.Success(Unit)
        } catch (e: Exception) {
            SecureCoreResult.Error(
                com.securecore.SecureCoreError.IoError(java.io.IOException("metadata save failed", e))
            )
        }
    }

    fun get(docId: String): SecureCoreResult<DocumentEntity?> {
        return try {
            SecureCoreResult.Success(dao.findById(docId))
        } catch (e: Exception) {
            SecureCoreResult.Error(
                com.securecore.SecureCoreError.IoError(java.io.IOException("metadata get failed", e))
            )
        }
    }

    fun list(): SecureCoreResult<List<DocumentEntity>> {
        return try {
            SecureCoreResult.Success(dao.findAll())
        } catch (e: Exception) {
            SecureCoreResult.Error(
                com.securecore.SecureCoreError.IoError(java.io.IOException("metadata list failed", e))
            )
        }
    }

    fun delete(docId: String): SecureCoreResult<Int> {
        return try {
            SecureCoreResult.Success(dao.delete(docId))
        } catch (e: Exception) {
            SecureCoreResult.Error(
                com.securecore.SecureCoreError.IoError(java.io.IOException("metadata delete failed", e))
            )
        }
    }
}
