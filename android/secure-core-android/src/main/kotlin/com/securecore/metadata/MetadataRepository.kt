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
                com.securecore.SecureCoreError.IoError("metadata save failed: ${e.message}")
            )
        }
    }

    fun get(docId: String): SecureCoreResult<DocumentEntity?> {
        return try {
            SecureCoreResult.Success(dao.findById(docId))
        } catch (e: Exception) {
            SecureCoreResult.Error(
                com.securecore.SecureCoreError.IoError("metadata get failed: ${e.message}")
            )
        }
    }

    fun list(): SecureCoreResult<List<DocumentEntity>> {
        return try {
            SecureCoreResult.Success(dao.findAll())
        } catch (e: Exception) {
            SecureCoreResult.Error(
                com.securecore.SecureCoreError.IoError("metadata list failed: ${e.message}")
            )
        }
    }

    fun delete(docId: String): SecureCoreResult<Int> {
        return try {
            SecureCoreResult.Success(dao.delete(docId))
        } catch (e: Exception) {
            SecureCoreResult.Error(
                com.securecore.SecureCoreError.IoError("metadata delete failed: ${e.message}")
            )
        }
    }
}
