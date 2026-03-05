package com.securecore.metadata

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.Update

@Dao
interface DocumentDao {

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    fun insert(doc: DocumentEntity)

    @Query("SELECT * FROM documents WHERE docId = :docId")
    fun findById(docId: String): DocumentEntity?

    @Query("SELECT * FROM documents ORDER BY createdAt DESC")
    fun findAll(): List<DocumentEntity>

    @Query("DELETE FROM documents WHERE docId = :docId")
    fun delete(docId: String): Int

    @Update
    fun update(doc: DocumentEntity)
}
