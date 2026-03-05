package com.securecore.metadata

import android.content.Context
import android.util.Base64
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase
import androidx.room.migration.Migration
import androidx.sqlite.db.SupportSQLiteDatabase
import org.json.JSONObject

/**
 * Room database for document metadata.
 *
 * Version 1: initial schema with `documents` table (wrappedDek as BLOB).
 * Version 2: wrappedDek column changed to TEXT (WrapsEnvelope JSON),
 *            removed recoveryWrap and wrapAlgorithm columns.
 *
 * All future schema changes must use numbered migrations (no destructive fallback).
 */
@Database(entities = [DocumentEntity::class], version = 2, exportSchema = true)
abstract class AppDatabase : RoomDatabase() {

    abstract fun documentDao(): DocumentDao

    companion object {
        private const val DB_NAME = "secure_core_metadata.db"

        @Volatile
        private var instance: AppDatabase? = null

        /**
         * Migration from V1 (wrappedDek BLOB + recoveryWrap + wrapAlgorithm)
         * to V2 (wrappedDek TEXT containing WrapsEnvelope JSON).
         *
         * Converts each row's raw wrapped DEK bytes into a WrapsEnvelope JSON string.
         * The raw format was: nonce (12 bytes) || ciphertext+tag.
         * The new format splits iv, ciphertext, and tag into separate base64 fields.
         */
        val MIGRATION_1_2 = object : Migration(1, 2) {
            override fun migrate(db: SupportSQLiteDatabase) {
                // Create new table with updated schema
                db.execSQL("""
                    CREATE TABLE documents_new (
                        docId TEXT NOT NULL PRIMARY KEY,
                        filename TEXT NOT NULL,
                        mimeType TEXT,
                        createdAt INTEGER NOT NULL,
                        plaintextSize INTEGER,
                        ciphertextSize INTEGER NOT NULL,
                        contentHash TEXT,
                        wrappedDek TEXT NOT NULL
                    )
                """)

                // Migrate data: convert BLOB wrappedDek to WrapsEnvelope JSON
                val cursor = db.query("SELECT * FROM documents")
                while (cursor.moveToNext()) {
                    val docId = cursor.getString(cursor.getColumnIndexOrThrow("docId"))
                    val filename = cursor.getString(cursor.getColumnIndexOrThrow("filename"))
                    val mimeType = cursor.getStringOrNull(cursor.getColumnIndexOrThrow("mimeType"))
                    val createdAt = cursor.getLong(cursor.getColumnIndexOrThrow("createdAt"))
                    val plaintextSize = cursor.getLongOrNull(cursor.getColumnIndexOrThrow("plaintextSize"))
                    val ciphertextSize = cursor.getLong(cursor.getColumnIndexOrThrow("ciphertextSize"))
                    val contentHash = cursor.getStringOrNull(cursor.getColumnIndexOrThrow("contentHash"))
                    val wrappedDekBlob = cursor.getBlob(cursor.getColumnIndexOrThrow("wrappedDek"))
                    val wrapAlgorithm = cursor.getString(cursor.getColumnIndexOrThrow("wrapAlgorithm"))

                    // Convert raw bytes to WrapsEnvelope JSON
                    val envelopeJson = convertBlobToEnvelopeJson(wrappedDekBlob, wrapAlgorithm)

                    db.execSQL(
                        """INSERT INTO documents_new
                           (docId, filename, mimeType, createdAt, plaintextSize, ciphertextSize, contentHash, wrappedDek)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                        arrayOf(docId, filename, mimeType, createdAt, plaintextSize, ciphertextSize, contentHash, envelopeJson)
                    )
                }
                cursor.close()

                // Swap tables
                db.execSQL("DROP TABLE documents")
                db.execSQL("ALTER TABLE documents_new RENAME TO documents")
            }

            private fun convertBlobToEnvelopeJson(blob: ByteArray, wrapAlgorithm: String): String {
                // V1 raw format: nonce (12) || ciphertext+tag
                val iv = blob.copyOfRange(0, 12)
                val ctAndTag = blob.copyOfRange(12, blob.size)
                val tagStart = ctAndTag.size - 16
                val ciphertext = ctAndTag.copyOfRange(0, tagStart)
                val tag = ctAndTag.copyOfRange(tagStart, ctAndTag.size)

                val algo = when (wrapAlgorithm) {
                    "AES-GCM-KEYSTORE" -> "AES-256-GCM-KEYSTORE"
                    else -> wrapAlgorithm
                }

                val deviceObj = JSONObject().apply {
                    put("algo", algo)
                    put("key_alias", "secure_core_master_key_v1")
                    put("iv", Base64.encodeToString(iv, Base64.NO_WRAP))
                    put("tag", Base64.encodeToString(tag, Base64.NO_WRAP))
                    put("ciphertext", Base64.encodeToString(ciphertext, Base64.NO_WRAP))
                }
                return JSONObject().apply {
                    put("schema_version", "1.1")
                    put("device", deviceObj)
                    put("recovery", JSONObject.NULL)
                }.toString()
            }

            private fun android.database.Cursor.getStringOrNull(index: Int): String? =
                if (isNull(index)) null else getString(index)

            private fun android.database.Cursor.getLongOrNull(index: Int): Long? =
                if (isNull(index)) null else getLong(index)
        }

        fun getInstance(context: Context): AppDatabase {
            return instance ?: synchronized(this) {
                instance ?: Room.databaseBuilder(
                    context.applicationContext,
                    AppDatabase::class.java,
                    DB_NAME
                )
                    .addMigrations(MIGRATION_1_2)
                    .build()
                    .also { instance = it }
            }
        }

        /**
         * Creates an in-memory database for testing.
         */
        fun createInMemory(context: Context): AppDatabase {
            return Room.inMemoryDatabaseBuilder(
                context.applicationContext,
                AppDatabase::class.java
            )
                .allowMainThreadQueries()
                .build()
        }
    }
}
