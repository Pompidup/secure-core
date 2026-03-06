package com.securecore.export

import android.net.Uri
import com.securecore.SecureCoreLib
import com.securecore.SecureCoreResult
import com.securecore.keymanager.KeyManager
import com.securecore.metadata.DocumentEntity
import com.securecore.metadata.MetadataRepository
import com.securecore.store.DocumentStore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.io.OutputStream
import java.security.MessageDigest
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone
import java.util.zip.ZipEntry
import java.util.zip.ZipInputStream
import java.util.zip.ZipOutputStream

data class ExportReport(
    val exportedCount: Int,
    val failedCount: Int,
    val failedDocIds: List<String>
)

data class ImportReport(
    val importedCount: Int,
    val skippedCount: Int,
    val failedCount: Int,
    val failedDocIds: List<String>
)

/**
 * Handles export and import of recovery bundles.
 *
 * See docs/recovery-format-v1.md for the bundle format specification.
 */
class ExportService(
    private val keyManager: KeyManager,
    private val documentStore: DocumentStore,
    private val metadataRepository: MetadataRepository,
    private val outputStreamProvider: (Uri) -> OutputStream,
    private val inputStreamProvider: (Uri) -> java.io.InputStream
) {

    /**
     * Exports selected documents into a recovery bundle zip.
     *
     * For each document:
     * 1. Unwraps the DEK from the device keystore
     * 2. Re-wraps the DEK with the passphrase via Rust FFI
     * 3. Writes the .enc file, metadata, and recovery wrap to the zip
     * 4. Zeroizes the DEK
     */
    suspend fun exportBundle(
        docIds: List<String>,
        passphrase: String,
        outputUri: Uri
    ): Result<ExportReport> = withContext(Dispatchers.IO) {
        val failed = mutableListOf<String>()
        var exported = 0

        try {
            val outputStream = outputStreamProvider(outputUri)
            ZipOutputStream(outputStream).use { zip ->
                for (docId in docIds) {
                    try {
                        exportDocument(zip, docId, passphrase)
                        exported++
                    } catch (e: Exception) {
                        failed.add(docId)
                    }
                }

                // Write manifest
                val manifest = buildManifest(docIds.filter { it !in failed })
                zip.putNextEntry(ZipEntry("manifest.json"))
                zip.write(manifest.toByteArray(Charsets.UTF_8))
                zip.closeEntry()
            }

            Result.success(ExportReport(exported, failed.size, failed))
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    /**
     * Imports documents from a recovery bundle zip.
     *
     * For each document:
     * 1. Reads the recovery wrap and unwraps the DEK with the passphrase via Rust FFI
     * 2. Re-wraps the DEK with the local device keystore
     * 3. Stores the .enc file and metadata
     * 4. Zeroizes the DEK
     */
    suspend fun importBundle(
        bundleUri: Uri,
        passphrase: String
    ): Result<ImportReport> = withContext(Dispatchers.IO) {
        val failed = mutableListOf<String>()
        var imported = 0
        var skipped = 0

        try {
            val entries = mutableMapOf<String, MutableMap<String, ByteArray>>()

            // First pass: read all entries from zip
            ZipInputStream(inputStreamProvider(bundleUri)).use { zip ->
                var entry = zip.nextEntry
                while (entry != null) {
                    val name = entry.name
                    val data = zip.readBytes()

                    when {
                        name.startsWith("documents/") && name.endsWith(".enc") -> {
                            val docId = name.removePrefix("documents/").removeSuffix(".enc")
                            entries.getOrPut(docId) { mutableMapOf() }["enc"] = data
                        }
                        name.startsWith("metadata/") && name.endsWith(".meta.json") -> {
                            val docId = name.removePrefix("metadata/").removeSuffix(".meta.json")
                            entries.getOrPut(docId) { mutableMapOf() }["meta"] = data
                        }
                        name.startsWith("wraps/") && name.endsWith(".wraps.json") -> {
                            val docId = name.removePrefix("wraps/").removeSuffix(".wraps.json")
                            entries.getOrPut(docId) { mutableMapOf() }["wraps"] = data
                        }
                    }

                    zip.closeEntry()
                    entry = zip.nextEntry
                }
            }

            // Second pass: import each document
            for ((docId, files) in entries) {
                try {
                    val encData = files["enc"] ?: continue
                    val metaData = files["meta"] ?: continue
                    val wrapsData = files["wraps"] ?: continue

                    // Check for duplicate
                    val existing = when (val result = metadataRepository.get(docId)) {
                        is SecureCoreResult.Success -> result.value
                        is SecureCoreResult.Error -> null
                    }
                    if (existing != null) {
                        skipped++
                        continue
                    }

                    // Parse recovery wrap and unwrap DEK
                    val wrapsJson = String(wrapsData, Charsets.UTF_8)
                    val wrapsObj = JSONObject(wrapsJson)
                    val recoveryObj = wrapsObj.getJSONObject("recovery")
                    val recoveryJson = recoveryObj.toString()

                    val dek = SecureCoreLib.unwrapDekWithPassphrase(recoveryJson, passphrase)
                    try {
                        // Re-wrap with device keystore
                        val deviceWrappedDek = keyManager.wrapDek(dek)

                        // Store encrypted file
                        documentStore.writeDocument(docId, encData)

                        // Parse and save metadata
                        val metaObj = JSONObject(String(metaData, Charsets.UTF_8))
                        val entity = DocumentEntity(
                            docId = metaObj.getString("docId"),
                            filename = metaObj.getString("filename"),
                            mimeType = metaObj.optString("mimeType", null),
                            createdAt = metaObj.getLong("createdAt"),
                            plaintextSize = if (metaObj.has("plaintextSize")) metaObj.getLong("plaintextSize") else null,
                            ciphertextSize = metaObj.getLong("ciphertextSize"),
                            contentHash = metaObj.optString("contentHash", null),
                            wrappedDek = deviceWrappedDek
                        )

                        when (val saveResult = metadataRepository.save(entity)) {
                            is SecureCoreResult.Success -> imported++
                            is SecureCoreResult.Error -> {
                                documentStore.deleteDocument(docId)
                                failed.add(docId)
                            }
                        }
                    } finally {
                        dek.fill(0)
                    }
                } catch (e: Exception) {
                    failed.add(docId)
                }
            }

            Result.success(ImportReport(imported, skipped, failed.size, failed))
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    // ── Private helpers ─────────────────────────────────────────────

    private suspend fun exportDocument(
        zip: ZipOutputStream,
        docId: String,
        passphrase: String
    ) {
        val entity = when (val result = metadataRepository.get(docId)) {
            is SecureCoreResult.Success -> result.value
                ?: throw IllegalStateException("Document not found: $docId")
            is SecureCoreResult.Error -> throw result.error
        }

        // Unwrap DEK from device keystore
        val dek = keyManager.unwrapDek(entity.wrappedDek)
        try {
            // Re-wrap DEK with passphrase via Rust FFI
            val recoveryWrapJson = SecureCoreLib.wrapDekWithPassphrase(dek, passphrase)

            // Build wraps envelope for bundle
            val wrapsEnvelope = JSONObject().apply {
                put("schema_version", "1.1")
                put("device", JSONObject.NULL)
                put("recovery", JSONObject(recoveryWrapJson))
            }

            // Write encrypted document
            val encData = documentStore.readDocument(docId)
            zip.putNextEntry(ZipEntry("documents/$docId.enc"))
            zip.write(encData)
            zip.closeEntry()

            // Write metadata (without wrappedDek)
            val metaJson = JSONObject().apply {
                put("docId", entity.docId)
                put("filename", entity.filename)
                put("mimeType", entity.mimeType)
                put("createdAt", entity.createdAt)
                put("plaintextSize", entity.plaintextSize)
                put("ciphertextSize", entity.ciphertextSize)
                put("contentHash", entity.contentHash)
            }
            zip.putNextEntry(ZipEntry("metadata/$docId.meta.json"))
            zip.write(metaJson.toString().toByteArray(Charsets.UTF_8))
            zip.closeEntry()

            // Write recovery wrap
            zip.putNextEntry(ZipEntry("wraps/$docId.wraps.json"))
            zip.write(wrapsEnvelope.toString().toByteArray(Charsets.UTF_8))
            zip.closeEntry()
        } finally {
            dek.fill(0)
        }
    }

    private fun buildManifest(exportedDocIds: List<String>): String {
        val sorted = exportedDocIds.sorted()
        val checksumInput = sorted.joinToString("\n")
        val digest = MessageDigest.getInstance("SHA-256")
        val checksum = digest.digest(checksumInput.toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02x".format(it) }

        val dateFormat = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'", Locale.US).apply {
            timeZone = TimeZone.getTimeZone("UTC")
        }

        return JSONObject().apply {
            put("format", "recovery_bundle_v1")
            put("version", 1)
            put("created_at", dateFormat.format(Date()))
            put("document_count", sorted.size)
            put("checksum", checksum)
        }.toString(2)
    }
}
