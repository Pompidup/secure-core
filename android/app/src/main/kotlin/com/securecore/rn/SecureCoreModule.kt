package com.securecore.rn

import android.net.Uri
import android.util.Base64
import com.facebook.react.bridge.Arguments
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReactContextBaseJavaModule
import com.facebook.react.bridge.ReactMethod
import com.securecore.SecureCoreError
import com.securecore.auth.AuthError
import com.securecore.auth.AuthGate
import com.securecore.`import`.ImportError
import com.securecore.`import`.ImportService
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import java.io.File

class SecureCoreModule(
    reactContext: ReactApplicationContext
) : ReactContextBaseJavaModule(reactContext) {

    override fun getName(): String = "SecureCore"

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    private val authGate: AuthGate
        get() = SecureCoreServiceLocator.authGate
            ?: throw IllegalStateException("AuthGate not initialized")

    private val importService: ImportService
        get() = SecureCoreServiceLocator.importService
            ?: throw IllegalStateException("ImportService not initialized")

    private val tempDir: File
        get() = File(reactApplicationContext.cacheDir, "previews")

    @ReactMethod
    fun importDocument(uriString: String, promise: Promise) {
        scope.launch {
            try {
                val uri = Uri.parse(uriString)
                importService.importFromUri(uri)
                    .fold(
                        onSuccess = { docId ->
                            val result = Arguments.createMap().apply {
                                putString("docId", docId)
                            }
                            promise.resolve(result)
                        },
                        onFailure = { rejectWithError(promise, it) }
                    )
            } catch (e: Exception) {
                rejectWithError(promise, e)
            }
        }
    }

    @ReactMethod
    fun decryptToMemory(docId: String, promise: Promise) {
        scope.launch {
            try {
                authGate.decryptDocument(docId)
                    .fold(
                        onSuccess = { bytes ->
                            val result = Arguments.createMap().apply {
                                putString("bytes", Base64.encodeToString(bytes, Base64.NO_WRAP))
                                putString("mimeType", getMimeType(docId))
                            }
                            promise.resolve(result)
                        },
                        onFailure = { rejectWithError(promise, it) }
                    )
            } catch (e: Exception) {
                rejectWithError(promise, e)
            }
        }
    }

    @ReactMethod
    fun decryptToTempFile(docId: String, promise: Promise) {
        scope.launch {
            try {
                authGate.decryptDocumentToTempFile(docId, tempDir)
                    .fold(
                        onSuccess = { file ->
                            val result = Arguments.createMap().apply {
                                putString("uri", Uri.fromFile(file).toString())
                            }
                            promise.resolve(result)
                        },
                        onFailure = { rejectWithError(promise, it) }
                    )
            } catch (e: Exception) {
                rejectWithError(promise, e)
            }
        }
    }

    @ReactMethod
    fun listDocuments(promise: Promise) {
        scope.launch {
            try {
                authGate.listDocuments()
                    .fold(
                        onSuccess = { docs ->
                            val array = Arguments.createArray()
                            for (doc in docs) {
                                val map = Arguments.createMap().apply {
                                    putString("docId", doc.docId)
                                    putString("filename", doc.filename)
                                    putString("mimeType", doc.mimeType)
                                    putDouble("createdAt", doc.createdAt.toDouble())
                                    putDouble("ciphertextSize", doc.ciphertextSize.toDouble())
                                }
                                array.pushMap(map)
                            }
                            promise.resolve(array)
                        },
                        onFailure = { rejectWithError(promise, it) }
                    )
            } catch (e: Exception) {
                rejectWithError(promise, e)
            }
        }
    }

    @ReactMethod
    fun exportBundle(docIds: com.facebook.react.bridge.ReadableArray, passphrase: String, promise: Promise) {
        scope.launch {
            try {
                val ids = (0 until docIds.size()).map { docIds.getString(it) }
                val exportService = SecureCoreServiceLocator.exportService
                    ?: throw IllegalStateException("ExportService not initialized")

                // Create temp file for the bundle
                val tempFile = File(reactApplicationContext.cacheDir, "recovery_bundle_${System.currentTimeMillis()}.zip")
                val outputUri = Uri.fromFile(tempFile)

                exportService.exportBundle(ids, passphrase, outputUri)
                    .fold(
                        onSuccess = { report ->
                            val result = Arguments.createMap().apply {
                                putString("uri", outputUri.toString())
                                putInt("exportedCount", report.exportedCount)
                                putInt("failedCount", report.failedCount)
                            }
                            promise.resolve(result)
                        },
                        onFailure = { rejectWithError(promise, it) }
                    )
            } catch (e: Exception) {
                rejectWithError(promise, e)
            }
        }
    }

    @ReactMethod
    fun importBundle(bundleUriString: String, passphrase: String, promise: Promise) {
        scope.launch {
            try {
                val bundleUri = Uri.parse(bundleUriString)
                val exportService = SecureCoreServiceLocator.exportService
                    ?: throw IllegalStateException("ExportService not initialized")

                exportService.importBundle(bundleUri, passphrase)
                    .fold(
                        onSuccess = { report ->
                            val result = Arguments.createMap().apply {
                                putInt("importedCount", report.importedCount)
                                putInt("skippedCount", report.skippedCount)
                                putInt("failedCount", report.failedCount)
                            }
                            promise.resolve(result)
                        },
                        onFailure = { rejectWithError(promise, it) }
                    )
            } catch (e: Exception) {
                rejectWithError(promise, e)
            }
        }
    }

    @ReactMethod
    fun deleteDocument(docId: String, promise: Promise) {
        scope.launch {
            try {
                authGate.deleteDocument(docId)
                    .fold(
                        onSuccess = {
                            val result = Arguments.createMap().apply {
                                putBoolean("deleted", true)
                            }
                            promise.resolve(result)
                        },
                        onFailure = { rejectWithError(promise, it) }
                    )
            } catch (e: Exception) {
                rejectWithError(promise, e)
            }
        }
    }

    override fun invalidate() {
        scope.cancel()
        super.invalidate()
    }

    private suspend fun getMimeType(docId: String): String {
        return authGate.listDocuments()
            .getOrNull()
            ?.find { it.docId == docId }
            ?.mimeType
            ?: "application/octet-stream"
    }

    companion object {
        internal fun rejectWithError(promise: Promise, error: Throwable) {
            val (code, message) = when (error) {
                is ImportError.UnsupportedMimeType -> "UNSUPPORTED_TYPE" to "Unsupported file type: ${error.found}"
                is ImportError.FileTooLarge -> "FILE_TOO_LARGE" to "File exceeds size limit"
                is ImportError.UriNotAccessible -> "URI_ERROR" to "Cannot access file"
                is AuthError.AuthRequired -> "AUTH_REQUIRED" to "Authentication required"
                is AuthError.UserCancelled -> "AUTH_REQUIRED" to "Authentication cancelled"
                is AuthError.LockedOut -> "AUTH_REQUIRED" to "Too many attempts, try again later"
                is AuthError.NoBiometrics -> "AUTH_REQUIRED" to "No biometrics enrolled"
                is AuthError.NotAvailable -> "AUTH_REQUIRED" to "Biometric hardware not available"
                is SecureCoreError.CryptoError -> "CRYPTO_ERROR" to "Cryptographic operation failed"
                is SecureCoreError.InvalidParameter -> "INVALID_PARAM" to "Invalid parameter"
                is SecureCoreError.IoError -> "IO_ERROR" to "I/O error"
                is SecureCoreError.InvalidFormat -> "CRYPTO_ERROR" to "Invalid data format"
                is SecureCoreError.UnsupportedVersion -> "CRYPTO_ERROR" to "Unsupported format version"
                is SecureCoreError.Unknown -> "CRYPTO_ERROR" to "Operation failed"
                is SecurityException -> "KEY_ERROR" to "Key access denied"
                is java.security.KeyStoreException -> "KEY_ERROR" to "Keystore error"
                is java.security.UnrecoverableKeyException -> "KEY_ERROR" to "Key unavailable"
                else -> "IO_ERROR" to "Unexpected error"
            }
            promise.reject(code, message)
        }
    }
}
