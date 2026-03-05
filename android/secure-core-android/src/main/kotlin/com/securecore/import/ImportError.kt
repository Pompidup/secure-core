package com.securecore.`import`

sealed class ImportError(message: String) : Exception(message) {
    class UnsupportedMimeType(val found: String) :
        ImportError("Unsupported MIME type: $found")

    class FileTooLarge(val sizeBytes: Long, val maxBytes: Long) :
        ImportError("File too large: $sizeBytes bytes (max $maxBytes)")

    class UriNotAccessible(val uri: String) :
        ImportError("URI not accessible: $uri")
}
