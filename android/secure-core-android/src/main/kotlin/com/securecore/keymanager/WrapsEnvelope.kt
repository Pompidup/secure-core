package com.securecore.keymanager

import android.util.Base64
import org.json.JSONObject

/**
 * Canonical envelope for a wrapped DEK.
 *
 * See `docs/wraps-schema-v1.md` for the frozen specification.
 */
data class WrapsEnvelope(
    val schemaVersion: String,
    val device: DeviceWrap?,
    val recovery: JSONObject? = null
) {
    companion object {
        const val CURRENT_SCHEMA_VERSION = "1.1"
        const val ALGO_AES_256_GCM_KEYSTORE = "AES-256-GCM-KEYSTORE"

        /**
         * Parses a [WrapsEnvelope] from its JSON string representation.
         *
         * @throws KeyManagerError.WrapFormatInvalid if JSON is malformed or missing required fields.
         * @throws KeyManagerError.VersionTooNew if schema_version is unsupported.
         */
        fun fromJson(json: String): WrapsEnvelope {
            val obj = try {
                JSONObject(json)
            } catch (e: Exception) {
                throw KeyManagerError.WrapFormatInvalid("invalid JSON: ${e.message}")
            }

            val version = obj.optString("schema_version", "")
            if (version.isEmpty()) {
                throw KeyManagerError.WrapFormatInvalid("missing schema_version")
            }
            if (version != CURRENT_SCHEMA_VERSION) {
                throw KeyManagerError.VersionTooNew(version, CURRENT_SCHEMA_VERSION)
            }

            val deviceObj = if (obj.isNull("device")) null else obj.optJSONObject("device")
            val device = deviceObj?.let { d ->
                DeviceWrap(
                    algo = d.optString("algo", "").also {
                        if (it.isEmpty()) throw KeyManagerError.WrapFormatInvalid("missing device.algo")
                    },
                    keyAlias = d.optString("key_alias", "").also {
                        if (it.isEmpty()) throw KeyManagerError.WrapFormatInvalid("missing device.key_alias")
                    },
                    iv = d.optString("iv", "").also {
                        if (it.isEmpty()) throw KeyManagerError.WrapFormatInvalid("missing device.iv")
                    },
                    tag = d.optString("tag", "").also {
                        if (it.isEmpty()) throw KeyManagerError.WrapFormatInvalid("missing device.tag")
                    },
                    ciphertext = d.optString("ciphertext", "").also {
                        if (it.isEmpty()) throw KeyManagerError.WrapFormatInvalid("missing device.ciphertext")
                    }
                )
            }

            val recovery = if (obj.isNull("recovery")) null else obj.optJSONObject("recovery")

            return WrapsEnvelope(
                schemaVersion = version,
                device = device,
                recovery = recovery
            )
        }
    }

    /**
     * Serializes this envelope to its canonical JSON string.
     */
    fun toJson(): String {
        val obj = JSONObject()
        obj.put("schema_version", schemaVersion)

        if (device != null) {
            val d = JSONObject()
            d.put("algo", device.algo)
            d.put("key_alias", device.keyAlias)
            d.put("iv", device.iv)
            d.put("tag", device.tag)
            d.put("ciphertext", device.ciphertext)
            obj.put("device", d)
        } else {
            obj.put("device", JSONObject.NULL)
        }

        if (recovery != null) {
            obj.put("recovery", recovery)
        } else {
            obj.put("recovery", JSONObject.NULL)
        }

        return obj.toString()
    }

    /**
     * Validates this envelope. Throws on error.
     *
     * @throws KeyManagerError.WrapFormatInvalid if device is null or fields are invalid.
     * @throws KeyManagerError.VersionTooNew if schema_version is unsupported.
     * @throws KeyManagerError.AlgoUnsupported if algo is not recognized.
     */
    fun validate() {
        if (schemaVersion != CURRENT_SCHEMA_VERSION) {
            throw KeyManagerError.VersionTooNew(schemaVersion, CURRENT_SCHEMA_VERSION)
        }
        val d = device ?: throw KeyManagerError.WrapFormatInvalid("device must not be null")
        if (d.algo.isEmpty()) throw KeyManagerError.WrapFormatInvalid("device.algo must not be empty")
        if (d.keyAlias.isEmpty()) throw KeyManagerError.WrapFormatInvalid("device.key_alias must not be empty")

        val ivBytes = d.ivBytes()
        if (ivBytes.size != 12) {
            throw KeyManagerError.WrapFormatInvalid("device.iv must be 12 bytes, got ${ivBytes.size}")
        }
        val tagBytes = d.tagBytes()
        if (tagBytes.size != 16) {
            throw KeyManagerError.WrapFormatInvalid("device.tag must be 16 bytes, got ${tagBytes.size}")
        }
        if (d.ciphertextBytes().isEmpty()) {
            throw KeyManagerError.WrapFormatInvalid("device.ciphertext must not be empty")
        }

        if (d.algo != ALGO_AES_256_GCM_KEYSTORE) {
            throw KeyManagerError.AlgoUnsupported(d.algo)
        }
    }
}

/**
 * Device-local DEK wrap produced by the OS keystore.
 */
data class DeviceWrap(
    val algo: String,
    val keyAlias: String,
    val iv: String,
    val tag: String,
    val ciphertext: String
) {
    fun ivBytes(): ByteArray = Base64.decode(iv, Base64.DEFAULT)
    fun tagBytes(): ByteArray = Base64.decode(tag, Base64.DEFAULT)
    fun ciphertextBytes(): ByteArray = Base64.decode(ciphertext, Base64.DEFAULT)
}
