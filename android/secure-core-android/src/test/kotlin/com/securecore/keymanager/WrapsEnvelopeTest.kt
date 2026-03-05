package com.securecore.keymanager

import android.util.Base64
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

class WrapsEnvelopeTest {

    private fun sampleEnvelope(): WrapsEnvelope = WrapsEnvelope(
        schemaVersion = WrapsEnvelope.CURRENT_SCHEMA_VERSION,
        device = DeviceWrap(
            algo = WrapsEnvelope.ALGO_AES_256_GCM_KEYSTORE,
            keyAlias = "secure_core_master_key_v1",
            iv = Base64.encodeToString(ByteArray(12) { 0xA0.toByte() }, Base64.NO_WRAP),
            tag = Base64.encodeToString(ByteArray(16) { 0xB0.toByte() }, Base64.NO_WRAP),
            ciphertext = Base64.encodeToString(byteArrayOf(1, 2, 3, 4), Base64.NO_WRAP)
        )
    )

    // ── Roundtrip ─────────────────────────────────────────────────────

    @Test
    fun testWrapsEnvelope_valid_roundtrip() {
        val envelope = sampleEnvelope()
        val json = envelope.toJson()
        val parsed = WrapsEnvelope.fromJson(json)

        assertEquals(envelope.schemaVersion, parsed.schemaVersion)
        assertEquals(envelope.device!!.algo, parsed.device!!.algo)
        assertEquals(envelope.device!!.keyAlias, parsed.device!!.keyAlias)
        assertEquals(envelope.device!!.iv, parsed.device!!.iv)
        assertEquals(envelope.device!!.tag, parsed.device!!.tag)
        assertEquals(envelope.device!!.ciphertext, parsed.device!!.ciphertext)
        assertNull(parsed.recovery)

        // Validate should pass
        parsed.validate()
    }

    // ── Null device rejected ──────────────────────────────────────────

    @Test(expected = KeyManagerError.WrapFormatInvalid::class)
    fun testWrapsEnvelope_null_device_rejected() {
        val envelope = WrapsEnvelope(
            schemaVersion = WrapsEnvelope.CURRENT_SCHEMA_VERSION,
            device = null
        )
        envelope.validate()
    }

    @Test(expected = KeyManagerError.WrapFormatInvalid::class)
    fun testWrapsEnvelope_null_device_in_json_rejected() {
        val json = JSONObject().apply {
            put("schema_version", WrapsEnvelope.CURRENT_SCHEMA_VERSION)
            put("device", JSONObject.NULL)
            put("recovery", JSONObject.NULL)
        }.toString()
        val envelope = WrapsEnvelope.fromJson(json)
        envelope.validate()
    }

    // ── Unknown schema version rejected ───────────────────────────────

    @Test(expected = KeyManagerError.VersionTooNew::class)
    fun testWrapsEnvelope_unknown_schema_version_rejected() {
        val json = JSONObject().apply {
            put("schema_version", "99.0")
            put("device", JSONObject().apply {
                put("algo", "AES-256-GCM-KEYSTORE")
                put("key_alias", "key")
                put("iv", "AAAAAAAAAAAAAAAA")
                put("tag", "AAAAAAAAAAAAAAAAAAAAAA==")
                put("ciphertext", "AQ==")
            })
            put("recovery", JSONObject.NULL)
        }.toString()
        WrapsEnvelope.fromJson(json)
    }

    // ── Recovery null accepted ────────────────────────────────────────

    @Test
    fun testWrapsEnvelope_recovery_null_accepted() {
        val envelope = sampleEnvelope()
        assertNull(envelope.recovery)
        envelope.validate() // should not throw
    }

    @Test
    fun testWrapsEnvelope_recovery_non_null_tolerated() {
        // In V1, recovery non-null is tolerated (ignored)
        val json = JSONObject().apply {
            put("schema_version", WrapsEnvelope.CURRENT_SCHEMA_VERSION)
            put("device", JSONObject().apply {
                put("algo", "AES-256-GCM-KEYSTORE")
                put("key_alias", "secure_core_master_key_v1")
                put("iv", Base64.encodeToString(ByteArray(12), Base64.NO_WRAP))
                put("tag", Base64.encodeToString(ByteArray(16), Base64.NO_WRAP))
                put("ciphertext", Base64.encodeToString(byteArrayOf(1), Base64.NO_WRAP))
            })
            put("recovery", JSONObject().apply { put("future", true) })
        }.toString()
        val envelope = WrapsEnvelope.fromJson(json)
        assertNotNull(envelope.recovery)
        envelope.validate() // should not throw despite recovery being non-null
    }

    // ── JSON field validation ─────────────────────────────────────────

    @Test(expected = KeyManagerError.WrapFormatInvalid::class)
    fun testWrapsEnvelope_missing_schema_version() {
        WrapsEnvelope.fromJson("""{"device":null,"recovery":null}""")
    }

    @Test(expected = KeyManagerError.WrapFormatInvalid::class)
    fun testWrapsEnvelope_missing_algo() {
        val json = JSONObject().apply {
            put("schema_version", WrapsEnvelope.CURRENT_SCHEMA_VERSION)
            put("device", JSONObject().apply {
                put("algo", "")
                put("key_alias", "key")
                put("iv", "AA==")
                put("tag", "AA==")
                put("ciphertext", "AA==")
            })
            put("recovery", JSONObject.NULL)
        }.toString()
        WrapsEnvelope.fromJson(json)
    }

    @Test(expected = KeyManagerError.WrapFormatInvalid::class)
    fun testWrapsEnvelope_invalid_json() {
        WrapsEnvelope.fromJson("not json at all")
    }

    // ── Algo validation ───────────────────────────────────────────────

    @Test(expected = KeyManagerError.AlgoUnsupported::class)
    fun testWrapsEnvelope_unsupported_algo_rejected() {
        val envelope = WrapsEnvelope(
            schemaVersion = WrapsEnvelope.CURRENT_SCHEMA_VERSION,
            device = DeviceWrap(
                algo = "CHACHA20-POLY1305-UNKNOWN",
                keyAlias = "key",
                iv = Base64.encodeToString(ByteArray(12), Base64.NO_WRAP),
                tag = Base64.encodeToString(ByteArray(16), Base64.NO_WRAP),
                ciphertext = Base64.encodeToString(byteArrayOf(1), Base64.NO_WRAP)
            )
        )
        envelope.validate()
    }

    // ── Base64 decode helpers ─────────────────────────────────────────

    @Test
    fun testDeviceWrap_decode_helpers() {
        val device = sampleEnvelope().device!!
        assertEquals(12, device.ivBytes().size)
        assertEquals(16, device.tagBytes().size)
        assertEquals(4, device.ciphertextBytes().size)
    }
}
