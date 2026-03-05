package com.securecore.keymanager

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * [KeyManager] backed by the Android Keystore.
 *
 * Uses AES-256-GCM to wrap/unwrap DEKs. The master key is hardware-backed
 * when the device supports it (StrongBox or TEE).
 *
 * Produces and consumes [WrapsEnvelope] JSON (see `docs/wraps-schema-v1.md`).
 */
class KeystoreKeyManager(
    private val alias: String = DEFAULT_ALIAS
) : KeyManager {

    companion object {
        const val DEFAULT_ALIAS = "secure_core_master_key_v1"
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val GCM_NONCE_LENGTH = 12
        private const val GCM_TAG_BITS = 128
        private const val GCM_TAG_BYTES = 16
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
    }

    private val keyStore: KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    override fun wrapDek(dek: ByteArray): String {
        require(dek.size == 32) { "DEK must be exactly 32 bytes" }
        try {
            val masterKey = getOrCreateKey()
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.ENCRYPT_MODE, masterKey)
            val iv = cipher.iv
            val output = cipher.doFinal(dek)

            // GCM appends the 16-byte tag to ciphertext
            val ciphertext = output.copyOfRange(0, output.size - GCM_TAG_BYTES)
            val tag = output.copyOfRange(output.size - GCM_TAG_BYTES, output.size)

            val envelope = WrapsEnvelope(
                schemaVersion = WrapsEnvelope.CURRENT_SCHEMA_VERSION,
                device = DeviceWrap(
                    algo = WrapsEnvelope.ALGO_AES_256_GCM_KEYSTORE,
                    keyAlias = alias,
                    iv = Base64.encodeToString(iv, Base64.NO_WRAP),
                    tag = Base64.encodeToString(tag, Base64.NO_WRAP),
                    ciphertext = Base64.encodeToString(ciphertext, Base64.NO_WRAP)
                )
            )
            return envelope.toJson()
        } catch (e: Exception) {
            throw KeyManagerError.WrapFailed(e)
        }
    }

    override fun unwrapDek(wrappedDekJson: String): ByteArray {
        try {
            val envelope = WrapsEnvelope.fromJson(wrappedDekJson)
            envelope.validate()

            val device = envelope.device
                ?: throw KeyManagerError.WrapFormatInvalid("device must not be null")

            val masterKey = loadKey()
                ?: throw KeyManagerError.KeyNotFound()

            val iv = device.ivBytes()
            val ciphertext = device.ciphertextBytes()
            val tag = device.tagBytes()

            // Reconstruct GCM input: ciphertext + tag
            val input = ciphertext + tag

            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.DECRYPT_MODE, masterKey, GCMParameterSpec(GCM_TAG_BITS, iv))
            return cipher.doFinal(input)
        } catch (e: KeyManagerError) {
            throw e
        } catch (e: Exception) {
            throw KeyManagerError.UnwrapFailed(e)
        }
    }

    override fun isKeyAvailable(): Boolean = loadKey() != null

    override fun deleteKey() {
        if (keyStore.containsAlias(alias)) {
            keyStore.deleteEntry(alias)
        }
    }

    private fun loadKey(): SecretKey? {
        val entry = keyStore.getEntry(alias, null) ?: return null
        return (entry as? KeyStore.SecretKeyEntry)?.secretKey
    }

    private fun getOrCreateKey(): SecretKey {
        loadKey()?.let { return it }

        val spec = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setUserAuthenticationRequired(false) // V1: app-level auth, not key-level (see docs/android-keystore-policy.md)
            .build()

        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        generator.init(spec)
        return generator.generateKey()
    }
}
