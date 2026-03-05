package com.securecore.keymanager

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
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
 * Wire format of a wrapped DEK: `nonce (12 bytes) || ciphertext+tag`.
 */
class KeystoreKeyManager(
    private val alias: String = DEFAULT_ALIAS
) : KeyManager {

    companion object {
        const val DEFAULT_ALIAS = "secure_core_master_key_v1"
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val GCM_NONCE_LENGTH = 12
        private const val GCM_TAG_BITS = 128
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
    }

    private val keyStore: KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    override fun wrapDek(dek: ByteArray): ByteArray {
        require(dek.size == 32) { "DEK must be exactly 32 bytes" }
        try {
            val masterKey = getOrCreateKey()
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.ENCRYPT_MODE, masterKey)
            val nonce = cipher.iv
            val ciphertext = cipher.doFinal(dek)
            return nonce + ciphertext
        } catch (e: Exception) {
            throw KeyManagerError.WrapFailed(e)
        }
    }

    override fun unwrapDek(wrappedDek: ByteArray): ByteArray {
        require(wrappedDek.size > GCM_NONCE_LENGTH) { "Wrapped DEK too short" }
        try {
            val masterKey = loadKey()
                ?: throw KeyManagerError.KeyNotFound()
            val nonce = wrappedDek.copyOfRange(0, GCM_NONCE_LENGTH)
            val ciphertext = wrappedDek.copyOfRange(GCM_NONCE_LENGTH, wrappedDek.size)
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.DECRYPT_MODE, masterKey, GCMParameterSpec(GCM_TAG_BITS, nonce))
            return cipher.doFinal(ciphertext)
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
