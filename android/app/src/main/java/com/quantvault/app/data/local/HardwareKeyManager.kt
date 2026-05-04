package com.quantvault.app.data.local

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import android.util.Base64
import java.security.MessageDigest

class HardwareKeyManager(private val context: Context) {

    companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val KEY_ALIAS = "pq_vault_hardware_key"
        private const val GCM_TAG_LENGTH = 128
        private const val GCM_IV_SIZE = 12
    }

    private val keyStore: KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply {
        load(null)
    }

    fun generateHardwareKey(): SecretKey {
        val keyGenerator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES,
            ANDROID_KEYSTORE
        )

        val spec = KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setUserAuthenticationRequired(true)
            .setUserAuthenticationParameters(
                300, // 5 minute timeout
                KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL
            )
            .setAttestationChallenge(context.packageName.toByteArray())
            .build()

        keyGenerator.init(spec)
        return keyGenerator.generateKey()
    }

    fun getOrCreateHardwareKey(): SecretKey {
        return if (keyStore.containsAlias(KEY_ALIAS)) {
            keyStore.getKey(KEY_ALIAS, null) as SecretKey
        } else {
            generateHardwareKey()
        }
    }

    fun isHardwareKeyAvailable(): Boolean {
        return try {
            keyStore.containsAlias(KEY_ALIAS)
        } catch (e: Exception) {
            false
        }
    }

    fun encryptWithHardwareKey(data: ByteArray): ByteArray {
        val key = getOrCreateHardwareKey()
        val iv = ByteArray(GCM_IV_SIZE).also { SecureRandom().nextBytes(it) }

        val cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, key)
        cipher.updateAAD("pq-vault-hardware".toByteArray())

        val encrypted = cipher.doFinal(data)
        return iv + encrypted
    }

    fun decryptWithHardwareKey(encryptedData: ByteArray): ByteArray {
        val key = getOrCreateHardwareKey()
        val iv = encryptedData.copyOfRange(0, GCM_IV_SIZE)
        val ciphertext = encryptedData.copyOfRange(GCM_IV_SIZE, encryptedData.size)

        val cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding")
        val spec = GCMParameterSpec(GCM_TAG_LENGTH, iv)
        cipher.init(javax.crypto.Cipher.DECRYPT_MODE, key, spec)
        cipher.updateAAD("pq-vault-hardware".toByteArray())

        return cipher.doFinal(ciphertext)
    }

    fun deleteHardwareKey() {
        if (keyStore.containsAlias(KEY_ALIAS)) {
            keyStore.deleteEntry(KEY_ALIAS)
        }
    }

    fun generateDeviceBoundSalt(): ByteArray {
        val deviceId = android.provider.Settings.Secure.getString(
            context.contentResolver,
            android.provider.Settings.Secure.ANDROID_ID
        ) ?: throw Exception("Device ID unavailable")

        val hardwareKey = try {
            getOrCreateHardwareKey()
        } catch (e: Exception) {
            null
        }

        return if (hardwareKey != null) {
            val hashed = MessageDigest.getInstance("SHA-256")
                .digest((deviceId + "pq-vault-salt").toByteArray())
            encryptWithHardwareKey(hashed)
        } else {
            val salt = ByteArray(32).also { SecureRandom().nextBytes(it) }
            val hashed = MessageDigest.getInstance("SHA-256")
                .digest((deviceId + "pq-vault-salt").toByteArray())
            hashed + salt
        }
    }

    fun getHardwareKeyBindingId(): String {
        val key = getOrCreateHardwareKey()
        val cert = keyStore.getCertificate(KEY_ALIAS)
        return if (cert != null) {
            val digest = MessageDigest.getInstance("SHA-256")
            Base64.encodeToString(digest.digest(cert.encoded), Base64.NO_WRAP)
        } else {
            "hardware_key_v1"
        }
    }
}