package com.quantvault.app.data.repository

import android.content.Context
import android.util.Base64
import com.quantvault.app.data.local.EncryptedVaultEntry
import com.quantvault.app.data.local.HardwareKeyManager
import com.quantvault.app.data.local.MetadataEncryptor
import com.quantvault.app.data.local.NativeVault
import com.quantvault.app.data.local.SecurePreferences
import com.quantvault.app.data.local.VaultEntry
import dagger.hilt.android.qualifiers.ApplicationContext
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import javax.inject.Inject
import javax.inject.Singleton
import javax.crypto.KeyGenerator
import com.kroller.argon2.Argon2
import com.kroller.argon2.Argon2Algorithm
import com.kroller.argon2.Argon2Type
import com.kroller.argon2.Argon2Version

@Singleton
class VaultRepository @Inject constructor(
    private val nativeVault: NativeVault,
    private val securePreferences: SecurePreferences,
    @ApplicationContext private val context: Context
) {
    private var vaultData: ByteArray? = null
    private var derivedMasterKey: ByteArray? = null

    private val hardwareKeyManager by lazy { HardwareKeyManager(context) }

    companion object {
        private const val AES_GCM_TAG_LENGTH = 128
        private const val AES_GCM_IV_SIZE = 12
        private const val SALT_SIZE = 32
        private const val KEY_SIZE = 32
    }

    fun isUnlocked(): Boolean = vaultData != null

    fun isDualKeyEnabled(): Boolean = securePreferences.isPinSetup || securePreferences.biometricKeyId != null

    fun isHardwareBacked(): Boolean = hardwareKeyManager.isHardwareKeyAvailable()

    fun getHardwareBindingId(): String? {
        return try {
            hardwareKeyManager.getHardwareKeyBindingId()
        } catch (e: Exception) {
            null
        }
    }

    fun getAuthMode(): String = securePreferences.authMode

    fun setupDualKey(pin: String? = null, useBiometric: Boolean = false): Result<Unit> {
        return try {
            val localKey = if (useBiometric) {
                generateBiometricKey()
            } else {
                deriveKeyFromPin(pin!!)
            }

            val deviceBoundSalt = try {
                hardwareKeyManager.generateDeviceBoundSalt()
            } catch (e: Exception) {
                ByteArray(SALT_SIZE).also { SecureRandom().nextBytes(it) }
            }

            val encryptedLocalKey = encryptLocalKeyWithHardware(localKey, deviceBoundSalt)

            securePreferences.localKeySalt = deviceBoundSalt
            securePreferences.encryptedLocalKey = encryptedLocalKey
            securePreferences.isPinSetup = pin != null
            securePreferences.biometricKeyId = if (useBiometric) "biometric_key_v1" else null
            securePreferences.authMode = if (useBiometric || pin != null) "dual_key" else "oauth_only"

            Result.success(Unit)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    private fun generateBiometricKey(): ByteArray {
        val keyGenerator = KeyGenerator.getInstance("AES")
        keyGenerator.init(256, SecureRandom())
        val key = keyGenerator.generateKey()
        return key.encoded
    }

    private fun deriveKeyFromPin(pin: String): ByteArray {
        val salt = securePreferences.localKeySalt ?: try {
            hardwareKeyManager.generateDeviceBoundSalt()
        } catch (e: Exception) {
            ByteArray(SALT_SIZE).also { SecureRandom().nextBytes(it) }
        }

        val pinBytes = pin.toByteArray(Charsets.UTF_8)

        val argon2 = Argon2.Builder()
            .setIterations(4)
            .setMemory(262144) // 256 MB
            .setParallelism(4)
            .setAlgorithm(Argon2Algorithm.ARGON2ID)
            .setType(Argon2Type.ARGON2)
            .setVersion(Argon2Version.V13)
            .build()

        val hash = argon2.hash(pinBytes, salt)
        return hash.getHashBytes()
    }

    private fun encryptLocalKeyWithHardware(key: ByteArray, salt: ByteArray): ByteArray {
        return try {
            hardwareKeyManager.encryptWithHardwareKey(key) + salt
        } catch (e: Exception) {
            val fallbackKey = deriveFallbackEncryptionKey()
            val iv = ByteArray(AES_GCM_IV_SIZE).also { SecureRandom().nextBytes(it) }
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(fallbackKey, "AES"), GCMParameterSpec(AES_GCM_TAG_LENGTH, iv))
            val encrypted = cipher.doFinal(key)
            iv + encrypted + salt
        }
    }

    private fun decryptLocalKeyWithHardware(): ByteArray {
        val encryptedData = securePreferences.encryptedLocalKey
            ?: throw Exception("No local key found")

        val encryptedKey = encryptedData.copyOfRange(0, encryptedData.size - SALT_SIZE)
        val storedSalt = encryptedData.copyOfRange(encryptedData.size - SALT_SIZE, encryptedData.size)

        return try {
            hardwareKeyManager.decryptWithHardwareKey(encryptedKey)
        } catch (e: Exception) {
            val fallbackKey = deriveFallbackEncryptionKey()
            val iv = encryptedKey.copyOfRange(0, AES_GCM_IV_SIZE)
            val ciphertext = encryptedKey.copyOfRange(AES_GCM_IV_SIZE, encryptedKey.size)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(fallbackKey, "AES"), GCMParameterSpec(AES_GCM_TAG_LENGTH, iv))
            cipher.doFinal(ciphertext)
        }
    }

    private fun deriveFallbackEncryptionKey(): ByteArray {
        val deviceId = try {
            android.provider.Settings.Secure.getString(
                context.contentResolver,
                android.provider.Settings.Secure.ANDROID_ID
            ) ?: "fallback_device_key"
        } catch (e: Exception) {
            "fallback_device_key"
        }

        val salt = "pq-vault-fallback".toByteArray()
        val combined = deviceId.toByteArray() + salt
        val digest = java.security.MessageDigest.getInstance("SHA-256")
        return digest.digest(combined)
    }

    private fun encryptLocalKey(key: ByteArray): ByteArray {
        val keySpec = getMasterEncryptionKey()
        val iv = ByteArray(AES_GCM_IV_SIZE).also { SecureRandom().nextBytes(it) }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, GCMParameterSpec(AES_GCM_TAG_LENGTH, iv))
        return iv + cipher.doFinal(key)
    }

    private fun getMasterEncryptionKey(): SecretKey {
        val deviceId = try {
            android.provider.Settings.Secure.getString(
                context.contentResolver,
                android.provider.Settings.Secure.ANDROID_ID
            ) ?: "default_device_key"
        } catch (e: Exception) {
            "default_device_key"
        }
        val keyBytes = java.security.MessageDigest.getInstance("SHA-256")
            .digest(deviceId.toByteArray())
        return SecretKeySpec(keyBytes, "AES")
    }

    private fun combineKeysWithHardware(oauthToken: String, localKey: ByteArray?): ByteArray {
        val oauthBytes = oauthToken.toByteArray(Charsets.UTF_8)

        val hardwareBinding = try {
            securePreferences.localKeySalt ?: hardwareKeyManager.generateDeviceBoundSalt()
        } catch (e: Exception) {
            localKey ?: ByteArray(32) { 0 }
        }

        val combined = if (localKey != null) {
            oauthBytes + localKey + hardwareBinding
        } else {
            oauthBytes + hardwareBinding
        }

        return hkdf(combined, "pq-vault-master".toByteArray(), 32)
    }

    private fun hkdf(ikm: ByteArray, salt: ByteArray, length: Int): ByteArray {
        val mac = javax.crypto.Mac.getInstance("HmacSHA256")
        mac.init(javax.crypto.spec.SecretKeySpec(salt, "HmacSHA256"))
        val prk = mac.doFinal(ikm)

        mac.init(javax.crypto.spec.SecretKeySpec(prk, "HmacSHA256"))
        mac.update(ByteArray(1) { 1 })
        mac.update("pq-vault-dual-key".toByteArray())
        return mac.doFinal().copyOf(length)
    }

    fun createVault(oauthToken: String, localKey: ByteArray? = null): Result<Unit> {
        val hardwareBinding = try {
            if (isHardwareBacked()) {
                hardwareKeyManager.generateDeviceBoundSalt()
            } else {
                ByteArray(SALT_SIZE).also { SecureRandom().nextBytes(it) }
            }
        } catch (e: Exception) {
            ByteArray(SALT_SIZE).also { SecureRandom().nextBytes(it) }
        }

        val masterKey = if (localKey != null && isDualKeyEnabled()) {
            combineKeysWithHardware(oauthToken, localKey)
        } else if (isHardwareBacked()) {
            combineKeysWithHardware(oauthToken, null)
        } else {
            oauthToken.take(32).padEnd(32, '0').toByteArray()
        }

        derivedMasterKey = masterKey.copyOf()
        return nativeVault.createVault(masterKey.decodeToString()).map { data ->
            vaultData = data
            securePreferences.vaultData = data
        }
    }

    fun unlockVault(oauthToken: String, localKey: ByteArray? = null): Result<Unit> {
        val encryptedData = securePreferences.vaultData
        return if (encryptedData != null) {
            val masterKey = if (localKey != null && isDualKeyEnabled()) {
                combineKeysWithHardware(oauthToken, localKey)
            } else if (isHardwareBacked()) {
                combineKeysWithHardware(oauthToken, null)
            } else {
                oauthToken.take(32).padEnd(32, '0').toByteArray()
            }

            derivedMasterKey = masterKey.copyOf()
            nativeVault.unlockVault(masterKey.decodeToString(), encryptedData).map { data ->
                vaultData = data
            }
        } else {
            Result.failure(Exception("No vault data"))
        }
    }

    fun unlockWithToken(token: String, pin: String? = null): Result<Unit> {
        val localKey = if (pin != null && isDualKeyEnabled()) {
            deriveKeyFromPin(pin)
        } else if (securePreferences.biometricKeyId != null) {
            decryptLocalKeyWithHardware()
        } else null

        return unlockVault(token, localKey)
    }

    fun unlockWithBiometric(oauthToken: String): Result<Unit> {
        val localKey = if (isDualKeyEnabled() && securePreferences.biometricKeyId != null) {
            decryptLocalKeyWithHardware()
        } else null

        return unlockVault(oauthToken, localKey)
    }

    fun verifyPin(pin: String): Boolean {
        return try {
            val derived = deriveKeyFromPin(pin)
            val stored = decryptLocalKeyWithHardware()
            derived.contentEquals(stored)
        } catch (e: Exception) {
            false
        }
    }

    fun disableDualKey(): Result<Unit> {
        return try {
            securePreferences.localKeySalt = null
            securePreferences.encryptedLocalKey = null
            securePreferences.isPinSetup = false
            securePreferences.biometricKeyId = null
            securePreferences.authMode = "oauth_only"
            Result.success(Unit)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    fun lock() {
        vaultData = null
        derivedMasterKey?.fill(0)
        derivedMasterKey = null
    }

    fun getEntries(): Result<List<VaultEntry>> {
        return vaultData?.let { nativeVault.getEntries(it) } ?: Result.failure(Exception("Vault locked"))
    }

    fun addEntry(entry: VaultEntry): Result<Unit> {
        return vaultData?.let { data ->
            nativeVault.addEntry(data, entry).map { newData ->
                vaultData = newData
                securePreferences.vaultData = newData
            }
        } ?: Result.failure(Exception("Vault locked"))
    }

    fun deleteEntry(entryId: String): Result<Unit> {
        return vaultData?.let { data ->
            nativeVault.deleteEntry(data, entryId).map { newData ->
                vaultData = newData
                securePreferences.vaultData = newData
            }
        } ?: Result.failure(Exception("Vault locked"))
    }

    fun exportVault(): ByteArray? = vaultData

    fun hasVault(): Boolean = securePreferences.vaultData != null

    private fun getMetadataEncryptor(): MetadataEncryptor {
        val key = derivedMasterKey ?: throw Exception("Vault is locked")
        return MetadataEncryptor(key)
    }

    fun encryptEntryMetadata(entry: VaultEntry): EncryptedVaultEntry {
        val encryptor = getMetadataEncryptor()
        return encryptor.encryptEntry(entry)
    }

    fun decryptEntryMetadata(encrypted: EncryptedVaultEntry): VaultEntry {
        val encryptor = getMetadataEncryptor()
        return encryptor.decryptEntry(encrypted)
    }

    fun serializeEncryptedEntry(entry: EncryptedVaultEntry): ByteArray {
        val encryptor = getMetadataEncryptor()
        return encryptor.serializeEncryptedEntry(entry)
    }

    fun deserializeEncryptedEntry(data: ByteArray): VaultEntry {
        val encryptor = getMetadataEncryptor()
        val encrypted = encryptor.deserializeEncryptedEntry(data)
        return encryptor.decryptEntry(encrypted)
    }

    fun getFullyEncryptedEntries(): Result<List<EncryptedVaultEntry>> {
        return vaultData?.let {
            val encryptor = getMetadataEncryptor()
            val entries = nativeVault.getEntries(it).getOrNull() ?: emptyList()
            Result.success(entries.map { entry ->
                encryptor.encryptEntry(entry)
            })
        } ?: Result.failure(Exception("Vault locked"))
    }

    fun getFullyEncryptedEntry(entryId: String): Result<EncryptedVaultEntry> {
        return getEntries().map { entries ->
            entries.find { it.id == entryId }?.let { entry ->
                encryptEntryMetadata(entry)
            } ?: throw Exception("Entry not found")
        }
    }
}